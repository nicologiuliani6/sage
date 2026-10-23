#!/usr/bin/env python3
"""Installer di SAGE: un solo comando, da lanciare su un master del cluster.

Mostra i nodi e chiede quali gestire, propone i gruppi (ondate), prepara la chiave
SSH dedicata e la installa sui nodi, configura l'LLM, installa il chart con Helm e
lancia un primo giro in simulazione. Rilanciato su un'installazione esistente parte
dalla configurazione attuale: serve anche per passare al vivo, sospendere i giri o
disinstallare.

Gira con il Python di sistema dei master (3.9 su Rocky 9) e la sola libreria
standard. Nessun valore di un cluster specifico: tutto arriva dal cluster stesso,
dalle risposte o, nelle release, dai dati scritti dalla CI (RELEASE).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import copy
import datetime
import getpass
import gzip
import hashlib
import io
import json
import os
import platform
import re
import select
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# Riempito dalla CI quando pubblica una release (ci/stamp_installer.py): immagine per
# digest, chart con checksum, Helm da scaricare se manca. Vuoto in una copia della repo:
# allora si usano il chart locale e --image.
RELEASE: dict = {}  # sage-install:release

# ------------------------------------------------------------------ costanti

# Valori indipendenti dal cluster: etichette di SAGE, default prudenti, preset pubblici.
GROUP_LABEL = "sage.io/group"
MANAGED_BY = "sage-install"
CONTROL_PLANE_LABELS = ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")
GPU_RESOURCE_PREFIXES = ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/")
# Famiglie supportate (ADR-0017): RHEL (dnf), SUSE (zypper), Debian e Ubuntu (apt).
SUPPORTED_OS = re.compile(
    r"rocky|red hat|rhel|almalinux|centos stream|oracle linux|fedora|amazon linux"
    r"|suse|sles|debian|ubuntu",
    re.I,
)
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
# Unit systemd o pacchetto (stessa regola della configurazione di SAGE).
SERVICE_RE = re.compile(r"^[A-Za-z0-9@._:+-]{1,128}$")
DEFAULT_POLICY = {
    "protected_packages": [
        "kernel*",
        "linux-image-*",
        "glibc",
        "libc6",
        "systemd",
        "dnf",
        "rpm",
        "zypper",
        "libzypp",
        "apt",
        "dpkg",
        "sudo",
        "openssh*",
        "NetworkManager",
        "network-manager",
    ],
    "protected_modules": [
        "nf_*",
        "ip_*",
        "ip6_*",
        "br_netfilter",
        "overlay",
        "vxlan",
        "veth",
        "xt_*",
    ],
}
# Storico delle modifiche fatte con l'installer: ConfigMap <release>-history.
HISTORY_KEY = "history.jsonl"
HISTORY_MAX = 1000
GENERIC_HOST_PARTS = {
    "api",
    "www",
    "com",
    "org",
    "net",
    "io",
    "ai",
    "it",
    "eu",
    "dev",
    "app",
    "cloud",
    "local",
    "internal",
    "localhost",
}
# Pausa tra la fine di un giro e l'inizio del successivo, in minuti.
PAUSES = [
    ("30 minuti", 30),
    ("nessuna: si riparte subito", 0),
    ("2 ore", 120),
    ("6 ore", 360),
]
KERNEL_MODES = [
    ("auto", "nel giro, come il resto (nodo svuotato e riavviato)"),
    ("manual", "mai in automatico (es. nodi GPU con driver legati al kernel)"),
]
PULL_ERRORS = ("ErrImagePull", "ImagePullBackOff", "InvalidImageName")
# Alcuni servizi (es. Groq, dietro Cloudflare) rifiutano con 403 lo User-Agent
# predefinito di urllib: ogni richiesta dell'installer si presenta con il suo.
USER_AGENT = "sage-install/" + RELEASE.get("version", "dev")
START_ERRORS = PULL_ERRORS + ("CreateContainerConfigError", "CreateContainerError")


class Fail(Exception):
    """Errore da mostrare all'utente così com'è, senza traceback."""


# ------------------------------------------------------------------ nodi


@dataclass
class NodeInfo:
    name: str
    ip: str | None
    os_image: str
    kernel: str
    ready: bool
    unschedulable: bool
    gpus: int
    labels: dict

    @property
    def control_plane(self) -> bool:
        return any(label in self.labels for label in CONTROL_PLANE_LABELS)

    @property
    def role(self) -> str:
        return "control-plane" if self.control_plane else "worker"

    @property
    def problem(self) -> str | None:
        """Motivo per cui il nodo non si può gestire, o None."""
        if not self.ip:
            return "senza InternalIP"
        if not SUPPORTED_OS.search(self.os_image):
            return "OS non supportato (servono dnf, zypper o apt)"
        return None

    def label(self, width: int) -> str:
        parts = [self.name.ljust(width), self.role.ljust(13), (self.ip or "-").ljust(15)]
        parts.append(self.os_image)
        if self.gpus:
            parts.append(f"GPU x{self.gpus}")
        if not self.ready:
            parts.append("NotReady")
        if self.unschedulable:
            parts.append("cordon")
        return "  ".join(parts)


def parse_nodes(doc: dict) -> list[NodeInfo]:
    nodes = []
    for item in doc.get("items", []):
        meta, status = item.get("metadata", {}), item.get("status", {})
        ip = next(
            (a["address"] for a in status.get("addresses", []) if a.get("type") == "InternalIP"),
            None,
        )
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in status.get("conditions", [])
        )
        gpus = 0
        for key, value in (status.get("capacity") or {}).items():
            if key.startswith(GPU_RESOURCE_PREFIXES):
                try:
                    gpus += int(value)
                except ValueError:
                    pass
        info = status.get("nodeInfo", {})
        nodes.append(
            NodeInfo(
                name=meta["name"],
                ip=ip,
                os_image=info.get("osImage", "?"),
                kernel=info.get("kernelVersion", "?"),
                ready=ready,
                unschedulable=bool(item.get("spec", {}).get("unschedulable")),
                gpus=gpus,
                labels=meta.get("labels") or {},
            )
        )
    return sorted(nodes, key=lambda n: (not n.control_plane, n.name))


# ------------------------------------------------------------------ gruppi

GROUP_KEYS = (
    "name",
    "selector",
    "order",
    "kernel",
    "canary",
    "allow_remove",
    "allow_mitigate",
    "requires_fallback",
    # campi di versioni precedenti, non più usati: non vengono riscritti
    "window",
    "concurrency",
    "canary_soak_minutes",
)


@dataclass
class Group:
    name: str
    order: int
    kernel: str = "auto"
    canary: str | None = None
    allow_remove: bool = False
    allow_mitigate: bool = False
    requires_fallback: bool = False
    extra: dict = field(default_factory=dict)  # altri campi della configurazione, conservati

    def to_config(self) -> dict:
        out = dict(self.extra)
        out.update(
            name=self.name,
            selector=f"{GROUP_LABEL}={self.name}",
            order=self.order,
            kernel=self.kernel,
            allow_remove=self.allow_remove,
            allow_mitigate=self.allow_mitigate,
        )
        if self.canary:
            out["canary"] = self.canary
        if self.requires_fallback:
            out["requires_fallback"] = True
        return out

    @classmethod
    def from_config(cls, raw: dict) -> Group:
        return cls(
            name=raw["name"],
            order=int(raw["order"]),
            # "window" (finestra di manutenzione) non esiste più: il kernel va nel giro.
            kernel="manual" if raw.get("kernel") == "manual" else "auto",
            canary=raw.get("canary") or None,
            allow_remove=bool(raw.get("allow_remove", False)),
            allow_mitigate=bool(raw.get("allow_mitigate", False)),
            requires_fallback=bool(raw.get("requires_fallback", False)),
            extra={k: v for k, v in raw.items() if k not in GROUP_KEYS},
        )

    def kernel_text(self) -> str:
        if self.kernel == "auto":
            return "kernel nel giro"
        return "kernel solo a mano"


def propose_groups(nodes: list[NodeInfo]) -> tuple[list[Group], dict[str, str]]:
    """Proposta iniziale: prima i worker, poi le GPU, i master per ultimi."""
    buckets = [
        ("worker", [n for n in nodes if not n.control_plane and not n.gpus], "auto"),
        ("gpu", [n for n in nodes if not n.control_plane and n.gpus], "manual"),
        ("master", [n for n in nodes if n.control_plane], "auto"),
    ]
    groups, assignment = [], {}
    for name, members, kernel in buckets:
        if not members:
            continue
        canary = members[0].name if len(members) > 1 else None
        groups.append(Group(name, len(groups) + 1, kernel, canary))
        assignment.update({n.name: name for n in members})
    return groups, assignment


def normalize_groups(groups: list[Group], assignment: dict[str, str]) -> list[Group]:
    """Toglie i gruppi vuoti, i canary non più membri, e rinumera le ondate."""
    kept = [g for g in groups if any(a == g.name for a in assignment.values())]
    kept.sort(key=lambda g: g.order)
    for i, g in enumerate(kept, start=1):
        g.order = i
        if g.canary and assignment.get(g.canary) != g.name:
            g.canary = None
    return kept


def members(assignment: dict[str, str], group: str) -> list[str]:
    return sorted(n for n, g in assignment.items() if g == group)


# ------------------------------------------------------------------ valori del chart


def split_image(ref: str) -> dict:
    """`repo@sha256:...` oppure `repo:tag` -> valori image del chart."""
    if "@" in ref:
        repo, digest = ref.split("@", 1)
        return {"repository": repo, "digest": digest, "tag": ""}
    head, _, last = ref.rpartition("/")
    if ":" in last:
        name, tag = last.rsplit(":", 1)
        return {"repository": f"{head}/{name}" if head else name, "digest": "", "tag": tag}
    raise Fail(f"immagine {ref!r}: serve un digest (@sha256:...) o un tag")


def image_ref(values: dict) -> str | None:
    image = values.get("image") or {}
    repo = image.get("repository")
    if not repo:
        return None
    if image.get("digest"):
        return f"{repo}@{image['digest']}"
    return f"{repo}:{image['tag']}" if image.get("tag") else None


def no_proxy(ips: list[str], api_ip: str | None) -> str:
    hosts = ["localhost", "127.0.0.1", ".svc", ".cluster.local"]
    if api_ip:
        hosts.append(api_ip)
    hosts.extend(sorted(set(ips)))
    return ",".join(hosts)


def proxy_env(proxy: str | None, ips: list[str], api_ip: str | None) -> list[dict]:
    if not proxy:
        return []
    return [
        {"name": "HTTPS_PROXY", "value": proxy},
        {"name": "HTTP_PROXY", "value": proxy},
        {"name": "NO_PROXY", "value": no_proxy(ips, api_ip)},
    ]


def without_proxy(env: list[dict]) -> list[dict]:
    names = {"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}
    return [e for e in env if e.get("name") not in names]


def build_values(
    base: dict,
    *,
    release: str,
    image: str | None,
    pull_secret: str | None,
    pause_minutes: int,
    timezone: str,
    suspend: bool,
    ssh_user: str,
    ssh_port: int,
    llm: dict,
    llm_secret: bool,
    groups: list[Group],
    proxy: list[dict],
    live: bool = False,
) -> dict:
    """Valori completi per Helm, partendo da quelli esistenti (campi ignoti conservati).

    dryRun resta quello attuale e, per una nuova installazione, vero: il passaggio al
    vivo è una scelta esplicita a parte.
    """
    values = copy.deepcopy(base)
    if image:
        values["image"] = {**values.get("image", {}), **split_image(image)}
    if pull_secret:
        values["imagePullSecrets"] = [{"name": pull_secret}]
    # Versioni precedenti: CronJob con orario fisso, sostituito dal controllore in loop.
    values.pop("schedule", None)
    values.pop("timeZone", None)
    values["suspend"] = suspend
    # --live: modalità reale da subito; altrimenti resta quella attuale (simulazione se nuova).
    values["dryRun"] = False if live else bool(base.get("dryRun", True))
    values["secrets"] = {
        **values.get("secrets", {}),
        "ssh": f"{release}-ssh",
        "llm": f"{release}-llm" if llm_secret else "",
    }
    values["extraEnv"] = without_proxy(values.get("extraEnv") or []) + proxy
    config = values.setdefault("config", {})
    config["timezone"] = timezone
    config["controller"] = {**(config.get("controller") or {}), "pause_minutes": pause_minutes}
    ssh = config.setdefault("ssh", {})
    ssh["user"] = ssh_user
    if ssh_port != 22 or "port" in ssh:
        ssh["port"] = ssh_port
    config["llm"] = {**config.get("llm", {}), **llm}
    config["groups"] = [g.to_config() for g in sorted(groups, key=lambda g: g.order)]
    policy = config.setdefault("policy", {})
    for key, default in DEFAULT_POLICY.items():
        policy.setdefault(key, list(default))
    return values


# ------------------------------------------------------------------ registro immagini


def parse_image(ref: str) -> tuple[str, str, str]:
    """(host del registro, percorso, riferimento) per l'API v2 dei registri."""
    if "@" in ref:
        name, reference = ref.split("@", 1)
    else:
        head, _, last = ref.rpartition("/")
        tag_name, _, tag = last.rpartition(":")
        name, reference = (f"{head}/{tag_name}" if head else tag_name), tag
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "registry-1.docker.io", name
        if "/" not in path:
            path = f"library/{path}"
    if host == "docker.io":
        host = "registry-1.docker.io"
    return host, path, reference


def parse_www_authenticate(header: str) -> dict:
    if not header.lower().startswith("bearer "):
        return {}
    return dict(re.findall(r'(\w+)="([^"]*)"', header[7:]))


MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


def image_access(ref: str, opener=urllib.request.urlopen) -> str:
    """'public' se i nodi la scaricano senza credenziali, 'private' se no, 'unknown: ...'."""
    host, path, reference = parse_image(ref)
    url = f"https://{host}/v2/{path}/manifests/{reference}"

    def head(token: str | None):
        headers = {"Accept": MANIFEST_TYPES, "User-Agent": USER_AGENT}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return opener(urllib.request.Request(url, headers=headers, method="HEAD"), timeout=15)

    try:
        head(None)
        return "public"
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return "private"
        auth = parse_www_authenticate(e.headers.get("WWW-Authenticate", ""))
    except (urllib.error.URLError, OSError) as e:
        return f"unknown: {getattr(e, 'reason', e)}"
    if "realm" not in auth:
        return "private"
    query = urllib.parse.urlencode({k: v for k, v in auth.items() if k in ("service", "scope")})
    try:
        token_req = urllib.request.Request(
            f"{auth['realm']}?{query}", headers={"User-Agent": USER_AGENT}
        )
        with opener(token_req, timeout=15) as resp:
            token = json.load(resp).get("token")
        head(token)
        return "public"
    except urllib.error.HTTPError:
        return "private"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"unknown: {getattr(e, 'reason', e)}"


# ------------------------------------------------------------------ SSH sui nodi


def key_blob(public_line: str) -> str:
    parts = public_line.split()
    if len(parts) < 2:
        raise Fail("chiave pubblica non valida")
    return parts[1]


def install_key_command(public_line: str) -> str:
    """Aggiunge la chiave ad authorized_keys se manca (idempotente)."""
    blob, line = shlex.quote(key_blob(public_line)), shlex.quote(public_line.strip())
    return (
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"{{ grep -qF {blob} ~/.ssh/authorized_keys || "
        f"printf '\\n%s\\n' {line} >> ~/.ssh/authorized_keys; }} && "
        "{ command -v restorecon >/dev/null 2>&1 && restorecon -R ~/.ssh >/dev/null 2>&1; true; }"
    )


def remove_key_command(public_line: str) -> str:
    blob = shlex.quote(key_blob(public_line))
    return (
        'f=~/.ssh/authorized_keys; [ -f "$f" ] || exit 0; '
        f"awk -v b={blob} '{{for (i = 1; i <= NF; i++) if ($i == b) next; print}}' "
        '"$f" > "$f.sage-tmp" && cat "$f.sage-tmp" > "$f"; rm -f "$f.sage-tmp"'
    )


# Cosa serve a SAGE su ogni nodo: sudo senza password, un gestore di pacchetti supportato,
# python3 >= 3.9 (collector e Ansible).
CHECK_COMMAND = (
    'p=""; sudo -n true >/dev/null 2>&1 || p="$p sudo"; '
    "{ command -v dnf || command -v zypper || command -v apt-get; } >/dev/null 2>&1 "
    '|| p="$p pm"; '
    "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' "
    '>/dev/null 2>&1 || p="$p python"; echo "SAGE-CHECK:$p"'
)
CHECK_MESSAGES = {
    "sudo": "sudo senza password non disponibile",
    "pm": "nessun gestore di pacchetti supportato (dnf, zypper, apt)",
    "python": "manca python3 >= 3.9 (es. RHEL 8 e SLES 15 hanno il 3.6)",
}


def parse_check(output: str) -> list[str] | None:
    """Problemi trovati dal controllo, oppure None se l'output non è quello atteso."""
    for line in output.splitlines():
        if line.startswith("SAGE-CHECK:"):
            return [CHECK_MESSAGES.get(p, p) for p in line[len("SAGE-CHECK:") :].split()]
    return None


def explain_ssh_error(stderr: str) -> str:
    text = stderr.strip().splitlines()[-1] if stderr.strip() else "errore sconosciuto"
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr or "Host key verification" in stderr:
        return "la chiave host del nodo è cambiata (nodo ricreato?)"
    if "Permission denied" in stderr:
        return "accesso negato"
    if "timed out" in stderr or "No route" in stderr or "Connection refused" in stderr:
        return f"non raggiungibile ({text})"
    return text


# ------------------------------------------------------------------ interfaccia


def parse_selection(text: str, keys: list[str], enabled: set[int]) -> set[int]:
    """Selezione testuale: 'tutti', '1,3', '2-4', nomi. Indici a base zero."""
    text = text.strip().lower()
    if text in ("", "tutti", "all", "*"):
        return set(enabled)
    if text in ("nessuno", "none", "-"):
        return set()
    chosen: set[int] = set()
    for token in re.split(r"[,\s]+", text):
        if not token:
            continue
        span = re.fullmatch(r"(\d+)-(\d+)", token)
        if span:
            lo, hi = int(span.group(1)), int(span.group(2))
            if lo > hi or lo < 1 or hi > len(keys):
                raise ValueError(f"intervallo non valido: {token}")
            chosen.update(range(lo - 1, hi))
        elif token.isdigit():
            if not 1 <= int(token) <= len(keys):
                raise ValueError(f"numero fuori lista: {token}")
            chosen.add(int(token) - 1)
        elif token in [k.lower() for k in keys]:
            chosen.add([k.lower() for k in keys].index(token))
        else:
            raise ValueError(f"non riconosciuto: {token}")
    blocked = sorted(chosen - enabled)
    if blocked:
        raise ValueError("non selezionabili: " + ", ".join(keys[i] for i in blocked))
    return chosen


def _fit(text: str, width: int) -> str:
    return text if len(text) < width else text[: max(width - 2, 1)] + "…"


def wrap(text: str, width: int) -> list[str]:
    """A capo sulle parole; righe vuote e rientri iniziali restano."""
    out = []
    for para in text.split("\n"):
        indent = " " * (len(para) - len(para.lstrip(" ")))
        out.extend(
            textwrap.wrap(
                para,
                max(width, 10),
                subsequent_indent=indent,
                break_on_hyphens=False,
                break_long_words=True,
            )
            or [""]
        )
    return out


def _scroll(cursor: int, top: int, visible: int) -> int:
    if cursor < top:
        return cursor
    if cursor >= top + visible:
        return cursor - visible + 1
    return top


# Widget: logica separata dal terminale, così si prova con i tasti scritti nei test.
# key(tasto) -> True quando la risposta è confermata; rows() -> righe (testo, stile).


class Checklist:
    """Caselle: frecce per muoversi, spazio per spuntare, invio per confermare.

    La riga 0 è "Tutti".
    """

    FOOTER = "frecce: muovi   spazio: seleziona   a: tutti   n: nessuno   invio: conferma"

    def __init__(self, labels, selected, disabled, all_label="Tutti", minimum=1):
        self.labels = list(labels)
        self.disabled = dict(disabled)  # indice -> motivo
        self.selected = {i for i in selected if i not in self.disabled}
        self.all_label = all_label
        self.minimum = minimum
        self.cursor = 0  # 0 = "Tutti", i + 1 = voce i
        self.top = 0
        self.message = ""

    @property
    def enabled(self) -> set[int]:
        return {i for i in range(len(self.labels)) if i not in self.disabled}

    def all_on(self) -> bool:
        return bool(self.enabled) and self.selected >= self.enabled

    def key(self, k: str) -> bool:
        self.message = ""
        k = k.lower() if len(k) == 1 else k
        rows = len(self.labels) + 1
        if k in ("up", "k"):
            self.cursor = (self.cursor - 1) % rows
        elif k in ("down", "j", "tab"):
            self.cursor = (self.cursor + 1) % rows
        elif k == "home":
            self.cursor = 0
        elif k == "end":
            self.cursor = rows - 1
        elif k == "a":
            self.selected = set(self.enabled)
        elif k == "n":
            self.selected = set()
        elif k in ("space", "x"):
            if self.cursor == 0:
                self.selected = set() if self.all_on() else set(self.enabled)
            else:
                i = self.cursor - 1
                if i in self.disabled:
                    self.message = f"non selezionabile: {self.disabled[i]}"
                else:
                    self.selected ^= {i}
        elif k == "enter":
            if len(self.selected) < self.minimum:
                self.message = f"seleziona almeno {self.minimum} voce"
                return False
            return True
        return False

    def rows(self, width: int, height: int) -> list:
        mark = "x" if self.all_on() else ("-" if self.selected else " ")
        items = [(f"[{mark}] {self.all_label} ({len(self.selected)} scelti)", False)]
        for i, text in enumerate(self.labels):
            box = "x" if i in self.selected else " "
            extra = f"  ({self.disabled[i]})" if i in self.disabled else ""
            items.append((f"[{box}] {text}{extra}", i in self.disabled))
        visible = max(height, 3)
        self.top = _scroll(self.cursor, self.top, visible)
        out = []
        for i in range(self.top, min(self.top + visible, len(items))):
            text, dim = items[i]
            current = i == self.cursor
            style = "current" if current else ("dim" if dim else "")
            out.append((_fit(("> " if current else "  ") + text, width), style))
        return out


class Menu:
    """Scelta singola con le frecce (o il numero della voce)."""

    FOOTER = "frecce: muovi   invio: conferma"

    def __init__(self, options, default=0):
        self.options = list(options)
        self.cursor = default
        self.top = 0
        self.message = ""

    def key(self, k: str) -> bool:
        if k in ("up", "k"):
            self.cursor = (self.cursor - 1) % len(self.options)
        elif k in ("down", "j", "tab"):
            self.cursor = (self.cursor + 1) % len(self.options)
        elif k.isdigit() and 1 <= int(k) <= len(self.options):
            self.cursor = int(k) - 1
        elif k in ("enter", "space"):
            return True
        return False

    def rows(self, width: int, height: int) -> list:
        visible = max(height, 3)
        self.top = _scroll(self.cursor, self.top, visible)
        out = []
        for i in range(self.top, min(self.top + visible, len(self.options))):
            current = i == self.cursor
            text = ("> " if current else "  ") + self.options[i]
            out.append((_fit(text, width), "current" if current else ""))
        return out


class TextInput:
    """Campo di testo su una riga, con il valore predefinito già scritto."""

    FOOTER = "invio: conferma   frecce: sposta il cursore   ctrl-u: cancella tutto"

    def __init__(self, default: str = "", secret: bool = False, check=None):
        self.value = default or ""
        self.pos = len(self.value)
        self.secret = secret
        self.check = check
        self.message = ""

    def key(self, k: str) -> bool:
        self.message = ""
        if k == "enter":
            problem = self.check(self.value.strip()) if self.check else None
            if problem:
                self.message = problem
                return False
            return True
        if k == "backspace":
            if self.pos:
                self.value = self.value[: self.pos - 1] + self.value[self.pos :]
                self.pos -= 1
        elif k == "delete":
            self.value = self.value[: self.pos] + self.value[self.pos + 1 :]
        elif k == "left":
            self.pos = max(self.pos - 1, 0)
        elif k == "right":
            self.pos = min(self.pos + 1, len(self.value))
        elif k == "home":
            self.pos = 0
        elif k == "end":
            self.pos = len(self.value)
        elif k == "ctrl-u":
            self.value, self.pos = "", 0
        else:
            char = " " if k == "space" else k
            if len(char) == 1 and char.isprintable():
                self.value = self.value[: self.pos] + char + self.value[self.pos :]
                self.pos += 1
        return False

    def rows(self, width: int, height: int) -> list:
        shown = "•" * len(self.value) if self.secret else self.value
        room = max(width - 4, 10)
        start = max(0, self.pos - room + 1)
        visible = shown[start : start + room]
        cursor = self.pos - start
        before, at, after = (
            visible[:cursor],
            visible[cursor : cursor + 1] or " ",
            visible[cursor + 1 :],
        )
        return [(("> " + before, at, after), "input")]


def common_suffix(names: list[str]) -> str:
    """Parte finale comune ai nomi, da un separatore in poi (es. "-cluster-x")."""
    if len(names) < 2:
        return ""
    rev = [n[::-1] for n in names]
    common = os.path.commonprefix(rev)[::-1]
    cut = min((common.find(c) for c in "-." if c in common), default=-1)
    suffix = common[cut:] if cut >= 0 else ""
    if len(suffix) < 4 or any(len(n) <= len(suffix) for n in names):
        return ""
    return suffix


class GroupBoard:
    """Gruppi in colonne: frecce per muoversi, spazio sposta il nodo nella colonna accanto."""

    FOOTER = "frecce: muovi   spazio: sposta nella colonna accanto   c: canary   invio: conferma"

    def __init__(self, groups: list[str], assignment: dict, canaries: dict):
        self.groups = list(groups)
        self.assignment = dict(assignment)
        self.canaries = dict(canaries)
        self.suffix = common_suffix(list(assignment))
        self.col = 0
        self.row = 0
        self.message = ""

    def column(self, i: int) -> list[str]:
        return sorted(n for n, g in self.assignment.items() if g == self.groups[i])

    def current(self):
        nodes = self.column(self.col)
        return nodes[self.row] if nodes else None

    def key(self, k: str) -> bool:
        self.message = ""
        k = k.lower() if len(k) == 1 else k
        count = len(self.groups)
        if k in ("left", "h"):
            self.col = (self.col - 1) % count
        elif k in ("right", "l", "tab"):
            self.col = (self.col + 1) % count
        elif k in ("up", "k"):
            self.row -= 1
        elif k in ("down", "j"):
            self.row += 1
        elif k in ("space", "x"):
            node = self.current()
            if node:
                old = self.groups[self.col]
                if self.canaries.get(old) == node:
                    self.canaries[old] = None
                self.col = (self.col + 1) % count
                self.assignment[node] = self.groups[self.col]
                self.row = self.column(self.col).index(node)
        elif k == "c":
            node = self.current()
            group = self.groups[self.col]
            if node:
                self.canaries[group] = None if self.canaries.get(group) == node else node
        elif k == "enter":
            return True
        size = len(self.column(self.col))
        self.row = max(0, min(self.row, size - 1))
        return False

    def short(self, name: str) -> str:
        return name[: -len(self.suffix)] + "-…" if self.suffix else name

    def rows(self, width: int, height: int) -> list:
        count = len(self.groups)
        cell = max((width - 3 * (count - 1)) // count, 8)
        heads = []
        for i, g in enumerate(self.groups):
            heads.append((_fit(f"{g} ({len(self.column(i))})", cell + 1).ljust(cell), "bold"))
        out = [self._join(heads), self._join([("─" * cell, "dim")] * count)]
        columns = [self.column(i) for i in range(count)]
        depth = max([len(c) for c in columns] + [1])
        for r in range(min(depth, max(height - 2, 1))):
            cells = []
            for i, nodes in enumerate(columns):
                if r < len(nodes):
                    node = nodes[r]
                    mark = "*" if self.canaries.get(self.groups[i]) == node else " "
                    current = i == self.col and r == self.row
                    # Nome breve; quello sotto il cursore per intero.
                    name = node if current else self.short(node)
                    text = _fit(("> " if current else "  ") + name + mark, cell + 1)
                    cells.append((text.ljust(cell), "current" if current else ""))
                else:
                    cells.append((" " * cell, ""))
            out.append(self._join(cells))
        node = self.current()
        if node:
            group = self.groups[self.col]
            out.append(("", ""))
            out.append((_fit(f"{node}  (gruppo {group})", width), "bold"))
        return out

    @staticmethod
    def _join(cells: list) -> tuple:
        parts = []
        for i, cell in enumerate(cells):
            if i:
                parts.append(("   ", ""))
            parts.append(cell)
        return (parts, "segments")


def read_key(fd: int) -> str:
    """Un tasto: nome ("up", "enter", ...) oppure il carattere, maiuscole comprese."""
    data = os.read(fd, 1)
    if data == b"\x1b":
        if not select.select([fd], [], [], 0.05)[0]:
            return "esc"
        second = os.read(fd, 1)
        if second not in (b"[", b"O"):
            return ""
        third = os.read(fd, 1)
        if third.isdigit():  # es. ESC [ 3 ~
            seq = third
            while True:
                more = os.read(fd, 1)
                if more in (b"~", b""):
                    break
                seq += more
            return {b"1": "home", b"7": "home", b"3": "delete", b"4": "end", b"8": "end"}.get(
                seq, ""
            )
        arrows = {b"A": "up", b"B": "down", b"C": "right", b"D": "left", b"H": "home", b"F": "end"}
        return arrows.get(third, "")
    named = {
        b"\r": "enter",
        b"\n": "enter",
        b" ": "space",
        b"\t": "tab",
        b"\x7f": "backspace",
        b"\x08": "backspace",
        b"\x15": "ctrl-u",
        b"\x01": "home",
        b"\x05": "end",
    }
    if data in named:
        return named[data]
    if data == b"\x03":
        raise KeyboardInterrupt
    if data in (b"\x04", b""):
        raise EOFError
    first = data[0]
    extra = 1 if 0xC0 <= first < 0xE0 else 2 if 0xE0 <= first < 0xF0 else 3 if first >= 0xF0 else 0
    while extra:
        more = os.read(fd, extra)
        if not more:
            break
        data += more
        extra -= len(more)
    text = data.decode(errors="ignore")
    return text if text.isprintable() else ""


class LineUI:
    """Domande su righe successive: terminali non interattivi e --no-tui."""

    tui = False

    def __init__(self, color: bool):
        self.color = color
        self.context = ""

    def _c(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def header(self, text: str) -> None:
        print(self._c("1", text))

    def cluster(self, text: str) -> None:
        self.context = text
        print(f"Cluster: {text}")

    def step(self, number: int, total: int, name: str) -> None:
        print("\n" + self._c("1", f"{number}/{total}. {name}"))

    def info(self, text: str = "") -> None:
        print(text)

    def ok(self, text: str) -> None:
        print(self._c("32", "ok ") + text)

    def warn(self, text: str) -> None:
        print(self._c("33", "attenzione: ") + text)

    def error(self, text: str) -> None:
        print(self._c("31", "errore: ") + text, file=sys.stderr)

    def busy(self, text: str) -> None:
        print(text)

    def close(self) -> None:
        pass

    def _help(self, help: str | None) -> None:
        if help:
            print(help)

    def ask(self, prompt: str, default: str | None = None, check=None, help=None) -> str:
        self._help(help)
        suffix = f" [{default}]" if default not in (None, "") else ""
        while True:
            answer = input(f"{prompt}{suffix}: ").strip()
            if not answer and default is not None:
                answer = default
            problem = check(answer) if check else (None if answer else "risposta obbligatoria")
            if not problem:
                return answer
            self.warn(problem)

    def ask_int(self, prompt: str, default: int, minimum: int = 1, help=None) -> int:
        def check(v):
            return None if v.isdigit() and int(v) >= minimum else f"un intero >= {minimum}"

        return int(self.ask(prompt, str(default), check, help))

    def yes(self, prompt: str, default: bool = True, help=None) -> bool:
        self._help(help)
        hint = "S/n" if default else "s/N"
        while True:
            answer = input(f"{prompt} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("s", "si", "sì", "y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def secret(self, prompt: str, help=None) -> str:
        self._help(help)
        return getpass.getpass(f"{prompt} (non viene mostrata): ").strip()

    def choose(self, title: str, options: list[str], default: int = 0, help=None) -> int:
        self._help(help)
        print(self._c("1", title))
        for i, text in enumerate(options, start=1):
            print(f"  {i}. {text}")

        def check(v):
            return None if v.isdigit() and 1 <= int(v) <= len(options) else "scegli un numero"

        return int(self.ask("Scelta", str(default + 1), check)) - 1

    def checklist(self, title, keys, labels, selected, disabled, minimum=1, help=None) -> set:
        self._help(help)
        print(self._c("1", title))
        for i, text in enumerate(labels, start=1):
            mark = "x" if i - 1 in selected else " "
            extra = f"  ({disabled[i - 1]})" if i - 1 in disabled else ""
            print(f"  {i:>3}. [{mark}] {text}{extra}")
        enabled = {i for i in range(len(labels)) if i not in disabled}
        while True:
            answer = input("Quali? (invio = quelli segnati; tutti, 1,3, 2-5, nomi): ")
            try:
                chosen = (
                    set(selected) if not answer.strip() else parse_selection(answer, keys, enabled)
                )
            except ValueError as e:
                self.warn(str(e))
                continue
            if len(chosen) >= minimum:
                return chosen
            self.warn(f"seleziona almeno {minimum} voce")

    def board(self, title, groups, assignment, canaries, help=None):
        """Senza schermo intero: un nodo alla volta, scegliendo il gruppo."""
        assignment, canaries = dict(assignment), dict(canaries)
        while True:
            nodes = sorted(assignment)
            labels = [f"{n}  (in {assignment[n]})" for n in nodes]
            pick = self.choose(title, ["Fatto"] + labels, 0, help)
            if pick == 0:
                return assignment, canaries
            node = nodes[pick - 1]
            old = assignment[node]
            target = self.choose(f"In quale gruppo va {node}?", groups, groups.index(old))
            if canaries.get(old) == node:
                canaries[old] = None
            assignment[node] = groups[target]


class ScreenUI(LineUI):
    """Installer a schermo intero: una domanda per pagina.

    Usa lo schermo alternativo del terminale; alla chiusura torna a quello normale e
    ristampa i messaggi, così quello che è successo resta visibile.
    """

    tui = True
    NOTES = 6

    def __init__(self, color: bool):
        super().__init__(color)
        self.title = "SAGE"
        self.step_info = None
        self.notes: list = []
        self.transcript: list = []
        self.active = False
        self.fd = None
        self.saved = None
        self.busy_text = None

    # --- terminale
    def start(self) -> None:
        if self.active:
            return
        import termios
        import tty

        self.fd = sys.stdin.fileno()
        self.saved = termios.tcgetattr(self.fd)
        tty.setcbreak(self.fd)
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()
        self.active = True

    def close(self) -> None:
        if not self.active:
            return
        import termios

        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)
        sys.stdout.write("\x1b[?25h\x1b[?1049l")
        sys.stdout.flush()
        self.active = False
        for kind, text in self.transcript:
            self._emit(kind, text)
        self.transcript = []

    # --- messaggi
    def _emit(self, kind: str, text: str) -> None:
        {"ok": LineUI.ok, "warn": LineUI.warn, "info": LineUI.info}[kind](self, text)

    def _note(self, kind: str, text: str) -> None:
        if not self.active:
            self._emit(kind, text)
            return
        self.notes.append((kind, text))
        self.transcript.append((kind, text))
        if self.busy_text:
            self._render(self.busy_text, None, None)

    def header(self, text: str) -> None:
        self.title = text

    def cluster(self, text: str) -> None:
        self.context = text

    def step(self, number: int, total: int, name: str) -> None:
        self.step_info = (number, total, name)
        self.notes = []

    def info(self, text: str = "") -> None:
        self._note("info", text)

    def ok(self, text: str) -> None:
        self._note("ok", text)

    def warn(self, text: str) -> None:
        self._note("warn", text)

    def error(self, text: str) -> None:
        self.close()
        super().error(text)

    def busy(self, text: str) -> None:
        self.start()
        self.busy_text = text
        self._render(text, None, None)

    # --- disegno
    def _size(self) -> tuple[int, int]:
        size = shutil.get_terminal_size()
        # Alcuni terminali (es. pty senza dimensioni) riportano 0x0.
        return max(size.columns or 80, 40), max(size.lines or 24, 12)

    def _style(self, text: str, style: str) -> str:
        codes = {"current": "1;36", "dim": "2", "bold": "1"}
        return self._c(codes[style], text) if style in codes else text

    def _row(self, row, width: int) -> str:
        content, style = row
        if style == "segments":
            return "  " + "".join(self._style(text, s) for text, s in content)
        if style == "input":
            before, at, after = content
            return "  " + before + self._c("7", at) + after
        return self._style("  " + content, style)

    def _render(self, title: str, help, widget) -> None:
        width, height = self._size()
        bar = f" {self.title}"
        right = f"{self.context} " if self.context else ""
        bar = _fit(bar + " " * max(1, width - len(bar) - len(right)) + right, width + 1)
        top = [self._c("7", bar.ljust(width)[:width]), ""]
        if self.step_info:
            n, total, name = self.step_info
            dots = "●" * n + "○" * (total - n)
            top.append(self._c("1", f" Passo {n} di {total}: {name}") + "   " + self._c("36", dots))
            top.append("")
        top += [self._c("1", " " + line) for line in wrap(title, width - 2)]
        top += ["  " + line for line in wrap(help or "", width - 4)] if help else []
        top.append("")
        notes = []
        for kind, text in self.notes[-self.NOTES :]:
            mark = {"ok": self._c("32", "✓ "), "warn": self._c("33", "! ")}.get(kind, "  ")
            notes.append(" " + mark + _fit(text, width - 4))
        footer = widget.FOOTER if widget else "attendi..."
        room = height - len(top) - len(notes) - 3
        body = []
        if widget:
            body = [self._row(r, width - 4) for r in widget.rows(width - 4, max(room, 3))]
            if widget.message:
                body.append(self._c("33", "  " + _fit(widget.message, width - 3)))
        lines = (top + body)[: height - len(notes) - 2]
        lines += [""] * (height - len(lines) - len(notes) - 2)
        lines += [""] + notes
        lines.append(self._c("7", _fit(" " + footer, width + 1).ljust(width)[:width]))
        out = "\x1b[H" + "\n".join(line + "\x1b[K" for line in lines[:height]) + "\x1b[J"
        sys.stdout.write(out)
        sys.stdout.flush()

    def _page(self, title: str, help, widget):
        self.start()
        self.busy_text = None
        while True:
            self._render(title, help, widget)
            if widget.key(read_key(self.fd)):
                return widget
            # Tasti già arrivati (es. testo incollato): si elaborano prima di ridisegnare.
            while select.select([self.fd], [], [], 0)[0]:
                if widget.key(read_key(self.fd)):
                    return widget

    # --- domande
    def ask(self, prompt: str, default: str | None = None, check=None, help=None) -> str:
        def full_check(v):
            if not v and default is None and not check:
                return "risposta obbligatoria"
            return check(v) if check else (None if v else "risposta obbligatoria")

        return self._page(prompt, help, TextInput(default or "", check=full_check)).value.strip()

    def secret(self, prompt: str, help=None) -> str:
        return self._page(prompt, help, TextInput("", secret=True)).value.strip()

    def yes(self, prompt: str, default: bool = True, help=None) -> bool:
        return self._page(prompt, help, Menu(["Sì", "No"], 0 if default else 1)).cursor == 0

    def choose(self, title: str, options: list[str], default: int = 0, help=None) -> int:
        return self._page(title, help, Menu(options, default)).cursor

    def checklist(self, title, keys, labels, selected, disabled, minimum=1, help=None) -> set:
        widget = Checklist(labels, selected, disabled, minimum=minimum)
        return self._page(title, help, widget).selected

    def board(self, title, groups, assignment, canaries, help=None):
        widget = GroupBoard(groups, assignment, canaries)
        self._page(title, help, widget)
        return widget.assignment, widget.canaries


# ------------------------------------------------------------------ comandi esterni


def transient_api_error(proc: subprocess.CompletedProcess) -> bool:
    text = (proc.stderr or "") + (proc.stdout or "")[-500:]
    return proc.returncode != 0 and any(e in text for e in TRANSIENT_API_ERRORS)


def retry_api(call, check=True, sleep=time.sleep) -> subprocess.CompletedProcess:
    """Ripete un comando kubectl o helm se fallisce per un errore di rete verso l'API
    (attese di 2, 4, 8 e 16 secondi). Gli altri errori passano subito."""
    proc = call()
    for attempt in range(API_RETRIES):
        if not transient_api_error(proc):
            break
        sleep(2 ** (attempt + 1))
        proc = call()
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise Fail(f"{' '.join(proc.args[:3])} fallito: {detail}")
    return proc


def run(args, input=None, check=True, timeout=None) -> subprocess.CompletedProcess:
    try:
        # Senza input, stdin chiuso: ssh e kubectl non devono leggere dal terminale.
        stdin = subprocess.DEVNULL if input is None else None
        proc = subprocess.run(
            args,
            input=input,
            stdin=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise Fail(f"comando non trovato: {args[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise Fail(f"tempo scaduto: {' '.join(args[:3])}") from e
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise Fail(f"{' '.join(args[:3])} fallito: {detail}")
    return proc


def download(url: str, sha256: str | None, limit: int = 200 * 1024 * 1024) -> bytes:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(limit + 1)
    except (urllib.error.URLError, OSError) as e:
        raise Fail(f"download di {url} fallito: {getattr(e, 'reason', e)}") from e
    if len(data) > limit:
        raise Fail(f"{url}: file troppo grande")
    if sha256 and hashlib.sha256(data).hexdigest() != sha256:
        raise Fail(f"{url}: checksum diverso da quello atteso, file scartato")
    return data


def local_timezone() -> str:
    try:
        tz = Path("/etc/timezone").read_text().strip()
        if valid_timezone(tz):
            return tz
    except OSError:
        pass
    target = os.path.realpath("/etc/localtime")
    if "zoneinfo/" in target:
        tz = target.split("zoneinfo/", 1)[1]
        if valid_timezone(tz):
            return tz
    return "UTC"


def valid_timezone(tz: str) -> bool:
    try:
        import zoneinfo

        zoneinfo.ZoneInfo(tz)
        return True
    except Exception:
        return False


def llm_models(base_url: str, key: str | None) -> tuple[str | None, list[str]]:
    """(problema o None, modelli offerti dall'endpoint)."""
    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/models", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "chiave rifiutata (HTTP 401)", []
        if e.code == 403:
            return "accesso negato (HTTP 403): chiave senza permessi o richiesta bloccata", []
        return f"risposta HTTP {e.code}", []
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"non raggiungibile da qui ({getattr(e, 'reason', e)})", []
    items = data.get("data", []) if isinstance(data, dict) else []
    ids = sorted({m["id"] for m in items if isinstance(m, dict) and isinstance(m.get("id"), str)})
    return None, ids


# Stesso controllo di llm_models, eseguito in un pod: per gli indirizzi che si risolvono
# solo dentro il cluster (es. http://ollama.llm.svc:11434/v1). La chiave arriva da stdin,
# non dagli argomenti, così non resta nella definizione del pod.
CLUSTER_LLM_CHECK = """
import json, sys, urllib.error, urllib.request
url, key = sys.argv[1], sys.stdin.readline().strip()
headers = {"Authorization": "Bearer " + key} if key else {}
try:
    req = urllib.request.Request(url.rstrip("/") + "/models", headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.load(resp)
    items = data.get("data", []) if isinstance(data, dict) else []
    ids = sorted({m["id"] for m in items if isinstance(m, dict) and isinstance(m.get("id"), str)})
    out = {"problem": None, "models": ids}
except urllib.error.HTTPError as e:
    out = {"problem": "risposta HTTP %d" % e.code, "models": []}
except Exception as e:
    out = {"problem": "non raggiungibile dal cluster (%s)" % getattr(e, "reason", e), "models": []}
print("SAGE-LLM:" + json.dumps(out))
"""


def parse_cluster_llm_check(output: str) -> tuple[str | None, list[str]]:
    for line in reversed(output.splitlines()):
        if line.startswith("SAGE-LLM:"):
            try:
                data = json.loads(line[len("SAGE-LLM:") :])
                return data.get("problem"), [str(m) for m in data.get("models") or []]
            except ValueError:
                break
    return "controllo dal cluster non riuscito", []


def endpoint_name(base_url: str, taken) -> str:
    """Nome breve dall'host (es. api.esempio.com -> esempio), unico tra quelli usati."""
    host = urllib.parse.urlparse(base_url).hostname or ""
    parts = [] if re.fullmatch(r"[0-9.:]+", host) else host.split(".")
    parts = [p for p in parts if p and p not in GENERIC_HOST_PARTS]
    base = re.sub(r"[^a-z0-9-]+", "-", (parts[0] if parts else "llm").lower()).strip("-")[:40]
    base = base or "llm"
    name, i = base, 2
    while name in taken:
        name, i = f"{base}-{i}", i + 1
    return name


def llm_text(llm: dict) -> str:
    return ", ".join(f"{e['name']} ({e['model']})" for e in llm.get("endpoints", []))


def llm_names(llm: dict, keys: dict) -> list[str]:
    return [e["name"] for e in llm.get("endpoints", []) if e.get("api_key_env") in keys]


# ------------------------------------------------------------------ storico


def who_text(kube_user: str | None) -> str:
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    host = socket.gethostname().split(".")[0]
    return f"{user}@{host}" + (f" ({kube_user})" if kube_user else "")


PHASES = {
    "scan": "controllo completo in corso",
    "remediate": "remediation dei nodi",
    "pause": "in pausa",
}


def progress_lines(doc: dict | None) -> tuple[list[str], str | None]:
    """Righe leggibili sullo stato del controllore e il Job in corso (o None)."""
    if not doc or not doc.get("cycle"):
        return ["Nessun giro ancora: il controllore non ha salvato uno stato."], None
    cycle = doc["cycle"]
    lines = [
        f"Giro {cycle.get('id')}: {PHASES.get(cycle.get('phase'), cycle.get('phase'))}"
        f" (iniziato {cycle.get('started', '?')}, motivo: {cycle.get('reason', '?')})"
    ]
    if doc.get("halted"):
        lines.append(f"FERMO: {doc.get('halt_reason')}")
    running = {
        n: st.get("job")
        for n, st in (doc.get("nodes") or {}).items()
        if st.get("status") == "running"
    }
    results = cycle.get("results") or {}
    for node in cycle.get("queue") or []:
        if node in running:
            state = f"remediation in corso ({running[node]})"
        else:
            state = (results.get(node) or {}).get("outcome", "da fare")
        lines.append(f"  {node}: {state}")
    if cycle.get("phase") == "pause":
        lines.append(f"Prossimo giro: {cycle.get('pause_until')}")
    if cycle.get("error"):
        lines.append(f"Errore: {cycle['error']}")
    job = next(iter(running.values()), None)
    if job is None and cycle.get("phase") == "scan":
        job = cycle.get("scan_job")
    if job is None:
        lines.append("Nessun lavoro in corso adesso.")
    return lines, job


# Il controllore guarda le richieste ogni 30 secondi (controller.poll_seconds).
SCAN_START_WAIT = 600
# Ogni quanto --resume rilegge lo stato quando non c'è un log da seguire.
RESUME_POLL = 10
# Riconnessioni al log di un Job prima di lasciar perdere.
LOG_RECONNECTS = 20
# Errori di rete verso l'API di Kubernetes che conviene ritentare (bilanciatore che chiude
# le connessioni, apiserver lento): il comando non è arrivato o la risposta si è persa.
TRANSIENT_API_ERRORS = (
    "Unable to connect to the server",
    "connection refused",
    "TLS handshake timeout",
    "i/o timeout",
    "unexpected EOF",
    "http2: client connection lost",
)
API_RETRIES = 4
# Dove l'eseguibile si installa come comando di sistema.
DEFAULT_BIN = "/usr/local/bin/sage"


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_k8s_time(value) -> float:
    """'2026-10-22T17:05:03Z' -> secondi epoch (0 se manca)."""
    if not value:
        return 0.0
    stamp = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return stamp.replace(tzinfo=datetime.timezone.utc).timestamp()


def history_entry(action: str, changes, note, kube_user, revision) -> dict:
    entry = {
        "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "kube_user": kube_user,
        "action": action,
        "installer": RELEASE.get("version", "dev"),
        "changes": list(changes),
    }
    if os.environ.get("SUDO_USER"):
        entry["sudo_user"] = os.environ["SUDO_USER"]
    if note:
        entry["note"] = note
    if revision:
        entry["helm_revision"] = revision
    return entry


def parse_history(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            entries.append(item)
    return entries


def history_line(e: dict) -> str:
    when = str(e.get("time", "?"))[:16].replace("T", " ")
    who = e.get("sudo_user") or e.get("user", "?")
    host = str(e.get("host", "?")).split(".")[0]
    note = f": {e['note']}" if e.get("note") else ""
    return f"{when}  {who}@{host}  {e.get('action', '?')}{note}"


def history_details(e: dict) -> str:
    who = e.get("user", "?")
    if e.get("sudo_user"):
        who = f"{e['sudo_user']} (con sudo come {who})"
    lines = [
        f"Quando      {e.get('time', '?')}",
        f"Chi         {who} su {e.get('host', '?')}",
        f"Kubernetes  {e.get('kube_user') or '?'}",
        f"Azione      {e.get('action', '?')}",
        f"Installer   {e.get('installer', '?')}"
        + (f", revisione Helm {e['helm_revision']}" if e.get("helm_revision") else ""),
    ]
    if e.get("note"):
        lines.append(f"Nota        {e['note']}")
    changes = e.get("changes") or []
    lines.append("Modifiche" + ("" if changes else "  nessuna registrata"))
    lines += [f"  {c}" for c in changes]
    return "\n".join(lines)


def _flatten(value, path: str, out: dict) -> None:
    if isinstance(value, dict) and value:
        for k, v in value.items():
            _flatten(v, f"{path}.{k}" if path else str(k), out)
    elif (
        isinstance(value, list)
        and value
        and all(isinstance(i, dict) and "name" in i for i in value)
    ):
        for item in value:
            rest = {k: v for k, v in item.items() if k != "name"}
            _flatten(rest or True, f"{path}[{item['name']}]", out)
    else:
        out[path] = value


def _fmt(value) -> str:
    return _fit(json.dumps(value, ensure_ascii=False), 80)


def diff_values(old: dict, new: dict) -> list[str]:
    """Differenze leggibili tra due insiemi di valori Helm (liste per nome)."""
    a, b = {}, {}
    _flatten(old, "", a)
    _flatten(new, "", b)
    changes = []
    for path in sorted(set(a) | set(b)):
        if path not in a:
            changes.append(f"{path}: {_fmt(b[path])} (nuovo)")
        elif path not in b:
            changes.append(f"{path}: {_fmt(a[path])} (tolto)")
        elif a[path] != b[path]:
            changes.append(f"{path}: {_fmt(a[path])} → {_fmt(b[path])}")
    return changes


def node_label_changes(nodes, assignment: dict) -> list[str]:
    changes = []
    for n in nodes:
        old, new = n.labels.get(GROUP_LABEL), assignment.get(n.name)
        if old == new:
            continue
        if old is None:
            changes.append(f"nodo {n.name}: aggiunto al gruppo {new}")
        elif new is None:
            changes.append(f"nodo {n.name}: non più gestito (era in {old})")
        else:
            changes.append(f"nodo {n.name}: dal gruppo {old} al gruppo {new}")
    return changes


def split_list(text: str) -> list:
    return [x.strip() for x in re.split(r"[,\s]+", text or "") if x.strip()]


def env_name(endpoint: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", endpoint.upper()) + "_API_KEY"


# ------------------------------------------------------------------ installer


class Installer:
    STEPS = 6

    def __init__(self, args, ui):
        self.args = args
        self.ui = ui
        self.ns = args.namespace
        self.release = args.release
        self.tmp = Path(tempfile.mkdtemp(prefix="sage-install-"))
        os.chmod(self.tmp, 0o700)
        self.helm_bin = "helm"
        self.port = args.ssh_port or 22
        self.pending_secrets: list = []  # creati solo dopo la conferma finale
        self.kube_user = None

    # --- comandi
    def kubectl(self, *args, ns=False, input=None, check=True):
        cmd = ["kubectl"]
        if self.args.context:
            cmd += ["--context", self.args.context]
        if ns:
            cmd += ["-n", self.ns]
        return retry_api(
            lambda: run(cmd + list(args), input=input, check=False, timeout=120), check
        )

    def kjson(self, *args, ns=False):
        return json.loads(self.kubectl(*args, "-o", "json", ns=ns).stdout)

    def helm(self, *args, check=True):
        cmd = [self.helm_bin] + list(args) + ["-n", self.ns]
        if self.args.context:
            cmd += ["--kube-context", self.args.context]
        return retry_api(lambda: run(cmd, check=False, timeout=600), check)

    def ssh(self, ip, command, user, key=None, known_hosts=None, input=None):
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(self.port)]
        cmd += ["-o", "StrictHostKeyChecking=accept-new"]
        if key:
            cmd += ["-i", str(key), "-o", "IdentitiesOnly=yes"]
        if known_hosts:
            cmd += ["-o", f"UserKnownHostsFile={known_hosts}"]
        return run(cmd + [f"{user}@{ip}", command], input=input, check=False, timeout=60)

    # --- avvio
    def run(self) -> int:
        try:
            return self._run()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self) -> int:
        ui = self.ui
        ui.header(f"SAGE {RELEASE.get('version', '(copia locale della repo)')}")
        self.install_command()
        ui.busy("Controllo il cluster e i permessi...")
        self.preflight()
        current = self.current_values()
        if self.args.dashboard or self.args.resume:
            if current is None:
                raise Fail(f"SAGE non è installato (release {self.release}, namespace {self.ns})")
            if self.args.resume:
                return self.resume_view()
            return self.open_dashboard(current)
        if current is None:
            return self.configure({}, new=True)
        if self.args.reinstall:
            if self.uninstall(current, reinstall=True) != 0:
                return 0
            return self.configure({}, new=True)
        if self.args.live:
            if not current.get("dryRun", True):
                ui.ok("SAGE è già in modalità reale")
                return 0
            return self.toggle_live(current)
        while True:
            live = not current.get("dryRun", True)
            suspended = current.get("suspend", True)
            status = (
                f"SAGE è già installato (release {self.release}, namespace {self.ns}).\n"
                f"Modalità: {'REALE' if live else 'simulazione'}. "
                f"Controllore: {'spento' if suspended else 'acceso, giro continuo'}."
            )
            entries = []
            target = self.args.image or RELEASE.get("image")
            if target and target != image_ref(current):
                version = RELEASE.get("version", "di questo installer")
                entries.append((f"Aggiorna SAGE alla versione {version}", "update"))
            entries += [
                (
                    "Riconfigura: nodi, gruppi, LLM, frequenza (parte da quella attuale)",
                    "configure",
                ),
                ("Modifica il cluster: servizi aggiuntivi dei nodi", "cluster"),
                (
                    "Torna alla simulazione"
                    if live
                    else "Passa al vivo: SAGE applicherà le remediation",
                    "live",
                ),
                (
                    "Riaccendi il controllore"
                    if suspended
                    else "Spegni il controllore (nessun giro)",
                    "suspend",
                ),
                ("Lancia un giro adesso", "run"),
                ("Apri la dashboard (sola lettura)", "dashboard"),
                ("Storico delle modifiche", "history"),
                ("Disinstalla SAGE", "uninstall"),
                ("Esci", "exit"),
            ]
            pick = ui.choose("Cosa vuoi fare?", [label for label, _ in entries], help=status)
            action = entries[pick][1]
            if action == "update":
                return self.update(current, target)
            if action == "configure":
                return self.configure(current, new=False)
            if action == "cluster":
                return self.edit_cluster(current)
            if action == "live":
                return self.toggle_live(current)
            if action == "suspend":
                return self.toggle_suspend(current)
            if action == "run":
                return self.run_now(current)
            if action == "dashboard":
                return self.open_dashboard(current)
            if action == "history":
                self.show_history()
                continue
            if action == "uninstall":
                return self.uninstall(current)
            return 0

    EXTRA_HELP = (
        "Servizi o pacchetti che il nodo usa fuori da Kubernetes: agent di backup o di "
        "monitoraggio, NFS, strumenti di amministrazione. Contano come necessari anche quando "
        "non girano: SAGE non li considera inutilizzati e non li rimuove. Nomi di unit "
        "systemd (es. backup.service) o di pacchetti (es. rsync), separati da virgole."
    )

    def ask_extra(self, title: str, current: list) -> list:
        def check(v):
            bad = [i for i in split_list(v) if not SERVICE_RE.match(i)]
            return f"nomi non validi: {', '.join(bad)}" if bad else None

        value = self.ui.ask(title, ", ".join(current), check, help=self.EXTRA_HELP)
        return split_list(value)

    def edit_cluster(self, current: dict) -> int:
        """Servizi aggiuntivi per nodo, fuori da Kubernetes."""
        ui = self.ui
        config = current.get("config", {})
        original = {k: list(v) for k, v in (config.get("extra_services") or {}).items()}
        extra = copy.deepcopy(original)
        nodes = [n for n in parse_nodes(self.kjson("get", "nodes")) if GROUP_LABEL in n.labels]
        if not nodes:
            raise Fail("nessun nodo gestito da SAGE: prima installa o riconfigura")
        groups = sorted({n.labels[GROUP_LABEL] for n in nodes})
        while True:
            options = ["Fatto: salva le modifiche", "Annulla"]
            options += [f"{n.name}: {', '.join(extra.get(n.name, [])) or '-'}" for n in nodes]
            options.append("Stessi servizi per tutti i nodi di un gruppo...")
            pick = ui.choose("Servizi aggiuntivi dei nodi", options, help=self.EXTRA_HELP)
            if pick == 0:
                break
            if pick == 1:
                ui.info("Nessuna modifica fatta.")
                return 0
            if pick == len(options) - 1:
                group = groups[ui.choose("Quale gruppo?", groups)]
                group_nodes = [n.name for n in nodes if n.labels[GROUP_LABEL] == group]
                items = self.ask_extra(
                    f"Servizi o pacchetti per i nodi del gruppo {group}",
                    extra.get(group_nodes[0], []),
                )
                targets = group_nodes
            else:
                node = nodes[pick - 2].name
                items = self.ask_extra(f"Servizi o pacchetti per {node}", extra.get(node, []))
                targets = [node]
            for name in targets:
                if items:
                    extra[name] = items
                else:
                    extra.pop(name, None)
        if extra == original:
            ui.info("Nessuna modifica.")
            return 0
        values = copy.deepcopy(current)
        values.setdefault("config", {})["extra_services"] = extra
        note = self.ask_note()
        ui.busy("Applico le modifiche...")
        revision = self.helm_apply(values, "servizi aggiuntivi dei nodi")
        self.record("servizi aggiuntivi dei nodi", diff_values(current, values), note, revision)
        ui.ok("servizi aggiuntivi salvati: valgono dal prossimo giro")
        return 0

    def update(self, current: dict, target: str) -> int:
        """Nuova immagine e nuovo chart, stessa configurazione."""
        old = image_ref(current) or "?"
        if not self.ui.yes(
            "Aggiorno SAGE?",
            help=f"Configurazione invariata. Immagine attuale:\n{old}\nnuova:\n{target}",
        ):
            return 0
        values = copy.deepcopy(current)
        pull = self.check_image(target, current)
        if pull:
            values["imagePullSecrets"] = [{"name": pull}]
        note = self.ask_note()
        self.ui.busy("Aggiorno SAGE...")
        for name, data, kind in self.pending_secrets:
            self.apply_secret(name, data, kind)
        revision = self.helm_apply(values, "aggiornamento")
        version = RELEASE.get("version", "?")
        self.record(
            "aggiornamento", [f"versione {version}", f"immagine: {old} → {target}"], note, revision
        )
        self.ui.ok(f"SAGE aggiornato alla versione {version}")
        if self.ui.yes("Mostro il log del prossimo controllo?"):
            return self.run_now(values)
        return 0

    def preflight(self) -> None:
        if not shutil.which("kubectl"):
            raise Fail(
                "kubectl non trovato: lancia l'installer da un master o da una macchina "
                "con kubectl configurato"
            )
        ctx = self.args.context or self.kubectl("config", "current-context", check=False).stdout
        ctx = ctx.strip()
        try:
            version = json.loads(self.kubectl("get", "--raw", "/version").stdout)["gitVersion"]
        except (Fail, KeyError, ValueError) as e:
            raise Fail(f"il cluster non risponde con il contesto {ctx!r}: {e}") from e
        missing = []
        for verb, resource in (
            ("create", "clusterrolebindings"),
            ("patch", "nodes"),
            ("create", "namespaces"),
            ("create", "secrets"),
        ):
            answer = self.kubectl("auth", "can-i", verb, resource, "-n", self.ns, check=False)
            if answer.stdout.strip() != "yes":
                missing.append(f"{verb} {resource}")
        if missing:
            raise Fail(
                "permessi insufficienti sul cluster (serve un amministratore): "
                + ", ".join(missing)
            )
        self.kube_user = self.whoami()
        self.ui.cluster(f"{ctx} · Kubernetes {version}")
        self.helm_bin = self.ensure_helm()

    def whoami(self) -> str | None:
        proc = self.kubectl(
            "auth", "whoami", "-o", "jsonpath={.status.userInfo.username}", check=False
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        proc = self.kubectl(
            "config", "view", "--minify", "-o", "jsonpath={.contexts[0].context.user}", check=False
        )
        return proc.stdout.strip() or None

    def ensure_helm(self) -> str:
        found = shutil.which("helm")
        if found:
            return found
        version = RELEASE.get("helm_version")
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        url, sha = RELEASE.get(f"helm_url_{arch}"), RELEASE.get(f"helm_sha256_{arch}")
        if not (version and url and sha):
            raise Fail(
                "Helm non trovato: installalo (https://helm.sh/docs/intro/install/) e rilancia"
            )
        target = Path.home() / ".local" / "share" / "sage" / "helm" / version / "helm"
        if target.exists():
            return str(target)
        if not self.ui.yes(
            f"Scarico Helm {version}?",
            help=(
                f"Helm non è installato su questa macchina. L'installer lo scarica in "
                f"{target.parent}, ne verifica il checksum e lo usa solo per SAGE."
            ),
        ):
            raise Fail("serve Helm per installare SAGE")
        self.ui.busy(f"Scarico Helm {version}...")
        data = download(url, sha)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            member = tar.extractfile(f"linux-{arch}/helm")
            if member is None:
                raise Fail("archivio di Helm inatteso")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(member.read())
        target.chmod(0o755)
        self.ui.ok(f"Helm {version} pronto")
        return str(target)

    def current_values(self) -> dict | None:
        status = self.helm("status", self.release, check=False)
        if status.returncode != 0:
            return None
        return json.loads(self.helm("get", "values", self.release, "-o", "json").stdout) or {}

    # --- configurazione
    def configure(self, current: dict, new: bool) -> int:
        ui = self.ui
        total = self.STEPS
        config = current.get("config", {})
        nodes = parse_nodes(self.kjson("get", "nodes"))
        if not nodes:
            raise Fail("il cluster non ha nodi")

        # 1. nodi
        ui.step(1, total, "Nodi")
        width = max(len(n.name) for n in nodes)
        disabled = {i: n.problem for i, n in enumerate(nodes) if n.problem}
        if new:
            preselected = {i for i in range(len(nodes)) if i not in disabled}
        else:
            preselected = {i for i, n in enumerate(nodes) if GROUP_LABEL in n.labels}
        chosen = ui.checklist(
            "Quali nodi deve gestire SAGE?",
            [n.name for n in nodes],
            [n.label(width) for n in nodes],
            preselected,
            disabled,
            help=(
                "Elenco letto da Kubernetes. I nodi non spuntati non vengono mai toccati. "
                "Quelli con un sistema operativo non supportato (servono dnf, zypper o "
                "apt) non sono selezionabili."
            ),
        )
        selected = [nodes[i] for i in sorted(chosen)]
        for n in selected:
            if not n.ready:
                ui.warn(f"{n.name} non è Ready: SAGE lo salterà finché non torna pronto")

        # 2. SSH: prima dei gruppi, perché i nodi irraggiungibili possono essere esclusi
        ui.step(2, total, "Accesso SSH")
        default_user = (
            config.get("ssh", {}).get("user") or os.environ.get("SUDO_USER") or getpass.getuser()
        )
        user = ui.ask(
            "Utente SSH sui nodi",
            default_user,
            help=(
                "Serve sudo senza password su tutti i nodi scelti; di solito è l'utente con "
                "cui sei entrato qui. L'installer crea una chiave dedicata a SAGE e la "
                "installa sui nodi con le tue credenziali (agent SSH)."
            ),
        )
        self.port = self.args.ssh_port or int(config.get("ssh", {}).get("port", 22))
        private, key_note, known_hosts = self.prepare_ssh(user, selected)

        # 3. gruppi
        ui.step(3, total, "Gruppi e ondate")
        groups, assignment = self.initial_groups(config, selected)
        groups = self.edit_groups(groups, assignment, selected, new)
        if self.args.allow_remove:
            for g in groups:
                g.allow_remove = True

        # 4. LLM
        ui.step(4, total, "LLM")
        llm, llm_keys = self.configure_llm(config.get("llm", {}), groups)

        # 5. frequenza e rete
        ui.step(5, total, "Frequenza e rete")
        # Per una nuova installazione il controllore parte acceso, salvo "spento".
        suspended = bool(current.get("suspend", True)) and not new
        current_pause = (config.get("controller") or {}).get("pause_minutes")
        pause, suspend = self.choose_pause(current_pause, suspended)
        timezone_name = ui.ask(
            "Fuso orario",
            config.get("timezone") or current.get("timeZone") or local_timezone(),
            lambda v: None if valid_timezone(v) else "fuso sconosciuto (es. Europe/Rome)",
            help="Vale per gli orari nel report, nei log e nella dashboard.",
        )
        api_ip = (
            self.kubectl(
                "get",
                "svc",
                "kubernetes",
                "-n",
                "default",
                "-o",
                "jsonpath={.spec.clusterIP}",
                check=False,
            ).stdout.strip()
            or None
        )
        proxy = self.choose_proxy(current, [n.ip for n in nodes if n.ip], api_ip)

        image = self.args.image or RELEASE.get("image") or image_ref(current)
        if not image:
            image = ui.ask("Immagine di SAGE", help="Es. registro/owner/sage@sha256:...")
        pull_secret = self.check_image(image, current)

        values = build_values(
            current,
            release=self.release,
            image=image,
            pull_secret=pull_secret,
            pause_minutes=pause,
            timezone=timezone_name,
            suspend=suspend,
            ssh_user=user,
            ssh_port=self.port,
            llm=llm,
            llm_secret=bool(llm_keys) or self.secret_exists(f"{self.release}-llm"),
            groups=groups,
            proxy=proxy,
            live=self.args.live,
        )
        label_changes = node_label_changes(nodes, assignment)
        changes = []
        if not new:
            changes = diff_values(current, values) + label_changes
        changes += [f"chiave API di {name}: aggiornata" for name in llm_names(llm, llm_keys)]
        if key_note:
            changes.append(key_note)

        # 6. riepilogo
        ui.step(6, total, "Riepilogo")
        summary = self.summary_text(image, groups, assignment, user, llm, values)
        if not new:
            summary += "\n\nModifiche rispetto a ora:\n" + (
                "\n".join(f"  {c}" for c in changes) if changes else "  nessuna"
            )
        if not ui.yes("Procedo?", help=summary):
            ui.info("Nessuna modifica fatta.")
            return 0
        note = self.ask_note()

        # applicazione
        ui.busy("Installo SAGE sul cluster...")
        self.ensure_namespace()
        for name, data, kind in self.pending_secrets:
            self.apply_secret(name, data, kind)
        self.apply_secret(
            f"{self.release}-ssh", {"id_ed25519": private, "known_hosts": known_hosts}
        )
        if llm_keys:
            existing = self.read_secret(f"{self.release}-llm")
            self.apply_secret(f"{self.release}-llm", {**existing, **llm_keys})
        self.apply_labels(nodes, assignment)
        action = "installazione" if new else "riconfigurazione"
        revision = self.helm_apply(values, action)
        if new:
            changes = [f"gruppo {g.name}: {', '.join(members(assignment, g.name))}" for g in groups]
            changes += [
                f"utente SSH {user}",
                "LLM: " + (llm_text(llm) or "nessuno"),
                ("controllore spento" if suspend else f"giro continuo, pausa {pause} minuti")
                + (", MODALITÀ REALE da subito (--live)" if self.args.live else ", simulazione"),
            ]
            if key_note:
                changes.append(key_note)
        self.record(action, changes, note, revision)
        ui.ok(f"SAGE {'installato' if new else 'aggiornato'} nel namespace {self.ns}")
        if ui.yes(
            "Lancio subito un giro e ne mostro il log?",
            new,
            help="Il log compare nel terminale normale, alla chiusura di questa schermata.",
        ):
            return self.run_now(values)
        return 0

    def summary_text(self, image, groups, assignment, user, llm, values) -> str:
        lines = [f"Immagine   {image}"]
        suffix = common_suffix(list(assignment))
        for g in sorted(groups, key=lambda g: g.order):
            names = ", ".join(
                (m[: -len(suffix)] if suffix else m) + ("*" if m == g.canary else "")
                for m in members(assignment, g.name)
            )
            lines.append(f"Gruppo {g.order}   {g.name}: {names}  ({g.kernel_text()})")
        if suffix:
            lines.append(f"           (nomi senza il suffisso comune {suffix}; * = canary)")
        lines.append(f"SSH        utente {user}, chiave dedicata")
        lines.append(f"LLM        {llm_text(llm) or 'nessuno: solo regole deterministiche'}")
        mode = "simulazione" if values["dryRun"] else "MODALITÀ REALE"
        pause = values["config"]["controller"]["pause_minutes"]
        when = (
            "controllore spento: nessun giro"
            if values["suspend"]
            else f"continuo, pausa di {pause} minuti tra un giro e l'altro"
        )
        lines.append(f"Giri       {when}, {mode}")
        removing = [g.name for g in groups if g.allow_remove]
        if removing:
            lines.append(
                f"Rimozioni  pacchetti inutilizzati da 7 giorni nei gruppi: {', '.join(removing)}"
            )
        if not values["dryRun"]:
            lines.append(
                "\nATTENZIONE: modalità reale. Finito il primo controllo, SAGE inizia ad "
                "aggiornare i nodi uno alla volta (drain e, se serve, riavvio)."
            )
        return "\n".join(lines)

    def ask_note(self) -> str:
        return self.ui.ask(
            "Nota per lo storico (facoltativa)",
            "",
            lambda v: None,
            help=(
                "Chi, quando e cosa cambia vengono registrati comunque nello storico "
                "delle modifiche. Qui puoi aggiungere il perché."
            ),
        )

    def initial_groups(self, config, selected):
        names = {n.name for n in selected}
        existing = [Group.from_config(g) for g in config.get("groups", []) if "name" in g]
        if not existing:
            return propose_groups(selected)
        proposed, fallback = propose_groups(selected)
        by_name = {g.name: g for g in existing}
        assignment = {}
        for n in selected:
            label = n.labels.get(GROUP_LABEL)
            if label in by_name:
                assignment[n.name] = label
            else:
                # Nodo nuovo: gruppo proposto, creato se manca.
                target = fallback[n.name]
                if target not in by_name:
                    group = next(g for g in proposed if g.name == target)
                    group.order = max((g.order for g in by_name.values()), default=0) + 1
                    by_name[target] = group
                assignment[n.name] = target
        assignment = {k: v for k, v in assignment.items() if k in names}
        return normalize_groups(list(by_name.values()), assignment), assignment

    def groups_text(self, groups, assignment, new: bool) -> str:
        if new:
            intro = (
                "Proposta calcolata da Kubernetes: i nodi con il ruolo control-plane vanno "
                "in master, quelli che dichiarano GPU in gpu, gli altri in worker. I gruppi "
                "si aggiornano uno dopo l'altro (ondate); ogni nodo riceverà l'etichetta "
                f"{GROUP_LABEL} con il suo gruppo."
            )
        else:
            intro = (
                f"Gruppi attuali, letti dall'etichetta {GROUP_LABEL} dei nodi. I nodi nuovi "
                "sono proposti in base a Kubernetes (control-plane, GPU, altri)."
            )
        suffix = common_suffix(list(assignment))
        lines = [intro, ""]
        for g in sorted(groups, key=lambda g: g.order):
            names = ", ".join(
                (m[: -len(suffix)] if suffix else m) + ("*" if m == g.canary else "")
                for m in members(assignment, g.name)
            )
            extras = []
            if g.allow_remove:
                extras.append("rimozioni")
            if g.allow_mitigate:
                extras.append("mitigazioni")
            if g.requires_fallback:
                extras.append("serve una riserva LLM")
            tail = f"; {', '.join(extras)}" if extras else ""
            lines.append(f"  Ondata {g.order}  {g.name}: {names}  ({g.kernel_text()}{tail})")
        lines.append("")
        lines.append(
            "* = canary: il primo nodo del gruppo ad aggiornarsi. I gruppi con i master "
            "vanno sempre per ultimi."
        )
        if suffix:
            lines.append(f"Nomi senza il suffisso comune {suffix}.")
        return "\n".join(lines)

    def edit_groups(self, groups, assignment, selected, new=True):
        ui = self.ui
        while True:
            groups = normalize_groups(groups, assignment)
            choice = ui.choose(
                "I gruppi vanno bene?",
                [
                    "Sì, continua",
                    "Sposta i nodi tra i gruppi",
                    "Modifica un gruppo (ordine, canary, kernel...)",
                    "Crea un gruppo nuovo",
                ],
                help=self.groups_text(groups, assignment, new),
            )
            if choice == 0:
                return groups
            if choice == 3:
                groups.append(self.new_group(groups))
            if choice in (1, 3):
                ordered = sorted(groups, key=lambda g: g.order)
                moved, canaries = ui.board(
                    "Sposta i nodi tra i gruppi",
                    [g.name for g in ordered],
                    assignment,
                    {g.name: g.canary for g in ordered},
                    help="Una colonna per gruppo, nell'ordine delle ondate.",
                )
                assignment.clear()
                assignment.update(moved)
                for g in groups:
                    g.canary = canaries.get(g.name)
            elif choice == 2:
                index = ui.choose("Quale gruppo?", [g.name for g in groups])
                self.edit_group(groups[index], groups, assignment)

    def new_group(self, groups) -> Group:
        taken = {g.name for g in groups}

        def check(v):
            if not NAME_RE.match(v):
                return "minuscole, cifre e trattini, massimo 63 caratteri"
            return "nome già usato" if v in taken else None

        name = self.ui.ask(
            "Nome del gruppo nuovo",
            None,
            check,
            help="Poi scegli quali nodi spostarci. Verrà aggiornato per ultimo.",
        )
        return Group(name, max((g.order for g in groups), default=0) + 1, "auto")

    def edit_group(self, group: Group, groups, assignment) -> None:
        ui = self.ui
        while True:
            group_members = members(assignment, group.name)
            options = [
                "Fatto",
                f"Ordine nel giro: {group.order}",
                f"Canary: {group.canary or 'nessuno'}",
                f"Aggiornamenti del kernel: {group.kernel_text()}",
                f"Rimozione dei pacchetti inutilizzati: {'sì' if group.allow_remove else 'no'}",
                "Blocco dei moduli del kernel vulnerabili: "
                + ("sì" if group.allow_mitigate else "no"),
                "Ospita l'LLM (serve una riserva fuori dal gruppo): "
                + ("sì" if group.requires_fallback else "no"),
            ]
            choice = ui.choose(f"Gruppo {group.name}", options)
            if choice == 0:
                return
            if choice == 1:
                order = ui.ask_int("Ordine nel giro (1 = per primo)", group.order)
                other = next((g for g in groups if g.order == order and g is not group), None)
                if other:
                    other.order = group.order  # scambio
                group.order = order
            elif choice == 2:
                opts = ["nessuno"] + group_members
                pick = ui.choose(
                    "Canary del gruppo",
                    opts,
                    opts.index(group.canary) if group.canary in opts else 0,
                    help=(
                        "Il canary è il primo nodo del gruppo nel giro: se la sua remediation "
                        "fallisce, SAGE si ferma prima di toccare gli altri."
                    ),
                )
                group.canary = None if pick == 0 else opts[pick]
            elif choice == 3:
                modes = [k for k, _ in KERNEL_MODES]
                pick = ui.choose(
                    "Aggiornamenti del kernel",
                    [f"{k}: {d}" for k, d in KERNEL_MODES],
                    modes.index(group.kernel) if group.kernel in modes else 0,
                    help="Un kernel nuovo richiede di svuotare e riavviare il nodo.",
                )
                group.kernel = modes[pick]
            elif choice == 4:
                group.allow_remove = not group.allow_remove
            elif choice == 5:
                group.allow_mitigate = not group.allow_mitigate
            else:
                group.requires_fallback = not group.requires_fallback

    # --- SSH
    def prepare_ssh(self, user: str, selected: list):
        ui = self.ui
        key = self.tmp / "id_ed25519"
        known_hosts = self.tmp / "known_hosts"
        existing = self.read_secret(f"{self.release}-ssh")
        if existing.get("id_ed25519"):
            # Riconfigurazione: stessa chiave, già installata sui nodi gestiti.
            key.write_text(existing["id_ed25519"])
            known_hosts.write_text(existing.get("known_hosts", ""))
            key.chmod(0o600)
            public = run(["ssh-keygen", "-y", "-f", str(key)]).stdout.strip()
            note = None
        else:
            comment = f"sage@{self.release}"
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key)])
            public = (self.tmp / "id_ed25519.pub").read_text().strip()
            known_hosts.write_text(existing.get("known_hosts", ""))
            ui.ok("chiave SSH dedicata creata (resta solo nel Secret del cluster)")
            note = f"chiave SSH di SAGE creata ({public.split()[0]})"

        pending = list(selected)
        while True:
            ui.busy("Controllo l'accesso SSH ai nodi...")
            failed = {}
            for n, problem in self.parallel(
                pending, lambda n: self.setup_node(n, user, key, public, known_hosts)
            ):
                if problem:
                    failed[n.name] = problem
                    ui.warn(f"{n.name}: {problem}")
                else:
                    ui.ok(f"{n.name}: chiave, sudo, gestore di pacchetti e python3 a posto")
            if not failed:
                break
            options = ["Riprova", "Escludi questi nodi e continua", "Interrompi"]
            changed = [n for n in failed if "chiave host" in failed[n]]
            if changed:
                options.insert(1, "Accetta la nuova chiave host dei nodi ricreati e riprova")
            help = "\n".join(f"{name}: {problem}" for name, problem in failed.items()) + (
                "\n\nSe l'accesso è negato, installa a mano questa chiave pubblica in "
                f"~{user}/.ssh/authorized_keys su quei nodi:\n{public}\n\n"
                "Su un master raggiunto con ssh -A (agent forwarding) di solito basta "
                "riprovare: l'installer usa le tue credenziali per installarla."
            )
            choice = options[
                ui.choose("Alcuni nodi non sono pronti. Come procedo?", options, help=help)
            ]
            if choice.startswith("Interrompi"):
                raise Fail("installazione interrotta, nessuna modifica al cluster")
            if choice.startswith("Accetta"):
                for n in selected:
                    if n.name in changed:
                        run(["ssh-keygen", "-R", n.ip, "-f", str(known_hosts)], check=False)
            elif choice.startswith("Escludi"):
                selected[:] = [n for n in selected if n.name not in failed]
                if not selected:
                    raise Fail("nessun nodo utilizzabile")
                break
            pending = [n for n in selected if n.name in failed]
        return key.read_text(), note, known_hosts.read_text()

    def setup_node(self, node, user, key, public, known_hosts) -> str | None:
        check = self.ssh(node.ip, CHECK_COMMAND, user, key, known_hosts)
        if check.returncode == 255:
            stderr = check.stderr
            if "Permission denied" in stderr:
                # La chiave di SAGE non è ancora sul nodo: la installo con le credenziali
                # di chi lancia l'installer (agent SSH o chiavi personali).
                result = self.ssh(node.ip, install_key_command(public), user)
                if result.returncode != 0:
                    return f"non riesco a installare la chiave ({explain_ssh_error(result.stderr)})"
                check = self.ssh(node.ip, CHECK_COMMAND, user, key, known_hosts)
            if check.returncode == 255:
                return explain_ssh_error(check.stderr)
        problems = parse_check(check.stdout)
        if problems is None:
            return "risposta inattesa dal nodo: " + explain_ssh_error(check.stderr)
        return ", ".join(problems) or None

    def parallel(self, nodes, fn):
        """Risultati nell'ordine in cui arrivano, così l'avanzamento si vede subito."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = {pool.submit(fn, n): n for n in nodes}
            for future in concurrent.futures.as_completed(futures):
                yield futures[future], future.result()

    # --- LLM
    def configure_llm(self, current: dict, groups) -> tuple[dict, dict]:
        ui = self.ui
        endpoints = list(current.get("endpoints") or [])
        options = []
        if endpoints:
            options.append(f"Mantieni quello attuale: {llm_text({'endpoints': endpoints})}")
        options += [
            "Configura un endpoint (API compatibile con OpenAI)",
            "Nessun LLM: solo regole deterministiche (nel dubbio si aggiorna)",
        ]
        choice = options[
            ui.choose(
                "Quale LLM usa SAGE per leggere le CVE?",
                options,
                help=(
                    "SAGE manda all'LLM solo i dati pubblici delle CVE, mai quelli dei nodi. "
                    "Va bene qualsiasi servizio con API compatibile con OpenAI: un server "
                    "vLLM o Ollama, l'endpoint del centro di calcolo, un servizio esterno."
                ),
            )
        ]
        if choice.startswith("Mantieni"):
            return {"endpoints": endpoints}, {}
        if choice.startswith("Nessun"):
            return {"endpoints": []}, {}
        endpoints, keys = [], {}
        while True:
            endpoint, key = self.ask_endpoint(groups, {e["name"] for e in endpoints}, not endpoints)
            endpoints.append(endpoint)
            if key:
                keys[endpoint["api_key_env"]] = key
            if not ui.yes(
                "Aggiungo un endpoint di riserva?",
                False,
                help=(
                    "La riserva si usa quando il primo endpoint non risponde. È consigliata "
                    "se l'LLM principale gira su un nodo del cluster: quel gruppo si "
                    "aggiorna solo con una riserva attiva."
                ),
            ):
                break
        return {"endpoints": endpoints}, keys

    def ask_endpoint(self, groups, taken, first: bool) -> tuple[dict, str | None]:
        ui = self.ui
        which = "principale" if first else "di riserva"
        base_url = ui.ask(
            f"URL dell'endpoint {which}",
            None,
            lambda v: (
                None
                if v.startswith(("http://", "https://"))
                else "deve iniziare con http:// o https://"
            ),
            help=(
                "Indirizzo di base dell'API compatibile con OpenAI, di solito finisce con "
                "/v1. Esempi: http://<server>:8000/v1 (vLLM), http://<server>:11434/v1 "
                "(Ollama), https://<servizio>/v1."
            ),
        ).rstrip("/")
        key = ui.secret(
            "Chiave API",
            help="Lasciala vuota se l'endpoint non la richiede. Viene salvata solo in un "
            "Secret del cluster e non compare nello storico.",
        )
        while True:
            ui.busy(f"Contatto {base_url}...")
            problem, models = llm_models(base_url, key or None)
            if problem is not None and problem.startswith("non raggiungibile"):
                # Es. un servizio del cluster (.svc): lo raggiungono i pod, non il master.
                ui.busy(f"Da qui non risponde: provo da un pod nel cluster ({base_url})...")
                problem, models = self.cluster_llm_models(base_url, key or None)
                if problem is None:
                    ui.ok(f"{base_url} risponde dal cluster")
            if problem == "risposta HTTP 404" and not base_url.endswith("/v1"):
                # Errore tipico con Ollama e vLLM: l'API compatibile OpenAI sta sotto /v1.
                alt = base_url + "/v1"
                alt_problem, alt_models = llm_models(alt, key or None)
                if alt_problem and alt_problem.startswith("non raggiungibile"):
                    alt_problem, alt_models = self.cluster_llm_models(alt, key or None)
                if alt_problem is None:
                    ui.ok(f"{base_url} risponde 404, {alt} sì: uso {alt}")
                    base_url, problem, models = alt, None, alt_models
            if problem is None:
                break
            ui.warn(f"{base_url}: {problem}")
            if problem.startswith(("chiave", "accesso")) and ui.yes(
                "Inserisco un'altra chiave?", problem.startswith("chiave"), help=problem
            ):
                key = ui.secret("Chiave API")
                continue
            # Es. endpoint raggiungibile dai pod ma non da qui: si prosegue.
            break
        if models:
            ui.ok(f"{base_url} risponde: {len(models)} modelli")
            options = models + ["Un altro: lo scrivo io"]
            pick = ui.choose(
                "Quale modello usa SAGE?",
                options,
                help="Elenco letto dall'endpoint. Serve un modello per chat che segua "
                "bene le istruzioni e risponda in JSON.",
            )
            model = models[pick] if pick < len(models) else ui.ask("Nome del modello")
        else:
            model = ui.ask(
                "Nome del modello",
                help="Non ho potuto leggere l'elenco dei modelli: scrivilo come lo vuole l'API.",
            )
        name = endpoint_name(base_url, taken)
        endpoint = {"name": name, "base_url": base_url, "model": model}
        if key:
            endpoint["api_key_env"] = env_name(name)
        where = ui.choose(
            "Dove gira questo LLM?",
            ["Fuori dai nodi gestiti da SAGE"]
            + [f"Su un nodo del gruppo {g.name}" for g in groups],
            help=(
                "Se gira su un nodo che SAGE aggiorna, quel gruppo verrà aggiornato solo "
                "quando una riserva fuori dal gruppo risponde: l'LLM non resta mai senza "
                "alternativa."
            ),
        )
        if where:
            group = groups[where - 1]
            endpoint["hosted_in_group"] = group.name
            group.requires_fallback = True
        return endpoint, key or None

    # --- frequenza e rete
    def choose_pause(self, current: int | None, suspended: bool) -> tuple[int, bool]:
        """(minuti di pausa tra un giro e l'altro, controllore spento)."""
        options = [text for text, _ in PAUSES]
        values = [minutes for _, minutes in PAUSES]
        if current is not None and current not in values:
            options.insert(0, f"come ora ({current} minuti)")
            values.insert(0, current)
        options.append("altro (in minuti)")
        options.append("spento: nessun giro finché non lo riaccendi")
        off = len(options) - 1
        default = off if suspended else (values.index(current) if current in values else 0)
        pick = self.ui.choose(
            "Pausa tra un giro e il successivo",
            options,
            default,
            help=(
                "SAGE gira in continuo: controlla tutti i nodi, li sistema uno alla volta "
                "(prima i worker, poi i master) e ricomincia. La pausa evita di interrogare "
                "i nodi di continuo quando non c'è niente da fare. In simulazione dice cosa "
                "farebbe senza toccare niente."
            ),
        )
        if pick == off:
            return (current if current is not None else values[0]), True
        if pick < len(values):
            return values[pick], False
        return self.ui.ask_int("Minuti di pausa", current or 30), False

    def choose_proxy(self, current: dict, ips, api_ip) -> list[dict]:
        env = {e.get("name"): e.get("value") for e in current.get("extraEnv") or []}
        detected = (
            env.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
        )
        if detected and detected.startswith("socks"):
            detected = None  # un tunnel SOCKS locale non vale per i pod
        if not self.ui.yes(
            "I pod escono su Internet tramite un proxy HTTP?",
            bool(detected),
            help=(
                "SAGE scarica i cataloghi pubblici delle CVE (CISA KEV, EPSS, CVE Program) "
                "e chiama l'LLM. Se i pod non escono direttamente, serve un proxy."
            ),
        ):
            return []
        proxy = self.ui.ask(
            "URL del proxy",
            detected,
            lambda v: (
                None
                if v.startswith(("http://", "https://"))
                else "deve iniziare con http:// o https://"
            ),
            help="Es. http://proxy:3128. I nodi e i servizi del cluster restano esclusi.",
        )
        return proxy_env(proxy, ips, api_ip)

    # --- immagine
    def check_image(self, image: str, current: dict) -> str | None:
        ui = self.ui
        pull = (current.get("imagePullSecrets") or [{}])[0].get("name")
        ui.busy("Controllo che i nodi possano scaricare l'immagine...")
        access = image_access(image)
        if access == "public" or pull:
            return pull
        if access.startswith("unknown"):
            ui.warn(f"non riesco a verificare l'immagine da qui ({access[9:]}): proseguo")
            return None
        choice = ui.choose(
            "L'immagine non si scarica senza credenziali. Come procedo?",
            [
                "Creo un pull secret con utente e token del registro",
                "Proseguo lo stesso (l'ho resa pubblica nel frattempo)",
                "Interrompi",
            ],
            help=f"{image}\n\nDi solito il pacchetto nel registro è ancora privato.",
        )
        if choice == 2:
            raise Fail("installazione interrotta, nessuna modifica al cluster")
        if choice == 1:
            return None
        host = parse_image(image)[0]
        username = ui.ask(f"Utente per {host}")
        token = ui.secret("Token con permesso di lettura dei pacchetti")
        auth = base64.b64encode(f"{username}:{token}".encode()).decode()
        config = {"auths": {host: {"username": username, "password": token, "auth": auth}}}
        name = f"{self.release}-pull"
        self.pending_secrets.append(
            (name, {".dockerconfigjson": json.dumps(config)}, "kubernetes.io/dockerconfigjson")
        )
        return name

    # --- cluster
    def secret_exists(self, name: str) -> bool:
        return self.kubectl("get", "secret", name, ns=True, check=False).returncode == 0

    def read_secret(self, name: str) -> dict:
        proc = self.kubectl("get", "secret", name, "-o", "json", ns=True, check=False)
        if proc.returncode != 0:
            return {}
        data = json.loads(proc.stdout).get("data") or {}
        return {k: base64.b64decode(v).decode() for k, v in data.items()}

    def cluster_llm_models(self, base_url: str, key: str | None) -> tuple[str | None, list[str]]:
        """Controlla l'endpoint LLM da un pod temporaneo con l'immagine di SAGE."""
        image = self.args.image or RELEASE.get("image")
        if not image:
            return "controllo dal cluster non possibile (immagine di SAGE sconosciuta)", []
        exists = self.kubectl("get", "namespace", self.ns, check=False).returncode == 0
        namespace = self.ns if exists else "default"
        name = "sage-llm-check-" + os.urandom(3).hex()
        container = {
            "name": name,
            "image": image,
            "command": ["python3", "-c", CLUSTER_LLM_CHECK, base_url],
            "stdin": True,
            "stdinOnce": True,
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
        }
        overrides = {
            "apiVersion": "v1",
            "spec": {
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [container],
            },
        }
        cmd = ["kubectl"] + (["--context", self.args.context] if self.args.context else [])
        cmd += ["-n", namespace, "run", name, "--image", image, "--restart=Never", "--rm"]
        cmd += ["-i", "--quiet", "--pod-running-timeout=120s"]
        cmd += ["--overrides", json.dumps(overrides)]
        try:
            proc = run(cmd, input=(key or "") + "\n", check=False, timeout=180)
        except Exception as e:  # timeout, kubectl assente
            return f"controllo dal cluster non riuscito ({e})", []
        finally:
            # --rm non basta se kubectl viene interrotto: il pod non deve restare.
            self.kubectl(
                "-n",
                namespace,
                "delete",
                "pod",
                name,
                "--ignore-not-found",
                "--wait=false",
                check=False,
            )
        problem, models = parse_cluster_llm_check(proc.stdout)
        if problem == "controllo dal cluster non riuscito" and proc.stderr.strip():
            problem += f" ({proc.stderr.strip().splitlines()[-1]})"
        return problem, models

    def ensure_namespace(self) -> None:
        if self.kubectl("get", "namespace", self.ns, check=False).returncode == 0:
            return
        manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": self.ns, "labels": {"app.kubernetes.io/managed-by": MANAGED_BY}},
        }
        self.kubectl("create", "-f", "-", input=json.dumps(manifest))

    def apply_object(self, manifest: dict) -> None:
        # Server-side apply: niente copia dei dati nell'annotazione last-applied.
        self.kubectl(
            "apply",
            "--server-side",
            "--force-conflicts",
            f"--field-manager={MANAGED_BY}",
            "-f",
            "-",
            input=json.dumps(manifest),
        )

    def apply_ca_bundle(self) -> dict:
        """Copia nel cluster le CA di questa macchina, per l'HTTPS dei pod di SAGE (KEV,
        EPSS, OSV, LLM). Con un proxy che ispeziona TLS servono le CA aziendali, che
        l'immagine di SAGE non conosce. Restituisce i valori `caBundle` del chart."""
        bundle = system_ca_bundle()
        if not bundle:
            return {"configMap": ""}
        try:
            data = Path(bundle).read_text()
        except (OSError, UnicodeDecodeError):
            return {"configMap": ""}
        if "BEGIN CERTIFICATE" not in data or len(data.encode()) > CA_BUNDLE_MAX:
            self.ui.warn(f"CA di {bundle} non copiate nel cluster (vuote o troppo grandi)")
            return {"configMap": ""}
        name = f"{self.release}-ca"
        self.apply_object(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": self.ns, "labels": self.labels()},
                "data": {"ca.crt": data},
            }
        )
        return {"configMap": name}

    def labels(self) -> dict:
        return {
            "app.kubernetes.io/managed-by": MANAGED_BY,
            "app.kubernetes.io/instance": self.release,
        }

    def apply_secret(self, name: str, data: dict, kind: str = "Opaque") -> None:
        self.apply_object(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": kind,
                "metadata": {"name": name, "namespace": self.ns, "labels": self.labels()},
                "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()},
            }
        )

    def apply_labels(self, nodes, assignment) -> None:
        for n in nodes:
            target = assignment.get(n.name)
            current = n.labels.get(GROUP_LABEL)
            if target and target != current:
                self.kubectl("label", "node", n.name, f"{GROUP_LABEL}={target}", "--overwrite")
            elif not target and current is not None:
                self.kubectl("label", "node", n.name, f"{GROUP_LABEL}-")

    def chart(self) -> str:
        if self.args.chart:
            return self.args.chart
        if RELEASE.get("chart_b64"):
            # Chart dentro l'installer: niente download, e nessun disallineamento possibile
            # tra installer e chart pubblicati (es. una release compilata due volte).
            data = base64.b64decode(RELEASE["chart_b64"])
            if hashlib.sha256(data).hexdigest() != RELEASE.get("chart_sha256"):
                raise Fail("chart incluso nell'installer danneggiato: riscarica l'installer")
            path = self.tmp / "sage-chart.tgz"
            path.write_bytes(data)
            return str(path)
        if RELEASE.get("chart_url"):
            data = download(RELEASE["chart_url"], RELEASE.get("chart_sha256"))
            path = self.tmp / "sage-chart.tgz"
            path.write_bytes(data)
            return str(path)
        local = Path(__file__).resolve().parent.parent / "chart" / "sage"
        if local.is_dir():
            return str(local)
        raise Fail("chart non trovato: usa l'installer di una release o --chart")

    def helm_apply(self, values: dict, action: str) -> str | None:
        """Installa o aggiorna la release; restituisce il numero di revisione di Helm."""
        image = self.args.image or RELEASE.get("image")
        if image:
            values = {**values, "image": {**values.get("image", {}), **split_image(image)}}
        values = {**values, "caBundle": self.apply_ca_bundle()}
        path = self.tmp / "values.json"
        path.write_text(json.dumps(values, indent=2))
        description = f"{who_text(self.kube_user)}: {action}"[:200]
        self.helm(
            "upgrade",
            "--install",
            self.release,
            self.chart(),
            "-f",
            str(path),
            "--description",
            description,
        )
        status = self.helm("status", self.release, "-o", "json", check=False)
        try:
            return str(json.loads(status.stdout)["version"])
        except (ValueError, KeyError):
            return None

    # --- storico
    def history_name(self) -> str:
        return f"{self.release}-history"

    def read_history(self) -> list[dict]:
        proc = self.kubectl(
            "get", "configmap", self.history_name(), "-o", "json", ns=True, check=False
        )
        if proc.returncode != 0:
            return []
        text = (json.loads(proc.stdout).get("data") or {}).get(HISTORY_KEY, "")
        return parse_history(text)

    def record(self, action: str, changes: list, note: str | None = None, revision=None) -> None:
        """Aggiunge una voce allo storico delle modifiche (ConfigMap nel namespace di SAGE)."""
        entry = history_entry(action, changes, note, self.kube_user, revision)
        entries = (self.read_history() + [entry])[-HISTORY_MAX:]
        self.apply_object(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": self.history_name(),
                    "namespace": self.ns,
                    "labels": self.labels(),
                },
                "data": {
                    HISTORY_KEY: "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries)
                },
            }
        )

    def show_history(self) -> None:
        ui = self.ui
        entries = list(reversed(self.read_history()))
        if not entries:
            ui.choose("Storico delle modifiche", ["Indietro"], help="Nessuna voce registrata.")
            return
        while True:
            options = ["Indietro"] + [history_line(e) for e in entries]
            pick = ui.choose(
                "Storico delle modifiche",
                options,
                help="Dalla più recente. Scegli una voce per vederne i dettagli.",
            )
            if pick == 0:
                return
            ui.choose(
                history_line(entries[pick - 1]),
                ["Indietro"],
                help=history_details(entries[pick - 1]),
            )

    # --- azioni
    def toggle_live(self, current: dict) -> int:
        ui = self.ui
        values = copy.deepcopy(current)
        if not current.get("dryRun", True):
            note = self.ask_note()
            values["dryRun"] = True
            revision = self.helm_apply(values, "ritorno alla simulazione")
            self.record("ritorno alla simulazione", ["dryRun: false → true"], note, revision)
            ui.ok("tornato in simulazione: nessuna remediation verrà avviata")
            return 0
        if not ui.yes(
            "Passo al vivo?",
            False,
            help=(
                "Nella modalità reale SAGE applica le remediation: cordon, drain, "
                "aggiornamenti e riavvii, un nodo alla volta, prima il canary di ogni gruppo. "
                "Un errore ferma tutto finché una persona non controlla."
            ),
        ):
            return 0
        note = self.ask_note()
        values["dryRun"] = False
        revision = self.helm_apply(values, "passaggio al vivo")
        self.record("passaggio al vivo", ["dryRun: true → false"], note, revision)
        ui.ok("modalità reale attiva dal prossimo giro")
        return 0

    def toggle_suspend(self, current: dict) -> int:
        values = copy.deepcopy(current)
        values["suspend"] = not current.get("suspend", True)
        action = "controllore spento" if values["suspend"] else "controllore riacceso"
        note = self.ask_note()
        revision = self.helm_apply(values, action)
        change = f"suspend: {json.dumps(not values['suspend'])} → {json.dumps(values['suspend'])}"
        self.record(action, [change], note, revision)
        self.ui.ok(action)
        return 0

    def command_name(self) -> str:
        """Come rilanciare questo programma: `sage` se è installato come comando."""
        if shutil.which("sage") and os.path.realpath(shutil.which("sage")) == os.path.realpath(
            self.args.bin
        ):
            return "sage"
        return sys.argv[0]

    def install_command(self) -> None:
        """L'eseguibile si installa come comando di sistema (`sage`), se non c'è già uguale.

        Solo per l'eseguibile compilato: lo script Python si lancia con python3.
        """
        if not getattr(sys, "frozen", False):
            return
        me = os.path.realpath(sys.executable)
        target = self.args.bin
        if os.path.realpath(target) == me:
            return
        if os.path.exists(target) and file_sha256(target) == file_sha256(me):
            return
        verb = "Aggiorno" if os.path.exists(target) else "Installo"
        if not self.ui.yes(
            f"{verb} il comando {target}?",
            True,
            help=(
                "Così da qualsiasi cartella basta scrivere `sage` (anche `sage --dashboard` e "
                "`sage --resume`), e il file scaricato si può cancellare."
            ),
        ):
            return
        cmd = ["install", "-m", "0755", me, target]
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        result = run(cmd, check=False)
        if result.returncode == 0:
            self.ui.ok(f"comando installato: {target}")
        else:
            self.ui.warn(
                f"non sono riuscito a installare {target} (serve sudo senza password): "
                f"sudo install -m 0755 {me} {target}"
            )

    def read_json_cm(self, name: str) -> dict | None:
        """Stato salvato da SAGE in una ConfigMap (JSON compresso, come sage.kube)."""
        out = self.kubectl("get", "configmap", name, "-o", "json", ns=True, check=False)
        if out.returncode != 0:
            return None
        blob = (json.loads(out.stdout).get("binaryData") or {}).get("data.json.gz")
        return json.loads(gzip.decompress(base64.b64decode(blob))) if blob else None

    def resume_view(self) -> int:
        """Stato del giro e log di quello che SAGE sta facendo, nodo dopo nodo.

        Resta attaccato: quando un lavoro finisce passa al successivo (controllo o
        remediation), aspettando che il pod parta. Ctrl+C esce, il lavoro continua.
        Con --once mostra lo stato e il lavoro attuale una volta sola.
        """
        self.ui.close()
        shown, followed = None, set()
        try:
            while True:
                lines, job = progress_lines(self.read_json_cm(f"{self.release}-controller"))
                text = "\n".join(lines)
                if text != shown:
                    print(("\n" if shown else "") + text)
                    shown = text
                if job and job not in followed:
                    followed.add(job)
                    if self.wait_pod(job):
                        print(f"\nLog di {job} (Ctrl+C per uscire, il lavoro continua):\n")
                        self.follow_logs(job)
                    continue
                if self.args.once:
                    return 0
                time.sleep(RESUME_POLL)
        except KeyboardInterrupt:
            ignore_interrupts()
            print("\nUscito: il lavoro di SAGE nel cluster continua.")
        return 0

    def job_active(self, job: str) -> bool | None:
        """Il Job sta ancora lavorando? None se non si riesce a saperlo."""
        proc = self.kubectl("get", "job", job, "-o", "json", ns=True, check=False)
        if proc.returncode != 0:
            return None if "NotFound" not in proc.stderr else False
        status = json.loads(proc.stdout).get("status", {})
        return not (status.get("succeeded") or status.get("failed"))

    def follow_logs(self, job: str) -> None:
        """`kubectl logs -f`, che si ricollega se la connessione cade (bilanciatori con
        timeout corti, API sotto carico) finché il Job lavora."""
        cmd = ["kubectl"] + (["--context", self.args.context] if self.args.context else [])
        cmd += ["-n", self.ns, "logs", "-f", f"job/{job}"]
        since = None
        for _ in range(LOG_RECONNECTS):
            started = time.time()
            subprocess.run(cmd + ([f"--since={since}s"] if since else []), check=False)
            active = None
            for _ in range(10):  # l'API può non rispondere per qualche secondo
                active = self.job_active(job)
                if active is not None:
                    break
                time.sleep(3)
            if active is False:
                return
            print("\n(connessione al log interrotta: mi ricollego)\n")
            time.sleep(2)
            # Le righe scritte durante l'interruzione: qualcuna può ripetersi, nessuna manca.
            since = int(time.time() - started) if since is None else since
            since = min(since, 600) + 5

    def wait_pod(self, job: str, timeout: int = 600) -> bool:
        """Aspetta che il pod del Job sia partito (o finito). False se non parte."""
        deadline = time.time() + timeout
        said = False
        while time.time() < deadline:
            pods = self.kjson("get", "pods", "-l", f"job-name={job}", ns=True).get("items", [])
            status = pods[0].get("status", {}) if pods else {}
            if status.get("phase") in ("Running", "Succeeded", "Failed"):
                return True
            for c in status.get("containerStatuses", []):
                reason = (c.get("state", {}).get("waiting") or {}).get("reason")
                if reason in START_ERRORS:
                    print(f"il pod di {job} non parte: {reason}")
                    return False
            if not said:
                print(f"\n{job}: attendo che il pod parta...")
                said = True
            time.sleep(3)
        print(f"il pod di {job} non è partito in {timeout // 60} minuti")
        return False

    def open_dashboard(self, current: dict) -> int:
        """Port-forward verso la dashboard: resta aperto finché non si preme Ctrl+C."""
        dashboard = current.get("dashboard") or {}
        if dashboard.get("enabled") is False:
            raise Fail(
                "dashboard disattivata (dashboard.enabled: false nei valori): "
                "riattivala riconfigurando con quel valore a true"
            )
        port = int(dashboard.get("port") or 8080)
        local = self.args.dashboard_port
        deploy = f"deploy/{self.release}-dashboard"
        self.kubectl("rollout", "status", deploy, "--timeout=120s", ns=True)
        self.ui.close()
        print(
            f"\nDashboard di SAGE: http://localhost:{local}\n"
            f"Da un altro computer: ssh -L {local}:localhost:{local} "
            f"{getpass.getuser()}@{socket.gethostname()}, poi lo stesso indirizzo.\n"
            "Ctrl+C per chiudere.\n"
        )
        cmd = ["kubectl"] + (["--context", self.args.context] if self.args.context else [])
        cmd += ["-n", self.ns, "port-forward", "--address", "127.0.0.1", deploy, f"{local}:{port}"]
        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            ignore_interrupts()
            print("\ndashboard chiusa")
        return 0

    def run_now(self, values: dict) -> int:
        """Con il controllore acceso gli chiede un giro subito; spento, lancia solo il
        controllo (senza remediation). In entrambi i casi mostra il log del controllo."""
        ui = self.ui
        if values.get("suspend", True):
            job = self.create_scan_job()
            self.record("controllo manuale (controllore spento)", [f"job {job}"])
        else:
            since = time.time()
            doc = self.read_json_cm(f"{self.release}-controller")
            phase = ((doc or {}).get("cycle") or {}).get("phase")
            self.kubectl("create", "configmap", f"{self.release}-scan-now", ns=True, check=False)
            self.record("giro richiesto a mano", [])
            if phase in ("scan", "remediate"):
                # Un giro è già in corso: non si interrompe. Si mostra a che punto è e si
                # segue il lavoro attuale; il giro richiesto parte appena questo finisce.
                ui.close()
                print(
                    "\nC'è già un giro in corso: il prossimo parte appena finisce "
                    "(richiesta registrata).\n"
                )
                return self.resume_view()
            job = self.wait_scan_job(since, SCAN_START_WAIT, "Chiesto un giro al controllore")
            if not job:
                # Su un cluster nuovo il pod può metterci molto (download dell'immagine):
                # invece di uscire si segue il giro, che il controllore avvierà.
                ui.close()
                print("\nIl controllo non è ancora partito: seguo il giro.\n")
                return self.resume_view()
        return self.follow_job(job)

    def create_scan_job(self) -> str:
        template = self.kjson("get", "configmap", f"{self.release}-scan-template", ns=True)
        text = template.get("data", {}).get("job.yaml", "")
        if "metadata:\n" not in text:
            raise Fail(f"modello del controllo mancante ({self.release}-scan-template)")
        job = f"{self.release}-scan-{time.strftime('%y%m%d%H%M%S')}"
        text = text.replace("metadata:\n", f"metadata:\n  name: {job}\n", 1)
        self.kubectl("create", "-f", "-", ns=True, input=text)
        return job

    def wait_scan_job(self, since: float, timeout: int, what: str = "") -> str | None:
        """Il primo Job di controllo creato dopo `since` (o None)."""
        start = time.time()
        deadline = start + timeout
        while time.time() < deadline:
            if what:
                waited = int(time.time() - start)
                self.ui.busy(f"{what}: attendo che parta il controllo ({waited} s di {timeout})")
            items = self.kjson("get", "jobs", "-l", "sage.io/role=scan", ns=True).get("items", [])
            newer = [
                j["metadata"]["name"]
                for j in items
                if parse_k8s_time(j["metadata"].get("creationTimestamp")) >= since - 5
            ]
            if newer:
                return sorted(newer)[-1]
            time.sleep(3)
        return None

    def follow_job(self, job: str) -> int:
        ui = self.ui
        ui.busy(f"Controllo avviato (job {job}), attendo il pod...")
        deadline = time.time() + 300
        while time.time() < deadline:
            pods = self.kjson("get", "pods", "-l", f"job-name={job}", ns=True).get("items", [])
            if pods:
                status = pods[0].get("status", {})
                for c in status.get("containerStatuses", []) + status.get(
                    "initContainerStatuses", []
                ):
                    waiting = c.get("state", {}).get("waiting") or {}
                    if waiting.get("reason") in START_ERRORS:
                        hint = ""
                        if waiting["reason"] in PULL_ERRORS:
                            hint = " (immagine privata o nome errato?)"
                        raise Fail(
                            f"il pod non parte: {waiting['reason']}{hint}: "
                            f"{waiting.get('message', '')}"
                        )
                if status.get("phase") in ("Running", "Succeeded", "Failed"):
                    break
            time.sleep(2)
        else:
            raise Fail(
                f"il pod del job {job} non è partito in 5 minuti: "
                f"kubectl -n {self.ns} describe job {job}"
            )
        # Il log va nel terminale normale, dove resta leggibile.
        ui.close()
        print(f"\nLog del controllo (job {job}; Ctrl+C esce, il controllo continua):\n")
        try:
            self.follow_logs(job)
        except KeyboardInterrupt:
            ignore_interrupts()
            # Si smette solo di leggere il log: il Job gira nel cluster, indipendente da qui.
            print(
                f"\nSmesso di seguire il log: il controllo continua nel cluster. "
                f"Per riprenderlo: {self.command_name()} --resume"
            )
            return 0
        # Il log finisce un attimo prima che il Job risulti completato: si aspetta l'esito.
        result = {}
        for _ in range(30):
            result = self.kjson("get", "job", job, ns=True).get("status", {})
            if result.get("succeeded") or result.get("failed"):
                break
            time.sleep(2)
        if result.get("succeeded"):
            ui.ok("controllo completato: il controllore prosegue con i nodi (vedi la dashboard)")
            ui.info(
                "Report completo:\n"
                f"  kubectl -n {self.ns} get configmap {self.release}-report "
                "-o jsonpath='{.binaryData.data\\.json\\.gz}' | base64 -d | gunzip | "
                "python3 -m json.tool | less"
            )
            return 0
        ui.warn(f"il controllo non è finito bene: kubectl -n {self.ns} describe job {job}")
        return 1

    def uninstall(self, current: dict, reinstall: bool = False) -> int:
        """Disinstalla. Con `reinstall` tiene namespace, storico e cache dell'LLM (le CVE
        già analizzate non si richiedono) e restituisce 1 se l'utente rinuncia."""
        ui = self.ui
        active = self.kjson(
            "get",
            "jobs",
            "-l",
            f"sage.io/role=remediate,app.kubernetes.io/instance={self.release}",
            ns=True,
        ).get("items", [])
        running = [j["metadata"]["name"] for j in active if j.get("status", {}).get("active")]
        if reinstall:
            help = (
                "Toglie la configurazione attuale (chiave SSH, etichette, segreti, stato) e "
                "riparte da zero con le domande dell'installazione. Restano lo storico e la "
                "cache dell'LLM."
            )
        else:
            help = (
                "Toglie SAGE dal cluster, la sua chiave dai nodi e le etichette dei gruppi. "
                "Lo storico delle modifiche viene salvato anche in un file qui."
            )
        if running:
            help += (
                "\n\nATTENZIONE: remediation in corso (" + ", ".join(running) + "): un nodo "
                "potrebbe restare in cordon se interrompi ora."
            )
        if not ui.yes(
            "Reinstallo SAGE da zero?" if reinstall else "Disinstallo SAGE?", False, help=help
        ):
            return 1 if reinstall else 0
        note = self.ask_note()
        ui.busy("Tolgo l'installazione attuale..." if reinstall else "Disinstallo SAGE...")
        self.record(
            "reinstallazione: tolta la configurazione" if reinstall else "disinstallazione",
            [],
            note,
        )
        nodes = parse_nodes(self.kjson("get", "nodes"))
        labelled = [n for n in nodes if GROUP_LABEL in n.labels]
        secret = self.read_secret(f"{self.release}-ssh")
        user = current.get("config", {}).get("ssh", {}).get("user")
        self.port = int(current.get("config", {}).get("ssh", {}).get("port", 22))
        if secret.get("id_ed25519") and user and labelled:
            # Nomi propri: con --reinstall nella stessa cartella si crea poi la chiave nuova.
            key = self.tmp / "old_id_ed25519"
            key.write_text(secret["id_ed25519"])
            key.chmod(0o600)
            known_hosts = self.tmp / "old_known_hosts"
            known_hosts.write_text(secret.get("known_hosts", ""))
            public = run(["ssh-keygen", "-y", "-f", str(key)]).stdout.strip()
            for n, proc in self.parallel(
                labelled,
                lambda n: self.ssh(n.ip, remove_key_command(public), user, key, known_hosts),
            ):
                if proc.returncode == 0:
                    ui.ok(f"{n.name}: chiave di SAGE rimossa")
                else:
                    ui.warn(
                        f"{n.name}: chiave non rimossa ({explain_ssh_error(proc.stderr)}); "
                        f"togli a mano la riga con '{key_blob(public)[-16:]}'"
                    )
        for n in labelled:
            self.kubectl("label", "node", n.name, f"{GROUP_LABEL}-")
        self.helm("uninstall", self.release)
        for job in active:
            self.kubectl("delete", "job", job["metadata"]["name"], ns=True, check=False)
        # Copia locale dello storico: il namespace (e la ConfigMap) può sparire.
        saved = Path.cwd() / f"sage-storico-{self.release}-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
        history = self.read_history()
        saved.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in history))
        ui.ok(f"storico salvato in {saved}")
        ns = self.kjson("get", "namespace", self.ns)
        ours = ns["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by") == MANAGED_BY
        if reinstall:
            for suffix in ("state", "report", "controller", "resume", "scan-now", "ca"):
                self.kubectl(
                    "delete", "configmap", f"{self.release}-{suffix}", ns=True, check=False
                )
            for suffix in ("ssh", "llm", "pull"):
                self.kubectl("delete", "secret", f"{self.release}-{suffix}", ns=True, check=False)
            ui.ok("installazione precedente tolta: storico e cache dell'LLM conservati")
            return 0
        if ours and ui.yes(
            f"Elimino anche il namespace {self.ns}?",
            help="Contiene stato, report, segreti e storico di SAGE (lo storico è già salvato).",
        ):
            self.kubectl("delete", "namespace", self.ns, "--wait=false")
        else:
            for suffix in (
                "state",
                "report",
                "controller",
                "llm-cache",
                "resume",
                "scan-now",
                "ca",
            ):
                self.kubectl(
                    "delete", "configmap", f"{self.release}-{suffix}", ns=True, check=False
                )
            for suffix in ("ssh", "llm", "pull"):
                self.kubectl("delete", "secret", f"{self.release}-{suffix}", ns=True, check=False)
        ui.ok("SAGE disinstallato")
        if os.path.exists(self.args.bin):
            ui.info(f"Il comando resta in {self.args.bin}: per toglierlo, sudo rm {self.args.bin}")
        return 0


# ------------------------------------------------------------------ main


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="sage",
        description="Installa, riconfigura o disinstalla SAGE sul cluster di kubectl.",
    )
    p.add_argument("--namespace", default="sage", help="namespace di SAGE (default: sage)")
    p.add_argument("--release", default="sage", help="nome della release Helm (default: sage)")
    p.add_argument("--context", help="contesto kubectl (default: quello attuale)")
    p.add_argument(
        "--image",
        help="immagine, es. registro/owner/sage@sha256:... (default: quella della release)",
    )
    p.add_argument(
        "--chart",
        help="chart da usare: cartella o .tgz (default: quello della release o della repo)",
    )
    p.add_argument("--ssh-port", type=int, help="porta SSH dei nodi (default: 22)")
    p.add_argument(
        "--live",
        action="store_true",
        help=(
            "modalità reale: nuova installazione (o --reinstall) senza simulazione; "
            "su un'installazione esistente passa al vivo"
        ),
    )
    p.add_argument(
        "--reinstall",
        action="store_true",
        help="toglie l'installazione attuale e la rifà da zero (tiene storico e cache LLM)",
    )
    p.add_argument(
        "--allow-remove",
        action="store_true",
        help="permette a tutti i gruppi di rimuovere i pacchetti inutilizzati",
    )
    p.add_argument(
        "--dashboard", action="store_true", help="apre subito la dashboard (port-forward)"
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="con --resume: mostra lo stato e il lavoro attuale una volta sola, poi esce",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help=(
            "segue il giro: stato e log di quello che SAGE sta facendo, nodo dopo nodo, "
            "finché non premi Ctrl+C"
        ),
    )
    p.add_argument(
        "--bin",
        default=DEFAULT_BIN,
        help=f"dove installare il comando sage (default: {DEFAULT_BIN})",
    )
    p.add_argument(
        "--dashboard-port",
        type=int,
        default=8080,
        help="porta locale per aprire la dashboard (default: 8080)",
    )
    p.add_argument("--no-tui", action="store_true", help="domande su righe, senza schermo intero")
    p.add_argument(
        "--version", action="version", version=RELEASE.get("version", "copia locale della repo")
    )
    args = p.parse_args(argv)
    if not NAME_RE.match(args.release) or len(args.release) > 40:
        p.error("--release: minuscole, cifre e trattini, massimo 40 caratteri")
    return args


def ignore_interrupts() -> None:
    """Dopo il primo Ctrl+C gli altri si ignorano. L'eseguibile compilato (un solo file)
    riceve il Ctrl+C due volte: dal terminale e dal processo di avvio che glielo inoltra.
    Senza questo il secondo arriva mentre si esce e stampa un altro messaggio."""
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):  # non nel thread principale
        pass


# Certificati delle CA del sistema, nelle varie distro. L'eseguibile è compilato su Rocky e
# cerca i certificati dove li mette RHEL: su Debian, Ubuntu e SUSE stanno altrove.
SYSTEM_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Rocky, Fedora
    "/etc/ssl/ca-bundle.pem",  # SUSE
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
)
# Oltre questa dimensione le CA non entrano in una ConfigMap (limite 1 MiB, con margine).
CA_BUNDLE_MAX = 900_000


def system_ca_bundle() -> str | None:
    """Il file delle CA che il sistema usa davvero (SSL_CERT_FILE se impostato)."""
    configured = os.environ.get("SSL_CERT_FILE")
    if configured and os.path.isfile(configured):
        return configured
    default = ssl.get_default_verify_paths().cafile
    for path in (*SYSTEM_CA_BUNDLES, default):
        if path and os.path.isfile(path):
            return path
    return None


def use_system_ca() -> None:
    """HTTPS dell'installer con le CA del sistema, comprese quelle aziendali (proxy che
    ispezionano TLS). Python le legge da SSL_CERT_FILE."""
    if os.environ.get("SSL_CERT_FILE"):
        return
    bundle = system_ca_bundle()
    if bundle:
        os.environ["SSL_CERT_FILE"] = bundle


def main(argv=None) -> int:
    args = parse_args(argv)
    use_system_ca()
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    term_ok = os.environ.get("TERM", "dumb") != "dumb"
    color = interactive and term_ok and "NO_COLOR" not in os.environ
    ui = ScreenUI(color) if interactive and term_ok and not args.no_tui else LineUI(color)
    try:
        return Installer(args, ui).run()
    except Fail as e:
        ui.error(str(e))
        return 1
    except (KeyboardInterrupt, EOFError):
        ignore_interrupts()
        ui.close()
        print(
            "\ninterrotto: si ferma solo questo programma. Quello che SAGE sta facendo nel "
            "cluster (controllo o remediation) continua: sage --resume per vederlo."
        )
        return 130
    finally:
        ui.close()


if __name__ == "__main__":
    sys.exit(main())
