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
import getpass
import hashlib
import io
import json
import os
import platform
import re
import select
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
# La remediation usa dnf: per ora solo la famiglia RHEL.
SUPPORTED_OS = re.compile(r"rocky|red hat|rhel|almalinux|centos stream|oracle linux|fedora", re.I)
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
DAYS = "(mon|tue|wed|thu|fri|sat|sun)"
WINDOW_RE = re.compile(rf"^{DAYS}(,{DAYS})* ([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
DEFAULT_WINDOW = "sat 02:00-06:00"
DEFAULT_POLICY = {
    "protected_packages": [
        "kernel*",
        "glibc",
        "systemd",
        "dnf",
        "rpm",
        "sudo",
        "openssh*",
        "NetworkManager",
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
GROQ = {
    "name": "groq",
    "base_url": "https://api.groq.com/openai/v1",
    "model": "openai/gpt-oss-120b",
    "api_key_env": "GROQ_API_KEY",
}
GROQ_MIN_INTERVAL = 2.5  # piano gratuito: poche richieste al minuto
SCHEDULES = [
    ("ogni 6 ore", "0 */6 * * *"),
    ("ogni 12 ore", "0 */12 * * *"),
    ("una volta al giorno, alle 03:00", "0 3 * * *"),
]
KERNEL_MODES = [
    ("auto", "subito, appena serve (nodo svuotato e riavviato)"),
    ("window", "solo nella finestra di manutenzione"),
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
            return "OS non supportato, serve dnf"
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
    "window",
    "canary",
    "concurrency",
    "allow_remove",
    "allow_mitigate",
    "requires_fallback",
)


@dataclass
class Group:
    name: str
    order: int
    kernel: str = "window"
    window: str | None = None
    canary: str | None = None
    concurrency: int = 1
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
            concurrency=self.concurrency,
            allow_remove=self.allow_remove,
            allow_mitigate=self.allow_mitigate,
        )
        for key in ("window", "canary"):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.requires_fallback:
            out["requires_fallback"] = True
        return out

    @classmethod
    def from_config(cls, raw: dict) -> Group:
        return cls(
            name=raw["name"],
            order=int(raw["order"]),
            kernel=raw.get("kernel", "window"),
            window=raw.get("window") or None,
            canary=raw.get("canary") or None,
            concurrency=int(raw.get("concurrency", 1)),
            allow_remove=bool(raw.get("allow_remove", False)),
            allow_mitigate=bool(raw.get("allow_mitigate", False)),
            requires_fallback=bool(raw.get("requires_fallback", False)),
            extra={k: v for k, v in raw.items() if k not in GROUP_KEYS},
        )

    def kernel_text(self) -> str:
        if self.kernel == "window":
            return f"kernel nella finestra {self.window}"
        if self.kernel == "auto":
            return "kernel subito"
        return "kernel solo a mano"


def propose_groups(nodes: list[NodeInfo]) -> tuple[list[Group], dict[str, str]]:
    """Proposta iniziale: prima i worker, poi le GPU, i master per ultimi."""
    buckets = [
        ("worker", [n for n in nodes if not n.control_plane and not n.gpus], "auto", None),
        ("gpu", [n for n in nodes if not n.control_plane and n.gpus], "manual", None),
        ("master", [n for n in nodes if n.control_plane], "window", DEFAULT_WINDOW),
    ]
    groups, assignment = [], {}
    for name, members, kernel, window in buckets:
        if not members:
            continue
        canary = members[0].name if len(members) > 1 else None
        groups.append(Group(name, len(groups) + 1, kernel, window, canary))
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
    schedule: str,
    timezone: str,
    suspend: bool,
    ssh_user: str,
    ssh_port: int,
    llm: dict,
    llm_secret: bool,
    groups: list[Group],
    proxy: list[dict],
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
    values["schedule"] = schedule
    values["timeZone"] = timezone
    values["suspend"] = suspend
    values["dryRun"] = bool(base.get("dryRun", True))
    values["secrets"] = {
        **values.get("secrets", {}),
        "ssh": f"{release}-ssh",
        "llm": f"{release}-llm" if llm_secret else "",
    }
    values["extraEnv"] = without_proxy(values.get("extraEnv") or []) + proxy
    config = values.setdefault("config", {})
    config["timezone"] = timezone
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


# Cosa serve a SAGE su ogni nodo: sudo senza password, dnf, python3 >= 3.9 (collector).
CHECK_COMMAND = (
    'p=""; sudo -n true >/dev/null 2>&1 || p="$p sudo"; '
    'command -v dnf >/dev/null 2>&1 || p="$p dnf"; '
    "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' "
    '>/dev/null 2>&1 || p="$p python"; echo "SAGE-CHECK:$p"'
)
CHECK_MESSAGES = {
    "sudo": "sudo senza password non disponibile",
    "dnf": "dnf assente",
    "python": "manca python3 >= 3.9",
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


class Checklist:
    """Lista con caselle: frecce per muoversi, spazio per spuntare, invio per confermare.

    La riga 0 è "Tutti". Logica separata dal terminale, così si può provare.
    """

    HELP = "frecce: muovi  spazio: seleziona  a: tutti  n: nessuno  invio: conferma"

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
        """Applica un tasto. True quando la scelta è confermata."""
        self.message = ""
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

    def lines(self, width: int, height: int) -> list[str]:
        mark = "x" if self.all_on() else ("-" if self.selected else " ")
        head = f"[{mark}] {self.all_label} ({len(self.selected)} scelti)"
        rows = [(self.cursor == 0, head, False)]
        for i, text in enumerate(self.labels):
            box = "x" if i in self.selected else " "
            extra = f"  ({self.disabled[i]})" if i in self.disabled else ""
            rows.append((self.cursor == i + 1, f"[{box}] {text}{extra}", i in self.disabled))
        visible = max(height - 2, 3)
        if self.cursor < self.top:
            self.top = self.cursor
        elif self.cursor >= self.top + visible:
            self.top = self.cursor - visible + 1
        out = [_fit(self.HELP, width)]
        for current, text, dim in rows[self.top : self.top + visible]:
            out.append((_fit(("> " if current else "  ") + text, width), current, dim))
        out.append(_fit(self.message, width))
        return out


class Menu:
    """Scelta singola con le frecce."""

    def __init__(self, options, default=0):
        self.options = list(options)
        self.cursor = default
        self.top = 0

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

    def lines(self, width: int, height: int) -> list:
        visible = max(height - 1, 3)
        if self.cursor < self.top:
            self.top = self.cursor
        elif self.cursor >= self.top + visible:
            self.top = self.cursor - visible + 1
        out = []
        for i in range(self.top, min(self.top + visible, len(self.options))):
            current = i == self.cursor
            out.append((_fit(("> " if current else "  ") + self.options[i], width), current, False))
        return out


def read_key(fd: int) -> str:
    data = os.read(fd, 1)
    if data == b"\x1b":
        if not select.select([fd], [], [], 0.05)[0]:
            return "esc"
        second = os.read(fd, 1)
        if second not in (b"[", b"O"):
            return ""
        third = os.read(fd, 1)
        if third.isdigit():  # es. ESC [ 5 ~
            while os.read(fd, 1) not in (b"~", b""):
                pass
            return ""
        return {b"A": "up", b"B": "down", b"H": "home", b"F": "end"}.get(third, "")
    if data in (b"\r", b"\n"):
        return "enter"
    if data == b" ":
        return "space"
    if data == b"\t":
        return "tab"
    if data == b"\x03":
        raise KeyboardInterrupt
    if data in (b"\x04", b""):
        raise EOFError
    return data.decode(errors="ignore").lower()


class UI:
    def __init__(self, tui: bool, color: bool):
        self.tui = tui
        self.color = color

    def _c(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def title(self, text: str) -> None:
        print("\n" + self._c("1", text))

    def info(self, text: str = "") -> None:
        print(text)

    def ok(self, text: str) -> None:
        print(self._c("32", "ok ") + text)

    def warn(self, text: str) -> None:
        print(self._c("33", "attenzione: ") + text)

    def error(self, text: str) -> None:
        print(self._c("31", "errore: ") + text, file=sys.stderr)

    def ask(self, prompt: str, default: str | None = None, check=None) -> str:
        suffix = f" [{default}]" if default not in (None, "") else ""
        while True:
            answer = input(f"{prompt}{suffix}: ").strip()
            if not answer and default is not None:
                answer = default
            problem = check(answer) if check else (None if answer else "risposta obbligatoria")
            if not problem:
                return answer
            self.warn(problem)

    def ask_int(self, prompt: str, default: int, minimum: int = 1) -> int:
        def check(v):
            return None if v.isdigit() and int(v) >= minimum else f"un intero >= {minimum}"

        return int(self.ask(prompt, str(default), check))

    def yes(self, prompt: str, default: bool = True) -> bool:
        hint = "S/n" if default else "s/N"
        while True:
            answer = input(f"{prompt} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("s", "si", "sì", "y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def secret(self, prompt: str) -> str:
        return getpass.getpass(f"{prompt} (non viene mostrata): ").strip()

    def _loop(self, widget) -> None:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        out = sys.stdout
        drawn = 0
        out.write("\x1b[?25l")
        try:
            tty.setcbreak(fd)
            while True:
                size = shutil.get_terminal_size()
                # Alcuni terminali (es. pty senza dimensioni) riportano 0x0.
                columns, height = size.columns or 80, size.lines or 24
                rows = widget.lines(columns, max(height - 4, 5))
                if drawn:
                    out.write(f"\r\x1b[{drawn}A")
                for row in rows:
                    if isinstance(row, tuple):
                        text, current, dim = row
                        if dim:
                            text = self._c("2", text)
                        elif current:
                            text = self._c("1;36", text)
                    else:
                        text = row
                    out.write("\x1b[2K" + text + "\n")
                for _ in range(drawn - len(rows)):
                    out.write("\x1b[2K\n")
                if drawn > len(rows):
                    out.write(f"\r\x1b[{drawn - len(rows)}A")
                drawn = len(rows)
                out.flush()
                if widget.key(read_key(fd)):
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            out.write("\x1b[?25h")
            out.flush()

    def choose(self, title: str, options: list[str], default: int = 0) -> int:
        print(self._c("1", title))
        if self.tui:
            menu = Menu(options, default)
            self._loop(menu)
            return menu.cursor
        for i, text in enumerate(options, start=1):
            print(f"  {i}. {text}")

        def check(v):
            return None if v.isdigit() and 1 <= int(v) <= len(options) else "scegli un numero"

        return int(self.ask("Scelta", str(default + 1), check)) - 1

    def checklist(self, title, keys, labels, selected, disabled, minimum=1) -> set[int]:
        print(self._c("1", title))
        if self.tui:
            widget = Checklist(labels, selected, disabled, minimum=minimum)
            self._loop(widget)
            return widget.selected
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


# ------------------------------------------------------------------ comandi esterni


def run(args, input=None, check=True, timeout=None) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(
            args, input=input, capture_output=True, text=True, timeout=timeout, check=False
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


def llm_probe(base_url: str, key: str | None, model: str) -> str | None:
    """None se l'endpoint risponde e conosce il modello, altrimenti il problema."""
    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base_url.rstrip("/") + "/models", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "chiave rifiutata (HTTP 401)"
        if e.code == 403:
            return (
                "accesso negato (HTTP 403): chiave senza permessi o richiesta bloccata dalla rete"
            )
        return f"risposta HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"non raggiungibile da qui ({getattr(e, 'reason', e)})"
    ids = [m.get("id") for m in data.get("data", []) if isinstance(m, dict)]
    if ids and model not in ids:
        return f"il modello {model} non è tra quelli disponibili (es. {', '.join(ids[:8])})"
    return None


def env_name(endpoint: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", endpoint.upper()) + "_API_KEY"


# ------------------------------------------------------------------ installer


class Installer:
    def __init__(self, args, ui: UI):
        self.args = args
        self.ui = ui
        self.ns = args.namespace
        self.release = args.release
        self.tmp = Path(tempfile.mkdtemp(prefix="sage-install-"))
        os.chmod(self.tmp, 0o700)
        self.helm_bin = "helm"
        self.port = args.ssh_port or 22
        self.pending_secrets: list = []  # creati solo dopo la conferma finale

    # --- comandi
    def kubectl(self, *args, ns=False, input=None, check=True):
        cmd = ["kubectl"]
        if self.args.context:
            cmd += ["--context", self.args.context]
        if ns:
            cmd += ["-n", self.ns]
        return run(cmd + list(args), input=input, check=check, timeout=120)

    def kjson(self, *args, ns=False):
        return json.loads(self.kubectl(*args, "-o", "json", ns=ns).stdout)

    def helm(self, *args, check=True):
        cmd = [self.helm_bin] + list(args) + ["-n", self.ns]
        if self.args.context:
            cmd += ["--kube-context", self.args.context]
        return run(cmd, check=check, timeout=600)

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
        version = RELEASE.get("version", "copia locale della repo")
        ui.title(f"SAGE, installer ({version})")
        self.preflight()
        current = self.current_values()
        if current is None:
            return self.configure({}, new=True)
        mode = "simulazione" if current.get("dryRun", True) else "REALE"
        auto = "sospesi" if current.get("suspend", True) else "attivi"
        ui.info(
            f"SAGE è già installato (release {self.release}, namespace {self.ns}): "
            f"modalità {mode}, giri automatici {auto}."
        )
        live = not current.get("dryRun", True)
        options = [
            "Riconfigura (nodi, gruppi, LLM, frequenza) partendo da quella attuale",
            "Torna alla simulazione" if live else "Passa al vivo: SAGE applicherà le remediation",
            "Riattiva i giri automatici" if current.get("suspend", True) else "Sospendi i giri",
            "Lancia un giro adesso",
            "Disinstalla SAGE",
            "Esci",
        ]
        choice = ui.choose("Cosa vuoi fare?", options)
        if choice == 0:
            return self.configure(current, new=False)
        if choice == 1:
            return self.toggle_live(current)
        if choice == 2:
            values = copy.deepcopy(current)
            values["suspend"] = not current.get("suspend", True)
            self.helm_apply(values)
            ui.ok("giri automatici " + ("sospesi" if values["suspend"] else "attivi"))
            return 0
        if choice == 3:
            return self.run_now()
        if choice == 4:
            return self.uninstall(current)
        return 0

    def preflight(self) -> None:
        ui = self.ui
        if not shutil.which("kubectl"):
            raise Fail(
                "kubectl non trovato: lancia l'installer da un master o da una macchina "
                "con kubectl configurato"
            )
        ctx = self.kubectl("config", "current-context", check=False).stdout.strip()
        if self.args.context:
            ctx = self.args.context
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
        ui.info(f"Cluster: {ctx} (Kubernetes {version}), namespace {self.ns}")
        self.helm_bin = self.ensure_helm()

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
            f"Helm non è installato. Scarico Helm {version} in {target.parent} "
            "(checksum verificato, usato solo dall'installer)?"
        ):
            raise Fail("serve Helm per installare SAGE")
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
        config = current.get("config", {})
        nodes = parse_nodes(self.kjson("get", "nodes"))
        if not nodes:
            raise Fail("il cluster non ha nodi")

        # 1. nodi
        ui.title("1. Nodi da far gestire a SAGE")
        width = max(len(n.name) for n in nodes)
        disabled = {i: n.problem for i, n in enumerate(nodes) if n.problem}
        if new:
            preselected = {i for i in range(len(nodes)) if i not in disabled}
        else:
            preselected = {i for i, n in enumerate(nodes) if GROUP_LABEL in n.labels}
        chosen = ui.checklist(
            "Scegli i nodi:",
            [n.name for n in nodes],
            [n.label(width) for n in nodes],
            preselected,
            disabled,
        )
        selected = [nodes[i] for i in sorted(chosen)]
        for n in selected:
            if not n.ready:
                ui.warn(f"{n.name} non è Ready: SAGE lo salterà finché non torna pronto")

        # 2. SSH: prima dei gruppi, perché i nodi irraggiungibili possono essere esclusi
        ui.title("2. Accesso SSH ai nodi")
        default_user = (
            config.get("ssh", {}).get("user") or os.environ.get("SUDO_USER") or getpass.getuser()
        )
        user = ui.ask("Utente SSH sui nodi (con sudo senza password)", default_user)
        self.port = self.args.ssh_port or int(config.get("ssh", {}).get("port", 22))
        private, _, known_hosts = self.prepare_ssh(user, selected)

        # 3. gruppi
        ui.title("3. Gruppi e ondate")
        groups, assignment = self.initial_groups(config, selected)
        groups = self.edit_groups(groups, assignment, selected)

        # 4. LLM
        ui.title("4. LLM")
        llm, llm_keys = self.configure_llm(config.get("llm", {}), groups)

        # 5. quando e come
        ui.title("5. Frequenza e rete")
        schedule = self.choose_schedule(current.get("schedule"))
        tz_default = current.get("timeZone") or local_timezone()
        timezone = ui.ask(
            "Fuso orario (finestre di manutenzione e giri)",
            tz_default,
            lambda v: None if valid_timezone(v) else "fuso sconosciuto",
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
        if new:
            suspend = not ui.yes(f"Attivo i giri automatici ({schedule}) in simulazione?")
        else:
            suspend = bool(current.get("suspend", True))

        # 6. immagine
        image = self.args.image or RELEASE.get("image") or image_ref(current)
        if not image:
            image = ui.ask("Immagine di SAGE (es. registro/owner/sage@sha256:...)")
        pull_secret = self.check_image(image, current)

        values = build_values(
            current,
            release=self.release,
            image=image,
            pull_secret=pull_secret,
            schedule=schedule,
            timezone=timezone,
            suspend=suspend,
            ssh_user=user,
            ssh_port=self.port,
            llm=llm,
            llm_secret=bool(llm_keys) or self.secret_exists(f"{self.release}-llm"),
            groups=groups,
            proxy=proxy,
        )

        # 7. riepilogo
        ui.title("Riepilogo")
        ui.info(f"  Immagine   {image}")
        for g in groups:
            names = ", ".join(f"{m}*" if m == g.canary else m for m in members(assignment, g.name))
            ui.info(f"  Ondata {g.order}   {g.name}: {names}  ({g.kernel_text()})")
        ui.info("             (* = canary)")
        ui.info(f"  SSH        utente {user}, chiave dedicata")
        llm_text = ", ".join(f"{e['name']} ({e['model']})" for e in llm.get("endpoints", []))
        ui.info(f"  LLM        {llm_text or 'nessuno: solo regole deterministiche'}")
        when = "sospesi" if suspend else schedule
        ui.info(
            f"  Giri       {when} ({timezone}), "
            + ("simulazione" if values["dryRun"] else "MODALITÀ REALE")
        )
        if not ui.yes("Procedo?"):
            ui.info("Nessuna modifica fatta.")
            return 0

        # 8. applicazione
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
        self.helm_apply(values)
        ui.ok(f"SAGE installato nel namespace {self.ns}")
        if ui.yes("Lancio subito un giro in simulazione e ne mostro il log?", new):
            return self.run_now()
        return 0

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

    def show_groups(self, groups, assignment) -> None:
        for g in sorted(groups, key=lambda g: g.order):
            names = ", ".join(f"{m}*" if m == g.canary else m for m in members(assignment, g.name))
            extras = []
            if g.concurrency > 1:
                extras.append(f"{g.concurrency} nodi alla volta")
            if g.allow_remove:
                extras.append("rimozioni")
            if g.allow_mitigate:
                extras.append("mitigazioni")
            if g.requires_fallback:
                extras.append("serve una riserva LLM")
            tail = f"; {', '.join(extras)}" if extras else ""
            self.ui.info(f"  {g.order}. {g.name}: {names}  ({g.kernel_text()}{tail})")
        self.ui.info("  (* = canary: il primo del gruppo, poi qualche ora di osservazione)")

    def edit_groups(self, groups, assignment, selected):
        ui = self.ui
        while True:
            groups = normalize_groups(groups, assignment)
            self.show_groups(groups, assignment)
            choice = ui.choose(
                "I gruppi vanno bene?",
                [
                    "Sì, continua",
                    "Sposta un nodo in un altro gruppo",
                    "Modifica un gruppo (ordine, canary, kernel, parallelismo...)",
                    "Crea un gruppo nuovo",
                ],
            )
            if choice == 0:
                return groups
            if choice == 1:
                names = [n.name for n in selected]
                labels = [f"{n}  (ora in {assignment[n]})" for n in names]
                node = names[ui.choose("Quale nodo?", labels)]
                options = [g.name for g in groups] + ["un gruppo nuovo..."]
                target = ui.choose(f"In quale gruppo va {node}?", options)
                if target == len(groups):
                    group = self.new_group(groups)
                    groups.append(group)
                    assignment[node] = group.name
                else:
                    assignment[node] = groups[target].name
            elif choice == 2:
                index = ui.choose("Quale gruppo?", [g.name for g in groups])
                self.edit_group(groups[index], groups, assignment)
            else:
                group = self.new_group(groups)
                groups.append(group)
                names = [n.name for n in selected]
                moved = ui.checklist(f"Nodi da mettere in {group.name}:", names, names, set(), {})
                for i in moved:
                    assignment[names[i]] = group.name

    def new_group(self, groups) -> Group:
        taken = {g.name for g in groups}

        def check(v):
            if not NAME_RE.match(v):
                return "minuscole, cifre e trattini, massimo 63 caratteri"
            return "nome già usato" if v in taken else None

        name = self.ui.ask("Nome del gruppo", None, check)
        return Group(name, max((g.order for g in groups), default=0) + 1, "window", DEFAULT_WINDOW)

    def edit_group(self, group: Group, groups, assignment) -> None:
        ui = self.ui
        while True:
            group_members = members(assignment, group.name)
            options = [
                "Fatto",
                f"Ordine dell'ondata: {group.order}",
                f"Canary: {group.canary or 'nessuno'}",
                f"Aggiornamenti del kernel: {group.kernel_text()}",
                f"Nodi aggiornati insieme: {group.concurrency}",
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
                order = ui.ask_int("Ordine (1 = per primo)", group.order)
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
                )
                group.canary = None if pick == 0 else opts[pick]
            elif choice == 3:
                modes = [k for k, _ in KERNEL_MODES]
                pick = ui.choose(
                    "Aggiornamenti del kernel",
                    [f"{k}: {d}" for k, d in KERNEL_MODES],
                    modes.index(group.kernel) if group.kernel in modes else 1,
                )
                group.kernel = modes[pick]
                if group.kernel == "window":
                    group.window = ui.ask(
                        "Finestra (giorni e orario, es. sat 02:00-06:00 o sat,sun 01:00-05:00)",
                        group.window or DEFAULT_WINDOW,
                        lambda v: None if WINDOW_RE.match(v) else "formato: sat 02:00-06:00",
                    )
            elif choice == 4:
                group.concurrency = ui.ask_int("Quanti nodi del gruppo insieme", group.concurrency)
            elif choice == 5:
                group.allow_remove = not group.allow_remove
            elif choice == 6:
                group.allow_mitigate = not group.allow_mitigate
            else:
                group.requires_fallback = not group.requires_fallback

    # --- SSH
    def prepare_ssh(self, user: str, selected: list[NodeInfo]):
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
        else:
            comment = f"sage@{self.release}"
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(key)])
            public = (self.tmp / "id_ed25519.pub").read_text().strip()
            known_hosts.write_text(existing.get("known_hosts", ""))
            ui.ok("chiave SSH dedicata creata (resta solo nel Secret del cluster)")

        pending = list(selected)
        while True:
            results = self.parallel(
                pending, lambda n: self.setup_node(n, user, key, public, known_hosts)
            )
            failed = {n.name: problem for n, problem in results if problem}
            for n, problem in results:
                if not problem:
                    ui.ok(f"{n.name}: chiave installata, sudo, dnf e python3 presenti")
            if not failed:
                break
            ui.warn("alcuni nodi non sono pronti:")
            for name, problem in failed.items():
                ui.info(f"  {name}: {problem}")
            ui.info(
                "Se l'accesso è negato, installa a mano questa chiave pubblica in "
                f"~{user}/.ssh/authorized_keys su quei nodi:\n  {public}\n"
                "Su un master raggiunto con `ssh -A` (agent forwarding) di solito basta "
                "rilanciare: l'installer usa le tue credenziali per installarla."
            )
            options = ["Riprova", "Escludi questi nodi e continua", "Interrompi"]
            changed = [n for n in failed if "chiave host" in failed[n]]
            if changed:
                options.insert(1, "Accetta la nuova chiave host dei nodi ricreati e riprova")
            choice = options[ui.choose("Come procedo?", options)]
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
        return key.read_text(), public, known_hosts.read_text()

    def setup_node(self, node: NodeInfo, user, key, public, known_hosts) -> str | None:
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            return list(zip(nodes, pool.map(fn, nodes)))

    # --- LLM
    def configure_llm(self, current: dict, groups) -> tuple[dict, dict]:
        ui = self.ui
        endpoints = list(current.get("endpoints") or [])
        options = []
        if endpoints:
            names = ", ".join(f"{e['name']} ({e['model']})" for e in endpoints)
            options.append(f"Mantieni quello attuale: {names}")
        options += [
            "Groq (gratuito, serve una chiave API da console.groq.com)",
            "Un altro endpoint compatibile con l'API OpenAI (vLLM, Ollama, server CINECA...)",
            "Nessun LLM: solo regole deterministiche (nel dubbio si aggiorna)",
        ]
        choice = options[ui.choose("Quale LLM usa SAGE per leggere le CVE?", options)]
        if choice.startswith("Mantieni"):
            return {"endpoints": endpoints}, {}
        if choice.startswith("Nessun"):
            return {"endpoints": []}, {}
        endpoints, keys = [], {}
        kind = "groq" if choice.startswith("Groq") else "custom"
        while True:
            endpoint, key = self.ask_endpoint(kind, groups, {e["name"] for e in endpoints})
            endpoints.append(endpoint)
            if key:
                keys[endpoint["api_key_env"]] = key
            if not ui.yes(
                "Aggiungo un endpoint di riserva (usato se il primo non risponde)?", False
            ):
                break
            pick = ui.choose("Riserva:", ["Groq", "Un altro endpoint compatibile OpenAI"])
            kind = "groq" if pick == 0 else "custom"
        llm = {"endpoints": endpoints}
        if any(e["base_url"] == GROQ["base_url"] for e in endpoints):
            llm["min_interval_seconds"] = max(
                float(current.get("min_interval_seconds", 0)), GROQ_MIN_INTERVAL
            )
        return llm, keys

    def ask_endpoint(self, kind, groups, taken) -> tuple[dict, str | None]:
        ui = self.ui
        if kind == "groq":
            endpoint = dict(GROQ)
            if endpoint["name"] in taken:
                endpoint["name"] = "groq-2"
                endpoint["api_key_env"] = "GROQ_2_API_KEY"
            endpoint["model"] = ui.ask("Modello", GROQ["model"])
        else:
            name = ui.ask(
                "Nome breve dell'endpoint",
                None,
                lambda v: (
                    None
                    if NAME_RE.match(v) and v not in taken
                    else "minuscole, cifre e trattini, non già usato"
                ),
            )
            endpoint = {
                "name": name,
                "base_url": ui.ask(
                    "URL di base (es. http://host:8000/v1)",
                    None,
                    lambda v: (
                        None
                        if v.startswith(("http://", "https://"))
                        else "deve iniziare con http:// o https://"
                    ),
                ),
                "model": ui.ask("Modello"),
            }
            group_names = [g.name for g in groups]
            where = ui.choose(
                "Dove gira?",
                ["Fuori dal cluster gestito"] + [f"Su un nodo del gruppo {g}" for g in group_names],
            )
            if where:
                endpoint["hosted_in_group"] = group_names[where - 1]
                groups[where - 1].requires_fallback = True
                ui.info(
                    f"Il gruppo {group_names[where - 1]} si aggiornerà solo con una riserva "
                    "LLM attiva fuori da quel gruppo."
                )
        while True:
            key = ui.secret(
                f"Chiave API per {endpoint['name']}"
                + ("" if kind == "groq" else " (vuota se non serve)")
            )
            if kind == "groq" and not key:
                ui.warn("per Groq serve la chiave")
                continue
            break
        while True:
            problem = llm_probe(endpoint["base_url"], key or None, endpoint["model"])
            if not problem:
                ui.ok(f"{endpoint['name']} risponde")
                break
            ui.warn(f"{endpoint['name']}: {problem}")
            if problem.startswith(("chiave", "accesso")) and ui.yes(
                "Inserisco un'altra chiave?", problem.startswith("chiave")
            ):
                key = ui.secret(f"Chiave API per {endpoint['name']}")
            elif "modello" in problem and ui.yes("Scelgo un altro modello?"):
                endpoint["model"] = ui.ask("Modello", endpoint["model"])
            else:
                # Es. endpoint interno raggiungibile dai pod ma non da qui: si prosegue.
                break
        if key and kind != "groq":
            endpoint["api_key_env"] = env_name(endpoint["name"])
        return endpoint, key or None

    # --- frequenza e rete
    def choose_schedule(self, current: str | None) -> str:
        options = [f"{text} ({cron})" for text, cron in SCHEDULES]
        crons = [cron for _, cron in SCHEDULES]
        default = crons.index(current) if current in crons else 0
        if current and current not in crons:
            options.insert(0, f"come ora ({current})")
            crons.insert(0, current)
        options.append("personalizzata (espressione cron)")
        pick = self.ui.choose("Ogni quanto controlla i nodi?", options, default)
        if pick < len(crons):
            return crons[pick]
        return self.ui.ask(
            "Espressione cron (minuto ora giorno mese giorno-settimana)",
            None,
            lambda v: None if len(v.split()) == 5 else "servono 5 campi",
        )

    def choose_proxy(self, current: dict, ips, api_ip) -> list[dict]:
        env = {e.get("name"): e.get("value") for e in current.get("extraEnv") or []}
        detected = (
            env.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
        )
        if detected and detected.startswith("socks"):
            detected = None  # un tunnel SOCKS locale non vale per i pod
        if not self.ui.yes(
            "I pod del cluster escono su Internet tramite un proxy HTTP?", bool(detected)
        ):
            return []
        proxy = self.ui.ask(
            "URL del proxy (es. http://proxy:3128)",
            detected,
            lambda v: (
                None
                if v.startswith(("http://", "https://"))
                else "deve iniziare con http:// o https://"
            ),
        )
        return proxy_env(proxy, ips, api_ip)

    # --- immagine
    def check_image(self, image: str, current: dict) -> str | None:
        ui = self.ui
        pull = (current.get("imagePullSecrets") or [{}])[0].get("name")
        access = image_access(image)
        if access == "public" or pull:
            return pull
        if access.startswith("unknown"):
            ui.warn(f"non riesco a verificare l'immagine da qui ({access[9:]}): proseguo")
            return None
        ui.warn("l'immagine non si scarica senza credenziali (pacchetto privato?).")
        choice = ui.choose(
            "Come procedo?",
            [
                "Creo un pull secret con utente e token del registro",
                "Proseguo lo stesso (l'ho resa pubblica nel frattempo)",
                "Interrompi",
            ],
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

    def ensure_namespace(self) -> None:
        if self.kubectl("get", "namespace", self.ns, check=False).returncode == 0:
            return
        manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": self.ns, "labels": {"app.kubernetes.io/managed-by": MANAGED_BY}},
        }
        self.kubectl("create", "-f", "-", input=json.dumps(manifest))

    def apply_secret(self, name: str, data: dict, kind: str = "Opaque") -> None:
        # Server-side apply: niente copia dei dati nell'annotazione last-applied.
        manifest = {
            "apiVersion": "v1",
            "kind": "Secret",
            "type": kind,
            "metadata": {
                "name": name,
                "namespace": self.ns,
                "labels": {
                    "app.kubernetes.io/managed-by": MANAGED_BY,
                    "app.kubernetes.io/instance": self.release,
                },
            },
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()},
        }
        self.kubectl(
            "apply",
            "--server-side",
            "--force-conflicts",
            f"--field-manager={MANAGED_BY}",
            "-f",
            "-",
            input=json.dumps(manifest),
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
        if RELEASE.get("chart_url"):
            data = download(RELEASE["chart_url"], RELEASE.get("chart_sha256"))
            path = self.tmp / "sage-chart.tgz"
            path.write_bytes(data)
            return str(path)
        local = Path(__file__).resolve().parent.parent / "chart" / "sage"
        if local.is_dir():
            return str(local)
        raise Fail("chart non trovato: usa l'installer di una release o --chart")

    def helm_apply(self, values: dict) -> None:
        image = self.args.image or RELEASE.get("image")
        if image:
            values = {**values, "image": {**values.get("image", {}), **split_image(image)}}
        path = self.tmp / "values.json"
        path.write_text(json.dumps(values, indent=2))
        self.helm("upgrade", "--install", self.release, self.chart(), "-f", str(path))

    # --- azioni
    def toggle_live(self, current: dict) -> int:
        ui = self.ui
        values = copy.deepcopy(current)
        if not current.get("dryRun", True):
            values["dryRun"] = True
            self.helm_apply(values)
            ui.ok("tornato in simulazione: nessuna remediation verrà avviata")
            return 0
        ui.warn(
            "nella modalità reale SAGE applica le remediation: cordon, drain, aggiornamenti "
            "e riavvii, un nodo alla volta, prima il canary di ogni gruppo."
        )
        if not ui.yes("Passo al vivo?", False):
            return 0
        values["dryRun"] = False
        self.helm_apply(values)
        ui.ok("modalità reale attiva dal prossimo giro")
        return 0

    def run_now(self) -> int:
        ui = self.ui
        job = f"{self.release}-manual-{time.strftime('%m%d%H%M%S')}"
        self.kubectl("create", "job", f"--from=cronjob/{self.release}-scan", job, ns=True)
        ui.info(f"Giro avviato (job {job}), attendo il pod...")
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
        cmd = ["kubectl"] + (["--context", self.args.context] if self.args.context else [])
        subprocess.run(cmd + ["-n", self.ns, "logs", "-f", f"job/{job}"], check=False)
        result = self.kjson("get", "job", job, ns=True).get("status", {})
        if result.get("succeeded"):
            ui.ok("giro completato")
            ui.info(
                "Report completo:\n"
                f"  kubectl -n {self.ns} get configmap {self.release}-report "
                "-o jsonpath='{.binaryData.data\\.json\\.gz}' | base64 -d | gunzip | "
                "python3 -m json.tool | less"
            )
            return 0
        ui.warn(f"il giro non è finito bene: kubectl -n {self.ns} describe job {job}")
        return 1

    def uninstall(self, current: dict) -> int:
        ui = self.ui
        active = self.kjson(
            "get",
            "jobs",
            "-l",
            f"sage.io/role=remediate,app.kubernetes.io/instance={self.release}",
            ns=True,
        ).get("items", [])
        running = [j["metadata"]["name"] for j in active if j.get("status", {}).get("active")]
        if running:
            ui.warn(
                "remediation in corso (" + ", ".join(running) + "): un nodo potrebbe "
                "restare in cordon se interrompi ora."
            )
        if not ui.yes("Disinstallo SAGE?", False):
            return 0
        nodes = parse_nodes(self.kjson("get", "nodes"))
        labelled = [n for n in nodes if GROUP_LABEL in n.labels]
        secret = self.read_secret(f"{self.release}-ssh")
        user = current.get("config", {}).get("ssh", {}).get("user")
        self.port = int(current.get("config", {}).get("ssh", {}).get("port", 22))
        if secret.get("id_ed25519") and user and labelled:
            key = self.tmp / "id_ed25519"
            key.write_text(secret["id_ed25519"])
            key.chmod(0o600)
            known_hosts = self.tmp / "known_hosts"
            known_hosts.write_text(secret.get("known_hosts", ""))
            public = run(["ssh-keygen", "-y", "-f", str(key)]).stdout.strip()
            results = self.parallel(
                labelled,
                lambda n: self.ssh(n.ip, remove_key_command(public), user, key, known_hosts),
            )
            for n, proc in results:
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
        ns = self.kjson("get", "namespace", self.ns)
        ours = ns["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by") == MANAGED_BY
        if ours and ui.yes(f"Elimino anche il namespace {self.ns} (stato, report, segreti)?"):
            self.kubectl("delete", "namespace", self.ns, "--wait=false")
        else:
            for suffix in ("state", "report", "llm-cache", "resume"):
                self.kubectl(
                    "delete", "configmap", f"{self.release}-{suffix}", ns=True, check=False
                )
            for suffix in ("ssh", "llm", "pull"):
                self.kubectl("delete", "secret", f"{self.release}-{suffix}", ns=True, check=False)
        ui.ok("SAGE disinstallato")
        return 0


# ------------------------------------------------------------------ main


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="sage-install",
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
    p.add_argument("--no-tui", action="store_true", help="liste numerate invece dei menu")
    p.add_argument(
        "--version", action="version", version=RELEASE.get("version", "copia locale della repo")
    )
    args = p.parse_args(argv)
    if not NAME_RE.match(args.release) or len(args.release) > 40:
        p.error("--release: minuscole, cifre e trattini, massimo 40 caratteri")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    term_ok = os.environ.get("TERM", "dumb") != "dumb"
    ui = UI(
        tui=interactive and term_ok and not args.no_tui,
        color=interactive and term_ok and "NO_COLOR" not in os.environ,
    )
    try:
        return Installer(args, ui).run()
    except Fail as e:
        ui.error(str(e))
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\ninterrotto")
        return 130


if __name__ == "__main__":
    sys.exit(main())
