"""Nodi e gruppi: dai label Kubernetes all'inventario Ansible."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml

from sage.config import Config, NodeGroup, SshConfig
from sage.kube import Node


@dataclass(frozen=True)
class Requirement:
    key: str
    op: str  # "=", "!=", "exists", "!exists"
    value: str | None = None

    def matches(self, labels: dict[str, str]) -> bool:
        if self.op == "exists":
            return self.key in labels
        if self.op == "!exists":
            return self.key not in labels
        if self.op == "=":
            return labels.get(self.key) == self.value
        return labels.get(self.key) != self.value


def parse_selector(selector: str) -> list[Requirement]:
    """Sottoinsieme dei label selector Kubernetes: `a=b`, `a==b`, `a!=b`, `a`, `!a`, con virgole."""
    reqs = []
    for term in (t.strip() for t in selector.split(",")):
        if not term:
            continue
        if "!=" in term:
            key, value = term.split("!=", 1)
            reqs.append(Requirement(key.strip(), "!=", value.strip()))
        elif "=" in term:
            key, value = term.replace("==", "=").split("=", 1)
            reqs.append(Requirement(key.strip(), "=", value.strip()))
        elif term.startswith("!"):
            reqs.append(Requirement(term[1:].strip(), "!exists"))
        else:
            reqs.append(Requirement(term, "exists"))
    if not reqs:
        raise ValueError(f"selector vuoto: {selector!r}")
    return reqs


def assign_groups(
    nodes: list[Node], groups: tuple[NodeGroup, ...]
) -> tuple[dict[str, NodeGroup | None], list[str]]:
    """Gruppo di ogni nodo.

    Un nodo in più gruppi è un errore di configurazione: non viene toccato.
    """
    parsed = [(g, parse_selector(g.selector)) for g in groups]
    result: dict[str, NodeGroup | None] = {}
    warnings: list[str] = []
    for node in nodes:
        matching = [g for g, reqs in parsed if all(r.matches(node.labels) for r in reqs)]
        if len(matching) > 1:
            names = ", ".join(g.name for g in matching)
            warnings.append(f"nodo {node.name} in più gruppi ({names}): non verrà toccato")
            result[node.name] = None
        elif not matching:
            warnings.append(f"nodo {node.name} senza gruppo: non verrà toccato")
            result[node.name] = None
        else:
            result[node.name] = matching[0]
    return result, warnings


def known_hosts_configured(ssh: SshConfig) -> bool:
    return bool(ssh.known_hosts_path and Path(ssh.known_hosts_path).is_file())


def prepare_ssh(ssh: SshConfig, workdir: Path) -> tuple[Path, list[str]]:
    """Copia la chiave con permessi 0600 (OpenSSH rifiuta chiavi leggibili da altri)
    e restituisce le opzioni SSH da passare ad Ansible."""
    workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = workdir / "id"
    shutil.copyfile(ssh.key_path, key)
    os.chmod(key, 0o600)
    # Keepalive: un nodo che si spegne a connessione aperta non risponde e non chiude, e senza
    # keepalive Ansible resta appeso fino al limite del Job (ore) fermando tutto il giro.
    # 15 s x 8 = 2 minuti: un nodo carico risponde comunque ai keepalive (lo fa sshd).
    options = [
        "-o BatchMode=yes",
        "-o ConnectTimeout=20",
        "-o ServerAliveInterval=15",
        "-o ServerAliveCountMax=8",
    ]
    if known_hosts_configured(ssh):
        options += ["-o StrictHostKeyChecking=yes", f"-o UserKnownHostsFile={ssh.known_hosts_path}"]
    else:
        options += [
            "-o StrictHostKeyChecking=accept-new",
            f"-o UserKnownHostsFile={workdir / 'known_hosts'}",
        ]
    if ssh.proxy_jump:
        options.append(f"-o ProxyJump={ssh.proxy_jump}")
    return key, options


def write_inventory(nodes: list[Node], cfg: Config, workdir: Path) -> tuple[Path, list[str]]:
    """Inventario YAML con i soli nodi passati; host = nome del nodo Kubernetes."""
    key, ssh_options = prepare_ssh(cfg.ssh, workdir / "ssh")
    warnings = []
    if not known_hosts_configured(cfg.ssh):
        warnings.append("known_hosts non configurato: le chiavi dei nodi non vengono verificate")
    hosts = {}
    for node in nodes:
        if not node.internal_ip:
            warnings.append(f"nodo {node.name} senza InternalIP: escluso")
            continue
        hosts[node.name] = {
            "ansible_host": node.internal_ip,
            "sage_extra_services": list(cfg.extra_services.get(node.name, ())),
        }
    inventory = {
        "all": {
            "hosts": hosts,
            "vars": {
                "ansible_user": cfg.ssh.user,
                "ansible_port": cfg.ssh.port,
                "ansible_ssh_private_key_file": str(key),
                "ansible_ssh_common_args": " ".join(ssh_options),
            },
        }
    }
    path = workdir / "inventory.yml"
    path.write_text(yaml.safe_dump(inventory, sort_keys=True))
    return path, warnings
