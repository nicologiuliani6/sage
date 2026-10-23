"""Raccolta dai nodi: lancia `collect.yml` e legge i report JSON."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from sage import paths
from sage.config import Config
from sage.inventory import write_inventory
from sage.kube import Node

log = logging.getLogger(__name__)


def collect(nodes: list[Node], cfg: Config, workdir: Path) -> dict[str, dict[str, Any]]:
    """Report per nodo. I nodi irraggiungibili mancano dal risultato (e non vengono toccati)."""
    if not nodes:
        return {}
    inventory, warnings = write_inventory(nodes, cfg, workdir)
    for w in warnings:
        log.warning(w)
    out_dir = workdir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ansible-playbook",
        "-i",
        str(inventory),
        str(paths.ansible_dir() / "collect.yml"),
        "-e",
        f"sage_out_dir={out_dir}",
    ]
    parallel = cfg.controller.scan_parallel
    log.info("raccolta da %d nodi (%d alla volta)", len(nodes), parallel)
    _run(cmd + ["--forks", str(parallel)])
    # Un nodo che non ha risposto (lento, carico) si riprova una volta, da solo.
    missing = [n.name for n in nodes if not (out_dir / f"{n.name}.json").is_file()]
    if missing:
        log.info("nuovo tentativo, uno alla volta, su: %s", ", ".join(missing))
        _run(cmd + ["--forks", "1", "--limit", ",".join(missing)])
    reports = {}
    for node in nodes:
        path = out_dir / f"{node.name}.json"
        if not path.is_file():
            log.warning("nessun report da %s: nodo escluso da questo giro", node.name)
            continue
        try:
            reports[node.name] = json.loads(path.read_text())
        except json.JSONDecodeError:
            log.warning("report di %s non valido: nodo escluso da questo giro", node.name)
    return reports


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=paths.ansible_dir())
    if proc.returncode != 0:
        # Codice != 0 anche se un solo nodo non risponde: si prosegue con gli altri.
        log.warning("ansible-playbook collect.yml terminato con codice %d", proc.returncode)
        log.warning("%s", _tail(proc.stdout))


def _tail(text: str, lines: int = 30) -> str:
    return "\n".join(text.splitlines()[-lines:])
