"""`sage remediate`: esegue il piano su un nodo con remediate.yml (dentro un Job)."""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from sage import paths
from sage.config import Config
from sage.inventory import assign_groups, write_inventory
from sage.kube import KubeApi

log = logging.getLogger(__name__)


def extra_vars(node_name: str, control_plane: bool, plan: dict[str, Any], group) -> dict[str, Any]:
    # Solo blocchi di moduli: niente cordon, drain né riavvio. Un riavvio pendente per
    # altri motivi non deve partire senza aver prima svuotato il nodo.
    light = (
        not plan.get("update_advisories")
        and not plan.get("remove_packages")
        and not plan.get("reboot")
    )
    return {
        "sage_light": light,
        "sage_reboot_pending": bool(plan.get("reboot")),
        "sage_node_name": node_name,
        "sage_update_advisories": plan.get("update_advisories", []),
        "sage_update_packages": plan.get("update_packages", []),
        "sage_remove_packages": plan.get("remove_packages", []),
        "sage_denylist_modules": plan.get("denylist_modules", []),
        "sage_drain_mode": group.drain,
        "sage_drain_timeout": group.drain_timeout_seconds,
        # Il Job viene creato solo dopo aver verificato una riserva LLM (act.step).
        "sage_disable_eviction": group.requires_fallback,
        "sage_control_plane": control_plane,
        "sage_health_urls": list(group.health_urls),
    }


def run(
    cfg: Config,
    kube: KubeApi,
    node_name: str,
    plan: dict[str, Any],
    workdir: Path,
    config_path: str | None = None,
) -> int:
    nodes = kube.list_nodes()
    node = next((n for n in nodes if n.name == node_name), None)
    if node is None:
        log.error("nodo %s non trovato", node_name)
        return 2
    groups, _ = assign_groups(nodes, cfg.groups)
    group = groups.get(node_name)
    if group is None:
        log.error("nodo %s senza gruppo: SAGE non lo tocca", node_name)
        return 2
    inventory, warnings = write_inventory([node], cfg, workdir)
    for w in warnings:
        log.warning(w)
    vars_path = workdir / "remediate-vars.json"
    extra_vars_dict = extra_vars(node_name, node.control_plane, plan, group)
    if config_path:
        extra_vars_dict["sage_config_path"] = config_path
    vars_path.write_text(json.dumps(extra_vars_dict))
    log.info("remediation di %s: %s", node_name, json.dumps(plan))
    cmd = [
        "ansible-playbook",
        "-i",
        str(inventory),
        str(paths.ansible_dir() / "remediate.yml"),
        "-e",
        f"@{vars_path}",
    ]
    proc = subprocess.Popen(
        cmd, cwd=paths.ansible_dir(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    tail: collections.deque[str] = collections.deque(maxlen=400)
    for line in proc.stdout or []:
        sys.stdout.write(line)
        sys.stdout.flush()
        tail.append(line)
    code = proc.wait()
    if code:
        write_termination_message(failure_message("".join(tail), code))
    return code


MSG_RE = re.compile(r'"msg": "((?:[^"\\]|\\.)*)"')


def failure_message(output: str, code: int) -> str:
    """Il motivo leggibile del fallimento: l'ultimo `msg` di Ansible (il passo Fallimento del
    rescue dice cosa è successo), altrimenti il codice d'uscita."""
    found = MSG_RE.findall(output)
    if not found:
        return f"remediation fallita (codice {code})"
    try:
        text = json.loads(f'"{found[-1]}"')
    except json.JSONDecodeError:
        text = found[-1]
    return " ".join(text.split())[:1000]


def write_termination_message(text: str) -> None:
    """Kubernetes lo mette nello stato del pod: il controllore lo legge e la dashboard lo
    mostra (vale anche dove i log dei pod non si possono leggere)."""
    path = os.environ.get("SAGE_TERMINATION_LOG", "/dev/termination-log")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError:
        log.warning("messaggio di terminazione non scritto: %s", text)
