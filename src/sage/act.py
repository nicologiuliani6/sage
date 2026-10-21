"""Remediation a ondate: piani per nodo, canary, concorrenza, finestre, Job.

Ogni giro dello scan fa avanzare le ondate di un passo, leggendo lo stato dei Job
precedenti. Una remediation fallita ferma tutto finché una persona non controlla
il nodo e lancia `sage resume`.
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import yaml

from sage.analyze import PackageDecision
from sage.config import Config, NodeGroup
from sage.kube import KubeApi, Node
from sage.llm import LlmChain
from sage.schedule import in_window

log = logging.getLogger(__name__)

ROLE_LABEL = "sage.io/role"
NODE_ANNOTATION = "sage.io/node-name"


@dataclass
class Plan:
    update_advisories: list[str] = field(default_factory=list)
    update_packages: list[str] = field(default_factory=list)
    remove_packages: list[str] = field(default_factory=list)
    denylist_modules: list[str] = field(default_factory=list)
    deferred: list[dict[str, str]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.update_advisories or self.remove_packages or self.denylist_modules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "update_advisories": self.update_advisories,
            "update_packages": self.update_packages,
            "remove_packages": self.remove_packages,
            "denylist_modules": self.denylist_modules,
            "deferred": self.deferred,
        }


def build_plans(
    decisions: dict[str, list[PackageDecision]],
    groups: dict[str, NodeGroup | None],
    now_local: datetime,
) -> dict[str, Plan]:
    plans: dict[str, Plan] = {}
    for node, items in decisions.items():
        group = groups.get(node)
        if group is None:
            continue
        plan = Plan()
        advisories: set[str] = set()
        for d in items:
            if d.action not in ("update", "remove", "mitigate"):
                continue
            # Le regole del kernel valgono per l'aggiornamento (nuovo kernel, riavvio),
            # non per il blocco di un modulo, che non richiede né l'uno né l'altro.
            if d.action == "update" and d.schedule == "manual":
                plan.deferred.append(
                    {"package": d.package, "reason": "kernel: solo intervento manuale"}
                )
                continue
            if (
                d.action == "update"
                and d.schedule == "window"
                and not in_window(group.window, now_local)
            ):
                plan.deferred.append(
                    {"package": d.package, "reason": f"fuori dalla finestra ({group.window})"}
                )
                continue
            if d.action == "update":
                advisories.update(d.advisories)
                plan.update_packages.append(d.package)
            elif d.action == "remove":
                plan.remove_packages.append(d.package)
            else:
                plan.denylist_modules.extend(d.modules)
        plan.update_advisories = sorted(advisories)
        plan.update_packages.sort()
        plan.remove_packages.sort()
        plan.denylist_modules = sorted(set(plan.denylist_modules))
        plans[node] = plan
    return plans


def job_name(release: str, node: str, now: datetime) -> str:
    short = re.sub(r"[^a-z0-9-]", "-", node.lower()).strip("-")
    suffix = now.strftime("%y%m%d%H%M")
    prefix = f"{release}-fix-"
    room = 63 - len(prefix) - len(suffix) - 1
    return f"{prefix}{short[:room].rstrip('-')}-{suffix}"


def job_manifest(
    template: dict[str, Any], release: str, node: str, plan: Plan, now: datetime
) -> dict[str, Any]:
    m = copy.deepcopy(template)
    meta = m.setdefault("metadata", {})
    meta["name"] = job_name(release, node, now)
    meta.setdefault("labels", {})[ROLE_LABEL] = "remediate"
    meta.setdefault("annotations", {})[NODE_ANNOTATION] = node
    pod = m["spec"]["template"]
    pod.setdefault("metadata", {}).setdefault("labels", {})[ROLE_LABEL] = "remediate"
    container = pod["spec"]["containers"][0]
    encoded = base64.b64encode(json.dumps(plan.to_dict()).encode()).decode()
    container["args"] = list(container.get("args", [])) + ["--node", node, "--plan", encoded]
    # Mai sul nodo che si sta per svuotare e riavviare.
    exclude = {"key": "metadata.name", "operator": "NotIn", "values": [node]}
    required = (
        pod["spec"]
        .setdefault("affinity", {})
        .setdefault("nodeAffinity", {})
        .setdefault("requiredDuringSchedulingIgnoredDuringExecution", {})
    )
    terms = required.setdefault("nodeSelectorTerms", [])
    if not terms:
        terms.append({})
    for term in terms:
        term.setdefault("matchFields", []).append(exclude)
    return m


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def refresh_state(state: dict[str, Any], kube: KubeApi, release: str, now: datetime) -> None:
    """Aggiorna lo stato dei nodi dai Job esistenti."""
    nodes = state.setdefault("nodes", {})
    jobs = kube.list_jobs(f"{ROLE_LABEL}=remediate,app.kubernetes.io/instance={release}")
    existing = {job.name for job in jobs}
    for node, st in nodes.items():
        if st.get("status") == "running" and st.get("job") not in existing:
            # Job cancellato a mano o scaduto: non si sa in che stato sia il nodo.
            st["status"] = "failed"
            state["halted"] = True
            state["halt_reason"] = f"Job di remediation {st.get('job')} su {node} scomparso"
    for job in jobs:
        if not job.node:
            continue
        st = nodes.setdefault(job.node, {})
        if st.get("job") != job.name:
            continue
        if job.active:
            st["status"] = "running"
        elif job.succeeded and st.get("status") == "running":
            st["status"] = "done"
            st["last_success"] = job.completion_time or now.isoformat()
        elif job.failed and st.get("status") == "running":
            st["status"] = "failed"
            state["halted"] = True
            state["halt_reason"] = f"remediation fallita su {job.node} (job {job.name})"


def step(
    cfg: Config,
    kube: KubeApi,
    chain: LlmChain,
    release: str,
    nodes: list[Node],
    groups: dict[str, NodeGroup | None],
    plans: dict[str, Plan],
    state: dict[str, Any],
    now: datetime,
    dry_run: bool,
) -> list[str]:
    """Un passo delle ondate. Restituisce messaggi leggibili su cosa è stato fatto."""
    refresh_state(state, kube, release, now)
    if state.get("halted"):
        return [
            f"FERMO: {state.get('halt_reason')}. Controlla il nodo, poi crea la ConfigMap "
            f"{release}-resume (o lancia `sage resume`)."
        ]

    node_by_name = {n.name: n for n in nodes}
    nodes_state = state.setdefault("nodes", {})
    active = {n for n, s in nodes_state.items() if s.get("status") == "running"}

    for group in cfg.groups:
        members = sorted(n for n, g in groups.items() if g and g.name == group.name)
        pending = [n for n in members if n in plans and not plans[n].empty and n not in active]
        active_here = active & set(members)
        if not pending and not active_here:
            continue
        others = active - set(members)
        if others:
            return [f"attendo la fine della remediation su {', '.join(sorted(others))}"]

        blocked = []
        for n in list(pending):
            node = node_by_name.get(n)
            if node is None or not node.ready or node.unschedulable:
                pending.remove(n)
                blocked.append(n)
        notes = [f"{n}: non Ready o già in cordon, lo salto" for n in blocked]
        if blocked and not pending and not active_here:
            # Un gruppo non si considera finito se ha nodi da sistemare ma non pronti:
            # i gruppi successivi (es. i master) aspettano.
            return notes + [f"[{group.name}] nodi in attesa non pronti: le ondate aspettano"]

        canary = group.canary if group.canary in members else None
        if canary and canary not in plans:
            # Nessun report dal canary in questo giro: non si sa se è aggiornato.
            return notes + [f"[{group.name}] canary {canary} non raggiunto: il gruppo aspetta"]
        if canary and canary in blocked:
            return notes + [f"[{group.name}] il canary {canary} non è pronto: il gruppo aspetta"]
        if canary and canary in active_here:
            return notes + [f"[{group.name}] canary {canary} in corso"]
        if canary and canary in pending:
            if active_here:
                return notes + [f"[{group.name}] attendo {', '.join(sorted(active_here))}"]
            candidates, budget = [canary], 1
        else:
            if canary:
                last = _parse_time(nodes_state.get(canary, {}).get("last_success"))
                soak = timedelta(minutes=group.canary_soak_minutes)
                if last and now - last < soak:
                    return notes + [
                        f"[{group.name}] canary {canary} in osservazione fino a "
                        f"{(last + soak).isoformat(timespec='minutes')}"
                    ]
            candidates = pending
            budget = group.concurrency - len(active_here)

        if not candidates:
            if active_here:
                return notes + [f"[{group.name}] in corso: {', '.join(sorted(active_here))}"]
            continue
        if budget <= 0:
            return notes + [f"[{group.name}] concorrenza massima raggiunta"]
        if group.requires_fallback and not chain.fallback_available(group.name):
            return notes + [
                f"[{group.name}] nessuna riserva LLM fuori dal gruppo disponibile: rimandato"
            ]

        chosen = candidates[:budget]
        if dry_run:
            return notes + [
                f"[{group.name}] (simulazione) avvierei la remediation su {', '.join(chosen)}"
            ]
        template_text = kube.read_text(f"{release}-remediate-template", "job.yaml")
        if not template_text:
            return notes + ["template del Job di remediation mancante: reinstalla il chart"]
        template = yaml.safe_load(template_text)
        started = []
        for n in chosen:
            manifest = job_manifest(template, release, n, plans[n], now)
            kube.create_job(manifest)
            nodes_state[n] = {
                **nodes_state.get(n, {}),
                "status": "running",
                "job": manifest["metadata"]["name"],
                "started": now.isoformat(),
            }
            started.append(n)
        return notes + [f"[{group.name}] remediation avviata su {', '.join(started)}"]

    return ["nessuna azione da eseguire"]


def resume(state: dict[str, Any]) -> list[str]:
    """Sblocca le ondate dopo un errore controllato a mano."""
    failed = [n for n, s in state.get("nodes", {}).items() if s.get("status") == "failed"]
    for n in failed:
        state["nodes"][n]["status"] = "idle"
    state["halted"] = False
    state.pop("halt_reason", None)
    return failed
