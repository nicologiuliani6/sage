"""Piani di remediation per nodo e Job che li eseguono.

Chi decide quando e su quale nodo partire è il controllore (sage.controller).
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sage.analyze import CveResult, PackageDecision
from sage.config import NodeGroup

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
    # Riavvio in sospeso: aggiornamenti già installati (es. da unattended-upgrades o a
    # mano) che diventano attivi solo dopo un riavvio. SAGE lo fa con drain, come sempre.
    reboot: bool = False

    @property
    def empty(self) -> bool:
        return not (
            self.update_advisories or self.remove_packages or self.denylist_modules or self.reboot
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "update_advisories": self.update_advisories,
            "update_packages": self.update_packages,
            "remove_packages": self.remove_packages,
            "denylist_modules": self.denylist_modules,
            "deferred": self.deferred,
            "reboot": self.reboot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Plan:
        lists = {k: list(data.get(k) or []) for k in cls().to_dict() if k != "reboot"}
        return cls(**lists, reboot=bool(data.get("reboot")))


def decision_from_dict(d: dict[str, Any]) -> PackageDecision:
    """Decisione salvata nel report -> oggetto (per l'avanzamento tra due controlli)."""
    return PackageDecision(
        **{**d, "cves": [CveResult(**c) for c in d.get("cves", [])]},
    )


def build_plans(
    decisions: dict[str, list[PackageDecision]],
    groups: dict[str, NodeGroup | None],
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


def add_pending_reboots(
    plans: dict[str, Plan],
    reports: dict[str, dict[str, Any]],
    groups: dict[str, NodeGroup | None],
) -> None:
    """Nodi con un riavvio in sospeso (segnalato dal collector): il piano lo include.
    Nei gruppi con il kernel solo a mano il riavvio resta a una persona."""
    for node, plan in plans.items():
        pending = (reports.get(node) or {}).get("reboot") or {}
        if not pending.get("required"):
            continue
        group = groups.get(node)
        if group is not None and group.kernel == "manual":
            plan.deferred.append(
                {"package": "riavvio", "reason": "riavvio in sospeso: kernel solo a mano"}
            )
            continue
        plan.reboot = True


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
