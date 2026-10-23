"""Report del giro: riepilogo leggibile, JSON per la ConfigMap e documento OpenVEX."""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from typing import Any

from sage import __version__
from sage.analyze import Analysis, PackageDecision

ACTION_LABEL = {
    "not_affected": "non affetto",
    "mitigate": "mitiga",
    "remove": "rimuovi",
    "update": "aggiorna",
    "skip": "ignorato (nodo senza gruppo)",
}


def purl(name: str, installed: str, report: dict[str, Any]) -> str:
    """pkg:rpm/<distro>/<nome>@<versione>?arch=...&distro=... (pkg:deb per Debian e Ubuntu)."""
    node = report.get("node", {})
    os_info = node.get("os", {})
    distro = os_info.get("id") or (os_info.get("name") or "linux").split()[0].lower()
    kind = "deb" if node.get("package_manager") == "apt" else "rpm"
    # rpm: l'epoca va nel qualificatore, non nella versione; deb: fa parte della versione.
    version = installed.split(":", 1)[-1] if kind == "rpm" else installed
    arch = node.get("arch") or "noarch"
    if kind == "deb":
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    distro_version = f"{distro}-{os_info.get('version', '')}"
    return f"pkg:{kind}/{distro}/{name}@{version}?arch={arch}&distro={distro_version}"


def openvex(
    analysis: Analysis, reports: dict[str, dict[str, Any]], now: datetime
) -> dict[str, Any]:
    statements = []
    for node, decisions in sorted(analysis.decisions.items()):
        for d in decisions:
            if d.action != "not_affected":
                continue
            products = [{"@id": purl(d.package, v, reports[node])} for v in d.installed]
            for cve in d.cves:
                statements.append(
                    {
                        "vulnerability": {"name": cve.id},
                        "products": products,
                        "status": "not_affected",
                        "justification": cve.justification,
                        "impact_statement": f"{node}: " + "; ".join(cve.evidence),
                        "timestamp": now.isoformat(),
                    }
                )
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": f"SAGE {__version__}",
        "timestamp": now.isoformat(),
        "version": 1,
        "statements": statements,
    }


def to_json(
    analysis: Analysis,
    plans: dict[str, Any],
    messages: list[str],
    warnings: list[str],
    now: datetime,
    dry_run: bool,
) -> dict[str, Any]:
    return {
        "generated_at": now.isoformat(),
        "version": __version__,
        "dry_run": dry_run,
        "kev_available": analysis.kev_available,
        "llm_calls": analysis.llm_calls,
        "warnings": warnings,
        "messages": messages,
        "plans": plans,
        "nodes": {
            node: [asdict(d) for d in decisions]
            for node, decisions in sorted(analysis.decisions.items())
        },
    }


def summary(
    analysis: Analysis,
    groups: dict[str, Any],
    plans: dict[str, Any],
    messages: list[str],
    warnings: list[str],
    dry_run: bool,
    reports: dict[str, Any] | None = None,
) -> str:
    lines = [
        f"SAGE {__version__}" + (" (simulazione: nessuna modifica ai nodi)" if dry_run else "")
    ]
    if not analysis.kev_available:
        lines.append("ATTENZIONE: catalogo KEV non disponibile, nessuna CVE dichiarata non affetta")
    lines.append(f"chiamate LLM in questo giro: {analysis.llm_calls}")
    for w in warnings:
        lines.append(f"avviso: {w}")
    for node, decisions in sorted(analysis.decisions.items()):
        group = groups.get(node)
        counts = Counter(d.action for d in decisions)
        parts = ", ".join(f"{ACTION_LABEL.get(a, a)} {n}" for a, n in sorted(counts.items()))
        lines.append("")
        lines.append(f"== {node} [{group.name if group else 'senza gruppo'}]: {parts or 'niente'}")
        lines += profile_lines((reports or {}).get(node, {}))
        for d in sorted(decisions, key=_sort_key):
            if d.action in ("update", "skip"):
                continue
            lines.append(f"   {ACTION_LABEL[d.action]:<12} {d.package}  {_why(d)}")
        plan = plans.get(node)
        if plan:
            lines.append(f"   piano: {plan_text(plan)}")
    if messages:
        lines.append("")
        lines += [f"> {m}" for m in messages]
    return "\n".join(lines)


def profile_lines(report: dict[str, Any]) -> list[str]:
    """Cosa serve al nodo e cosa no, dal profilo del collector."""
    profile = report.get("profile")
    if not profile:
        return []
    packages = report.get("packages", {})
    unneeded = sorted(n for n, p in packages.items() if not p["context"].get("needed_by"))
    lines = [
        f"   profilo: {len(profile.get('units', []))} servizi del nodo, "
        f"{len(profile.get('required', {}))} pacchetti necessari su "
        f"{profile.get('installed_packages', '?')} installati"
    ]
    if profile.get("container_processes"):
        lines[0] += f"; {profile['container_processes']} processi dei container esclusi"
    if profile.get("process_scan_ok") is False:
        lines.append(
            "   ATTENZIONE, lettura dei processi non affidabile: "
            "nessun pacchetto dichiarato inattivo"
        )
    if profile.get("units") and not profile.get("required"):
        lines.append(
            "   ATTENZIONE, nessun pacchetto ricondotto ai servizi: profilo non utilizzabile"
        )
    if profile.get("extra"):
        lines.append("   aggiunti a mano: " + ", ".join(profile["extra"]))
    if profile.get("extra_missing"):
        lines.append("   ATTENZIONE, non trovati sul nodo: " + ", ".join(profile["extra_missing"]))
    if unneeded:
        shown = ", ".join(unneeded[:12]) + (
            f" e altri {len(unneeded) - 12}" if len(unneeded) > 12 else ""
        )
        lines.append(f"   con advisory ma non necessari ai servizi ({len(unneeded)}): {shown}")
    return lines


def plan_text(plan: dict[str, Any]) -> str:
    parts = []
    if plan.get("update_advisories"):
        parts.append(f"{len(plan['update_advisories'])} advisory da applicare")
    if plan.get("remove_packages"):
        parts.append("rimuovere " + ", ".join(plan["remove_packages"]))
    if plan.get("denylist_modules"):
        parts.append("bloccare " + ", ".join(plan["denylist_modules"]))
    if plan.get("deferred"):
        parts.append(f"{len(plan['deferred'])} rimandati")
    return "; ".join(parts) or "nessuna azione"


def _sort_key(d: PackageDecision) -> tuple[int, str]:
    return ({"act": 0, "attend": 1, "track": 2}.get(d.priority, 3), d.package)


def _why(d: PackageDecision) -> str:
    if d.action == "mitigate":
        return "bloccando " + ", ".join(d.modules)
    if d.action == "remove":
        return "inutilizzato, nessun altro pacchetto dipende"
    evidence = {e for c in d.cves for e in c.evidence}
    return "; ".join(sorted(evidence))[:160]
