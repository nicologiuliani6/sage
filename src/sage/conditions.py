"""Verifica sul nodo delle condizioni proposte dall'LLM (ADR-0001).

Ogni verifica restituisce "true", "false" o "unknown". Solo un "false" ottenuto da
fatti raccolti sul nodo può rendere una CVE non applicabile. Tutto ciò che non è
verificabile resta "unknown" e, a valle, conta come applicabile (fail closed).
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import Any

AUTOSTART_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect")

# Giustificazioni OpenVEX
NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
MITIGATIONS_EXIST = "inline_mitigations_already_exist"


@dataclass(frozen=True)
class Check:
    state: str  # "true" | "false" | "unknown"
    evidence: str
    justification: str | None = None


@dataclass(frozen=True)
class CveStatus:
    status: str  # "affected" | "not_affected" | "unknown"
    verified: bool
    evidence: list[str]
    justification: str | None = None


def module_matches_files(module_dir: str | None, program_files: list[str]) -> bool:
    """Il modulo contiene almeno uno dei file sorgente colpiti dalla CVE?"""
    if not module_dir or not program_files:
        return False
    for path in program_files:
        directory = os.path.dirname(path)
        if directory == module_dir or directory.startswith(module_dir + "/"):
            return True
    return False


def service_active(ctx: dict[str, Any]) -> bool:
    return any(
        u.get("active") == "active" or u.get("enabled") in AUTOSTART_STATES
        for u in ctx.get("units", {}).values()
    )


def in_use(ctx: dict[str, Any]) -> bool:
    return bool(
        ctx.get("binaries_running")
        or ctx.get("libraries_loaded")
        or ctx.get("listening")
        or service_active(ctx)
    )


def verify(
    cond: dict[str, Any],
    package: str,
    ctx: dict[str, Any],
    kernel: dict[str, Any],
    record: dict[str, Any] | None,
    idle_confirmed: bool,
    idle_scans_required: int,
) -> Check:
    record = record or {}
    kind = cond.get("type")
    is_kernel = package.startswith("kernel")

    if kind == "kernel_module":
        if not is_kernel:
            return Check("unknown", "condizione sul kernel per un pacchetto non kernel")
        module = cond.get("module", "")
        info = kernel.get("modules", {}).get(module)
        if info is None:
            return Check("unknown", f"modulo {module} assente dai metadati del kernel")
        files = record.get("program_files") or []
        if not files:
            return Check("unknown", "file sorgente colpiti non noti: modulo non verificabile")
        if not module_matches_files(info.get("dir"), files):
            return Check(
                "unknown", f"il modulo {module} ({info.get('dir')}) non contiene i file colpiti"
            )
        if info["state"] == "loaded":
            return Check("true", f"modulo {module} caricato")
        if info["state"] == "builtin":
            return Check("true", f"modulo {module} compilato nel kernel")
        if module in kernel.get("install_blocked", []):
            return Check(
                "false", f"modulo {module} bloccato (install /bin/false)", MITIGATIONS_EXIST
            )
        if (kernel.get("sysctl") or {}).get("kernel.modules_disabled") == 1:
            return Check("false", "caricamento dei moduli disabilitato", MITIGATIONS_EXIST)
        return Check("true", f"modulo {module} caricabile su richiesta")

    if kind == "network_service":
        if is_kernel:
            return Check("unknown", "servizio di rete non applicabile al kernel")
        av = record.get("attack_vector")
        if av not in ("network", "adjacent"):
            return Check("unknown", f"vettore d'attacco {av or 'ignoto'}: non è un attacco di rete")
        if not (ctx.get("units") or ctx.get("has_binaries")):
            return Check("unknown", "il pacchetto non fornisce un servizio")
        if ctx.get("listening") or service_active(ctx):
            return Check("true", "servizio attivo, abilitato o in ascolto")
        if not idle_confirmed:
            return Check(
                "unknown", f"servizio spento, ma non da {idle_scans_required} scansioni consecutive"
            )
        return Check(
            "false",
            f"nessuna porta in ascolto, unit spente e non abilitate da {idle_scans_required} "
            "scansioni",
            NOT_IN_EXECUTE_PATH,
        )

    if kind == "component_in_use":
        if is_kernel:
            return Check("unknown", "il kernel è sempre in uso")
        if ctx.get("privileged_files"):
            return Check("unknown", "contiene file setuid, setgid o con capability")
        if in_use(ctx):
            return Check("true", "codice del pacchetto in esecuzione o caricato")
        if not idle_confirmed:
            return Check(
                "unknown", f"inutilizzato, ma non da {idle_scans_required} scansioni consecutive"
            )
        return Check(
            "false",
            f"nessun processo usa il pacchetto da {idle_scans_required} scansioni",
            NOT_IN_EXECUTE_PATH,
        )

    return Check("unknown", f"tipo di condizione sconosciuto: {kind}")


def evaluate(checks: list[Check], has_conditions: bool) -> CveStatus:
    """Le condizioni sono tutte necessarie: basta una falsa verificata."""
    if not has_conditions:
        return CveStatus("affected", True, ["nessuna condizione: sfruttabile se installato"])
    false = [c for c in checks if c.state == "false"]
    if false:
        return CveStatus("not_affected", True, [c.evidence for c in false], false[0].justification)
    if all(c.state == "true" for c in checks):
        return CveStatus("affected", True, [c.evidence for c in checks])
    return CveStatus("unknown", False, [c.evidence for c in checks])


def mitigation_ok(
    mitigation: dict[str, Any] | None,
    package: str,
    kernel: dict[str, Any],
    record: dict[str, Any] | None,
    protected_modules: tuple[str, ...],
    loaded_in_group: set[str],
) -> tuple[bool, str]:
    """Si può bloccare il modulo senza rischi per il nodo?"""
    if not mitigation or mitigation.get("type") != "module_denylist":
        return False, "nessuna mitigazione proposta"
    if not package.startswith("kernel"):
        return False, "denylist di moduli solo per CVE del kernel"
    module = mitigation["module"]
    if any(fnmatch.fnmatch(module, p) for p in protected_modules):
        return False, f"modulo {module} protetto da configurazione"
    info = kernel.get("modules", {}).get(module)
    if info is None or info["state"] != "available":
        return False, f"modulo {module} non bloccabile (assente, caricato o compilato nel kernel)"
    if module in kernel.get("install_blocked", []):
        return False, f"modulo {module} già bloccato"
    if module in loaded_in_group:
        return False, f"modulo {module} caricato su un altro nodo del gruppo"
    if not module_matches_files(info.get("dir"), (record or {}).get("program_files") or []):
        return False, f"il modulo {module} non contiene i file colpiti"
    return True, f"bloccare {module} rende la CVE non sfruttabile"
