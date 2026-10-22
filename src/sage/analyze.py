"""Analisi: per ogni (nodo, pacchetto) la CVE si applica? E quindi, cosa fare?

Flusso per pacchetto:
1. Se una CVE è nel catalogo KEV, o il catalogo non è disponibile, niente LLM:
   il pacchetto non potrà essere dichiarato non affetto.
2. Per ogni CVE (dalla più probabile da sfruttare) si prendono le condizioni
   dalla cache o dall'LLM e si verificano su ogni nodo.
3. Appena su un nodo una CVE risulta applicabile e non mitigabile, quel nodo è
   deciso; quando lo sono tutti, le CVE restanti non servono (risparmio di chiamate).
4. OPA prende la decisione finale per ogni (nodo, pacchetto).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sage import conditions, llm
from sage.config import Config, NodeGroup
from sage.llm import LlmChain

log = logging.getLogger(__name__)

# Ogni quante risposte nuove dell'LLM si salva la cache durante il giro.
SAVE_EVERY = 10

SEVERITY_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
FALLBACK_RECHECK = timedelta(hours=24)
OPA_CONTEXT_KEYS = (
    "binaries_running",
    "libraries_loaded",
    "listening",
    "units",
    "removal_also_removes",
)

RecordFetcher = Callable[[str], dict[str, Any] | None]
Decider = Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, str]]]


@dataclass
class CveResult:
    id: str
    kev: bool
    epss: float | None
    status: str
    verified: bool
    evidence: list[str]
    justification: str | None = None
    mitigation_module: str | None = None


@dataclass
class PackageDecision:
    package: str
    action: str
    schedule: str
    priority: str
    advisories: list[str]
    installed: list[str]
    cves: list[CveResult]
    modules: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    decisions: dict[str, list[PackageDecision]]
    idle: dict[str, dict[str, Any]]
    cache: dict[str, Any]
    llm_calls: int
    kev_available: bool


def update_idle(
    reports: dict[str, dict[str, Any]], previous: dict[str, Any], now: datetime
) -> dict[str, dict[str, Any]]:
    """Per ogni (nodo, pacchetto) inutilizzato: controlli consecutivi e da quando.

    Un controllo in cui il pacchetto è in uso azzera tutto. Le voci di versioni precedenti
    (solo il numero di controlli) ripartono da adesso: nel dubbio, il periodo ricomincia.
    """
    idle: dict[str, dict[str, Any]] = {}
    for node, report in reports.items():
        for name, pkg in report.get("packages", {}).items():
            if pkg.get("context", {}).get("idle"):
                key = f"{node}|{name}"
                old = previous.get(key)
                if isinstance(old, dict):
                    idle[key] = {"count": old.get("count", 0) + 1, "since": old["since"]}
                else:
                    idle[key] = {"count": (old or 0) + 1, "since": now.isoformat()}
    for key, value in previous.items():
        if key.split("|", 1)[0] not in reports:  # nodo non raggiunto: si conserva
            idle[key] = (
                value if isinstance(value, dict) else {"count": value, "since": now.isoformat()}
            )
    return idle


def idle_confirmed(entry: Any, policy, now: datetime) -> bool:
    if not isinstance(entry, dict):
        return False
    since = datetime.fromisoformat(entry["since"])
    return entry.get("count", 0) >= policy.idle_scans_required and now - since >= timedelta(
        days=policy.idle_days_required
    )


def idle_label(policy) -> str:
    """'da 7 giorni (almeno 3 controlli)' per le prove leggibili."""
    if policy.idle_days_required:
        return (
            f"da {policy.idle_days_required} giorni (almeno {policy.idle_scans_required} controlli)"
        )
    return f"da {policy.idle_scans_required} controlli consecutivi"


def cve_severity(pkg: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for adv in pkg.get("advisories", []):
        for cve in adv.get("cves", []):
            current = result.get(cve)
            if current is None or SEVERITY_RANK.get(adv["severity"], 0) > SEVERITY_RANK.get(
                current, 0
            ):
                result[cve] = adv["severity"]
    return result


def priority(cves: list[CveResult], records: dict[str, dict[str, Any]], threshold: float) -> str:
    """Priorità ispirata a SSVC: act > attend > track."""
    if any(c.kev for c in cves):
        return "act"
    ssvc = [records.get(c.id, {}).get("ssvc", {}) for c in cves]
    if any(s.get("exploitation") == "active" for s in ssvc):
        return "act"
    if any((c.epss or 0) >= threshold for c in cves) or any(
        s.get("exploitation") == "poc" and s.get("automatable") == "yes" for s in ssvc
    ):
        return "attend"
    return "track"


class Analyzer:
    def __init__(
        self,
        cfg: Config,
        chain: LlmChain,
        fetch_record: RecordFetcher,
        decide: Decider,
        now: datetime,
        save_cache: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.cfg = cfg
        self.chain = chain
        self.fetch_record = fetch_record
        self.decide = decide
        self.now = now
        # Salvataggio della cache durante il giro: un giro interrotto non perde le risposte.
        self.save_cache = save_cache
        self.new_entries = 0

    # ------------------------------------------------------------ cache e LLM

    def _conditions(
        self, cve: str, package: str, severity: str, cache: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Condizioni della CVE per il pacchetto (sorgente): una risposta vale per tutti i
        sottopacchetti, es. glibc, glibc-common e glibc-langpack-en."""
        key = f"{cve}|{package}"
        entry = cache.get(key)
        if entry and entry.get("v") == llm.PROMPT_VERSION:
            from_fallback = entry.get("endpoint") != self.chain.primary
            age = self.now - datetime.fromisoformat(entry["at"])
            if not (from_fallback and age > FALLBACK_RECHECK and self.chain.budget_left()):
                return entry
        previous = entry if entry and entry.get("v") == llm.PROMPT_VERSION else None
        if not self.chain.budget_left():
            return previous
        record = self.fetch_record(cve)
        if record is None:
            # Senza record (descrizione, file colpiti, CVSS) la risposta sarebbe povera e,
            # messa in cache, renderebbe la CVE non verificabile per sempre: si riprova dopo.
            return previous
        answer = self.chain.ask(cve, package, record, severity)
        if answer is None:
            return previous
        result, endpoint = answer
        entry = {
            "v": llm.PROMPT_VERSION,
            "result": result,
            "record": {k: v for k, v in record.items() if k != "description"},
            "endpoint": endpoint.name,
            "model": endpoint.model,
            "at": self.now.isoformat(),
        }
        cache[key] = entry
        self.new_entries += 1
        if self.save_cache and self.new_entries % SAVE_EVERY == 0:
            self.save_cache(cache)
            log.debug("cache LLM salvata (%d risposte nuove)", self.new_entries)
        return entry

    # ------------------------------------------------------------ analisi

    def run(
        self,
        reports: dict[str, dict[str, Any]],
        groups: dict[str, NodeGroup | None],
        idle_previous: dict[str, Any],
        cache: dict[str, Any],
        kev: set[str] | None,
        epss: dict[str, float],
    ) -> Analysis:
        idle = update_idle(reports, idle_previous, self.now)
        policy = self.cfg.policy
        label = idle_label(policy)
        kev_available = kev is not None
        kev = kev or set()

        # pacchetto -> [(nodo, dati)] solo per nodi con gruppo
        by_package: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for node, report in reports.items():
            if groups.get(node) is None:
                continue
            for name, pkg in report.get("packages", {}).items():
                by_package.setdefault(name, []).append((node, pkg))

        loaded_by_group: dict[str, set[str]] = {}
        for node, report in reports.items():
            group = groups.get(node)
            if group is None:
                continue
            modules = report.get("kernel", {}).get("modules", {})
            loaded = {m for m, info in modules.items() if info.get("state") == "loaded"}
            loaded_by_group.setdefault(group.name, set()).update(loaded)

        # (nodo, pacchetto) -> {cve: CveResult}
        results: dict[tuple[str, str], dict[str, CveResult]] = {}
        records: dict[str, dict[str, Any]] = {}

        total = len(by_package)
        log.info("analisi di %d pacchetti con advisory di sicurezza", total)
        for index, (name, entries) in enumerate(sorted(by_package.items()), start=1):
            sev = {}
            all_cves: set[str] = set()
            for _, pkg in entries:
                sev.update(cve_severity(pkg))
                all_cves |= set(cve_severity(pkg))
            ordered = sorted(all_cves, key=lambda c: (-(epss.get(c) or 0), c))
            skip_llm = (not kev_available) or any(c in kev for c in all_cves)
            undecided = {node for node, _ in entries}
            source = next(
                (p["context"].get("source") for _, p in entries if p["context"].get("source")),
                name,
            )
            log.info(
                "pacchetto %d/%d %s: %d CVE su %d nodi%s",
                index,
                total,
                name,
                len(all_cves),
                len(entries),
                "" if not skip_llm else " (KEV o KEV assente: si aggiorna)",
            )

            for cve in ordered:
                if skip_llm or not undecided:
                    break
                entry = self._conditions(cve, source, sev.get(cve, ""), cache)
                if entry is None:
                    break  # budget esaurito o LLM non disponibile: il resto resta "unknown"
                record = entry.get("record") or {}
                records[cve] = record
                answer = entry["result"]
                for node, pkg in entries:
                    if node not in undecided or cve not in cve_severity(pkg):
                        continue  # nodo già deciso, o CVE che su questo nodo non c'è
                    report = reports[node]
                    ctx = pkg.get("context", {})
                    checks = [
                        conditions.verify(
                            c,
                            name,
                            ctx,
                            report.get("kernel", {}),
                            record,
                            idle_confirmed(idle.get(f"{node}|{name}"), policy, self.now),
                            label,
                        )
                        for c in answer["conditions"]
                    ]
                    status = conditions.evaluate(checks, bool(answer["conditions"]))
                    group = groups[node]
                    mitigable, why = (False, "")
                    if status.status != "not_affected" and group and group.allow_mitigate:
                        mitigable, why = conditions.mitigation_ok(
                            answer.get("mitigation"),
                            name,
                            report.get("kernel", {}),
                            record,
                            self.cfg.policy.protected_modules,
                            loaded_by_group.get(group.name, set()),
                        )
                    evidence = status.evidence + ([why] if mitigable else [])
                    results.setdefault((node, name), {})[cve] = CveResult(
                        id=cve,
                        kev=False,
                        epss=epss.get(cve),
                        status=status.status,
                        verified=status.verified,
                        evidence=evidence,
                        justification=status.justification,
                        mitigation_module=(answer["mitigation"]["module"] if mitigable else None),
                    )
                    if status.status != "not_affected" and not mitigable:
                        undecided.discard(node)

        # ------------------------------------------------------------ OPA
        items, keys = [], []
        prepared: dict[tuple[str, str], tuple[list[CveResult], list[str]]] = {}
        for node, report in sorted(reports.items()):
            group = groups.get(node)
            for name, pkg in sorted(report.get("packages", {}).items()):
                evaluated = results.get((node, name), {})
                cve_list = []
                for cve in sorted(cve_severity(pkg)):
                    cve_list.append(
                        evaluated.get(cve)
                        or CveResult(
                            id=cve,
                            kev=False,
                            epss=epss.get(cve),
                            status="unknown",
                            verified=False,
                            evidence=["non analizzata"],
                        )
                    )
                for c in cve_list:
                    c.kev = c.id in kev
                modules = sorted({c.mitigation_module for c in cve_list if c.mitigation_module})
                all_covered = bool(cve_list) and all(
                    (c.status == "not_affected" and c.verified) or c.mitigation_module
                    for c in cve_list
                )
                proposal = (
                    {"action": "mitigate", "mitigation": {"verified": True}}
                    if modules and all_covered
                    else {}
                )
                ctx = pkg.get("context", {})
                items.append(
                    {
                        "node": {"group": group.name if group else ""},
                        "group": {
                            "allow_remove": bool(group and group.allow_remove),
                            "allow_mitigate": bool(group and group.allow_mitigate),
                            "kernel": group.kernel if group else "manual",
                        },
                        "kev_available": kev_available,
                        "package": {
                            "name": name,
                            "context": {k: ctx.get(k) for k in OPA_CONTEXT_KEYS},
                            "idle_confirmed": idle_confirmed(
                                idle.get(f"{node}|{name}"), policy, self.now
                            ),
                        },
                        "cves": [
                            {
                                "kev": c.kev,
                                "applicability": {
                                    "status": c.status,
                                    "verified": c.verified,
                                    "justification": c.justification,
                                },
                            }
                            for c in cve_list
                        ],
                        "proposal": proposal,
                    }
                )
                keys.append((node, name))
                prepared[(node, name)] = (cve_list, modules if proposal else [])

        outcomes = self.decide(items, self.cfg.to_policy_data())

        decisions: dict[str, list[PackageDecision]] = {node: [] for node in reports}
        for (node, name), outcome in zip(keys, outcomes, strict=True):
            pkg = reports[node]["packages"][name]
            cve_list, modules = prepared[(node, name)]
            decisions[node].append(
                PackageDecision(
                    package=name,
                    action=outcome["action"],
                    schedule=outcome["schedule"],
                    priority=priority(cve_list, records, self.cfg.policy.epss_attend_threshold),
                    advisories=sorted({a["id"] for a in pkg.get("advisories", [])}),
                    installed=pkg.get("context", {}).get("installed", []),
                    cves=cve_list,
                    modules=modules if outcome["action"] == "mitigate" else [],
                )
            )
        return Analysis(
            decisions=decisions,
            idle=idle,
            cache=cache,
            llm_calls=self.chain.calls,
            kev_available=kev_available,
        )
