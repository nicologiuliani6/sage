"""Debian e Ubuntu: dagli aggiornamenti di sicurezza alle advisory e alle CVE (ADR-0017).

apt sa quali aggiornamenti arrivano dal repository di sicurezza, ma non a quali advisory
(DSA, DLA, USN) e CVE corrispondono. Il collector li segna con un `lookup` (ecosistema,
pacchetto sorgente, versione installata e versione nuova); qui si chiede a OSV quali
vulnerabilità della versione installata sono corrette dalla versione nuova.

A OSV arrivano solo nome e versione dei pacchetti sorgente e la release della distro, mai
nomi o indirizzi dei nodi. `sources.osv_url` può puntare a un mirror interno.
Se OSV non risponde il pacchetto resta senza CVE e la policy lo aggiorna (fail closed).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from sage import __version__
from sage.config import SourcesConfig
from sage.sources import http_json

log = logging.getLogger(__name__)

ADVISORY_PREFIXES = ("DSA-", "DLA-", "DTSA-", "USN-")
CVE = re.compile(r"CVE-\d{4}-\d+$")
QUERY_BATCH = 500
FETCH_WORKERS = 8


# ------------------------------------------------------------ versioni Debian


def _order(c: str) -> int:
    """Ordine dei caratteri secondo dpkg: fine stringa e cifre 0, '~' prima di tutto,
    lettere prima degli altri simboli."""
    if c == "" or c.isdigit():
        return 0
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _compare_part(a: str, b: str) -> int:
    """Traduzione di verrevcmp di dpkg."""

    def at(s: str, k: int) -> str:
        return s[k] if k < len(s) else ""

    i = j = 0
    while i < len(a) or j < len(b):
        while (at(a, i) and not at(a, i).isdigit()) or (at(b, j) and not at(b, j).isdigit()):
            ac, bc = _order(at(a, i)), _order(at(b, j))
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while at(a, i) == "0":
            i += 1
        while at(b, j) == "0":
            j += 1
        first_diff = 0
        while at(a, i).isdigit() and at(b, j).isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if at(a, i).isdigit():
            return 1
        if at(b, j).isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _split(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.rpartition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Confronto di versioni Debian come `dpkg --compare-versions`: -1, 0 o 1."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)


# ------------------------------------------------------------ OSV


def _post_json(url: str, body: dict[str, Any], timeout: int) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "User-Agent": f"sage/{__version__}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL da config)
        return json.load(resp)


def fixed_versions(vuln: dict[str, Any], ecosystem: str, source: str) -> list[str]:
    """Versioni che correggono `vuln` per quel pacchetto sorgente in quella release."""
    fixed = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != source:
            continue
        for rng in affected.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if e.get("fixed")]
    return fixed


def cves_of(vuln: dict[str, Any]) -> set[str]:
    ids = [vuln.get("id", "")] + vuln.get("aliases", []) + vuln.get("upstream", [])
    ids += vuln.get("related", [])
    found = set()
    for i in ids:
        i = re.sub(r"^(DEBIAN|UBUNTU)-", "", i)
        if CVE.match(i):
            found.add(i)
    return found


def severity_of(vuln: dict[str, Any]) -> str:
    for sev in vuln.get("severity", []):
        if sev.get("type") == "Ubuntu" and sev.get("score"):
            return str(sev["score"]).capitalize()
    return ""


def advisories_for(
    lookup: dict[str, Any], vulns: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Advisory (DSA, DLA, USN) e CVE corrette passando da `installed` a `fixed`.

    Le CVE che nessuna advisory elenca restano nel segnaposto del collector."""
    eco, src = lookup["ecosystem"], lookup["source"]
    installed, new = lookup["installed"], lookup["fixed"]
    advisories: dict[str, dict[str, Any]] = {}
    loose: set[str] = set()
    for vuln in vulns:
        fixes = [
            f
            for f in fixed_versions(vuln, eco, src)
            if compare_versions(installed, f) < 0 and compare_versions(f, new) <= 0
        ]
        if not fixes:
            continue  # non riguarda questo aggiornamento (già corretta o non ancora)
        vid = vuln.get("id", "")
        if vid.startswith(ADVISORY_PREFIXES):
            advisories[vid] = {
                "id": vid,
                "severity": severity_of(vuln),
                "fixed_version": new,
                "cves": sorted(cves_of(vuln)),
                "issued": vuln.get("published", ""),
            }
        else:
            loose |= cves_of(vuln)
    covered = {c for a in advisories.values() for c in a["cves"]}
    result = sorted(advisories.values(), key=lambda a: a["id"])
    return result, sorted(loose - covered)


def _drop_unless_security(pending: list[tuple[Any, ...]]) -> None:
    """Senza OSV si tengono solo gli aggiornamenti dal repository di sicurezza."""
    for report, name, _pkg, _adv, lk in pending:
        if not lk.get("security"):
            report.get("packages", {}).pop(name, None)


def enrich(reports: dict[str, dict[str, Any]], src: SourcesConfig) -> int:
    """Completa le advisory dei pacchetti con `lookup` (Debian e Ubuntu).

    Il collector elenca tutti gli aggiornamenti disponibili; qui restano quelli che
    correggono almeno una vulnerabilità. Nel dubbio (OSV giù o una vulnerabilità non
    letta) si tengono quelli del repository di sicurezza, senza CVE: la policy li
    aggiorna. Restituisce quanti pacchetti restano da aggiornare.
    """
    pending = []
    for report in reports.values():
        for name, pkg in report.get("packages", {}).items():
            for adv in pkg.get("advisories", []):
                lk = adv.get("lookup")
                if lk:
                    pending.append((report, name, pkg, adv, lk))
    if not pending:
        return 0
    known = [p for p in pending if p[4].get("ecosystem") and p[4].get("source")]
    _drop_unless_security([p for p in pending if p not in known])
    keys = sorted({(lk["ecosystem"], lk["source"], lk["installed"]) for *_, lk in known})
    ids_by_key: dict[tuple[str, str, str], list[str]] = {}
    try:
        for i in range(0, len(keys), QUERY_BATCH):
            batch = keys[i : i + QUERY_BATCH]
            body = {
                "queries": [
                    {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in batch
                ]
            }
            data = _post_json(f"{src.osv_url}/querybatch", body, src.timeout_seconds)
            results = data.get("results", [])
            if len(results) != len(batch):
                raise ValueError("risposta di OSV incompleta")
            for key, result in zip(batch, results, strict=True):
                ids_by_key[key] = [v["id"] for v in result.get("vulns", []) or []]
    except Exception as exc:  # rete, JSON, formato
        log.warning(
            "OSV non disponibile (%s): restano solo gli aggiornamenti del repository di "
            "sicurezza, senza CVE (si aggiornano)",
            exc,
        )
        _drop_unless_security(known)
        return sum(1 for *_, lk in known if lk.get("security"))

    def fetch(vid: str) -> tuple[str, dict[str, Any] | None]:
        try:
            return vid, http_json(f"{src.osv_url}/vulns/{vid}", src.timeout_seconds)
        except Exception as exc:
            log.warning("OSV: %s non disponibile (%s)", vid, exc)
            return vid, None

    wanted = sorted({vid for ids in ids_by_key.values() for vid in ids})
    with ThreadPoolExecutor(FETCH_WORKERS) as pool:
        vulns = {vid: v for vid, v in pool.map(fetch, wanted) if v}

    kept = 0
    for report, name, pkg, placeholder, lk in known:
        ids = ids_by_key.get((lk["ecosystem"], lk["source"], lk["installed"]), [])
        missing = any(i not in vulns for i in ids)
        advisories, loose = advisories_for(lk, [vulns[i] for i in ids if i in vulns])
        if not advisories and not loose and not missing and not lk.get("security"):
            report["packages"].pop(name, None)  # aggiornamento senza correzioni note
            continue
        rest = [a for a in pkg["advisories"] if a is not placeholder]
        if loose or not advisories:
            placeholder["cves"] = loose
            rest.append(placeholder)
        pkg["advisories"] = sorted(rest + advisories, key=lambda a: a["id"])
        kept += 1
    log.info(
        "OSV: %d aggiornamenti Debian/Ubuntu su %d correggono vulnerabilità note (%d lette)",
        kept,
        len(known),
        len(vulns),
    )
    return kept
