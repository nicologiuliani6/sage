"""Fonti pubbliche: record CVE (CVE Program, con l'arricchimento CISA), KEV, EPSS.

Tutte le chiamate rispettano HTTPS_PROXY/NO_PROXY dell'ambiente. Un errore di rete
non blocca SAGE: il dato manca e le decisioni diventano più prudenti.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from typing import Any

from sage import __version__
from sage.config import SourcesConfig

log = logging.getLogger(__name__)

EPSS_BATCH = 50
DESCRIPTION_LIMIT = 2000
AV_MAP = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}


def http_json(url: str, timeout: int) -> Any:
    req = urllib.request.Request(
        url, headers={"User-Agent": f"sage/{__version__}", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL da config)
        return json.load(resp)


def fetch_kev(src: SourcesConfig) -> set[str] | None:
    """CVE nel catalogo CISA KEV; None se il catalogo non è raggiungibile."""
    try:
        data = http_json(src.kev_url, src.timeout_seconds)
        return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    except Exception as exc:  # rete, JSON, formato
        log.warning(
            "catalogo KEV non disponibile (%s): nessuna CVE sarà dichiarata non affetta", exc
        )
        return None


def fetch_epss(src: SourcesConfig, cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    unique = sorted(set(cves))
    for i in range(0, len(unique), EPSS_BATCH):
        batch = unique[i : i + EPSS_BATCH]
        url = f"{src.epss_url}?{urllib.parse.urlencode({'cve': ','.join(batch)})}"
        try:
            for row in http_json(url, src.timeout_seconds).get("data", []):
                scores[row["cve"]] = float(row["epss"])
        except Exception as exc:
            log.warning("EPSS non disponibile per %d CVE (%s)", len(batch), exc)
    return scores


def fetch_cve_record(src: SourcesConfig, cve: str) -> dict[str, Any] | None:
    try:
        raw = http_json(f"{src.cve_api_url}/{cve}", src.timeout_seconds)
    except Exception as exc:
        log.warning("record %s non disponibile (%s)", cve, exc)
        return None
    return extract_record(raw)


def extract_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Dal formato CVE JSON 5 ai soli campi usati da SAGE."""
    containers = raw.get("containers", {})
    cna = containers.get("cna", {})
    description = next(
        (
            d.get("value", "")
            for d in cna.get("descriptions", [])
            if str(d.get("lang", "")).lower().startswith("en")
        ),
        "",
    )
    program_files = sorted(
        {f for a in cna.get("affected", []) for f in a.get("programFiles", []) or []}
    )
    vectors = [_cvss_vector(m) for m in cna.get("metrics", [])]
    ssvc: dict[str, str] = {}
    for adp in containers.get("adp", []):
        vectors += [_cvss_vector(m) for m in adp.get("metrics", [])]
        for metric in adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                for option in other.get("content", {}).get("options", []):
                    ssvc.update({k.lower(): str(v).lower() for k, v in option.items()})
    vector = next((v for v in vectors if v), None)
    return {
        "description": description[:DESCRIPTION_LIMIT],
        "program_files": program_files,
        "cvss_vector": vector,
        "attack_vector": attack_vector(vector),
        "ssvc": ssvc,
    }


def _cvss_vector(metric: dict[str, Any]) -> str | None:
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        if key in metric and metric[key].get("vectorString"):
            return metric[key]["vectorString"]
    return None


def attack_vector(vector: str | None) -> str | None:
    if not vector:
        return None
    match = re.search(r"(?:^|/)AV:([NALP])(?:/|$)", vector)
    return AV_MAP.get(match.group(1)) if match else None
