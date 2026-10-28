"""SAGE si aggiorna da solo (ADR-0021).

Gira in un Job lanciato dal controllore in pausa, una volta ogni `check_hours`:

1. sceglie l'ultima release del canale (patch: stessa 0.X; minor: stessa versione maggiore),
   escluse quelle già fallite;
2. verifica la firma keyless di SHA256SUMS (cosign: identità = workflow di pubblicazione della
   repo su un tag) e il checksum del chart;
3. `helm upgrade` con i valori attuali;
4. verifica che SAGE **lavori**: chiede un controllo completo e aspetta un report nuovo. Un
   controllore acceso ma fermo conta come guasto;
5. altrimenti `helm rollback` alla revisione di prima e la versione non si riprova più.

Ogni esito finisce nello storico delle modifiche (chi: "sage (automatico)").
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sage import __version__
from sage.config import Config
from sage.kube import KubeApi

log = logging.getLogger(__name__)

VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
ISSUER = "https://token.actions.githubusercontent.com"
# Quanto aspettare il primo report del SAGE nuovo prima di dichiararlo guasto.
PROOF_TIMEOUT = 45 * 60
HISTORY_KEY = "history.jsonl"


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    m = VERSION_RE.match(text or "")
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def pick_release(
    releases: list[dict[str, Any]], current: str, channel: str, skipped: list[str]
) -> dict[str, Any] | None:
    """La release più recente consentita dal canale, più nuova di quella attuale."""
    now = parse_version(current)
    if now is None or channel == "off":
        return None
    best = None
    for r in releases:
        v = parse_version(r.get("tag_name"))
        if v is None or r.get("draft") or r.get("prerelease") or r["tag_name"] in skipped:
            continue
        if v <= now or v[0] != now[0] or (channel == "patch" and v[1] != now[1]):
            continue
        if best is None or v > parse_version(best["tag_name"]):
            best = r
    return best


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sage", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL da config)
        return resp.read()


def verify(workdir: Path, assets: dict[str, str], repository: str, chart: str) -> Path:
    """Scarica e verifica. Restituisce il chart; solleva se la firma o il checksum non
    tornano (in quel caso non si tocca niente)."""
    names = ("SHA256SUMS", "SHA256SUMS.sigstore.json", chart)
    missing = [name for name in names if name not in assets]
    if missing:
        raise RuntimeError(f"la release non ha {', '.join(missing)}: non firmata, non si aggiorna")
    for name in names:
        (workdir / name).write_bytes(_get(assets[name]))
    identity = (
        rf"^https://github\.com/{re.escape(repository)}/\.github/workflows/publish\.yml@refs/tags/v"
    )
    proc = subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--bundle",
            str(workdir / "SHA256SUMS.sigstore.json"),
            "--certificate-identity-regexp",
            identity,
            "--certificate-oidc-issuer",
            ISSUER,
            str(workdir / "SHA256SUMS"),
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode:
        raise RuntimeError(f"firma non valida: {(proc.stderr or proc.stdout).strip()[:300]}")
    sums = dict(
        reversed(line.split()) for line in (workdir / "SHA256SUMS").read_text().splitlines() if line
    )
    digest = hashlib.sha256((workdir / chart).read_bytes()).hexdigest()
    if sums.get(chart) != digest:
        raise RuntimeError(f"checksum del chart {chart} non corrisponde")
    return workdir / chart


def helm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["helm", *args], capture_output=True, text=True)


def last_good_revision(release: str, namespace: str) -> str | None:
    proc = helm("history", release, "-n", namespace, "-o", "json")
    try:
        history = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return None
    good = [h for h in history if h.get("status") in ("deployed", "superseded")]
    return str(good[-1]["revision"]) if good else None


def wait_for_work(kube: KubeApi, release: str, since: str | None, sleep=time.sleep) -> bool:
    """Il SAGE nuovo deve produrre un report più recente di `since` (controllo completo
    chiesto con <release>-scan-now)."""
    kube.set_flag(f"{release}-scan-now")
    deadline = time.monotonic() + PROOF_TIMEOUT
    while time.monotonic() < deadline:
        sleep(30)
        try:
            report = kube.read_json(f"{release}-report") or {}
        except Exception:  # noqa: BLE001 (API lenta durante l'aggiornamento: si riprova)
            continue
        new = _when(report.get("generated_at"))
        if new and (since is None or new > _when(since)):
            return True
    return False


def _when(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def record(kube: KubeApi, release: str, action: str, changes: list[str], note: str) -> None:
    entry = {
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "user": "sage (automatico)",
        "action": action,
        "installer": __version__,
        "changes": changes,
        "note": note,
    }
    try:
        kube.append_text(
            f"{release}-history", HISTORY_KEY, json.dumps(entry, ensure_ascii=False) + "\n"
        )
    except Exception:  # noqa: BLE001
        log.warning("storico non aggiornato: %s", entry, exc_info=True)


def run(cfg: Config, kube: KubeApi, release: str, namespace: str) -> int:
    su = cfg.self_update
    if su.channel == "off" or not su.repository:
        log.info(
            "aggiornamento automatico spento (canale %s, repository %s)", su.channel, su.repository
        )
        return 0
    state = kube.read_json(f"{release}-update") or {}
    skipped = state.get("skipped", [])
    current = os.environ.get("SAGE_VERSION") or __version__
    releases = json.loads(_get(f"{su.api_url}/repos/{su.repository}/releases?per_page=30"))
    target = pick_release(releases, current, su.channel, skipped)
    state["last_check"] = datetime.now(UTC).isoformat(timespec="seconds")
    if target is None:
        log.info("nessuna release nuova per %s (canale %s)", current, su.channel)
        kube.write_json(f"{release}-update", state)
        return 0
    tag = target["tag_name"]
    version = tag.lstrip("v")
    assets = {a["name"]: a["browser_download_url"] for a in target.get("assets", [])}
    log.info("aggiornamento %s -> %s", current, version)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            chart = verify(Path(tmp), assets, su.repository, f"sage-{version}.tgz")
        except Exception as exc:  # noqa: BLE001
            log.error("release %s non verificata: %s", tag, exc)
            state["last"] = {"version": version, "ok": False, "detail": str(exc)[:300]}
            state["skipped"] = skipped + [tag]
            kube.write_json(f"{release}-update", state)
            record(
                kube, release, "aggiornamento rifiutato", [f"versione {version}"], str(exc)[:300]
            )
            return 1
        before = (kube.read_json(f"{release}-report") or {}).get("generated_at")
        previous = last_good_revision(release, namespace)
        description = f"sage (automatico): aggiornamento a {version}"
        proc = helm(
            "upgrade", release, str(chart), "-n", namespace,
            "--reset-then-reuse-values", "--description", description, "--wait", "--timeout", "10m",
        )  # fmt: skip
    ok = proc.returncode == 0 and wait_for_work(kube, release, before)
    if ok:
        state["last"] = {"version": version, "ok": True}
        record(kube, release, "aggiornamento automatico", [f"versione {current} → {version}"], "")
        log.info("SAGE %s al lavoro: aggiornamento riuscito", version)
    else:
        why = (proc.stderr or "").strip()[:300] or "nessun report nuovo: SAGE non lavora"
        log.error("aggiornamento a %s non riuscito (%s): rollback a %s", version, why, previous)
        if previous:
            helm("rollback", release, previous, "-n", namespace, "--wait", "--timeout", "10m")
        state["last"] = {"version": version, "ok": False, "detail": why}
        state["skipped"] = skipped + [tag]
        record(kube, release, "aggiornamento annullato", [f"versione {version}"], why)
    kube.write_json(f"{release}-update", state)
    return 0 if ok else 1
