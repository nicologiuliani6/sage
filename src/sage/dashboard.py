"""Dashboard web di sola lettura: sicurezza di ogni nodo, allarmi, avanzamento (ADR-0014).

Legge solo quello che SAGE ha già scritto nel cluster (report, stato del controllore,
storico, Lease, nodi) e non modifica niente: il ServiceAccount ha solo permessi di
lettura. Il server ascolta in locale nel pod e si apre con `kubectl port-forward`, così
l'accesso lo decide l'RBAC di Kubernetes e non serve un login proprio.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from zoneinfo import ZoneInfo

from sage import __version__, config
from sage.inventory import assign_groups
from sage.kube import KubeApi, Node

log = logging.getLogger(__name__)

PENDING_ACTIONS = ("update", "remove", "mitigate")
PRIORITY_RANK = {"act": 3, "attend": 2, "track": 1}
LEVEL_RANK = {"critical": 3, "warning": 2, "ok": 1, "unknown": 0}
MAX_CVES = 300
MAX_HISTORY = 30
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
# Solo risorse della dashboard stessa: niente script o stili da altre origini.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


# ------------------------------------------------------------------ modello


def _parse(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="minutes") if value else None


def parse_history(text: str | None) -> list[dict[str, Any]]:
    entries = []
    for line in (text or "").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            entries.append(
                {
                    k: item.get(k)
                    for k in ("time", "user", "sudo_user", "kube_user", "host", "action", "note")
                    if item.get(k)
                }
                | {"changes": len(item.get("changes") or [])}
            )
    return entries[-MAX_HISTORY:][::-1]


def profile_warnings(profile: dict[str, Any] | None) -> list[str]:
    if not profile:
        return []
    warnings = []
    if profile.get("process_scan_ok") is False:
        warnings.append("lettura dei processi non affidabile")
    if profile.get("units") and not profile.get("required"):
        warnings.append("nessun pacchetto ricondotto ai servizi")
    if profile.get("extra_missing"):
        warnings.append("non trovati sul nodo: " + ", ".join(profile["extra_missing"]))
    return warnings


def urgent_deadlines(
    state: dict[str, Any], report: dict[str, Any], hours: int
) -> dict[str, list[dict[str, Any]]]:
    """CVE gravi ancora da sistemare per nodo, con la scadenza (scoperta + `hours`)."""
    pending = {
        (node, d.get("package"))
        for node, items in (report.get("nodes") or {}).items()
        for d in items
        if d.get("priority") == "act" and d.get("action") in PENDING_ACTIONS
    }
    result: dict[str, list[dict[str, Any]]] = {}
    for key, found in (state.get("urgent") or {}).items():
        node, _, package = key.partition("|")
        seen = _parse(found)
        if (node, package) in pending and seen:
            result.setdefault(node, []).append(
                {"package": package, "found": found, "deadline": seen + timedelta(hours=hours)}
            )
    for items in result.values():
        items.sort(key=lambda i: i["deadline"])
    return result


def node_status(
    node: Node | None,
    name: str,
    group: config.NodeGroup | None,
    decisions: list[dict[str, Any]] | None,
    plan: dict[str, Any] | None,
    wave: dict[str, Any],
    outcome: dict[str, Any] | None,
    profile: dict[str, Any] | None,
    urgent: list[dict[str, Any]],
    now: datetime,
) -> dict[str, Any]:
    decisions = decisions or []
    pending = [d for d in decisions if d.get("action") in PENDING_ACTIONS]
    kev = sorted({c["id"] for d in pending for c in d.get("cves", []) if c.get("kev")})
    priorities = Counter(d.get("priority") for d in pending)
    plan = plan or {}
    deferred = plan.get("deferred") or []
    deadline = urgent[0]["deadline"] if urgent else None

    reasons: list[str] = []
    level = "ok"

    def raise_to(new: str, why: str) -> None:
        nonlocal level
        reasons.append(why)
        if LEVEL_RANK[new] > LEVEL_RANK[level]:
            level = new

    if node is None:
        raise_to("warning", "nodo non più nel cluster")
    else:
        if not node.ready:
            raise_to("critical", "nodo non Ready")
        if node.unschedulable:
            raise_to("warning", "nodo in cordon")
    if wave.get("status") == "failed":
        raise_to("critical", "remediation fallita")
    if deadline and deadline < now:
        raise_to("critical", f"CVE gravi oltre la scadenza ({len(urgent)} pacchetti)")
    if kev:
        raise_to("critical", f"{len(kev)} CVE sfruttate attivamente (KEV) da sistemare")
    elif priorities.get("act"):
        raise_to("critical", f"{priorities['act']} pacchetti con priorità act")
    if priorities.get("attend"):
        raise_to("warning", f"{priorities['attend']} pacchetti con priorità attend")
    for w in profile_warnings(profile):
        raise_to("warning", w)
    if decisions == [] and profile is None:
        level = "unknown" if level == "ok" else level
        reasons.append("nessun dato dall'ultimo giro")

    actions = Counter(d.get("action") for d in decisions)
    return {
        "name": name,
        "group": group.name if group else None,
        "order": group.order if group else None,
        "canary": bool(group and group.canary == name),
        "ready": bool(node and node.ready),
        "cordoned": bool(node and node.unschedulable),
        "level": level,
        "reasons": reasons,
        "actions": {
            a: actions.get(a, 0) for a in ("update", "remove", "mitigate", "not_affected", "skip")
        },
        "priorities": {p: priorities.get(p, 0) for p in ("act", "attend", "track")},
        "kev": kev,
        "plan": {
            "advisories": len(plan.get("update_advisories") or []),
            "packages": len(plan.get("update_packages") or []),
            "remove": plan.get("remove_packages") or [],
            "mitigate": plan.get("denylist_modules") or [],
            "deferred": deferred,
        },
        "deadline": _iso(deadline),
        "urgent": [u["package"] for u in urgent],
        "wave": {
            "status": wave.get("status") or "idle",
            "job": wave.get("job"),
            "started": wave.get("started"),
            "last_success": wave.get("last_success"),
            "outcome": (outcome or {}).get("outcome"),
        },
        "profile": {
            "units": len((profile or {}).get("units") or []),
            "required": len((profile or {}).get("required") or {}),
            "installed": (profile or {}).get("installed_packages"),
            "container_processes": (profile or {}).get("container_processes", 0),
            "extra": (profile or {}).get("extra") or [],
        }
        if profile
        else None,
        "packages": sorted(
            (
                {
                    "package": d.get("package"),
                    "action": d.get("action"),
                    "priority": d.get("priority"),
                    "schedule": d.get("schedule"),
                    "kev": any(c.get("kev") for c in d.get("cves", [])),
                    "cves": len(d.get("cves", [])),
                    "evidence": sorted(
                        {e for c in d.get("cves", []) for e in c.get("evidence", [])}
                    )[:4],
                }
                for d in decisions
                if d.get("action") != "skip"
            ),
            key=lambda p: (
                p["action"] not in PENDING_ACTIONS,
                -PRIORITY_RANK.get(p["priority"], 0),
                not p["kev"],
                p["package"] or "",
            ),
        ),
    }


def cve_table(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Una riga per CVE: su quali nodi, con quale azione, quanto è urgente."""
    rows: dict[str, dict[str, Any]] = {}
    for node, decisions in (report.get("nodes") or {}).items():
        for d in decisions:
            if d.get("action") == "skip":
                continue
            for c in d.get("cves", []):
                row = rows.setdefault(
                    c["id"],
                    {"id": c["id"], "kev": False, "epss": None, "priority": None, "where": []},
                )
                row["kev"] = row["kev"] or bool(c.get("kev"))
                if c.get("epss") is not None:
                    row["epss"] = max(row["epss"] or 0, c["epss"])
                if PRIORITY_RANK.get(d.get("priority"), 0) > PRIORITY_RANK.get(row["priority"], 0):
                    row["priority"] = d.get("priority")
                row["where"].append(
                    {
                        "node": node,
                        "package": d.get("package"),
                        "action": d.get("action"),
                        "status": c.get("status"),
                    }
                )
    ordered = sorted(
        rows.values(),
        key=lambda r: (
            not any(w["action"] in PENDING_ACTIONS for w in r["where"]),
            not r["kev"],
            -PRIORITY_RANK.get(r["priority"], 0),
            -(r["epss"] or 0),
            r["id"],
        ),
    )
    return ordered[:MAX_CVES]


def controller_status(
    doc: dict[str, Any] | None,
    lease: dict[str, Any] | None,
    deployment: dict[str, Any] | None,
    now: datetime,
) -> dict[str, Any]:
    """In che punto del giro è il controllore, e se è vivo."""
    doc = doc or {}
    cycle = doc.get("cycle") or {}
    suspended = bool(deployment is not None and deployment.get("replicas") == 0)
    renewed = _parse((lease or {}).get("renew_time"))
    alive = bool(renewed and now - renewed < timedelta(minutes=5))
    queue = cycle.get("queue") or []
    results = cycle.get("results") or {}
    running = next(
        (n for n, st in (doc.get("nodes") or {}).items() if st.get("status") == "running"), None
    )
    phase = cycle.get("phase")
    if suspended:
        text = "spento (giri sospesi)"
    elif not cycle:
        text = "in avvio"
    elif phase == "scan":
        text = "controllo completo in corso"
    elif phase == "remediate":
        text = f"remediation su {running}" if running else "sceglie il prossimo nodo"
    else:
        text = "in pausa"
    return {
        "suspended": suspended,
        "alive": alive,
        "holder": (lease or {}).get("holder"),
        "renewed": _iso(renewed),
        "cycle": cycle.get("id"),
        "phase": phase,
        "text": text,
        "started": cycle.get("started"),
        "next_cycle": cycle.get("pause_until") if phase == "pause" else None,
        "done": len([n for n in queue if n in results]),
        "queue": len(queue),
        "running": running,
        "results": [{"node": n, **results[n]} for n in queue if n in results],
        "halted": bool(doc.get("halted")),
        "halt_reason": doc.get("halt_reason"),
        "error": cycle.get("error"),
    }


def build_status(
    *,
    cfg: config.Config | None,
    config_error: str | None,
    nodes: list[Node],
    report: dict[str, Any] | None,
    state: dict[str, Any] | None,
    controller: dict[str, Any] | None,
    lease: dict[str, Any] | None,
    deployment: dict[str, Any] | None,
    history_text: str | None,
    now: datetime,
) -> dict[str, Any]:
    """Tutto quello che mostra la dashboard, calcolato dai dati già nel cluster."""
    report = report or {}
    state = state or {}
    alarms: list[dict[str, str]] = []

    def alarm(level: str, text: str) -> None:
        alarms.append({"level": level, "text": text})

    local_now = now.astimezone(ZoneInfo(cfg.timezone if cfg else "UTC"))
    if config_error:
        alarm("critical", f"configurazione di SAGE non leggibile: {config_error}")
    groups = assign_groups(nodes, cfg.groups)[0] if cfg else {}
    ctl = controller_status(controller, lease, deployment, local_now)
    if ctl["halted"]:
        alarm("critical", f"SAGE FERMO: {ctl['halt_reason']}")
    if ctl["suspended"]:
        alarm("warning", "controllore spento: nessun giro finché non lo riattivi")
    elif not ctl["alive"]:
        alarm("critical", "controllore fermo: non dà segni di vita da più di 5 minuti")
    if ctl["error"]:
        alarm("warning", f"ultimo giro: {ctl['error']}")
    if ctl["running"]:
        alarm("info", f"remediation in corso su {ctl['running']}")
    if report and not report.get("kev_available", True):
        alarm(
            "warning", "catalogo KEV non disponibile all'ultimo controllo: nessuna CVE non affetta"
        )
    for w in report.get("warnings") or []:
        alarm("warning", w)
    if not report:
        alarm("warning", "nessun report: SAGE non ha ancora completato un controllo")

    hours = cfg.policy.urgent_deadline_hours if cfg else 6
    urgent = urgent_deadlines(state, report, hours)
    names = sorted(set(report.get("nodes") or {}) | {n for n, g in groups.items() if g is not None})
    by_name = {n.name: n for n in nodes}
    waves = (controller or {}).get("nodes") or {}
    results = ((controller or {}).get("cycle") or {}).get("results") or {}
    node_rows = [
        node_status(
            by_name.get(name),
            name,
            groups.get(name),
            (report.get("nodes") or {}).get(name),
            (report.get("plans") or {}).get(name),
            waves.get(name) or {},
            results.get(name),
            (report.get("profiles") or {}).get(name),
            urgent.get(name, []),
            local_now,
        )
        for name in names
    ]
    node_rows.sort(key=lambda r: (r["order"] is None, r["order"] or 0, not r["canary"], r["name"]))
    for row in node_rows:
        if row["level"] == "critical":
            alarm("critical", f"{row['name']}: " + "; ".join(row["reasons"]))
    deadlines = [u["deadline"] for items in urgent.values() for u in items]

    with_work = [r for r in node_rows if r["plan"]["advisories"] or r["plan"]["remove"]]
    totals = {
        "nodes": len(node_rows),
        "nodes_clean": len(node_rows) - len(with_work),
        "advisories": sum(r["plan"]["advisories"] for r in node_rows),
        "deferred": sum(len(r["plan"]["deferred"]) for r in node_rows),
        "kev": len({c for r in node_rows for c in r["kev"]}),
        "urgent": sum(len(items) for items in urgent.values()),
        "next_deadline": _iso(min(deadlines)) if deadlines else None,
        "deadline_hours": hours,
        "levels": dict(Counter(r["level"] for r in node_rows)),
        "llm_calls": report.get("llm_calls"),
    }
    alarms.sort(key=lambda a: -LEVEL_RANK.get(a["level"], 1))
    return {
        "now": _iso(local_now),
        "dashboard_version": __version__,
        "sage_version": report.get("version"),
        "report_at": report.get("generated_at"),
        "dry_run": report.get("dry_run", True),
        "controller": ctl,
        "alarms": alarms,
        "totals": totals,
        "nodes": node_rows,
        "groups": [
            {"name": g.name, "order": g.order, "canary": g.canary}
            for g in sorted(cfg.groups, key=lambda g: g.order)
        ]
        if cfg
        else [],
        "cves": cve_table(report),
        "history": parse_history(history_text),
    }


# ------------------------------------------------------------------ server

# Sotto i 2 secondi le letture dall'API Kubernetes non servono a niente: i dati cambiano
# al passo del controllore (poll_seconds).
MIN_REFRESH = 2


class Source:
    """Legge i dati dal cluster, con una piccola cache per non chiamare l'API a ogni clic."""

    def __init__(self, kube: KubeApi, release: str, config_path: str, ttl: float = 5):
        self.kube = kube
        self.release = release
        self.config_path = config_path
        self.ttl = ttl
        self._lock = threading.Lock()
        self._cached: tuple[float, dict[str, Any], dict[str, Any] | None] | None = None

    def _load(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        cfg, error = None, None
        try:
            cfg = config.load(self.config_path)
        except (OSError, config.ConfigError) as exc:
            error = str(exc)
        r = self.release
        report = self.kube.read_json(f"{r}-report")
        status = build_status(
            cfg=cfg,
            config_error=error,
            nodes=self.kube.list_nodes(),
            report=report,
            state=self.kube.read_json(f"{r}-state"),
            controller=self.kube.read_json(f"{r}-controller"),
            lease=self.kube.read_lease(f"{r}-controller"),
            deployment=self.kube.read_deployment(f"{r}-controller"),
            history_text=self.kube.read_text(f"{r}-history", "history.jsonl"),
            now=datetime.now().astimezone(),
        )
        return status, (report or {}).get("vex")

    def get(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        with self._lock:
            if self._cached and time.monotonic() - self._cached[0] < self.ttl:
                return self._cached[1], self._cached[2]
            status, vex = self._load()
            self._cached = (time.monotonic(), status, vex)
            return status, vex


def host_allowed(host: str | None) -> bool:
    """Solo richieste dirette a localhost (port-forward): difesa dal DNS rebinding."""
    if not host:
        return False
    name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    return name in LOCAL_HOSTS


def make_handler(source: Source, refresh_seconds: int) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "sage-dashboard"
        sys_version = ""

        def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for key, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, extra: dict[str, str] | None = None) -> None:
            body = json.dumps(data, ensure_ascii=False).encode()
            self._send(200, body, "application/json; charset=utf-8", extra)

        def do_GET(self) -> None:  # noqa: N802 (nome imposto da http.server)
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send(200, b"ok", "text/plain")
                return
            if not host_allowed(self.headers.get("Host")):
                self._send(403, b"solo da localhost (kubectl port-forward)", "text/plain")
                return
            if path in STATIC:
                name, ctype = STATIC[path]
                self._send(200, resources.files("sage.web").joinpath(name).read_bytes(), ctype)
                return
            try:
                if path == "/api/status":
                    status, _ = source.get()
                    self._json({**status, "refresh_seconds": refresh_seconds})
                    return
                if path == "/api/vex":
                    _, vex = source.get()
                    if not vex:
                        self._send(404, b"nessun VEX: manca il report", "text/plain")
                        return
                    self._json(
                        vex, {"Content-Disposition": 'attachment; filename="sage-openvex.json"'}
                    )
                    return
            except Exception as exc:  # noqa: BLE001 (errore mostrato, server vivo)
                log.exception("lettura dei dati fallita")
                self._send(502, f"lettura dal cluster fallita: {exc}".encode(), "text/plain")
                return
            self._send(404, b"non trovato", "text/plain")

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(source: Source, bind: str, port: int, refresh_seconds: int) -> None:
    server = ThreadingHTTPServer((bind, port), make_handler(source, refresh_seconds))
    log.info("dashboard in ascolto su %s:%d (sola lettura)", bind, port)
    server.serve_forever()
