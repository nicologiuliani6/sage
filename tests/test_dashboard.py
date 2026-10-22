"""Dashboard di sola lettura: modello dei dati e server, con un cluster finto."""

import http.client
import json
import threading
from datetime import datetime
from http.server import ThreadingHTTPServer
from zoneinfo import ZoneInfo

import pytest

from sage import dashboard, schedule
from sage.kube import Node
from tests.conftest import base_config

ROME = ZoneInfo("Europe/Rome")
NOW = datetime(2026, 10, 22, 18, 0, tzinfo=ROME)  # giovedì


def node(name, group, ready=True, cordon=False):
    return Node(name, {"sage.io/group": group}, "10.0.0.1", ready, cordon)


NODES = [node("w1", "worker"), node("w2", "worker", cordon=True), node("m1", "master")]
for n in NODES[2:]:
    n.labels["node-role.kubernetes.io/control-plane"] = ""


def cve(cid, kev=False, epss=0.01, evidence=("prova",)):
    return {"id": cid, "kev": kev, "epss": epss, "status": "affected", "evidence": list(evidence)}


def decision(package, action, priority="track", cves=()):
    return {
        "package": package,
        "action": action,
        "priority": priority,
        "schedule": "now",
        "advisories": ["RLSA-1"],
        "cves": list(cves),
    }


REPORT = {
    "generated_at": "2026-10-22T15:00:00+02:00",
    "version": "0.3.1",
    "dry_run": True,
    "kev_available": True,
    "llm_calls": 12,
    "warnings": [],
    "messages": ["[worker] (simulazione) avvierei la remediation su w1"],
    "plans": {
        "w1": {
            "update_advisories": ["RLSA-1", "RLSA-2"],
            "update_packages": ["openssl", "curl"],
            "remove_packages": [],
            "denylist_modules": [],
            "deferred": [],
        },
        "w2": {"update_advisories": [], "remove_packages": [], "deferred": []},
        "m1": {
            "update_advisories": [],
            "remove_packages": [],
            "deferred": [{"package": "kernel", "reason": "fuori dalla finestra (sat 02:00-06:00)"}],
        },
    },
    "nodes": {
        "w1": [
            decision("openssl", "update", "act", [cve("CVE-2026-1", kev=True)]),
            decision("curl", "update", "attend", [cve("CVE-2026-2", epss=0.4)]),
            decision("glibc", "not_affected", "track", [cve("CVE-2026-3")]),
        ],
        "w2": [decision("glibc", "not_affected", "track", [cve("CVE-2026-3")])],
        "m1": [decision("kernel", "update", "track", [cve("CVE-2026-4")])],
    },
    "profiles": {
        "w1": {
            "units": ["a.service"],
            "required": {"openssl": "a.service"},
            "process_scan_ok": True,
        },
        "w2": {"units": ["a.service"], "required": {}, "process_scan_ok": False},
        "m1": {"units": [], "required": {}},
    },
    "vex": {"statements": []},
}
STATE = {"nodes": {"w1": {"status": "done", "last_success": "2026-10-22T16:00:00+02:00"}}}
HISTORY = (
    json.dumps({"time": "2026-10-20T10:00:00+02:00", "user": "rocky", "action": "installa"})
    + "\nriga rotta\n"
    + json.dumps(
        {"time": "2026-10-21T10:00:00+02:00", "user": "rocky", "action": "vivo", "changes": [1, 2]}
    )
    + "\n"
)
CRONJOB = {
    "schedule": "0 */6 * * *",
    "time_zone": "Europe/Rome",
    "suspend": False,
    "last_schedule": None,
    "last_success": None,
    "active": 0,
}


def status(**overrides):
    args = {
        "cfg": base_config(timezone="Europe/Rome"),
        "config_error": None,
        "nodes": NODES,
        "report": REPORT,
        "state": STATE,
        "history_text": HISTORY,
        "cronjob": CRONJOB,
        "now": NOW,
    }
    args.update(overrides)
    return dashboard.build_status(**args)


def by_name(result):
    return {n["name"]: n for n in result["nodes"]}


def test_node_levels_and_reasons():
    nodes = by_name(status())
    w1 = nodes["w1"]
    assert w1["level"] == "critical" and w1["kev"] == ["CVE-2026-1"]
    assert w1["canary"] and w1["plan"]["advisories"] == 2
    # canary aggiornato alle 16, osservazione di 360 minuti: fino alle 22
    assert w1["wave"]["soak_until"] == "2026-10-22T22:00+02:00"
    assert w1["packages"][0]["package"] == "openssl"  # act e KEV per primo
    w2 = nodes["w2"]
    assert w2["level"] == "warning"
    assert "nodo in cordon" in w2["reasons"]
    assert "lettura dei processi non affidabile" in w2["reasons"]
    m1 = nodes["m1"]
    assert m1["next_window"] == "2026-10-24T02:00+02:00"  # sabato
    assert m1["level"] == "ok"


def test_order_alarms_and_totals():
    result = status()
    assert [n["name"] for n in result["nodes"]] == ["w1", "w2", "m1"]  # canary, gruppo, ordine
    assert result["next_scan"] == "2026-10-23T00:00+02:00"  # alle 18:00 il giro è già partito
    assert result["alarms"][0]["level"] == "critical"
    assert any("w1:" in a["text"] for a in result["alarms"])
    totals = result["totals"]
    assert totals["nodes"] == 3 and totals["nodes_clean"] == 2
    assert totals["advisories"] == 2 and totals["deferred"] == 1 and totals["kev"] == 1
    assert [h["action"] for h in result["history"]] == ["vivo", "installa"]
    assert result["history"][0]["changes"] == 2


def test_cve_table_urgent_first():
    rows = status()["cves"]
    assert rows[0]["id"] == "CVE-2026-1" and rows[0]["kev"]
    assert rows[-1]["id"] == "CVE-2026-3"  # solo non affetta: in fondo
    assert {w["node"] for w in rows[-1]["where"]} == {"w1", "w2"}


def test_problems_become_alarms():
    texts = [
        a["text"]
        for a in status(
            report=None,
            state={"halted": True, "halt_reason": "remediation fallita su w1"},
            cronjob={**CRONJOB, "suspend": True},
            config_error="file mancante",
        )["alarms"]
    ]
    assert any("FERME" in t for t in texts)
    assert "giri automatici sospesi" in texts
    assert any("nessun report" in t for t in texts)
    assert any("configurazione" in t for t in texts)
    stale = status(report={**REPORT, "generated_at": "2026-10-20T00:00:00+02:00"})
    assert any("troppo vecchio" in a["text"] for a in stale["alarms"])
    missing = status(cronjob=None)
    assert any("CronJob" in a["text"] for a in missing["alarms"])


@pytest.mark.parametrize(
    ("expr", "after", "expected"),
    [
        ("0 */6 * * *", datetime(2026, 10, 22, 13, 5), datetime(2026, 10, 22, 18, 0)),
        ("0 3 * * *", datetime(2026, 10, 22, 3, 0), datetime(2026, 10, 23, 3, 0)),
        ("30 2 * * 6", datetime(2026, 10, 22, 0, 0), datetime(2026, 10, 24, 2, 30)),
        ("0 0 1,15 * 1", datetime(2026, 10, 22, 0, 0), datetime(2026, 10, 26, 0, 0)),
        ("@daily", datetime(2026, 10, 22, 0, 0), datetime(2026, 10, 23, 0, 0)),
        ("1-10/3 * * * *", datetime(2026, 10, 22, 0, 4), datetime(2026, 10, 22, 0, 7)),
        ("non valida", datetime(2026, 10, 22), None),
        ("61 * * * *", datetime(2026, 10, 22), None),
    ],
)
def test_next_run(expr, after, expected):
    assert schedule.next_run(expr, after) == expected


def test_next_window():
    assert schedule.next_window("sat 02:00-06:00", NOW) == datetime(2026, 10, 24, 2, 0, tzinfo=ROME)
    inside = datetime(2026, 10, 24, 3, 0, tzinfo=ROME)
    assert schedule.next_window("sat 02:00-06:00", inside) == inside
    assert schedule.next_window(None, NOW) is None


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("localhost:8080", True),
        ("127.0.0.1:8080", True),
        ("[::1]:8080", True),
        ("localhost", True),
        ("evil.example:8080", False),
        ("10.0.0.5:8080", False),
        (None, False),
    ],
)
def test_host_allowed(host, allowed):
    assert dashboard.host_allowed(host) is allowed


class FakeKube:
    namespace = "sage"

    def list_nodes(self):
        return NODES

    def read_json(self, name):
        return {"sage-report": REPORT, "sage-state": STATE}.get(name)

    def read_text(self, name, key):
        return HISTORY if name == "sage-history" else None

    def cronjob(self, name):
        return CRONJOB if name == "sage-scan" else None


@pytest.fixture
def server(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        json.dumps(
            {
                "ssh": {"user": "admin", "key_path": "/chiave"},
                "groups": [
                    {
                        "name": "worker",
                        "selector": "sage.io/group=worker",
                        "order": 1,
                        "kernel": "auto",
                    }
                ],
            }
        )
    )
    source = dashboard.Source(FakeKube(), "sage", str(cfg))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(source, 30))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()


def get(port, path, host="localhost"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": f"{host}:{port}"})
    resp = conn.getresponse()
    return resp.status, dict(resp.getheaders()), resp.read()


def test_server_serves_page_and_status(server):
    code, headers, body = get(server, "/")
    assert code == 200 and b"/app.js" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    for path in ("/app.js", "/style.css"):
        assert get(server, path)[0] == 200
    code, _, body = get(server, "/api/status")
    data = json.loads(body)
    assert code == 200 and data["refresh_seconds"] == 30
    assert {n["name"] for n in data["nodes"]} == {"w1", "w2", "m1"}
    assert not any("configurazione" in a["text"] for a in data["alarms"])
    code, headers, body = get(server, "/api/vex")
    assert code == 200 and "attachment" in headers["Content-Disposition"]


def test_server_refuses_other_hosts(server):
    assert get(server, "/api/status", host="evil.example")[0] == 403
    assert get(server, "/healthz", host="10.0.0.5")[0] == 200  # sonda di Kubernetes
    assert get(server, "/../etc/passwd")[0] == 404
