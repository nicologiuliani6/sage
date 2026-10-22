"""Dashboard di sola lettura: modello dei dati e server, con un cluster finto."""

import http.client
import json
import threading
from datetime import datetime
from http.server import ThreadingHTTPServer
from zoneinfo import ZoneInfo

import pytest

from sage import dashboard
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
            "deferred": [{"package": "kernel", "reason": "kernel: solo intervento manuale"}],
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
STATE = {
    "last_scan": "2026-10-22T15:00:00+02:00",
    # openssl su w1 è grave (act) dalle 13: scadenza alle 19; curl non è più act
    "urgent": {"w1|openssl": "2026-10-22T13:00:00+02:00", "w1|curl": "2026-10-22T10:00:00+02:00"},
}
CONTROLLER = {
    "cycle": {
        "id": 4,
        "phase": "remediate",
        "started": "2026-10-22T15:00:00+02:00",
        "queue": ["w1", "w2", "m1"],
        "results": {"w1": {"outcome": "fatto", "at": "2026-10-22T16:00:00+02:00"}},
    },
    "nodes": {
        "w1": {"status": "done", "last_success": "2026-10-22T16:00:00+02:00"},
        "w2": {"status": "running", "job": "sage-fix-w2"},
    },
    "halted": False,
}
LEASE = {"holder": "sage-controller-abc", "renew_time": "2026-10-22T15:59:30+00:00"}
DEPLOYMENT = {"replicas": 1, "ready": 1}
HISTORY = (
    json.dumps({"time": "2026-10-20T10:00:00+02:00", "user": "rocky", "action": "installa"})
    + "\nriga rotta\n"
    + json.dumps(
        {"time": "2026-10-21T10:00:00+02:00", "user": "rocky", "action": "vivo", "changes": [1, 2]}
    )
    + "\n"
)


def status(**overrides):
    args = {
        "cfg": base_config(timezone="Europe/Rome"),
        "config_error": None,
        "nodes": NODES,
        "report": REPORT,
        "state": STATE,
        "controller": CONTROLLER,
        "lease": LEASE,
        "deployment": DEPLOYMENT,
        "history_text": HISTORY,
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
    assert w1["wave"]["outcome"] == "fatto"
    assert w1["deadline"] == "2026-10-22T19:00+02:00" and w1["urgent"] == ["openssl"]
    assert w1["packages"][0]["package"] == "openssl"  # act e KEV per primo
    w2 = nodes["w2"]
    assert w2["level"] == "warning" and w2["wave"]["status"] == "running"
    assert "nodo in cordon" in w2["reasons"]
    assert "lettura dei processi non affidabile" in w2["reasons"]
    assert nodes["m1"]["level"] == "ok"


def test_deadline_passed_is_critical():
    late = status(now=datetime(2026, 10, 22, 19, 30, tzinfo=ROME))
    assert "CVE gravi oltre la scadenza (1 pacchetti)" in by_name(late)["w1"]["reasons"]


def test_controller_summary_and_totals():
    result = status()
    ctl = result["controller"]
    assert ctl["alive"] and ctl["text"] == "remediation su w2"
    assert (ctl["done"], ctl["queue"], ctl["cycle"]) == (1, 3, 4)
    assert [n["name"] for n in result["nodes"]] == ["w1", "w2", "m1"]  # canary, gruppo, ordine
    assert result["alarms"][0]["level"] == "critical"
    assert any("remediation in corso su w2" in a["text"] for a in result["alarms"])
    totals = result["totals"]
    assert totals["nodes"] == 3 and totals["nodes_clean"] == 2
    assert totals["urgent"] == 1 and totals["next_deadline"] == "2026-10-22T19:00+02:00"
    assert totals["advisories"] == 2 and totals["deferred"] == 1 and totals["kev"] == 1
    assert [h["action"] for h in result["history"]] == ["vivo", "installa"]
    assert result["history"][0]["changes"] == 2


def test_cve_table_urgent_first():
    rows = status()["cves"]
    assert rows[0]["id"] == "CVE-2026-1" and rows[0]["kev"]
    assert rows[-1]["id"] == "CVE-2026-3"  # solo non affetta: in fondo
    assert {w["node"] for w in rows[-1]["where"]} == {"w1", "w2"}


def test_problems_become_alarms():
    halted = {**CONTROLLER, "halted": True, "halt_reason": "remediation fallita su w1"}
    texts = [
        a["text"]
        for a in status(report=None, controller=halted, config_error="file mancante")["alarms"]
    ]
    assert any("SAGE FERMO" in t for t in texts)
    assert any("nessun report" in t for t in texts)
    assert any("configurazione" in t for t in texts)
    dead = status(lease={**LEASE, "renew_time": "2026-10-22T15:00:00+00:00"})
    assert any("controllore fermo" in a["text"] for a in dead["alarms"])
    off = status(deployment={"replicas": 0, "ready": 0}, lease=None)
    texts = [a["text"] for a in off["alarms"]]
    assert any("controllore spento" in t for t in texts)
    assert not any("controllore fermo" in t for t in texts)
    assert off["controller"]["text"] == "spento (giri sospesi)"
    pause = {
        **CONTROLLER,
        "cycle": {
            **CONTROLLER["cycle"],
            "phase": "pause",
            "pause_until": "2026-10-22T18:30:00+02:00",
        },
    }
    assert status(controller=pause)["controller"]["next_cycle"] == "2026-10-22T18:30:00+02:00"


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
        return {"sage-report": REPORT, "sage-state": STATE, "sage-controller": CONTROLLER}.get(name)

    def read_lease(self, name):
        return LEASE

    def read_deployment(self, name):
        return DEPLOYMENT

    def read_text(self, name, key):
        return HISTORY if name == "sage-history" else None


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
