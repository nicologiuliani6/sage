"""`sage scan` dall'inizio alla fine con un cluster finto: verifica che i pezzi si parlino."""

import base64
import gzip
import json

import yaml

from sage import cli, collect, kube, sources
from sage.kube import Node
from tests.conftest import advisory, needs_opa, package, report

CONFIG = {
    "timezone": "Europe/Rome",
    "ssh": {"user": "admin", "key_path": "/chiave"},
    "groups": [
        {
            "name": "worker",
            "selector": "sage.io/group=worker",
            "order": 1,
            "kernel": "auto",
            "canary": "w1",
            "allow_remove": True,
        },
    ],
    "policy": {"idle_scans_required": 1, "idle_days_required": 0},
}

TEMPLATE = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {"labels": {"app.kubernetes.io/instance": "sage"}},
    "spec": {"template": {"spec": {"containers": [{"name": "sage", "args": ["remediate"]}]}}},
}


class FakeCluster:
    instances = []

    def __init__(self):
        self.namespace = "sage"
        self.store = {}
        self.jobs = []
        self.created = []
        self.flags = set()
        FakeCluster.instances.append(self)

    def list_nodes(self):
        return [
            Node("w1", {"sage.io/group": "worker"}, "192.0.2.1", True, False),
            Node("w2", {"sage.io/group": "worker"}, "192.0.2.2", True, False),
            Node("x1", {}, "192.0.2.9", True, False),
        ]

    def read_json(self, name):
        return self.store.get(name)

    def write_json(self, name, data):
        # stesso giro di codifica della ConfigMap reale
        self.store[name] = kube.decode(kube.encode(data))

    def read_text(self, name, key):
        return yaml.safe_dump(TEMPLATE)

    def list_jobs(self, selector):
        return self.jobs

    def create_job(self, manifest):
        self.created.append(manifest)

    def pop_flag(self, name):
        if name in self.flags:
            self.flags.discard(name)
            return True
        return False


def fake_reports(nodes, cfg, workdir):
    assert {n.name for n in nodes} == {"w1", "w2"}  # il nodo senza gruppo non si tocca via SSH
    units = {"cockpit.socket": {"active": "inactive", "enabled": "disabled"}}
    pkgs = {
        "openssl": package([advisory("RLSA-1", ["CVE-2026-0001"])], running=["/usr/bin/x"]),
        "cockpit-ws": package(
            [advisory("RLSA-2", ["CVE-2026-0002"])], idle=True, units=units, removal=[]
        ),
    }
    return {n.name: report(pkgs) for n in nodes}


def setup(monkeypatch, tmp_path):
    FakeCluster.instances.clear()
    cluster = FakeCluster()
    monkeypatch.setattr(kube, "Kube", lambda *a, **k: cluster)
    monkeypatch.setattr(collect, "collect", fake_reports)
    monkeypatch.setattr(sources, "fetch_kev", lambda src: {"CVE-2026-0001"})
    monkeypatch.setattr(sources, "fetch_epss", lambda src, cves: {})
    monkeypatch.setattr(sources, "fetch_cve_record", lambda src, cve: None)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(CONFIG))
    return cluster, str(cfg_path)


@needs_opa
def test_scan_dry_run_writes_report_and_creates_nothing(monkeypatch, tmp_path, capsys):
    cluster, cfg = setup(monkeypatch, tmp_path)
    assert cli.main(["scan", "--config", cfg, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "simulazione" in out and "== w1" in out
    assert "nodo x1 senza gruppo" in out and "== x1" not in out  # avvisato, mai analizzato
    rep = cluster.store["sage-report"]
    actions = {d["package"]: d["action"] for d in rep["nodes"]["w1"]}
    assert actions == {"openssl": "update", "cockpit-ws": "remove"}
    assert rep["plans"]["w1"]["remove_packages"] == ["cockpit-ws"]
    assert rep["dry_run"] is True and rep["vex"]["statements"] == []
    assert cluster.created == []
    idle = cluster.store["sage-state"]["idle"]
    assert set(idle) == {"w1|cockpit-ws", "w2|cockpit-ws"} and idle["w1|cockpit-ws"]["count"] == 1


@needs_opa
def test_scan_never_touches_nodes_and_tracks_urgent(monkeypatch, tmp_path, capsys):
    """Il controllo non avvia remediation (lo fa il controllore) e segna le CVE gravi."""
    cluster, cfg = setup(monkeypatch, tmp_path)
    assert cli.main(["scan", "--config", cfg]) == 0
    assert cluster.created == []
    rep = cluster.store["sage-report"]
    assert rep["plans"]["w1"]["update_advisories"] == ["RLSA-1"]
    state = cluster.store["sage-state"]
    # openssl ha una CVE in KEV: priorità act, da sistemare entro la scadenza.
    first = state["urgent"]["w1|openssl"]
    assert state["last_scan"] and set(state["urgent"]) == {"w1|openssl", "w2|openssl"}
    # Al controllo successivo la data di scoperta resta quella di prima.
    assert cli.main(["scan", "--config", cfg]) == 0
    assert cluster.store["sage-state"]["urgent"]["w1|openssl"] == first


def test_state_roundtrip_is_compact():
    data = {"idle": {f"w{i}|pkg{j}": j for i in range(10) for j in range(200)}}
    blob = kube.encode(data)
    assert kube.decode(blob) == data
    assert len(base64.b64decode(blob)) < len(json.dumps(data)) / 4
    assert gzip.decompress(base64.b64decode(blob))
