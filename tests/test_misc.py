from datetime import datetime
from pathlib import Path

import pytest
import yaml

from sage import config, remediate, report
from sage.analyze import Analysis, CveResult, PackageDecision
from tests.conftest import base_config


def test_config_new_fields():
    cfg = base_config(timezone="Europe/Rome")
    assert cfg.timezone == "Europe/Rome"
    assert cfg.policy.idle_scans_required == 2
    assert cfg.sources.kev_url.startswith("https://www.cisa.gov/")


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"timezone": "Marte/Olympus"}, "timezone"),
        (
            {
                "llm": {
                    "endpoints": [
                        {
                            "name": "a",
                            "base_url": "http://x",
                            "model": "m",
                            "hosted_in_group": "nessuno",
                        }
                    ]
                }
            },
            "hosted_in_group",
        ),
        ({"policy": {"protected_modules": "nf_*"}}, "protected_modules"),
        ({"policy": {"epss_attend_threshold": 3}}, "epss_attend_threshold"),
        ({"sources": {"kev_url": "ftp://x"}}, "kev_url"),
        ({"llm": {"max_calls_per_run": -1}}, "max_calls_per_run"),
    ],
)
def test_config_new_fields_validated(overrides, fragment):
    with pytest.raises(config.ConfigError) as exc:
        base_config(**overrides)
    assert fragment in str(exc.value)


def test_extra_vars_from_group():
    cfg = base_config(
        groups=[
            {
                "name": "gpu-llm",
                "selector": "a",
                "order": 1,
                "kernel": "auto",
                "drain": "wait-empty",
                "drain_timeout_seconds": 600,
                "requires_fallback": True,
                "health_urls": ["http://vllm/health"],
            }
        ]
    )
    group = cfg.group("gpu-llm")
    v = remediate.extra_vars("g1", False, {"update_advisories": ["RLSA-1"]}, group)
    assert v["sage_drain_mode"] == "wait-empty" and v["sage_drain_timeout"] == 600
    assert v["sage_disable_eviction"] is True and v["sage_health_urls"] == ["http://vllm/health"]
    assert v["sage_update_advisories"] == ["RLSA-1"] and v["sage_remove_packages"] == []


def test_openvex_only_for_not_affected():
    cve = CveResult(
        "CVE-2026-1",
        False,
        None,
        "not_affected",
        True,
        ["modulo bloccato"],
        "inline_mitigations_already_exist",
    )
    decisions = {
        "w1": [
            PackageDecision(
                "kernel-core", "not_affected", "auto", "track", [], ["0:5.14.0-500.el9"], [cve]
            ),
            PackageDecision("openssl", "update", "auto", "track", [], ["1:3.0.7-1.el9"], [cve]),
        ]
    }
    analysis = Analysis(decisions, {}, {}, 0, True)
    reports = {"w1": {"node": {"os": {"name": "Rocky Linux", "version": "9.4"}, "arch": "x86_64"}}}
    doc = report.openvex(analysis, reports, datetime.fromisoformat("2026-10-21T12:00:00+00:00"))
    assert doc["@context"].startswith("https://openvex.dev/")
    assert len(doc["statements"]) == 1
    st = doc["statements"][0]
    assert st["products"] == [
        {"@id": "pkg:rpm/rocky/kernel-core@5.14.0-500.el9?arch=x86_64&distro=rocky-9.4"}
    ]
    assert st["justification"] == "inline_mitigations_already_exist"
    assert st["impact_statement"] == "w1: modulo bloccato"


def test_light_mode_only_for_module_blocks():
    group = base_config().group("worker")
    assert remediate.extra_vars("w1", False, {"denylist_modules": ["sctp"]}, group)["sage_light"]
    for plan in ({"update_advisories": ["RLSA-1"]}, {"remove_packages": ["cockpit-ws"]}):
        assert not remediate.extra_vars("w1", False, plan, group)["sage_light"]


def test_collect_retries_missing_nodes_one_at_a_time(tmp_path, monkeypatch):
    """Un nodo lento che non risponde al primo passaggio viene riprovato, da solo."""
    import subprocess

    from sage import collect
    from sage.kube import Node

    nodes = [Node(n, {}, "192.0.2.1", True, False) for n in ("n1", "n2")]
    monkeypatch.setattr(collect, "write_inventory", lambda n, c, w: (tmp_path / "inv", []))
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        out = tmp_path / "reports"
        names = ["n1"] if "--limit" not in cmd else cmd[cmd.index("--limit") + 1].split(",")
        for name in names:
            (out / f"{name}.json").write_text('{"packages": {}}')
        return subprocess.CompletedProcess(cmd, 2 if "--limit" not in cmd else 0, "", "")

    monkeypatch.setattr(collect.subprocess, "run", run)
    reports = collect.collect(nodes, base_config(), tmp_path)
    assert set(reports) == {"n1", "n2"}
    assert calls[0][calls[0].index("--forks") + 1] == "3"
    assert calls[1][-4:] == ["--forks", "1", "--limit", "n2"]


def _tasks(items):
    for t in items:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _tasks(t.get(key, []))


def test_kube_calls_retry_on_api_errors():
    """Cordon, drain e uncordon riprovano: un errore passeggero dell'API dopo un riavvio
    riuscito farebbe annullare l'aggiornamento dal rescue."""

    play = yaml.safe_load((Path(__file__).parents[1] / "ansible" / "remediate.yml").read_text())[0]
    # Tutte le scritture verso l'API: cordon, drain, uncordon e segno del cordon.
    writes = [
        t
        for t in _tasks(play["tasks"])
        if "kubernetes.core.k8s_drain" in t or "kubernetes.core.k8s" in t
    ]
    assert len(writes) >= 9
    for t in writes:
        assert t["until"] == f"{t['register']} is succeeded", t["name"]
        retries = t["retries"]
        assert isinstance(retries, str) or retries >= 3, t["name"]  # stringa: da drain_timeout


def test_failure_message_from_ansible_output():
    """Il motivo leggibile del fallimento arriva alla dashboard (messaggio di terminazione)."""
    out = (
        'TASK [Fallimento] ***\nfatal: [w1]: FAILED! => {"changed": false, "msg": '
        '"aggiornamento NON riuscito: il nodo non \\u00e8 ripartito dopo il riavvio. '
        'Passo: Riavvia il nodo."}\n'
    )
    assert remediate.failure_message(out, 2).startswith("aggiornamento NON riuscito: il nodo non è")
    assert remediate.failure_message("niente", 3) == "remediation fallita (codice 3)"


def test_control_plane_labels_of_every_distribution():
    from sage.kube import Node

    for label in (
        "node-role.kubernetes.io/control-plane",  # kubeadm
        "node-role.kubernetes.io/master",  # cluster vecchi, k3s
        "node-role.kubernetes.io/etcd",  # RKE2 e k3s con nodi solo etcd
    ):
        assert Node("n", {label: "true"}, None, True, False).control_plane
    assert not Node(
        "n", {"node-role.kubernetes.io/worker": "true"}, None, True, False
    ).control_plane
