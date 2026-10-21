"""Analisi end-to-end con dati sintetici, LLM finto e la vera policy OPA."""

import json
from datetime import UTC, datetime, timedelta

from sage import opa
from sage.analyze import Analyzer, priority, update_idle
from sage.llm import LlmChain
from tests.conftest import advisory, base_config, kernel_facts, needs_opa, package, report

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)

COPY_FAIL = {
    "conditions": [{"type": "kernel_module", "module": "algif_aead", "reason": "crypto/"}],
    "mitigation": {"type": "module_denylist", "module": "algif_aead"},
    "summary": "copy fail",
}
COCKPIT = {
    "conditions": [{"type": "network_service", "reason": "ws"}],
    "mitigation": None,
    "summary": "cockpit-ws",
}
ALWAYS = {"conditions": [], "mitigation": None, "summary": "sempre"}

RECORDS = {
    "CVE-2026-31431": {
        "program_files": ["crypto/algif_aead.c"],
        "attack_vector": "local",
        "description": "algif_aead",
        "ssvc": {"exploitation": "poc"},
    },
    "CVE-2026-0003": {"program_files": [], "attack_vector": "network", "ssvc": {}},
    "CVE-2026-0010": {"program_files": [], "attack_vector": "local", "ssvc": {}},
    "CVE-2026-0011": {"program_files": [], "attack_vector": "local", "ssvc": {}},
}
ANSWERS = {
    "CVE-2026-31431": COPY_FAIL,
    "CVE-2026-0003": COCKPIT,
    "CVE-2026-0010": ALWAYS,
    "CVE-2026-0011": ALWAYS,
}


class FakeLlm:
    def __init__(self, fail=False):
        self.asked = []
        self.fail = fail

    def __call__(self, url, body, headers, timeout):
        cve = body["messages"][1]["content"].split("CVE: ")[1].split("\n")[0]
        self.asked.append(cve)
        if self.fail:
            raise OSError("LLM giù")
        return {"choices": [{"message": {"content": json.dumps(ANSWERS[cve])}}]}


def run(
    reports,
    groups,
    kev=frozenset(),
    epss=None,
    idle=None,
    cache=None,
    fake=None,
    cfg=None,
    max_calls=None,
):
    cfg = cfg or base_config()
    if max_calls is not None:
        cfg = base_config(
            llm={
                "endpoints": [{"name": "primario", "base_url": "http://llm/v1", "model": "m"}],
                "max_calls_per_run": max_calls,
            }
        )
    fake = fake or FakeLlm()
    chain = LlmChain(cfg.llm, env={}, post=fake)
    analyzer = Analyzer(cfg, chain, RECORDS.get, opa.decide, NOW)
    analysis = analyzer.run(
        reports,
        groups,
        idle or {},
        cache if cache is not None else {},
        set(kev) if kev is not None else None,
        epss or {},
    )
    return analysis, fake


def groups_for(cfg, *names, group="worker"):
    return {n: cfg.group(group) for n in names}


def decision(analysis, node, pkg):
    return next(d for d in analysis.decisions[node] if d.package == pkg)


def kernel_report(blocked=()):
    return report(
        {
            "kernel-core": package(
                [advisory("RLSA-1", ["CVE-2026-31431"])], installed=["0:5.14.0-500.el9"]
            )
        },
        kernel=kernel_facts(blocked=blocked),
    )


@needs_opa
def test_copy_fail_is_mitigated_then_not_affected():
    cfg = base_config()
    analysis, _ = run({"w1": kernel_report()}, groups_for(cfg, "w1"))
    d = decision(analysis, "w1", "kernel-core")
    assert d.action == "mitigate" and d.modules == ["algif_aead"]

    # Al giro dopo il modulo è bloccato: la CVE non si applica più, con prova.
    analysis, fake = run(
        {"w1": kernel_report(blocked=["algif_aead"])}, groups_for(cfg, "w1"), cache=analysis.cache
    )
    d = decision(analysis, "w1", "kernel-core")
    assert d.action == "not_affected"
    assert d.cves[0].justification == "inline_mitigations_already_exist"
    assert fake.asked == []  # risposta dalla cache


@needs_opa
def test_mitigation_refused_if_group_does_not_allow_it():
    cfg = base_config()
    cfg_no = base_config(groups=[{"name": "worker", "selector": "a", "order": 1, "kernel": "auto"}])
    analysis, _ = run({"w1": kernel_report()}, groups_for(cfg_no, "w1"), cfg=cfg_no)
    assert decision(analysis, "w1", "kernel-core").action == "update"
    assert cfg.group("worker").allow_mitigate  # sanity: nel cfg di base è permessa


@needs_opa
def test_idle_cockpit_removed_only_after_enough_scans():
    cfg = base_config()
    units = {"cockpit.socket": {"active": "inactive", "enabled": "disabled"}}
    reports = {
        "w1": report(
            {
                "cockpit-ws": package(
                    [advisory("RLSA-3", ["CVE-2026-0003"])], idle=True, units=units, removal=[]
                )
            }
        )
    }
    groups = groups_for(cfg, "w1")
    first, _ = run(reports, groups)
    assert decision(first, "w1", "cockpit-ws").action == "update"  # 1 scansione su 2
    second, _ = run(reports, groups, idle=first.idle, cache=first.cache)
    assert decision(second, "w1", "cockpit-ws").action == "remove"


@needs_opa
def test_idle_service_not_affected_when_removal_not_allowed():
    cfg = base_config(groups=[{"name": "worker", "selector": "a", "order": 1, "kernel": "auto"}])
    units = {"cockpit.socket": {"active": "inactive", "enabled": "disabled"}}
    reports = {
        "w1": report(
            {
                "cockpit-ws": package(
                    [advisory("RLSA-3", ["CVE-2026-0003"])], idle=True, units=units, removal=[]
                )
            }
        )
    }
    analysis, _ = run(reports, groups_for(cfg, "w1"), idle={"w1|cockpit-ws": 5}, cfg=cfg)
    d = decision(analysis, "w1", "cockpit-ws")
    assert d.action == "not_affected"
    assert d.cves[0].justification == "vulnerable_code_not_in_execute_path"


@needs_opa
def test_kev_means_update_without_asking_the_llm():
    cfg = base_config()
    analysis, fake = run({"w1": kernel_report()}, groups_for(cfg, "w1"), kev={"CVE-2026-31431"})
    d = decision(analysis, "w1", "kernel-core")
    assert d.action == "update" and d.priority == "act"
    assert fake.asked == []


@needs_opa
def test_kev_catalog_unavailable_is_fail_closed():
    cfg = base_config()
    analysis, fake = run(
        {"w1": kernel_report(blocked=["algif_aead"])}, groups_for(cfg, "w1"), kev=None
    )
    assert decision(analysis, "w1", "kernel-core").action == "update"
    assert fake.asked == [] and analysis.kev_available is False


@needs_opa
def test_llm_down_is_fail_closed():
    cfg = base_config()
    analysis, fake = run(
        {"w1": kernel_report(blocked=["algif_aead"])},
        groups_for(cfg, "w1"),
        fake=FakeLlm(fail=True),
    )
    assert decision(analysis, "w1", "kernel-core").action == "update"
    assert fake.asked == ["CVE-2026-31431"]


@needs_opa
def test_early_stop_saves_llm_calls():
    cfg = base_config()
    pkg = package([advisory("RLSA-9", ["CVE-2026-0010", "CVE-2026-0011"])])
    analysis, fake = run(
        {"w1": report({"openssl": pkg}), "w2": report({"openssl": pkg})},
        groups_for(cfg, "w1", "w2"),
        epss={"CVE-2026-0011": 0.9, "CVE-2026-0010": 0.1},
    )
    # La CVE con EPSS più alto si applica sempre: inutile chiedere l'altra.
    assert fake.asked == ["CVE-2026-0011"]
    assert {decision(analysis, n, "openssl").action for n in ("w1", "w2")} == {"update"}


@needs_opa
def test_budget_exhausted_leaves_cves_unknown():
    cfg = base_config()
    analysis, fake = run(
        {"w1": kernel_report(blocked=["algif_aead"])}, groups_for(cfg, "w1"), max_calls=0
    )
    d = decision(analysis, "w1", "kernel-core")
    assert d.action == "update" and d.cves[0].status == "unknown"
    assert fake.asked == []


@needs_opa
def test_node_without_group_is_skipped_and_not_analyzed():
    analysis, fake = run({"x": kernel_report()}, {"x": None})
    assert decision(analysis, "x", "kernel-core").action == "skip"
    assert fake.asked == []


def test_fallback_entries_are_rechecked_after_a_day():
    cfg = base_config()
    old = {
        "CVE-2026-31431|kernel-core": {
            "v": "1",
            "result": COPY_FAIL,
            "record": RECORDS["CVE-2026-31431"],
            "endpoint": "groq",
            "model": "m",
            "at": (NOW - timedelta(days=2)).isoformat(),
        }
    }
    fake = FakeLlm()
    chain = LlmChain(cfg.llm, env={}, post=fake)
    analyzer = Analyzer(
        cfg,
        chain,
        RECORDS.get,
        lambda items, data: [{"action": "update", "schedule": "auto"} for _ in items],
        NOW,
    )
    analysis = analyzer.run({"w1": kernel_report()}, groups_for(cfg, "w1"), {}, old, set(), {})
    assert fake.asked == ["CVE-2026-31431"]
    assert analysis.cache["CVE-2026-31431|kernel-core"]["endpoint"] == "primario"


def test_update_idle_counts_consecutive_scans():
    reports = {"w1": report({"a": package([], idle=True), "b": package([], idle=False)})}
    idle = update_idle(reports, {"w1|a": 2, "w1|b": 4, "w9|z": 7})
    assert idle == {"w1|a": 3, "w9|z": 7}  # b resettato, nodo w9 non raggiunto: conservato


def test_priority():
    from sage.analyze import CveResult

    def cve(i, kev=False, epss=None):
        return CveResult(i, kev, epss, "unknown", False, [])

    assert priority([cve("A", kev=True)], {}, 0.1) == "act"
    assert priority([cve("A")], {"A": {"ssvc": {"exploitation": "active"}}}, 0.1) == "act"
    assert priority([cve("A", epss=0.5)], {}, 0.1) == "attend"
    assert (
        priority([cve("A")], {"A": {"ssvc": {"exploitation": "poc", "automatable": "yes"}}}, 0.1)
        == "attend"
    )
    assert priority([cve("A", epss=0.01)], {}, 0.1) == "track"


def test_missing_cve_record_is_not_cached_and_llm_not_called():
    cfg = base_config()
    fake = FakeLlm()
    chain = LlmChain(cfg.llm, env={}, post=fake)
    analyzer = Analyzer(
        cfg,
        chain,
        lambda cve: None,  # record CVE non scaricabile
        lambda items, data: [{"action": "update", "schedule": "auto"} for _ in items],
        NOW,
    )
    analysis = analyzer.run({"w1": kernel_report()}, groups_for(cfg, "w1"), {}, {}, set(), {})
    assert fake.asked == [] and analysis.cache == {}
