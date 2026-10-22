from datetime import datetime

import pytest

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
