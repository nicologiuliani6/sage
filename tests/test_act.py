"""Piani di remediation e manifest dei Job (il giro dei nodi è in test_controller)."""

import dataclasses
from datetime import UTC, datetime

from sage import act
from sage.analyze import CveResult, PackageDecision
from tests.conftest import base_config

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)

TEMPLATE = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {"labels": {"app.kubernetes.io/instance": "sage"}},
    "spec": {
        "template": {
            "spec": {
                "containers": [{"name": "sage", "args": ["remediate", "--config", "/c.yaml"]}],
                "restartPolicy": "Never",
            }
        }
    },
}

CFG = base_config()
GROUPS = {"w1": CFG.group("worker"), "w2": CFG.group("worker"), "m1": CFG.group("master")}


def dec(pkg, action="update", schedule="auto", modules=()):
    return PackageDecision(pkg, action, schedule, "track", [f"RLSA-{pkg}"], [], [], list(modules))


def test_build_plans():
    decisions = {
        "w1": [
            dec("openssl"),
            dec("cockpit-ws", "remove"),
            dec("kernel-core", "mitigate", modules=["algif_aead"]),
            dec("glibc", "not_affected"),
        ],
        "m1": [dec("kernel-core"), dec("bash")],
        "x": [dec("openssl")],
    }
    plans = act.build_plans(decisions, {**GROUPS, "x": None})
    w1 = plans["w1"]
    assert w1.update_advisories == ["RLSA-openssl"] and w1.remove_packages == ["cockpit-ws"]
    assert w1.denylist_modules == ["algif_aead"]
    assert plans["m1"].update_packages == ["bash", "kernel-core"]  # kernel nel giro
    assert "x" not in plans  # nodo senza gruppo: nessun piano


def test_manual_kernel_is_never_planned():
    plans = act.build_plans({"w1": [dec("kernel-core", schedule="manual")]}, GROUPS)
    assert plans["w1"].empty and plans["w1"].deferred


def test_mitigation_ignores_manual_kernel():
    # Bloccare un modulo non è un aggiornamento del kernel: niente riavvio.
    decisions = {"m1": [dec("kernel-core", "mitigate", schedule="manual", modules=["sctp"])]}
    plans = act.build_plans(decisions, GROUPS)
    assert plans["m1"].denylist_modules == ["sctp"] and not plans["m1"].deferred


def test_decision_round_trip():
    d = PackageDecision(
        "curl",
        "update",
        "auto",
        "act",
        ["RLSA-1"],
        ["0:1-1"],
        [CveResult("CVE-1", True, 0.5, "affected", True, ["prova"])],
    )
    assert act.decision_from_dict(dataclasses.asdict(d)) == d


def test_job_manifest():
    plan = act.Plan(update_advisories=["RLSA-1"])
    m = act.job_manifest(
        TEMPLATE, "sage", "worker01-a-very-long-node-name-from-kubespray-x", plan, NOW
    )
    assert len(m["metadata"]["name"]) <= 63
    assert m["metadata"]["labels"]["sage.io/role"] == "remediate"
    args = m["spec"]["template"]["spec"]["containers"][0]["args"]
    assert args[:3] == ["remediate", "--config", "/c.yaml"] and "--plan" in args
    term = m["spec"]["template"]["spec"]["affinity"]["nodeAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]["nodeSelectorTerms"][0]
    # Il Job non gira mai sul nodo che modifica.
    assert term["matchFields"][0] == {
        "key": "metadata.name",
        "operator": "NotIn",
        "values": ["worker01-a-very-long-node-name-from-kubespray-x"],
    }
    assert TEMPLATE["spec"]["template"]["spec"].get("affinity") is None  # template intatto


def test_pending_reboot_joins_the_plan():
    from sage.act import Plan, add_pending_reboots

    cfg = base_config()
    worker = cfg.group("worker")
    manual = worker.__class__(**{**worker.__dict__, "kernel": "manual"})
    plans = {"w1": Plan(), "w2": Plan(), "g1": Plan()}
    reports = {n: {"reboot": {"required": n != "w2", "reasons": ["x"]}} for n in plans}
    add_pending_reboots(plans, reports, {"w1": worker, "w2": worker, "g1": manual})
    assert plans["w1"].reboot and not plans["w1"].empty
    assert not plans["w2"].reboot and plans["w2"].empty
    assert not plans["g1"].reboot and plans["g1"].deferred  # kernel solo a mano: a una persona
    assert Plan.from_dict(plans["w1"].to_dict()).reboot is True
