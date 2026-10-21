from datetime import UTC, datetime, timedelta

import yaml

from sage import act
from sage.analyze import PackageDecision
from sage.kube import JobInfo, Node
from sage.llm import LlmChain
from tests.conftest import base_config

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)  # mercoledì
SATURDAY_3AM = datetime(2026, 10, 24, 3, 0, tzinfo=UTC)

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


class FakeKube:
    namespace = "sage"

    def __init__(self, jobs=None):
        self.jobs = jobs or []
        self.created = []

    def list_jobs(self, selector):
        assert "sage.io/role=remediate" in selector
        return self.jobs

    def read_text(self, name, key):
        assert name == "sage-remediate-template" and key == "job.yaml"
        return yaml.safe_dump(TEMPLATE)

    def create_job(self, manifest):
        self.created.append(manifest)


def node(name, ready=True, cordoned=False, master=False):
    labels = {"node-role.kubernetes.io/control-plane": ""} if master else {}
    return Node(name, labels, "192.0.2.1", ready, cordoned)


def dec(pkg, action="update", schedule="auto", modules=()):
    return PackageDecision(pkg, action, schedule, "track", [f"RLSA-{pkg}"], [], [], list(modules))


CFG = base_config()
GROUPS = {
    "w1": CFG.group("worker"),
    "w2": CFG.group("worker"),
    "w3": CFG.group("worker"),
    "m1": CFG.group("master"),
}
NODES = [node("w1"), node("w2"), node("w3"), node("m1", master=True)]


def plans_all():
    decisions = {n: [dec("openssl")] for n in GROUPS}
    return act.build_plans(decisions, GROUPS, NOW)


def step(
    plans, state, kube=None, dry_run=False, nodes=NODES, now=NOW, chain=None, cfg=CFG, groups=GROUPS
):
    kube = kube or FakeKube()
    chain = chain or LlmChain(cfg.llm, env={}, get_status=lambda *a: 200)
    msgs = act.step(cfg, kube, chain, "sage", nodes, groups, plans, state, now, dry_run)
    return msgs, kube


# --- piani


def test_build_plans_respects_schedule():
    decisions = {
        "w1": [
            dec("openssl"),
            dec("cockpit-ws", "remove"),
            dec("kernel-core", "mitigate", modules=["algif_aead"]),
            dec("glibc", "not_affected"),
        ],
        "m1": [dec("kernel-core", schedule="window"), dec("bash")],
        "x": [dec("openssl")],
    }
    groups = {**GROUPS, "x": None}
    plans = act.build_plans(decisions, groups, NOW)
    w1 = plans["w1"]
    assert w1.update_advisories == ["RLSA-openssl"] and w1.remove_packages == ["cockpit-ws"]
    assert w1.denylist_modules == ["algif_aead"]
    assert plans["m1"].update_packages == ["bash"]
    assert plans["m1"].deferred[0]["package"] == "kernel-core"
    assert "x" not in plans  # nodo senza gruppo: nessun piano
    in_window = act.build_plans(decisions, groups, SATURDAY_3AM)
    assert in_window["m1"].update_packages == ["bash", "kernel-core"]


def test_manual_kernel_is_never_planned():
    plans = act.build_plans({"w1": [dec("kernel-core", schedule="manual")]}, GROUPS, SATURDAY_3AM)
    assert plans["w1"].empty and plans["w1"].deferred


# --- ondate


def test_canary_goes_first_alone():
    state = {}
    msgs, kube = step(plans_all(), state)
    assert [j["metadata"]["annotations"]["sage.io/node-name"] for j in kube.created] == ["w1"]
    assert state["nodes"]["w1"]["status"] == "running"
    assert "canary" not in msgs[0] or "w1" in msgs[0]


def test_dry_run_creates_nothing():
    state = {}
    msgs, kube = step(plans_all(), state, dry_run=True)
    assert (
        kube.created == []
        and "simulazione" in msgs[0]
        and "nodes" not in state
        or not state["nodes"]
    )


def test_waits_while_canary_runs():
    state = {"nodes": {"w1": {"status": "running", "job": "j1"}}}
    jobs = [JobInfo("j1", "w1", True, False, False, None)]
    msgs, kube = step(plans_all(), state, FakeKube(jobs))
    assert kube.created == [] and "canary w1 in corso" in msgs[0]


def test_canary_soak_then_rest_of_group():
    finished = (NOW - timedelta(minutes=30)).isoformat()
    state = {"nodes": {"w1": {"status": "running", "job": "j1"}}}
    jobs = [JobInfo("j1", "w1", False, True, False, finished)]
    plans = plans_all()
    plans["w1"] = act.Plan()  # canary aggiornato: niente più da fare
    msgs, kube = step(plans, state, FakeKube(jobs))
    assert state["nodes"]["w1"]["status"] == "done"
    assert kube.created == [] and "osservazione" in msgs[0]
    # Passate le 6 ore di osservazione, parte il resto del gruppo (concorrenza 1).
    msgs, kube = step(plans, state, FakeKube(jobs), now=NOW + timedelta(hours=7))
    assert [j["metadata"]["annotations"]["sage.io/node-name"] for j in kube.created] == ["w2"]


def test_masters_only_after_workers():
    plans = plans_all()
    for n in ("w1", "w2", "w3"):
        plans[n] = act.Plan()
    msgs, kube = step(plans, {})
    assert [j["metadata"]["annotations"]["sage.io/node-name"] for j in kube.created] == ["m1"]


def test_failed_job_halts_everything_until_resume():
    state = {"nodes": {"w1": {"status": "running", "job": "j1"}}}
    jobs = [JobInfo("j1", "w1", False, False, True, None)]
    msgs, kube = step(plans_all(), state, FakeKube(jobs))
    assert state["halted"] and "FERMO" in msgs[0] and kube.created == []
    msgs, kube = step(plans_all(), state, FakeKube(jobs))
    assert kube.created == []
    assert act.resume(state) == ["w1"] and not state["halted"]


def test_vanished_running_job_halts():
    state = {"nodes": {"w1": {"status": "running", "job": "j1"}}}
    msgs, kube = step(plans_all(), state, FakeKube([]))
    assert state["halted"] and "scomparso" in state["halt_reason"] and kube.created == []


def test_resume_does_not_rehalt_on_old_failed_job():
    state = {"nodes": {"w1": {"status": "running", "job": "j1"}}}
    jobs = [JobInfo("j1", "w1", False, False, True, None)]
    step(plans_all(), state, FakeKube(jobs))
    act.resume(state)
    msgs, kube = step(plans_all(), state, FakeKube(jobs))
    assert not state.get("halted")
    # Il canary viene ritentato (una persona ha controllato il nodo prima di sbloccare).
    assert [j["metadata"]["annotations"]["sage.io/node-name"] for j in kube.created] == ["w1"]


def test_unready_canary_blocks_group():
    nodes = [node("w1", ready=False), node("w2"), node("w3"), node("m1", master=True)]
    msgs, kube = step(plans_all(), {}, nodes=nodes)
    assert kube.created == [] and "non è pronto" in msgs[-1]


def test_cordoned_node_is_skipped():
    plans = plans_all()
    plans["w1"] = act.Plan()
    nodes = [node("w1"), node("w2", cordoned=True), node("w3"), node("m1", master=True)]
    msgs, kube = step(plans, {}, nodes=nodes)
    assert [j["metadata"]["annotations"]["sage.io/node-name"] for j in kube.created] == ["w3"]
    assert any("w2" in m for m in msgs)


def test_requires_fallback_blocks_without_reserve():
    cfg = base_config(
        llm={
            "endpoints": [
                {
                    "name": "locale",
                    "base_url": "http://l/v1",
                    "model": "m",
                    "hosted_in_group": "llm",
                }
            ]
        },
        groups=[
            {
                "name": "llm",
                "selector": "a",
                "order": 1,
                "kernel": "auto",
                "requires_fallback": True,
            }
        ],
    )
    groups = {"g1": cfg.group("llm")}
    plans = act.build_plans({"g1": [dec("openssl")]}, groups, NOW)
    chain = LlmChain(cfg.llm, env={}, get_status=lambda *a: 200)
    msgs, kube = step(plans, {}, nodes=[node("g1")], chain=chain, cfg=cfg, groups=groups)
    assert kube.created == [] and "riserva" in msgs[0]


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
    assert term["matchFields"][0] == {
        "key": "metadata.name",
        "operator": "NotIn",
        "values": ["worker01-a-very-long-node-name-from-kubespray-x"],
    }
    assert TEMPLATE["spec"]["template"]["spec"].get("affinity") is None  # template intatto


def test_mitigation_ignores_kernel_window():
    # Bloccare un modulo non è un aggiornamento del kernel: niente attesa della finestra.
    decisions = {"m1": [dec("kernel-core", "mitigate", schedule="window", modules=["sctp"])]}
    plans = act.build_plans(decisions, GROUPS, NOW)
    assert plans["m1"].denylist_modules == ["sctp"] and not plans["m1"].deferred


def test_unready_pending_node_holds_later_groups():
    plans = plans_all()
    plans["w1"] = act.Plan()
    plans["w3"] = act.Plan()
    nodes = [node("w1"), node("w2", ready=False), node("w3"), node("m1", master=True)]
    msgs, kube = step(plans, {}, nodes=nodes)
    assert kube.created == [] and "aspettano" in msgs[-1]  # i master non partono


def test_unreachable_canary_holds_group():
    plans = plans_all()
    del plans["w1"]  # nessun report dal canary in questo giro
    msgs, kube = step(plans, {})
    assert kube.created == [] and "non raggiunto" in msgs[-1]
