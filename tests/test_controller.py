"""Il controllore: giro completo, un nodo alla volta, ripresa dopo un'interruzione."""

from datetime import UTC, datetime, timedelta

import yaml

from sage import controller, kube
from sage.controller import Controller
from sage.kube import JobInfo, Node
from sage.llm import LlmChain
from tests.conftest import base_config

T0 = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
JOB = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {"labels": {"app.kubernetes.io/instance": "sage"}},
    "spec": {"template": {"spec": {"containers": [{"name": "sage", "args": ["x"]}]}}},
}
PLAN = {
    "update_advisories": ["RLSA-1"],
    "update_packages": ["openssl"],
    "remove_packages": [],
    "denylist_modules": [],
    "deferred": [],
}
EMPTY = {k: [] for k in PLAN}


def node(name, master=False, ready=True, cordon=False):
    labels = {"sage.io/group": "worker"}
    if master:
        labels = {"node-role.kubernetes.io/control-plane": ""}
    return Node(name, labels, "192.0.2.1", ready, cordon)


class Cluster:
    """API Kubernetes finta: ConfigMap, Job (che si completano a comando), flag."""

    namespace = "sage"

    def __init__(self, nodes=None):
        self.nodes = nodes or [node("w1"), node("w2"), node("w3"), node("m1", master=True)]
        self.store = {}
        self.jobs = {}  # nome -> JobInfo
        self.created = []
        self.flags = set()

    def list_nodes(self):
        return self.nodes

    def read_json(self, name):
        return kube.decode(kube.encode(self.store[name])) if name in self.store else None

    def write_json(self, name, data):
        self.store[name] = kube.decode(kube.encode(data))

    def read_text(self, name, key):
        return yaml.safe_dump(JOB)

    def list_jobs(self, selector):
        role = selector.split(",")[0].split("=")[1]
        prefix = {"scan": "sage-scan-", "remediate": "sage-fix-"}[role]
        return [j for j in self.jobs.values() if j.name.startswith(prefix)]

    def create_job(self, manifest):
        name = manifest["metadata"]["name"]
        node_name = manifest["metadata"].get("annotations", {}).get("sage.io/node-name")
        self.created.append(manifest)
        self.jobs[name] = JobInfo(name, node_name, True, False, False, None)

    def finish(self, name, ok=True, at=None):
        job = self.jobs[name]
        self.jobs[name] = JobInfo(name, job.node, False, ok, not ok, at)

    def pop_flag(self, name):
        if name in self.flags:
            self.flags.discard(name)
            return True
        return False

    def report(self, plans, at):
        self.write_json("sage-report", {"generated_at": at.isoformat(), "plans": plans})


def make(cluster, dry_run=False, pause=30):
    cfg = base_config(controller={"pause_minutes": pause})
    chain = LlmChain(cfg.llm, env={}, get_status=lambda *a: 200)
    return Controller(cfg, cluster, "sage", dry_run, chain)


def run_scan(cluster, ctl, now, plans):
    """Il controllore ha lanciato il controllo: il Job finisce e scrive il report."""
    scan = ctl.load()["cycle"]["scan_job"]
    cluster.report(plans, now)
    cluster.finish(scan)
    return ctl.step(now)


def last_fix(cluster):
    return [m for m in cluster.created if m["metadata"]["labels"]["sage.io/role"] == "remediate"][
        -1
    ]["metadata"]["name"]


def remediated(cluster):
    return [
        m["metadata"]["annotations"]["sage.io/node-name"]
        for m in cluster.created
        if m["metadata"]["labels"]["sage.io/role"] == "remediate"
    ]


def test_full_cycle_one_node_at_a_time_workers_then_masters():
    cluster = Cluster()
    ctl = make(cluster)
    assert "controllo completo" in ctl.step(T0)
    assert "controllo in corso" in ctl.step(T0)
    plans = {"w1": PLAN, "w2": PLAN, "w3": EMPTY, "m1": PLAN}
    msg = run_scan(cluster, ctl, T0 + timedelta(minutes=1), plans)
    # canary w1 prima (base_config: canary w1), poi w2, w3 senza niente, il master per ultimo
    assert "w1, w2, w3, m1" in msg
    t = T0 + timedelta(minutes=2)
    assert "avviata su w1" in ctl.step(t)
    assert "in corso su w1" in ctl.step(t + timedelta(minutes=1))
    cluster.finish(last_fix(cluster), at=t.isoformat())
    assert "w1: remediation riuscita" == ctl.step(t)
    assert "avviata su w2" in ctl.step(t)
    cluster.finish(last_fix(cluster))
    ctl.step(t)
    assert ctl.step(t) == "w3: niente da fare"
    assert "avviata su m1" in ctl.step(t)
    cluster.finish(last_fix(cluster))
    ctl.step(t)
    assert "giro completato" in ctl.step(t)
    assert remediated(cluster) == ["w1", "w2", "m1"]
    # Pausa, poi si riparte dall'inizio con un nuovo controllo.
    assert "in pausa" in ctl.step(t + timedelta(minutes=10))
    assert "fine della pausa" in ctl.step(t + timedelta(minutes=31))
    assert ctl.load()["cycle"]["id"] == 2


def test_restart_resumes_where_it_was():
    """Il controllore muore durante una remediation: la copia nuova riprende, senza
    rilanciare il nodo e senza ricominciare il giro."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": PLAN, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)  # remediation su w1
    fresh = make(cluster)  # nuovo pod, altro nodo: legge solo lo stato salvato
    assert "in corso su w1" in fresh.step(T0 + timedelta(minutes=5))
    cluster.finish(last_fix(cluster))
    assert fresh.step(T0 + timedelta(minutes=9)) == "w1: remediation riuscita"
    assert "avviata su w2" in fresh.step(T0 + timedelta(minutes=9))
    assert remediated(cluster) == ["w1", "w2"]


def test_restart_during_scan_waits_for_the_same_job():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    fresh = make(cluster)
    assert "controllo in corso" in fresh.step(T0 + timedelta(minutes=3))
    assert len(cluster.created) == 1  # nessun secondo controllo


def test_scan_job_lost_is_relaunched_then_gives_up():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    cluster.jobs.clear()  # Job sparito (nodo riavviato, cancellato a mano)
    late = T0 + timedelta(minutes=5)
    assert "nuovo tentativo" in ctl.step(late)
    cluster.jobs.clear()
    ctl.step(late + timedelta(minutes=5))
    cluster.jobs.clear()
    assert "fallito 3 volte" in ctl.step(late + timedelta(minutes=10))
    assert ctl.load()["cycle"]["phase"] == "pause"


def test_failed_remediation_stops_everything_until_resume():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": PLAN, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)
    cluster.finish(last_fix(cluster), ok=False)
    assert "FERMO" in ctl.step(T0)
    assert "FERMO" in ctl.step(T0 + timedelta(hours=5))
    assert remediated(cluster) == ["w1"]  # nessun altro nodo
    cluster.flags.add("sage-resume")
    assert "ripreso" in ctl.step(T0 + timedelta(hours=6))
    assert "avviata su w2" in ctl.step(T0 + timedelta(hours=6))
    # Il nodo fallito viene ritentato al giro dopo: il tentativo fallito non conta come fatto.
    cluster.finish(last_fix(cluster))
    for _ in range(4):  # w2 riuscito, w3 e m1 niente da fare, giro completato
        ctl.step(T0 + timedelta(hours=7))
    assert ctl.load()["cycle"]["phase"] == "pause"
    later = T0 + timedelta(hours=8)
    assert "fine della pausa" in ctl.step(later)
    run_scan(cluster, ctl, later, {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY})
    assert "avviata su w1" in ctl.step(later)


def test_vanished_remediation_job_stops_everything():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    ctl.step(T0)
    cluster.jobs.clear()
    assert "FERMO" in ctl.step(T0 + timedelta(minutes=10))


def test_unready_and_unreached_nodes_are_skipped_not_waited():
    cluster = Cluster([node("w1"), node("w2", ready=False), node("w3", cordon=True)])
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY, "w2": PLAN, "w3": PLAN})
    cluster.nodes.append(node("w4"))  # aggiunto dopo il controllo: non è in coda
    msgs = [ctl.step(T0) for _ in range(4)]
    assert msgs[1].startswith("w2: saltato") and msgs[2].startswith("w3: saltato")
    assert "giro completato" in msgs[3] and remediated(cluster) == []


def test_node_without_report_is_skipped():
    cluster = Cluster([node("w1"), node("w2")])
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY})
    ctl.step(T0)
    assert ctl.step(T0) == "w2: saltato: non raggiunto dal controllo"


def test_same_advisories_after_success_are_not_repeated():
    """Niente drain e riavvii in loop se un'advisory resta dopo la remediation."""
    cluster = Cluster([node("w1")])
    ctl = make(cluster, pause=0)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    ctl.step(T0)
    cluster.finish(last_fix(cluster), at=T0.isoformat())
    ctl.step(T0)
    ctl.step(T0)  # giro completato
    later = T0 + timedelta(minutes=1)
    ctl.step(later)  # nuovo giro
    run_scan(cluster, ctl, later, {"w1": PLAN})
    assert "advisory ancora presenti" in ctl.step(later)
    assert remediated(cluster) == ["w1"]


def test_dry_run_simulates_and_keeps_cycling():
    cluster = Cluster()
    ctl = make(cluster, dry_run=True, pause=0)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": PLAN})
    msgs = [ctl.step(T0) for _ in range(5)]
    assert msgs[0].startswith("w1: simulato") and msgs[3].startswith("m1: simulato")
    assert "giro completato" in msgs[4]
    assert remediated(cluster) == []
    assert "controllo completo" in ctl.step(T0 + timedelta(seconds=1))


def test_scan_now_flag_ends_the_pause():
    cluster = Cluster([node("w1")])
    ctl = make(cluster, pause=600)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY})
    ctl.step(T0)
    ctl.step(T0)
    assert "in pausa" in ctl.step(T0 + timedelta(minutes=1))
    cluster.flags.add("sage-scan-now")
    assert "richiesto a mano" in ctl.step(T0 + timedelta(minutes=2))


def test_queue_order_canary_first():
    cfg = base_config()
    groups = {n: cfg.group("worker") for n in ("w3", "w1", "w2")} | {"m1": cfg.group("master")}
    assert controller.queue_order(cfg, groups) == ["w1", "w2", "w3", "m1"]


def test_scan_manifest():
    m = controller.scan_manifest(JOB, "sage", T0)
    assert m["metadata"]["name"] == "sage-scan-261022120000"
    assert m["metadata"]["labels"]["sage.io/role"] == "scan"
    assert JOB["metadata"].get("name") is None
