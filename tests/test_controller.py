"""Il controllore: giro completo, un nodo alla volta, ripresa dopo un'interruzione."""

from datetime import UTC, datetime, timedelta

import pytest
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
        self.problems = []  # controlli di /readyz che non passano
        self.messages = {}  # messaggio di terminazione per Job
        self.events = []  # (node, reason, message)

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

    def api_problems(self):
        return list(self.problems)

    def job_message(self, job):
        return self.messages.get(job)

    def pop_flag(self, name):
        if name in self.flags:
            self.flags.discard(name)
            return True
        return False

    def report(self, plans, at):
        self.write_json("sage-report", {"generated_at": at.isoformat(), "plans": plans})

    def post_event(self, node, reason, message):
        self.events.append((node, reason, message))


def make(cluster, dry_run=False, pause=30, stable=0):
    cfg = base_config(controller={"pause_minutes": pause, "control_plane_stable_seconds": stable})
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


def test_failed_canary_quarantines_node_and_stops_group():
    cluster = Cluster()
    ctl = make(cluster)
    assert "controllo completo" in ctl.step(T0)
    assert "controllo in corso" in ctl.step(T0)
    plans = {"w1": PLAN, "w2": PLAN, "w3": PLAN, "m1": PLAN}
    msg = run_scan(cluster, ctl, T0 + timedelta(minutes=1), plans)
    # canary w1 prima (base_config: canary w1), poi w2, w3, il master per ultimo
    assert "w1, w2, w3, m1" in msg
    t = T0 + timedelta(minutes=2)
    assert "avviata su w1" in ctl.step(t)
    assert "in corso su w1" in ctl.step(t + timedelta(minutes=1))
    cluster.finish(last_fix(cluster), ok=False)
    # Il canary fallisce: quarantena del nodo e gruppo fermato
    msg = ctl.step(t)
    assert "in quarantena fino a" in msg
    assert "gruppo worker fermo" in msg
    assert remediated(cluster) == ["w1"]  # nessun altro nodo avviato

    # I nodi successivi del gruppo vengono saltati
    assert "saltato: gruppo worker fermo" in ctl.step(t)
    assert "saltato: gruppo worker fermo" in ctl.step(t)

    # Il master viene avviato
    assert "avviata su m1" in ctl.step(t)

    # Lo stato è corretto
    doc = ctl.load()
    assert doc["halted"] is False
    assert "failures" in doc["nodes"]["w1"]
    assert "retry_after" in doc["nodes"]["w1"]
    assert "worker" in doc["groups"]

    # Eventi Kubernetes: SageQuarantine per w1 e SageGroupStopped
    assert any(e[1] == "SageQuarantine" and e[0] == "w1" for e in cluster.events)
    assert any(e[1] == "SageGroupStopped" for e in cluster.events)


def test_vanished_remediation_job_quarantines_node():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    ctl.step(T0)
    cluster.jobs.clear()
    msg = ctl.step(T0 + timedelta(minutes=10))
    # Il Job è scomparso: quarantena del nodo
    assert "scomparsa" in msg
    assert "in quarantena" in msg
    assert "FERMO" not in msg


def next_cycle(cluster, ctl, t, plans):
    """Chiude il giro in corso (i nodi rimasti vengono saltati) e ne avvia uno nuovo a t."""
    for _ in range(50):
        if ctl.load()["cycle"]["phase"] == "pause":
            break
        ctl.step(t)
    cluster.flags.add("sage-scan-now")
    ctl.step(t)
    return run_scan(cluster, ctl, t, plans)


def step_until(ctl, t, text):
    for _ in range(20):
        msg = ctl.step(t)
        if text in msg:
            return msg
    raise AssertionError(f"mai visto: {text}")


def test_quarantine_backoff_doubles():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    plans = {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY}
    run_scan(cluster, ctl, T0, plans)
    ctl.step(T0)
    cluster.finish(last_fix(cluster), ok=False)
    assert "in quarantena fino a" in ctl.step(T0)
    assert ctl.load()["nodes"]["w1"]["retry_after"] == (T0 + timedelta(hours=1)).isoformat()
    # Prima della fine dell'attesa il nodo (e il suo gruppo) non si tocca.
    t = T0 + timedelta(minutes=30)
    next_cycle(cluster, ctl, t, plans)
    assert "fermo" in ctl.step(t) and remediated(cluster) == ["w1"]
    # Dopo l'attesa si ritenta; un secondo errore raddoppia l'attesa.
    t = T0 + timedelta(hours=2)
    next_cycle(cluster, ctl, t, plans)
    assert "avviata su w1" in ctl.step(t)
    cluster.finish(last_fix(cluster), ok=False)
    ctl.step(t)
    assert ctl.load()["nodes"]["w1"]["retry_after"] == (t + timedelta(hours=2)).isoformat()


def test_non_canary_failure_below_quota_does_not_stop_group():
    nodes = [node(f"w{i:02d}") for i in range(1, 13)] + [node("m1", master=True)]
    cluster = Cluster(nodes)
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {n.name: PLAN for n in nodes})
    assert "avviata su w01" in ctl.step(T0)
    cluster.finish(last_fix(cluster))
    assert ctl.step(T0) == "w01: remediation riuscita"
    assert "avviata su w02" in ctl.step(T0)
    cluster.finish(last_fix(cluster), ok=False)
    msg = ctl.step(T0)
    assert "w02: remediation fallita" in msg and "gruppo" not in msg  # 1 errore su 12
    assert "avviata su w03" in ctl.step(T0)
    cluster.finish(last_fix(cluster), ok=False)
    assert "gruppo worker fermo" in ctl.step(T0)  # 2 errori: quota ceil(12 * 10%) = 2


def test_master_failure_stops_master_group():
    nodes = [node("w1"), node("m1", master=True), node("m2", master=True)]
    cluster = Cluster(nodes)
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY, "m1": PLAN, "m2": PLAN})
    step_until(ctl, T0, "avviata su m1")
    cluster.finish(last_fix(cluster), ok=False)
    assert "gruppo master fermo" in ctl.step(T0)
    assert "m2: saltato: gruppo master fermo" in ctl.step(T0)


def test_success_clears_quarantine():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    plans = {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY}
    run_scan(cluster, ctl, T0, plans)
    ctl.step(T0)
    cluster.finish(last_fix(cluster), ok=False)
    ctl.step(T0)
    t = T0 + timedelta(hours=2)
    next_cycle(cluster, ctl, t, plans)
    assert "avviata su w1" in ctl.step(t)
    cluster.finish(last_fix(cluster))
    assert "w1: remediation riuscita" in ctl.step(t)
    doc = ctl.load()
    assert "failures" not in doc["nodes"]["w1"] and "retry_after" not in doc["nodes"]["w1"]
    assert "worker" not in doc["groups"]


def test_sage_cordon_is_retried_human_cordon_is_not():
    labels = {"sage.io/group": "worker"}
    sage = Node("w1", labels, "192.0.2.1", True, True, {"sage.io/cordoned": "true"})
    human = Node("w2", labels, "192.0.2.2", True, True)
    cluster = Cluster([sage, human])
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": PLAN})
    assert "avviata su w1" in ctl.step(T0)
    cluster.finish(last_fix(cluster))
    ctl.step(T0)
    assert "w2: saltato: nodo non Ready o in cordon" in ctl.step(T0)


def test_job_creation_timeout_retries_instead_of_stopping():
    """etcd lento: create_job va in timeout e il Job non esiste. Il nodo non è stato
    toccato: si riprova, senza fermare il cluster."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    real_create = cluster.create_job

    def timeout(manifest):
        raise RuntimeError("etcdserver: request timed out")

    cluster.create_job = timeout
    with pytest.raises(RuntimeError):
        ctl.step(T0)
    cluster.create_job = real_create
    later = T0 + timedelta(minutes=10)
    assert "mai creato" in ctl.step(later)
    assert "avviata su w1" in ctl.step(later)
    assert not ctl.load().get("halted")


def test_job_created_despite_timeout_is_followed():
    """La risposta si perde ma il Job è stato creato: lo si segue, niente doppioni."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    real_create = cluster.create_job

    def lost_reply(manifest):
        real_create(manifest)
        raise RuntimeError("context deadline exceeded")

    cluster.create_job = lost_reply
    with pytest.raises(RuntimeError):
        ctl.step(T0)
    cluster.create_job = real_create
    assert "in corso" in ctl.step(T0 + timedelta(minutes=10))
    assert len(remediated(cluster)) == 1


def test_legacy_halted_state_becomes_quarantine():
    """Uno stato salvato dalla 0.6 con halted=True diventa quarantena del nodo fallito."""
    cluster = Cluster()
    # Prepara il vecchio stato con halted=True
    cluster.store["sage-controller"] = {
        "halted": True,
        "halt_reason": "vecchio stato",
        "nodes": {"w1": {"status": "failed"}},
        "cycle": None,
    }
    ctl = make(cluster)

    # Carica lo stato: deve diventare quarantena
    doc = ctl.load()
    assert doc["halted"] is False
    assert "failures" in doc["nodes"]["w1"]
    assert "retry_after" in doc["nodes"]["w1"]


def test_resume_clears_quarantine():
    """dopo un fallimento di w1, flag 'sage-resume' e un passo: messaggio con 'quarantene azzerate',
    doc['nodes']['w1'] senza retry_after, doc['groups'] vuoto."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": PLAN, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)

    # w1 fallisce
    cluster.finish(last_fix(cluster), ok=False)
    msg = ctl.step(T0)
    assert "in quarantena" in msg

    # Flag di resume e passo
    cluster.flags.add("sage-resume")
    msg = ctl.step(T0)
    assert "quarantene azzerate" in msg

    # Lo stato è corretto
    doc = ctl.load()
    assert "retry_after" not in doc["nodes"]["w1"]
    assert doc["groups"] == {}


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


def test_unready_and_unreached_nodes_are_skipped_not_waited():
    cluster = Cluster([node("w1"), node("w2", ready=False), node("w3", cordon=True)])
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY, "w2": PLAN, "w3": PLAN})
    cluster.nodes.append(node("w4"))  # aggiunto dopo il controllo: non è in coda
    msgs = [ctl.step(T0) for _ in range(4)]
    assert msgs[1].startswith("w2: saltato") and msgs[2].startswith("w3: saltato")
    assert "giro completato" in msgs[3] and remediated(cluster) == []


def test_steps_pass_idle_nodes_together():
    """I nodi senza niente da fare passano nello stesso giro di poll, senza aspettare."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    scan = ctl.load()["cycle"]["scan_job"]
    cluster.report({"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": PLAN}, T0)
    cluster.finish(scan)
    msgs = ctl.steps(T0)
    # coda pronta e w1 avviato subito; si ferma perché c'è un Job da aspettare
    assert msgs[0].startswith("giro 1: ordine") and "avviata su w1" in msgs[1]
    assert len(msgs) == 2
    cluster.finish(last_fix(cluster))
    msgs = ctl.steps(T0)
    assert msgs == [
        "w1: remediation riuscita",
        "w2: niente da fare",
        "w3: niente da fare",
        f"remediation avviata su m1 ({last_fix(cluster)})",
    ]
    cluster.finish(last_fix(cluster))
    assert "giro completato" in ctl.steps(T0)[-1]


def test_unstable_control_plane_delays_the_node():
    """Con etcd o l'API in difficoltà il nodo resta in coda, nessun drain."""
    cluster = Cluster([node("w1"), node("m1", master=True)])
    ctl = make(cluster, stable=60)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "m1": PLAN})
    cluster.problems = ["etcd"]
    assert "control plane instabile: etcd" in ctl.step(T0)
    assert remediated(cluster) == []
    cluster.problems = []
    t = T0 + timedelta(seconds=30)
    assert "sano da 0 s su 60" in ctl.step(t)
    assert "sano da 30 s su 60" in ctl.step(t + timedelta(seconds=30))
    assert "avviata su w1" in ctl.step(t + timedelta(seconds=60))
    cluster.finish(last_fix(cluster))
    t2 = t + timedelta(seconds=70)
    msgs = ctl.steps(t2)
    # per un master servono 3 volte tanto: sano da 70 s, ne servono 180
    assert msgs == ["w1: remediation riuscita", "m1: in attesa, control plane sano da 70 s su 180"]
    assert "avviata su m1" in ctl.step(t + timedelta(seconds=180))


def test_stability_restarts_after_a_long_gap():
    """Cluster spento e riacceso: uno "stabile da" di giorni prima non vale, si riconta."""
    cluster = Cluster([node("w1")])
    ctl = make(cluster, stable=60)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    assert "sano da 0 s su 60" in ctl.step(T0)
    later = T0 + timedelta(days=5)
    assert "sano da 0 s su 60" in ctl.step(later)
    assert "avviata su w1" in ctl.step(later + timedelta(seconds=60))


def test_simulation_does_not_wait():
    cluster = Cluster([node("w1")])
    cluster.problems = ["etcd"]
    ctl = make(cluster, dry_run=True, stable=60)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN})
    assert ctl.step(T0).startswith("w1: simulato")


def test_queue_order_canary_first():
    cfg = base_config()
    groups = {n: cfg.group("worker") for n in ("w3", "w1", "w2")} | {"m1": cfg.group("master")}
    assert controller.queue_order(cfg, groups) == ["w1", "w2", "w3", "m1"]


def test_masters_always_last_whatever_the_order():
    cfg = base_config()
    master, worker = cfg.group("master"), cfg.group("worker")
    groups = {"m1": master, "w1": worker, "w2": worker}
    cfg = cfg.__class__(**{**cfg.__dict__, "groups": (master, worker)})  # master con order 1
    assert controller.queue_order(cfg, groups, frozenset({"m1"})) == ["w1", "w2", "m1"]


def test_scan_manifest():
    m = controller.scan_manifest(JOB, "sage", T0)
    assert m["metadata"]["name"] == "sage-scan-261022120000"
    assert m["metadata"]["labels"]["sage.io/role"] == "scan"
    assert JOB["metadata"].get("name") is None


def test_finished_cycles_are_kept_for_the_dashboard():
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)
    cluster.finish(last_fix(cluster))
    step_until(ctl, T0, "giro completato")
    (cycle,) = cluster.read_json("sage-cycles")["cycles"]
    assert cycle["id"] == 1 and cycle["outcomes"] == {"fatto": 1, "niente da fare": 3}
    assert cycle["nodes"]["w1"]["outcome"] == "fatto"
    cluster.write_json("sage-cycles", {"cycles": [{"id": i} for i in range(200)]})
    doc = ctl.load()
    ctl._pause(doc, T0, "prova")
    kept = cluster.read_json("sage-cycles")["cycles"]
    assert len(kept) == 100 and kept[-1]["id"] == 1


def test_failure_reason_from_the_job_reaches_state_and_alerts():
    """Il motivo scritto da `sage remediate` (es. nodo non ripartito) finisce nell'esito."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)
    job = last_fix(cluster)
    cluster.messages[job] = "aggiornamento NON riuscito: il nodo non è ripartito dopo il riavvio"
    cluster.finish(job, ok=False)
    assert "NON riuscito" in ctl.step(T0)
    detail = ctl.load()["cycle"]["results"]["w1"]["detail"]
    assert detail.startswith("fallita: aggiornamento NON riuscito")


def test_drain_blocked_by_pdb_waits_without_stopping_the_group():
    """Un PodDisruptionBudget (es. Longhorn) non è un guasto del nodo: si ritenta più tardi,
    il gruppo prosegue."""
    cluster = Cluster()
    ctl = make(cluster)
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": PLAN, "w2": PLAN, "w3": EMPTY, "m1": EMPTY})
    ctl.step(T0)
    job = last_fix(cluster)
    cluster.messages[job] = "Cannot evict pod as it would violate the pod's disruption budget."
    cluster.finish(job, ok=False)
    msg = ctl.step(T0)
    assert "in quarantena" in msg and "gruppo" not in msg
    assert "avviata su w2" in ctl.step(T0)


def test_self_update_job_only_in_pause_and_once_per_interval():
    cluster = Cluster()
    cfg = base_config(self_update={"repository": "owner/sage", "check_hours": 24})
    ctl = Controller(
        cfg, cluster, "sage", False, LlmChain(cfg.llm, env={}, get_status=lambda *a: 200)
    )
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {"w1": EMPTY, "w2": EMPTY, "w3": EMPTY, "m1": EMPTY})
    step_until(ctl, T0, "giro completato")
    assert "aggiornamenti di SAGE" in ctl.step(T0 + timedelta(minutes=1))
    updates = [m for m in cluster.created if m["metadata"]["name"].startswith("sage-update-")]
    assert len(updates) == 1
    assert "in pausa" in ctl.step(T0 + timedelta(minutes=2))  # non un secondo Job


def parallel(workers=10, max_unavailable=4, per_zone=0, zones=1):
    def worker(i):
        labels = {"sage.io/group": "worker", "topology.kubernetes.io/zone": f"z{i % zones}"}
        return Node(f"w{i:02d}", labels, "192.0.2.1", True, False)

    nodes = [worker(i) for i in range(1, workers + 1)] + [
        node("m1", master=True),
        node("m2", master=True),
    ]
    cfg = base_config(
        controller={"control_plane_stable_seconds": 0},
        groups=[
            {
                "name": "worker",
                "selector": "sage.io/group=worker",
                "order": 1,
                "canary": "w01",
                "max_unavailable": max_unavailable,
                "max_unavailable_per_zone": per_zone,
            },
            {
                "name": "master",
                "selector": "node-role.kubernetes.io/control-plane",
                "order": 2,
                "max_unavailable": 3,
            },
        ],
    )
    cluster = Cluster(nodes)
    ctl = Controller(
        cfg, cluster, "sage", False, LlmChain(cfg.llm, env={}, get_status=lambda *a: 200)
    )
    ctl.step(T0)
    run_scan(cluster, ctl, T0, {n.name: PLAN for n in nodes})
    return cluster, ctl


def running_now(cluster):
    return sorted(
        j.node for j in cluster.jobs.values() if j.active and j.name.startswith("sage-fix-")
    )


def finish_all(cluster, ok=True):
    for name in [
        j.name for j in cluster.jobs.values() if j.active and j.name.startswith("sage-fix-")
    ]:
        cluster.finish(name, ok=ok)


def test_workers_in_parallel_grow_gradually_up_to_the_limit():
    cluster, ctl = parallel()
    sizes = []
    for _ in range(12):
        ctl.steps(T0)
        now = running_now(cluster)
        if not now:
            break
        assert len({n[0] for n in now}) == 1  # mai worker e master insieme
        if now[0].startswith("m"):
            break
        sizes.append(len(now))
        finish_all(cluster)
    assert sizes[:5] == [1, 1, 2, 4, 2]  # canary da solo, poi 1, 2, 4 (tetto), gli ultimi 2
    assert max(sizes) == 4


def test_masters_one_at_a_time_after_the_workers():
    cluster, ctl = parallel(workers=2)
    seen = []
    for _ in range(10):
        ctl.steps(T0)
        now = running_now(cluster)
        if not now:
            break
        seen.append(now)
        finish_all(cluster)
    assert ["m1"] in seen and ["m2"] in seen
    assert all(len(s) == 1 for s in seen if s[0].startswith("m"))


def test_zone_limit():
    cluster, ctl = parallel(workers=8, max_unavailable=4, per_zone=1, zones=2)
    for _ in range(6):
        ctl.steps(T0)
        now = running_now(cluster)
        zones = [int(n[1:]) % 2 for n in now]
        assert len(zones) == len(set(zones))  # mai due nodi della stessa zona insieme
        finish_all(cluster)


def test_failure_stops_new_nodes_but_running_ones_finish():
    cluster, ctl = parallel(workers=10, max_unavailable=4)
    for _ in range(3):  # canary, poi 1, poi 2 insieme
        ctl.steps(T0)
        finish_all(cluster)
    ctl.steps(T0)
    busy = running_now(cluster)
    assert len(busy) == 4
    first, *others = [
        j.name for j in cluster.jobs.values() if j.active and j.name.startswith("sage-fix-")
    ]
    cluster.finish(first, ok=False)
    msgs = ctl.steps(T0)
    assert any("gruppo worker fermo" in m for m in msgs)
    assert len(running_now(cluster)) == 3  # nessun nodo nuovo, gli altri continuano
    for name in others:
        cluster.finish(name)
    ctl.steps(T0)
    assert not [n for n in running_now(cluster) if n.startswith("w")]  # il gruppo resta fermo
