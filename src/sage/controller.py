"""Controllore di SAGE: un loop sempre acceso che fa il giro dei nodi (ADR-0015).

Un giro:
1. controllo completo (un Job `sage scan`: raccolta, analisi, decisioni, report);
2. remediation un nodo alla volta, nell'ordine dei gruppi (il canary per primo in ogni
   gruppo, i master per ultimi). Ogni remediation è un Job che gira su un altro nodo:
   un nodo non si modifica mai da solo;
3. pausa (`controller.pause_minutes`), poi si riparte dal punto 1.

Ogni passo è salvato nella ConfigMap `<release>-controller` prima di essere eseguito:
se il controllore muore a metà (drain del suo nodo, riavvio, crash), la copia che
riparte su un altro nodo riprende dallo stesso punto. Un Lease garantisce che ci sia
un solo controllore attivo alla volta. Una remediation fallita ferma tutto finché una
persona non controlla il nodo e crea la ConfigMap `<release>-resume`.
"""

from __future__ import annotations

import copy
import logging
import math
import os
import signal
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from sage import act, alerts
from sage.config import Config
from sage.inventory import assign_groups
from sage.kube import KubeApi
from sage.llm import LlmChain

log = logging.getLogger(__name__)

SCAN_ROLE = "scan"
SCAN_RETRIES = 3
# Un Job appena creato può non comparire subito nell'elenco: si aspetta prima di
# considerarlo scomparso.
JOB_GRACE = timedelta(minutes=2)
LEASE_SECONDS = 120
HEARTBEAT = Path(os.environ.get("SAGE_HEARTBEAT", "/tmp/sage-controller-alive"))

OUTCOME_DONE = "fatto"
OUTCOME_NOTHING = "niente da fare"
OUTCOME_SIMULATED = "simulato"
OUTCOME_FAILED = "fallito"
# Quarantena (ADR-0019): attesa prima di ritentare, raddoppia a ogni errore.
QUARANTINE_FIRST = timedelta(hours=1)
QUARANTINE_MAX = timedelta(days=7)
# Un gruppo si ferma per il giro se fallisce il canary, un master o questa quota dei nodi.
GROUP_FAILURE_RATIO = 0.1


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def queue_order(
    cfg: Config, groups: dict[str, Any], control_plane: frozenset[str] = frozenset()
) -> list[str]:
    """Ordine del giro: gruppi per `order`, in ogni gruppo il canary per primo.

    I gruppi con nodi del control plane vanno sempre in fondo, qualunque `order` abbiano:
    un master si aggiorna solo quando il resto del cluster è già passato."""
    workers, masters = [], []
    for group in cfg.groups:
        members = sorted(n for n, g in groups.items() if g is not None and g.name == group.name)
        if group.canary in members:
            members.remove(group.canary)
            members.insert(0, group.canary)
        (masters if any(m in control_plane for m in members) else workers).extend(members)
    return workers + masters


def plan_text(plan: act.Plan) -> str:
    parts = [f"{len(plan.update_advisories)} advisory"] if plan.update_advisories else []
    if plan.remove_packages:
        parts.append(f"{len(plan.remove_packages)} da rimuovere")
    if plan.denylist_modules:
        parts.append(f"{len(plan.denylist_modules)} moduli da bloccare")
    if plan.reboot:
        parts.append("riavvio in sospeso")
    return ", ".join(parts) or "niente"


def same_plan(plan: dict[str, Any], previous: dict[str, Any] | None) -> bool:
    """Il piano chiede esattamente quello che l'ultima remediation riuscita ha già fatto?"""
    if not previous:
        return False
    keys = ("update_advisories", "remove_packages", "denylist_modules")
    if bool(plan.get("reboot")) != bool(previous.get("reboot")):
        return False
    return all(sorted(plan.get(k) or []) == sorted(previous.get(k) or []) for k in keys)


def backoff(failures: int) -> timedelta:
    """1 ora, 2, 4... fino a 7 giorni."""
    return min(QUARANTINE_FIRST * 2 ** min(failures - 1, 20), QUARANTINE_MAX)


class Controller:
    def __init__(
        self,
        cfg: Config,
        kube: KubeApi,
        release: str,
        dry_run: bool,
        chain: LlmChain | None = None,
    ):
        self.cfg = cfg
        self.kube = kube
        self.release = release
        self.dry_run = dry_run
        self.chain = chain or LlmChain(cfg.llm)
        self.doc_name = f"{release}-controller"
        # True se l'ultimo passo non ha lanciato niente (nodo saltato, coda pronta):
        # il passo dopo si può fare subito, senza aspettare poll_seconds.
        self.again = False

    # ------------------------------------------------------------ stato

    def load(self) -> dict[str, Any]:
        doc = self.kube.read_json(self.doc_name) or {}
        doc.setdefault("cycle", None)
        doc.setdefault("nodes", {})
        doc.setdefault("halted", False)
        doc.setdefault("groups", {})
        if doc["halted"]:
            # Fermo globale delle versioni prima della 0.7 (ADR-0010): diventa quarantena del
            # nodo fallito, gli altri proseguono (ADR-0019).
            log.info("fermo della versione precedente convertito in quarantena")
            doc["halted"] = False
            doc.pop("halt_reason", None)
            for st in doc["nodes"].values():
                if st.get("status") == "failed" and not st.get("retry_after"):
                    st["failures"] = st.get("failures", 0) + 1
                    st["retry_after"] = _iso(datetime.now(UTC) + backoff(st["failures"]))
        return doc

    def save(self, doc: dict[str, Any]) -> None:
        self.kube.write_json(self.doc_name, doc)

    # ------------------------------------------------------------ un passo

    def step(self, now: datetime) -> str:
        """Un passo del giro. Restituisce cosa ha fatto (per il log)."""
        self.again = False
        doc = self.load()
        before = copy.deepcopy(doc)
        message = self._step(doc, now)
        if doc != before:
            self.save(doc)
        return message

    def _step(self, doc: dict[str, Any], now: datetime) -> str:
        resumed = self._resume(doc, now)
        cycle = doc["cycle"]
        if cycle is None:
            return self._start_cycle(doc, now, "primo giro")
        phase = cycle["phase"]
        if phase == "pause":
            if self.kube.pop_flag(f"{self.release}-scan-now"):
                return self._start_cycle(doc, now, "richiesto a mano")
            if now >= _time(cycle["pause_until"]):
                return self._start_cycle(doc, now, "fine della pausa")
            return resumed or f"in pausa fino a {cycle['pause_until']}"
        if phase == "scan":
            return self._wait_scan(doc, now)
        return resumed or self._remediate(doc, now)

    def _resume(self, doc: dict[str, Any], now: datetime) -> str:
        """`<release>-resume`: azzera quarantene e gruppi fermi (intervento a mano, mai
        necessario: le attese finiscono da sole)."""
        if not self.kube.pop_flag(f"{self.release}-resume"):
            return ""
        doc["groups"] = {}
        for st in doc["nodes"].values():
            st.pop("retry_after", None)
            st.pop("failures", None)
            if st.get("status") == "failed":
                st["status"] = "idle"
        if doc["cycle"]:
            doc["cycle"].pop("stopped_groups", None)
        log.info("quarantene azzerate su richiesta")
        return "quarantene azzerate su richiesta"

    # ------------------------------------------------------------ controllo completo

    def _start_cycle(self, doc: dict[str, Any], now: datetime, why: str) -> str:
        previous = doc["cycle"] or {}
        doc["cycle"] = {
            "id": previous.get("id", 0) + 1,
            "phase": "scan",
            "reason": why,
            "started": _iso(now),
            "scan_job": None,
            "scan_attempts": 0,
            "queue": [],
            "results": {},
        }
        return self._launch_scan(doc, now)

    def _launch_scan(self, doc: dict[str, Any], now: datetime) -> str:
        cycle = doc["cycle"]
        template = self.kube.read_text(f"{self.release}-scan-template", "job.yaml")
        if not template:
            return "modello del Job di controllo mancante: reinstalla SAGE"
        cycle["scan_attempts"] += 1
        manifest = scan_manifest(yaml.safe_load(template), self.release, now)
        cycle["scan_job"] = manifest["metadata"]["name"]
        cycle["scan_created"] = _iso(now)
        # Prima si salva quale Job si sta creando, poi lo si crea: se il controllore muore
        # in mezzo, al riavvio sa quale cercare (e se manca ne crea un altro).
        self.save(doc)
        self.kube.create_job(manifest)
        return f"giro {cycle['id']} ({cycle['reason']}): controllo completo {cycle['scan_job']}"

    def _wait_scan(self, doc: dict[str, Any], now: datetime) -> str:
        cycle = doc["cycle"]
        jobs = {j.name: j for j in self.kube.list_jobs(self._selector(SCAN_ROLE))}
        job = jobs.get(cycle.get("scan_job") or "")
        if job and job.active:
            return f"controllo in corso ({job.name})"
        report = self.kube.read_json(f"{self.release}-report")
        generated = _time((report or {}).get("generated_at"))
        if job and job.succeeded and generated and generated >= _time(cycle["started"]):
            return self._build_queue(doc, report, now)
        created = _time(cycle.get("scan_created"))
        if job is None and created and now - created < JOB_GRACE:
            return "controllo appena avviato"
        if cycle["scan_attempts"] >= SCAN_RETRIES:
            # Niente remediation su dati incompleti: si riprova dopo la pausa.
            cycle["error"] = f"controllo fallito {cycle['scan_attempts']} volte"
            return self._pause(doc, now, cycle["error"])
        return self._launch_scan(doc, now) + " (nuovo tentativo)"

    def _build_queue(self, doc: dict[str, Any], report: dict[str, Any], now: datetime) -> str:
        cycle = doc["cycle"]
        nodes = self.kube.list_nodes()
        groups, _ = assign_groups(nodes, self.cfg.groups)
        masters = frozenset(n.name for n in nodes if n.control_plane)
        cycle["queue"] = queue_order(self.cfg, groups, masters)
        cycle["phase"] = "remediate"
        cycle["scanned"] = _iso(now)
        self.again = True
        return f"giro {cycle['id']}: ordine {', '.join(cycle['queue']) or 'nessun nodo'}"

    # ------------------------------------------------------------ remediation

    def _remediate(self, doc: dict[str, Any], now: datetime) -> str:
        cycle = doc["cycle"]
        running = [n for n, st in doc["nodes"].items() if st.get("status") == "running"]
        if running:
            return self._check_running(doc, running[0], now)
        pending = [n for n in cycle["queue"] if n not in cycle["results"]]
        if not pending:
            return self._pause(doc, now, "giro completato")
        return self._start_node(doc, pending[0], now)

    def _check_running(self, doc: dict[str, Any], node: str, now: datetime) -> str:
        st = doc["nodes"][node]
        cycle = doc["cycle"]
        job = next(
            (j for j in self.kube.list_jobs(self._selector("remediate")) if j.name == st["job"]),
            None,
        )
        started = _time(st.get("started"))
        if job is None and started and now - started < JOB_GRACE:
            return f"remediation di {node} appena avviata"
        if job is not None:
            st["created"] = True
        elif not st.get("created"):
            # La creazione non è stata confermata (API in timeout) e il Job non c'è: il nodo
            # non è stato toccato, torna in coda invece di fermare tutto il cluster.
            name = st["job"]
            for key in ("status", "job", "started", "plan"):
                st.pop(key, None)
            self.again = True
            return f"{node}: Job {name} mai creato, si riprova"
        if job is not None and job.active:
            return f"remediation in corso su {node} ({job.name})"
        if job is not None and job.succeeded:
            st["status"] = "done"
            st["last_success"] = job.completion_time or _iso(now)
            # Solo un piano riuscito conta come "già applicato" (vedi same_plan).
            st["last_plan"] = st.get("plan")
            st.pop("failures", None)
            st.pop("retry_after", None)
            doc["groups"].pop(st.get("group"), None)
            cycle["results"][node] = {"outcome": OUTCOME_DONE, "at": _iso(now)}
            self.again = True  # il nodo dopo parte subito
            return f"{node}: remediation riuscita"
        why = "fallita" if job is not None else "scomparsa (Job cancellato?)"
        return self._quarantine(doc, node, why, now)

    def _quarantine(self, doc: dict[str, Any], node: str, why: str, now: datetime) -> str:
        """Il nodo fallito aspetta (sempre di più a ogni errore), gli altri proseguono."""
        st = doc["nodes"][node]
        cycle = doc["cycle"]
        st["status"] = "failed"
        st["failures"] = st.get("failures", 0) + 1
        until = now + backoff(st["failures"])
        st["retry_after"] = _iso(until)
        cycle["results"][node] = {"outcome": OUTCOME_FAILED, "detail": why, "at": _iso(now)}
        message = f"{node}: remediation {why} (job {st['job']}), in quarantena fino a {_iso(until)}"
        alerts.notify(self.cfg, self.kube, node, "SageQuarantine", message)
        stopped = self._group_breaker(doc, node, now)
        if stopped:
            message += f"; {stopped}"
        log.error("%s", message)
        self.again = True
        return message

    def _group_breaker(self, doc: dict[str, Any], node: str, now: datetime) -> str:
        """Ferma il gruppo per il resto del giro se fallisce il canary (il primo del gruppo
        nel giro), un master o almeno il 10% dei nodi del gruppo."""
        cycle = doc["cycle"]
        nodes = self.kube.list_nodes()
        groups, _ = assign_groups(nodes, self.cfg.groups)
        name = doc["nodes"][node].get("group") or (groups[node].name if node in groups else None)
        if name is None:
            return ""
        members = [n for n in cycle["queue"] if n in groups and groups[n].name == name]
        failed = [
            n for n in members if cycle["results"].get(n, {}).get("outcome") == OUTCOME_FAILED
        ]
        master = any(n.name == node and n.control_plane for n in nodes)
        canary = bool(members) and members[0] == node
        limit = max(1, math.ceil(len(members) * GROUP_FAILURE_RATIO))
        if not (master or canary or len(failed) >= limit):
            return ""
        gst = doc["groups"].setdefault(name, {})
        gst["stops"] = gst.get("stops", 0) + 1
        until = now + backoff(gst["stops"])
        gst["retry_after"] = _iso(until)
        gst["reason"] = f"{len(failed)} nodi falliti su {len(members)} (ultimo {node})"
        cycle.setdefault("stopped_groups", []).append(name)
        text = f"gruppo {name} fermo: {gst['reason']} fino a {_iso(until)}"
        alerts.notify(self.cfg, self.kube, node, "SageGroupStopped", text)
        return text

    def _skip(self, cycle: dict[str, Any], node: str, outcome: str, now: datetime) -> str:
        cycle["results"][node] = {"outcome": outcome, "at": _iso(now)}
        self.again = True
        return f"{node}: {outcome}"

    def _start_node(self, doc: dict[str, Any], name: str, now: datetime) -> str:
        cycle = doc["cycle"]
        report = self.kube.read_json(f"{self.release}-report") or {}
        plan_dict = (report.get("plans") or {}).get(name)
        nodes = {n.name: n for n in self.kube.list_nodes()}
        node = nodes.get(name)
        groups, _ = assign_groups(list(nodes.values()), self.cfg.groups)
        group = groups.get(name)
        if node is None or group is None:
            return self._skip(cycle, name, "saltato: non più nel cluster o senza gruppo", now)
        if plan_dict is None:
            return self._skip(cycle, name, "saltato: non raggiunto dal controllo", now)
        plan = act.Plan.from_dict(plan_dict)
        if plan.empty:
            return self._skip(cycle, name, OUTCOME_NOTHING, now)
        gst = doc["groups"].get(group.name, {})
        group_wait = _time(gst.get("retry_after"))
        if group.name in cycle.get("stopped_groups", []) or (group_wait and now < group_wait):
            why = f"saltato: gruppo {group.name} fermo fino a {gst.get('retry_after')}"
            return self._skip(cycle, name, why, now)
        retry = _time(doc["nodes"].get(name, {}).get("retry_after"))
        if retry and now < retry:
            why = f"saltato: in quarantena fino a {doc['nodes'][name]['retry_after']}"
            return self._skip(cycle, name, why, now)
        # Un cordon messo da una persona non si tocca; uno di SAGE (quarantena) sì.
        if not node.ready or (node.unschedulable and not node.cordoned_by_sage):
            return self._skip(cycle, name, "saltato: nodo non Ready o in cordon", now)
        if not self.dry_run:
            waiting = self._control_plane_unstable(doc, nodes.values(), node.control_plane, now)
            if waiting:
                # Il nodo resta in coda: si riprova al passo successivo.
                doc["waiting"] = waiting
                return f"{name}: in attesa, {waiting}"
        doc.pop("waiting", None)
        st = doc["nodes"].setdefault(name, {})
        if same_plan(plan_dict, st.get("last_plan")) and st.get("last_success"):
            # Dopo una remediation riuscita il controllo vede ancora le stesse advisory:
            # rifarla porterebbe a drain e riavvii continui. Serve un'occhiata a mano.
            return self._skip(
                cycle, name, "saltato: advisory ancora presenti dopo l'ultima remediation", now
            )
        if group.requires_fallback and not self.chain.fallback_available(group.name):
            return self._skip(cycle, name, "saltato: nessuna riserva LLM fuori dal gruppo", now)
        if self.dry_run:
            return self._skip(cycle, name, f"{OUTCOME_SIMULATED}: {plan_text(plan)}", now)
        template = self.kube.read_text(f"{self.release}-remediate-template", "job.yaml")
        if not template:
            return "modello del Job di remediation mancante: reinstalla SAGE"
        manifest = act.job_manifest(yaml.safe_load(template), self.release, name, plan, now)
        st.update(
            status="running",
            group=group.name,
            job=manifest["metadata"]["name"],
            started=_iso(now),
            plan=plan.to_dict(),
        )
        self.save(doc)  # prima lo stato, poi il Job: al riavvio si sa cosa cercare
        self.kube.create_job(manifest)
        st["created"] = True  # se create_job solleva, lo dice _check_running
        return f"remediation avviata su {name} ({st['job']})"

    def _control_plane_unstable(
        self, doc: dict[str, Any], nodes: Any, master: bool, now: datetime
    ) -> str | None:
        """Perché non è il momento di intervenire, o None se il control plane è stabile:
        /readyz sano (etcd compreso) e master tutti Ready, di fila da abbastanza tempo."""
        problems = self.kube.api_problems()
        problems += [f"master {n.name} non Ready" for n in nodes if n.control_plane and not n.ready]
        # "Di fila": se fra due verifiche passa troppo tempo (controllore fermo, cluster
        # spento e riacceso, un nodo appena finito) la stabilità va dimostrata da capo.
        last = _time(doc.get("stable_checked"))
        doc["stable_checked"] = _iso(now)
        if problems:
            doc["stable_since"] = None
            return "control plane instabile: " + ", ".join(problems[:3])
        gap = timedelta(seconds=max(2 * self.cfg.controller.poll_seconds, 120))
        since = _time(doc.get("stable_since"))
        if since is None or last is None or now - last > gap:
            doc["stable_since"] = _iso(now)
            since = now
        needed = self.cfg.controller.control_plane_stable_seconds * (3 if master else 1)
        stable = (now - since).total_seconds()
        if stable < needed:
            return f"control plane sano da {int(stable)} s su {needed}"
        return None

    def _pause(self, doc: dict[str, Any], now: datetime, why: str) -> str:
        doc.pop("waiting", None)
        cycle = doc["cycle"]
        cycle["phase"] = "pause"
        cycle["finished"] = _iso(now)
        until = now + timedelta(minutes=self.cfg.controller.pause_minutes)
        cycle["pause_until"] = _iso(until)
        return f"giro {cycle['id']}: {why}; prossimo giro alle {_iso(until)}"

    def steps(self, now: datetime, limit: int = 100) -> list[str]:
        """Passi di fila finché non c'è da aspettare: i nodi senza niente da fare passano
        tutti insieme invece che uno ogni poll_seconds."""
        messages = [self.step(now)]
        while self.again and len(messages) < limit:
            messages.append(self.step(now))
        return messages

    def _selector(self, role: str) -> str:
        return f"{act.ROLE_LABEL}={role},app.kubernetes.io/instance={self.release}"


def scan_manifest(template: dict[str, Any], release: str, now: datetime) -> dict[str, Any]:
    m = copy.deepcopy(template)
    meta = m.setdefault("metadata", {})
    meta["name"] = f"{release}-scan-{now.strftime('%y%m%d%H%M%S')}"
    meta.setdefault("labels", {})[act.ROLE_LABEL] = SCAN_ROLE
    pod = m["spec"]["template"]
    pod.setdefault("metadata", {}).setdefault("labels", {})[act.ROLE_LABEL] = SCAN_ROLE
    return m


def run(controller: Controller, now=None) -> None:  # pragma: no cover
    """Loop infinito: lease, i passi, attesa. Un errore non ferma il loop.

    Allo spegnimento (SIGTERM: aggiornamento, drain del nodo) finisce il passo in corso e
    libera il Lease, così la copia nuova parte subito invece di aspettare che scada.
    """
    now = now or (lambda: datetime.now().astimezone())
    holder = os.environ.get("HOSTNAME") or socket.gethostname()
    lease = f"{controller.release}-controller"
    poll = controller.cfg.controller.poll_seconds
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    log.info("controllore %s avviato (%s)", holder, "simulazione" if controller.dry_run else "VIVO")
    leader = False
    last = ""
    try:
        while not stop.is_set():
            HEARTBEAT.touch()
            try:
                got = controller.kube.acquire_lease(lease, holder, LEASE_SECONDS)
                if got is False and leader:
                    # Un altro controllore ha preso il lease: questa copia non deve più agire.
                    leader = False
                    log.error("lease perso: esco, Kubernetes mi riavvia")
                    raise SystemExit(1)
                leader = bool(got)
                if not leader:
                    if last != "lease":
                        log.info("un altro controllore è attivo: attendo")
                        last = "lease"
                else:
                    for message in controller.steps(now()):
                        if message != last:
                            log.info(message)
                            last = message
            except SystemExit:
                raise
            except Exception:  # noqa: BLE001 (API giù durante il riavvio di un master, ecc.)
                log.exception("passo non riuscito, riprovo")
            stop.wait(poll)
    finally:
        if leader:
            try:
                controller.kube.release_lease(lease, holder)
                log.info("controllore fermato: lease liberato")
            except Exception:  # noqa: BLE001
                log.exception("lease non liberato: il prossimo controllore aspetta che scada")
