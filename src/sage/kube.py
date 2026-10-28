"""Accesso minimo all'API Kubernetes: nodi, ConfigMap di stato, Job."""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

log = logging.getLogger(__name__)

STATE_KEY = "data.json.gz"


# Messa da remediate.yml sui nodi che SAGE mette in cordon (ADR-0019).
CORDON_ANNOTATION = "sage.io/cordoned"


@dataclass(frozen=True)
class Node:
    name: str
    labels: dict[str, str]
    internal_ip: str | None
    ready: bool
    unschedulable: bool
    annotations: dict[str, str] = field(default_factory=dict)
    kernel: str = ""
    os_image: str = ""

    @property
    def control_plane(self) -> bool:
        return "node-role.kubernetes.io/control-plane" in self.labels

    @property
    def cordoned_by_sage(self) -> bool:
        """In cordon per mano di SAGE (remediate.yml lo segna): SAGE lo può riprendere."""
        return self.unschedulable and self.annotations.get(CORDON_ANNOTATION) == "true"


@dataclass(frozen=True)
class JobInfo:
    name: str
    node: str | None
    active: bool
    succeeded: bool
    failed: bool
    completion_time: str | None


class KubeApi(Protocol):
    namespace: str

    def list_nodes(self) -> list[Node]: ...
    def read_json(self, name: str) -> dict[str, Any] | None: ...
    def write_json(self, name: str, data: dict[str, Any]) -> None: ...
    def read_text(self, name: str, key: str) -> str | None: ...
    def list_jobs(self, label_selector: str) -> list[JobInfo]: ...
    def create_job(self, manifest: dict[str, Any]) -> None: ...
    def pop_flag(self, name: str) -> bool: ...
    def set_flag(self, name: str) -> None: ...
    def acquire_lease(self, name: str, holder: str, seconds: int) -> bool: ...
    def release_lease(self, name: str, holder: str) -> None: ...
    def read_lease(self, name: str) -> dict[str, Any] | None: ...
    def read_deployment(self, name: str) -> dict[str, Any] | None: ...
    def api_problems(self) -> list[str]: ...
    def post_event(self, node: str, reason: str, message: str) -> None: ...
    def job_message(self, job: str) -> str | None: ...


def encode(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    return base64.b64encode(gzip.compress(raw)).decode()


def decode(blob: str) -> dict[str, Any]:
    return json.loads(gzip.decompress(base64.b64decode(blob)))


class KubeUnavailable(RuntimeError):
    pass


class Kube:
    """Implementazione reale con il client ufficiale `kubernetes`."""

    def __init__(self, namespace: str | None = None):
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException as exc:
                raise KubeUnavailable(
                    "nessun accesso all'API Kubernetes (né dal pod né da kubeconfig)"
                ) from exc
        self.core = client.CoreV1Api()
        self.batch = client.BatchV1Api()
        self._client = client
        self.namespace = namespace or os.environ.get("SAGE_NAMESPACE") or _incluster_namespace()

    def list_nodes(self) -> list[Node]:
        nodes = []
        for n in self.core.list_node().items:
            ip = next(
                (a.address for a in (n.status.addresses or []) if a.type == "InternalIP"), None
            )
            ready = any(
                c.type == "Ready" and c.status == "True" for c in (n.status.conditions or [])
            )
            nodes.append(
                Node(
                    name=n.metadata.name,
                    labels=dict(n.metadata.labels or {}),
                    internal_ip=ip,
                    ready=ready,
                    unschedulable=bool(n.spec.unschedulable),
                    annotations=dict(n.metadata.annotations or {}),
                    kernel=getattr(n.status.node_info, "kernel_version", "") or "",
                    os_image=getattr(n.status.node_info, "os_image", "") or "",
                )
            )
        return sorted(nodes, key=lambda x: x.name)

    def _read_cm(self, name: str):
        from kubernetes.client.exceptions import ApiException

        try:
            return self.core.read_namespaced_config_map(name, self.namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def read_json(self, name: str) -> dict[str, Any] | None:
        cm = self._read_cm(name)
        if cm is None or not cm.binary_data or STATE_KEY not in cm.binary_data:
            return None
        return decode(cm.binary_data[STATE_KEY])

    def write_json(self, name: str, data: dict[str, Any]) -> None:
        body = self._client.V1ConfigMap(
            metadata=self._client.V1ObjectMeta(
                name=name, labels={"app.kubernetes.io/name": "sage"}
            ),
            binary_data={STATE_KEY: encode(data)},
        )
        if self._read_cm(name) is None:
            self.core.create_namespaced_config_map(self.namespace, body)
        else:
            self.core.replace_namespaced_config_map(name, self.namespace, body)

    def read_text(self, name: str, key: str) -> str | None:
        cm = self._read_cm(name)
        if cm is None or not cm.data:
            return None
        return cm.data.get(key)

    def list_jobs(self, label_selector: str) -> list[JobInfo]:
        jobs = []
        for j in self.batch.list_namespaced_job(
            self.namespace, label_selector=label_selector
        ).items:
            status = j.status
            conditions = {c.type: c.status for c in (status.conditions or [])}
            jobs.append(
                JobInfo(
                    name=j.metadata.name,
                    node=(j.metadata.annotations or {}).get("sage.io/node-name"),
                    active=bool(status.active),
                    succeeded=conditions.get("Complete") == "True",
                    failed=conditions.get("Failed") == "True",
                    completion_time=(
                        status.completion_time.isoformat() if status.completion_time else None
                    ),
                )
            )
        return jobs

    def create_job(self, manifest: dict[str, Any]) -> None:
        self.batch.create_namespaced_job(self.namespace, manifest)

    def pop_flag(self, name: str) -> bool:
        """Esiste la ConfigMap `name`? Se sì la cancella (segnale a uso singolo)."""
        if self._read_cm(name) is None:
            return False
        self.core.delete_namespaced_config_map(name, self.namespace)
        return True

    def set_flag(self, name: str) -> None:
        """Crea la ConfigMap `name` come segnale per il controllore (se non c'è già)."""
        from kubernetes.client.exceptions import ApiException

        body = self._client.V1ConfigMap(
            metadata=self._client.V1ObjectMeta(name=name, labels={"app.kubernetes.io/name": "sage"})
        )
        try:
            self.core.create_namespaced_config_map(self.namespace, body)
        except ApiException as exc:
            if exc.status != 409:
                raise

    def api_problems(self) -> list[str]:
        """Controlli di /readyz dell'apiserver che non passano (etcd compreso); [] se è
        sano. /readyz è leggibile da tutti (ClusterRole system:public-info-viewer)."""
        api = self._client.ApiClient()
        request = api.param_serialize(
            method="GET",
            resource_path="/readyz",
            query_params=[("verbose", "true")],
            auth_settings=["BearerToken"],
        )
        try:
            # Con un controllo fallito l'apiserver risponde 500: call_api non solleva,
            # lo stato e il corpo con l'elenco dei controlli arrivano comunque.
            response = api.call_api(*request, _request_timeout=10)
            response.read()
        except (TypeError, AttributeError):
            raise  # errore di SAGE (firma del client cambiata), non un'API giù
        except Exception as exc:  # noqa: BLE001 (connessione, timeout)
            return [f"API non raggiungibile ({type(exc).__name__})"]
        status = response.status
        data = response.data.decode(errors="replace") if response.data else ""
        failed = [
            line[3:].split(" ", 1)[0] for line in str(data).splitlines() if line.startswith("[-]")
        ]
        if status != 200 and not failed:
            failed = [f"readyz HTTP {status}"]
        return failed

    def post_event(self, node: str, reason: str, message: str) -> None:
        """Evento Kubernetes di tipo Warning sul nodo (ADR-0019). Un avviso perso non deve
        mai fermare il controllore: qualsiasi errore finisce solo nel log."""
        try:
            from kubernetes import client

            # kubernetes >= 37: CoreV1Event; prima: V1Event.
            event_cls = getattr(client, "CoreV1Event", None) or client.V1Event
            now = datetime.now(UTC)
            event = event_cls(
                metadata=client.V1ObjectMeta(generate_name="sage-"),
                involved_object=client.V1ObjectReference(api_version="v1", kind="Node", name=node),
                reason=reason,
                message=message[:1024],
                type="Warning",
                source=client.V1EventSource(component="sage"),
                first_timestamp=now,
                last_timestamp=now,
                count=1,
            )
            self.core.create_namespaced_event(self.namespace, event)
        except Exception:  # noqa: BLE001
            log.warning("evento per %s (%s) non creato", node, reason, exc_info=True)

    def list_pods(self, label_selector: str) -> list[dict[str, Any]]:
        """Pod di SAGE nel namespace (dashboard, pagina Log), dal più recente."""
        pods = []
        for p in self.core.list_namespaced_pod(self.namespace, label_selector=label_selector).items:
            labels = p.metadata.labels or {}
            started = p.status.start_time
            pods.append(
                {
                    "name": p.metadata.name,
                    "phase": p.status.phase,
                    "role": labels.get("sage.io/role") or labels.get("app.kubernetes.io/component"),
                    "node": p.spec.node_name,
                    "started": started.isoformat() if started else None,
                }
            )
        return sorted(pods, key=lambda x: x["started"] or "", reverse=True)

    def pod_log(self, name: str, tail_lines: int) -> str:
        return self.core.read_namespaced_pod_log(
            name, self.namespace, tail_lines=tail_lines, _request_timeout=10
        )

    def job_message(self, job: str) -> str | None:
        """Messaggio di terminazione del pod di un Job (`sage remediate` ci scrive il motivo
        di un fallimento); None se non c'è o non si legge."""
        try:
            pods = self.core.list_namespaced_pod(self.namespace, label_selector=f"job-name={job}")
        except Exception:  # noqa: BLE001 (il motivo è un di più: senza si prosegue)
            return None
        for p in pods.items:
            for cs in p.status.container_statuses or []:
                done = cs.state.terminated if cs.state else None
                if done and done.message:
                    return done.message.strip()[:1000]
        return None

    def _lease_api(self):
        return self._client.CoordinationV1Api()

    def acquire_lease(self, name: str, holder: str, seconds: int) -> bool:
        """Prende o rinnova il Lease `name`. False se lo tiene un altro e non è scaduto.

        Gli aggiornamenti usano il resourceVersion letto: se due copie ci provano insieme,
        una riceve un conflitto (409) e perde.
        """
        from kubernetes.client.exceptions import ApiException

        api = self._lease_api()
        now = datetime.now(UTC)
        try:
            lease = api.read_namespaced_lease(name, self.namespace)
        except ApiException as exc:
            if exc.status != 404:
                raise
            body = self._client.V1Lease(
                metadata=self._client.V1ObjectMeta(
                    name=name, labels={"app.kubernetes.io/name": "sage"}
                ),
                spec=self._client.V1LeaseSpec(
                    holder_identity=holder,
                    lease_duration_seconds=seconds,
                    acquire_time=now,
                    renew_time=now,
                    lease_transitions=0,
                ),
            )
            try:
                api.create_namespaced_lease(self.namespace, body)
                return True
            except ApiException as exc2:
                if exc2.status == 409:
                    return False
                raise
        spec = lease.spec
        expired = spec.renew_time is None or now - spec.renew_time > timedelta(
            seconds=spec.lease_duration_seconds or seconds
        )
        if spec.holder_identity != holder and not expired:
            return False
        if spec.holder_identity != holder:
            spec.holder_identity = holder
            spec.acquire_time = now
            spec.lease_transitions = (spec.lease_transitions or 0) + 1
        spec.renew_time = now
        spec.lease_duration_seconds = seconds
        try:
            api.replace_namespaced_lease(name, self.namespace, lease)
        except ApiException as exc:
            if exc.status == 409:
                return False
            raise
        return True

    def release_lease(self, name: str, holder: str) -> None:
        """Lascia il Lease a chi viene dopo, se lo tiene ancora `holder`.

        Non lo cancella: la durata scende a 1 secondo, quindi scade subito ma resta l'ora
        dell'ultimo rinnovo (la dashboard la usa per dire se il controllore è vivo).
        """
        from kubernetes.client.exceptions import ApiException

        api = self._lease_api()
        try:
            lease = api.read_namespaced_lease(name, self.namespace)
            if lease.spec.holder_identity != holder:
                return
            lease.spec.lease_duration_seconds = 1
            api.replace_namespaced_lease(name, self.namespace, lease)
        except ApiException as exc:
            if exc.status not in (404, 409):
                raise

    def read_lease(self, name: str) -> dict[str, Any] | None:
        from kubernetes.client.exceptions import ApiException

        try:
            lease = self._lease_api().read_namespaced_lease(name, self.namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        spec = lease.spec
        return {
            "holder": spec.holder_identity,
            "renew_time": spec.renew_time.isoformat() if spec.renew_time else None,
            "duration": spec.lease_duration_seconds,
        }

    def read_deployment(self, name: str) -> dict[str, Any] | None:
        """Copie volute e pronte del Deployment `name` (0 volute = controllore spento)."""
        from kubernetes.client.exceptions import ApiException

        try:
            dep = self._client.AppsV1Api().read_namespaced_deployment(name, self.namespace)
        except ApiException as exc:
            if exc.status == 404:
                return None
            raise
        return {
            "replicas": dep.spec.replicas,
            "ready": (dep.status.ready_replicas or 0) if dep.status else 0,
        }


def _incluster_namespace() -> str:
    path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "default"
