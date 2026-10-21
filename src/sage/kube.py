"""Accesso minimo all'API Kubernetes: nodi, ConfigMap di stato, Job."""

from __future__ import annotations

import base64
import gzip
import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

STATE_KEY = "data.json.gz"


@dataclass(frozen=True)
class Node:
    name: str
    labels: dict[str, str]
    internal_ip: str | None
    ready: bool
    unschedulable: bool

    @property
    def control_plane(self) -> bool:
        return "node-role.kubernetes.io/control-plane" in self.labels


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


def _incluster_namespace() -> str:
    path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "default"
