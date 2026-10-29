"""Il Lease del controllore: chi si spegne lo libera e il successivo lo prende subito."""

import copy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from kubernetes import client
from kubernetes.client import rest
from kubernetes.client.exceptions import ApiException

from sage.kube import Kube


class LeaseApi:
    """CoordinationV1Api finta, con un solo Lease."""

    def __init__(self):
        self.lease = None

    def read_namespaced_lease(self, name, namespace):
        if self.lease is None:
            raise ApiException(status=404)
        return copy.deepcopy(self.lease)

    def create_namespaced_lease(self, namespace, body):
        self.lease = copy.deepcopy(body)

    def replace_namespaced_lease(self, name, namespace, body):
        self.lease = copy.deepcopy(body)


def kube(api):
    k = Kube.__new__(Kube)
    k.namespace = "sage"
    k._client = client
    k._lease_api = lambda: api
    return k


def test_release_lets_the_next_controller_in_at_once():
    api = LeaseApi()
    k = kube(api)
    assert k.acquire_lease("sage-controller", "vecchio", 120)
    assert not k.acquire_lease("sage-controller", "nuovo", 120)  # ancora valido
    renewed = api.lease.spec.renew_time
    k.release_lease("sage-controller", "vecchio")
    assert api.lease.spec.renew_time == renewed  # la dashboard vede ancora l'ultimo rinnovo
    api.lease.spec.renew_time = datetime.now(UTC) - timedelta(seconds=2)
    assert k.acquire_lease("sage-controller", "nuovo", 120)
    assert api.lease.spec.holder_identity == "nuovo"
    assert api.lease.spec.lease_duration_seconds == 120


def test_release_does_not_touch_someone_elses_lease():
    api = LeaseApi()
    k = kube(api)
    k.acquire_lease("sage-controller", "nuovo", 120)
    k.release_lease("sage-controller", "vecchio")
    assert api.lease.spec.lease_duration_seconds == 120
    k.release_lease("assente", "vecchio")  # niente errori se il Lease non c'è


def real_client(body=b"", status=200, error=None):
    """Il vero ApiClient di `kubernetes`, con finto solo il livello HTTP: se la firma del
    client cambia (è successo con la versione 37) il test se ne accorge."""
    api = client.ApiClient(client.Configuration(host="https://api.example.invalid"))
    calls = []

    def request(method, url, **kw):
        calls.append((method, url))
        if error:
            raise error
        return rest.RESTResponse(SimpleNamespace(status=status, reason="", data=body))

    api.rest_client.request = request
    return SimpleNamespace(ApiClient=lambda: api), calls


def test_api_problems_reads_readyz():
    k = Kube.__new__(Kube)
    healthy = b"[+]ping ok\n[+]etcd ok\n[+]etcd-readiness ok\nreadyz check passed\n"
    k._client, calls = real_client(healthy)
    assert k.api_problems() == []
    assert calls == [("GET", "https://api.example.invalid/readyz?verbose=true")]
    sick = b"[+]ping ok\n[-]etcd failed: reason withheld\n[-]etcd-readiness failed\n"
    k._client, _ = real_client(sick, 500)
    assert k.api_problems() == ["etcd", "etcd-readiness"]
    k._client, _ = real_client(b"", 503)
    assert k.api_problems() == ["readyz HTTP 503"]
    k._client, _ = real_client(error=TimeoutError())
    assert k.api_problems() == ["API non raggiungibile (TimeoutError)"]


def test_api_problems_programming_error_is_not_api_down():
    """Un errore di SAGE (TypeError) non deve diventare "API giù" per sempre."""
    k = Kube.__new__(Kube)
    k._client, _ = real_client(error=TypeError("firma cambiata"))
    with pytest.raises(TypeError):
        k.api_problems()


def test_post_event_builds_a_real_event_and_never_raises():
    """Con la vera libreria kubernetes: la classe dell'evento esiste (in 37 è CoreV1Event)
    e un errore dell'API non arriva al controllore."""
    k = Kube.__new__(Kube)
    k.namespace = "sage"
    sent = []
    k.core = SimpleNamespace(create_namespaced_event=lambda ns, ev: sent.append((ns, ev)))
    k.post_event("node7", "SageQuarantine", "x" * 2000)
    ((ns, event),) = sent
    # un Node non ha namespace: l'evento va in "default", non nel namespace di SAGE
    assert ns == "default" and event.metadata.namespace == "default"
    assert event.involved_object.name == "node7" and len(event.message) == 1024

    def broken(ns, ev):
        raise RuntimeError("API giù")

    k.core = SimpleNamespace(create_namespaced_event=broken)
    k.post_event("node7", "SageQuarantine", "x")  # nessuna eccezione


class FakeConfigMaps:
    """API delle ConfigMap in memoria, con gli oggetti veri del client."""

    def __init__(self):
        self.cms = {}

    def read_namespaced_config_map(self, name, ns):
        if name not in self.cms:
            raise ApiException(status=404)
        return self.cms[name]

    def create_namespaced_config_map(self, ns, body):
        self.cms[body.metadata.name] = body

    def replace_namespaced_config_map(self, name, ns, body):
        self.cms[name] = body

    def delete_namespaced_config_map(self, name, ns):
        del self.cms[name]


def big_report(n):
    import random

    rnd = random.Random(n)  # dati che il gzip non comprime: tanti nodi diversi
    return {"nodes": {f"n{i}": [rnd.random() for _ in range(40)] for i in range(n)}}


def test_large_json_split_across_configmaps_and_read_back():
    import sage.kube as kube_mod

    k = Kube.__new__(Kube)
    k.namespace, k._client, k.core = "sage", client, FakeConfigMaps()
    small = {"a": 1}
    k.write_json("sage-report", small)
    assert k.read_json("sage-report") == small and list(k.core.cms) == ["sage-report"]
    big = big_report(3000)
    k.write_json("sage-report", big)
    parts = sorted(k.core.cms)
    assert len(parts) > 1 and all(
        len(c.binary_data["data.json.gz"]) <= kube_mod.PART_BYTES for c in k.core.cms.values()
    )
    assert k.read_json("sage-report") == big
    k.write_json("sage-report", small)  # di nuovo piccolo: le parti avanzate spariscono
    assert list(k.core.cms) == ["sage-report"] and k.read_json("sage-report") == small
    k.write_json("sage-report", big)
    del k.core.cms["sage-report-part-1"]  # scrittura interrotta: niente miscugli
    assert k.read_json("sage-report") is None
