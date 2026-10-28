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
    assert ns == "sage" and event.involved_object.name == "node7" and len(event.message) == 1024

    def broken(ns, ev):
        raise RuntimeError("API giù")

    k.core = SimpleNamespace(create_namespaced_event=broken)
    k.post_event("node7", "SageQuarantine", "x")  # nessuna eccezione
