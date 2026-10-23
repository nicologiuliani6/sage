"""Il Lease del controllore: chi si spegne lo libera e il successivo lo prende subito."""

import copy
from datetime import UTC, datetime, timedelta

from kubernetes import client
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


class FakeApiClient:
    def __init__(self, body, status=200, error=None):
        self.body, self.status, self.error = body, status, error

    def __call__(self):
        return self

    def call_api(self, path, method, **kw):
        if self.error:
            raise self.error
        assert path == "/readyz" and ("verbose", "true") in kw["query_params"]
        return self.body, self.status, {}


def test_api_problems_reads_readyz():
    k = Kube.__new__(Kube)
    healthy = "[+]ping ok\n[+]etcd ok\n[+]etcd-readiness ok\nreadyz check passed\n"
    k._client = type("C", (), {"ApiClient": FakeApiClient(healthy)})
    assert k.api_problems() == []
    sick = "[+]ping ok\n[-]etcd failed: reason withheld\n[-]etcd-readiness failed\n"
    k._client = type("C", (), {"ApiClient": FakeApiClient(sick, 500)})
    assert k.api_problems() == ["etcd", "etcd-readiness"]
    # come il client vero: un 500 diventa un'eccezione con il corpo
    error = ApiException(status=500)
    error.body = sick.encode()
    k._client = type("C", (), {"ApiClient": FakeApiClient("", error=error)})
    assert k.api_problems() == ["etcd", "etcd-readiness"]
    k._client = type("C", (), {"ApiClient": FakeApiClient("", error=TimeoutError())})
    assert k.api_problems() == ["API non raggiungibile (TimeoutError)"]
