import os
import time

import pytest
from kubernetes import client

from sage.kube import Kube

# Se la variabile d'ambiente SAGE_KUBECONFIG manca, salta il test
if "SAGE_KUBECONFIG" not in os.environ:
    pytest.skip("SAGE_KUBECONFIG non impostata", allow_module_level=True)

os.environ["KUBECONFIG"] = os.environ["SAGE_KUBECONFIG"]


# Fixture di modulo che crea un namespace univoco e lo cancella alla fine
@pytest.fixture(scope="module")
def kube():
    # Genera un nome univoco per il namespace
    import secrets

    namespace_name = f"sage-live-{secrets.token_hex(4)}"
    kube_instance = Kube(namespace=namespace_name)  # carica il kubeconfig

    # Crea il namespace
    v1 = client.CoreV1Api()
    namespace = client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace_name))
    v1.create_namespace(namespace)

    try:
        yield kube_instance
    finally:
        # Cancella il namespace alla fine del test
        try:
            v1.delete_namespace(name=namespace_name, body=client.V1DeleteOptions())
        except Exception:
            pass  # Ignora errori durante la cancellazione


def test_api_problems_healthy(kube):
    """Verifica che l'API non abbia problemi"""
    for _ in range(30):  # Prova per 30 secondi
        problems = kube.api_problems()
        if problems == []:
            return
        time.sleep(1)
    pytest.fail(f"API problems found: {problems}")


def test_list_nodes(kube):
    """Verifica che ci siano almeno un nodo e uno con control_plane=True"""
    nodes = kube.list_nodes()
    assert len(nodes) >= 1
    control_plane_nodes = [node for node in nodes if node.control_plane]
    assert len(control_plane_nodes) >= 1


def test_json_roundtrip(kube):
    """Verifica il roundtrip JSON"""
    data = {"a": 1, "b": [1, 2]}
    kube.write_json("sage-live-state", data)
    read_data = kube.read_json("sage-live-state")
    assert read_data == data

    # Verifica che leggere un nome inesistente restituisca None
    assert kube.read_json("non-existent") is None


def test_flags(kube):
    """Verifica le funzioni di flag"""
    kube.set_flag("sage-live-flag")
    assert kube.pop_flag("sage-live-flag") is True
    assert kube.pop_flag("sage-live-flag") is False


def test_lease(kube):
    """Verifica le funzioni di lease"""
    # Acquisisci il lease con holder 'a'
    assert kube.acquire_lease("sage-live-lease", "a", 30) is True

    # Prova ad acquisire con un altro holder, dovrebbe fallire
    assert kube.acquire_lease("sage-live-lease", "b", 30) is False

    # Rilascia il lease
    kube.release_lease("sage-live-lease", "a")
    time.sleep(2)  # il rilascio porta la durata a 1 s: scade subito dopo

    # Ora l'acquisizione con holder 'b' dovrebbe funzionare
    assert kube.acquire_lease("sage-live-lease", "b", 30) is True

    # Leggi il lease e verifica che non sia None
    lease_data = kube.read_lease("sage-live-lease")
    assert lease_data is not None


def test_jobs(kube):
    """Verifica la creazione e lista dei job"""
    # Crea un manifest minimale di Job
    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "sage-live-job", "labels": {"sage.io/role": "live"}},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "busybox", "image": "busybox:1.36", "command": ["true"]}
                    ],
                    "restartPolicy": "Never",
                }
            },
            "backoffLimit": 0,
            # Sospeso: il Job esiste ma nessun pod parte, niente immagini da scaricare.
            "suspend": True,
        },
    }

    # Crea il job
    kube.create_job(job_manifest)

    # Verifica che il job sia stato creato
    for _ in range(30):  # Prova per 30 secondi
        jobs = kube.list_jobs("sage.io/role=live")
        if len(jobs) >= 1 and jobs[0].name == "sage-live-job":
            return
        time.sleep(1)

    pytest.fail("Job non trovato dopo 30 secondi")
