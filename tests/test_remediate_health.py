"""Condizione "pod di sistema del nodo pronti" di remediate.yml, valutata con dati finti."""

from pathlib import Path

import jinja2
import yaml

PLAYBOOK = Path(__file__).parents[1] / "ansible" / "remediate.yml"


def _task(name):
    def walk(items):
        for item in items or []:
            if item.get("name") == name:
                return item
            for key in ("tasks", "block", "rescue", "always"):
                found = walk(item.get(key))
                if found:
                    return found
        return None

    return walk(yaml.safe_load(PLAYBOOK.read_text()))


def _flatten(value):
    out = []
    for item in value:
        out.extend(item if isinstance(item, list) else [item])
    return out


def healthy(pods):
    """Valuta `until` del task come farebbe Ansible (jinja2 più il filtro flatten)."""
    env = jinja2.Environment()
    env.filters["flatten"] = _flatten
    expr = _task("Pod di sistema del nodo pronti (DaemonSet)")["until"]
    return env.compile_expression(expr)(sage_node_pods={"resources": pods})


def pod(kind, phase="Running", ready=(True,)):
    return {
        "metadata": {"ownerReferences": [{"kind": kind}]},
        "status": {"phase": phase, "containerStatuses": [{"ready": r} for r in ready]},
    }


def test_all_daemonset_pods_ready():
    assert healthy([pod("DaemonSet"), pod("DaemonSet", ready=(True, True))])


def test_crashing_kube_proxy_is_unhealthy():
    assert not healthy([pod("DaemonSet"), pod("DaemonSet", ready=(False,))])


def test_pod_stuck_in_init_is_unhealthy():
    # calico install-cni in errore: il pod resta Pending, senza containerStatuses
    stuck = {
        "metadata": {"ownerReferences": [{"kind": "DaemonSet"}]},
        "status": {"phase": "Pending"},
    }
    assert not healthy([pod("DaemonSet"), stuck])


def test_only_daemonsets_count():
    # un pod di un Deployment o senza proprietario non ferma la remediation
    other = pod("ReplicaSet", ready=(False,))
    bare = {"metadata": {}, "status": {"phase": "Pending"}}
    assert healthy([pod("DaemonSet"), other, bare])
