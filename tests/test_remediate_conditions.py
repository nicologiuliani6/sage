"""Condizioni Jinja di remediate.yml provate con dati finti (senza Ansible né cluster)."""

from pathlib import Path

import pytest

ANSIBLE_DIR = Path(__file__).parents[1] / "ansible"


def _until(task_name):
    import yaml

    play = yaml.safe_load((ANSIBLE_DIR / "remediate.yml").read_text())[0]

    def walk(tasks):
        for t in tasks:
            yield t
            for key in ("block", "rescue", "always"):
                yield from walk(t.get(key, []))

    task = next(t for t in walk(play["tasks"]) if t.get("name") == task_name)
    return task["until"], task["register"]


@pytest.mark.parametrize(
    "task", ["Attendi che il nodo sia Ready", "Master - attendi kube-apiserver pronto"]
)
def test_wait_survives_api_down(task):
    """Durante il riavvio di un master l'API non risponde: la condizione deve dire
    "non ancora" (e Ansible riprova), non andare in errore."""
    from jinja2 import Environment

    expr, var = _until(task)
    check = Environment().from_string("{{ " + expr + " }}")
    ready = {"status": {"conditions": [{"type": "Ready", "status": "True"}]}}
    assert check.render({var: {"failed": True, "msg": "connection refused"}}) == "False"
    assert check.render({var: {"resources": []}}) == "False"
    assert check.render({var: {"resources": [ready]}}) == "True"
