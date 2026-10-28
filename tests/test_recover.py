"""Scelta del recupero dopo un aggiornamento fallito (ADR-0019)."""

import io

import pytest

from sage import cli, config, recover
from tests.conftest import base_config


def cfg(*endpoints):
    return base_config(llm={"endpoints": list(endpoints)}).llm


INTERNAL = {"name": "interno", "base_url": "http://ollama/v1", "model": "m", "node_data": True}
EXTERNAL = {"name": "esterno", "base_url": "https://api.example/v1", "model": "m"}


def answer(content):
    calls = []

    def post(url, body, headers, timeout):
        calls.append((url, body))
        return {"choices": [{"message": {"content": content}}]}

    return post, calls


@pytest.mark.parametrize(
    ("pm", "log", "action"),
    [
        ("apt", "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by 42", "wait_lock"),
        ("apt", "E: Unable to acquire the dpkg frontend lock", "wait_lock"),
        (
            "apt",
            "E: dpkg was interrupted, you must manually run 'dpkg --configure -a'",
            "dpkg_configure",
        ),
        ("apt", "The following packages have unmet dependencies:", "fix_broken"),
        ("dnf", "Waiting for process with pid 1234 to finish.", "wait_lock"),
        ("zypper", "System management is locked by the application with pid 99", "wait_lock"),
        ("dnf", "[Errno 28] No space left on device", "clean_cache"),
        ("zypper", "Curl error (6): Couldn't resolve host name", "retry"),
        ("apt", "W: Failed to fetch http://deb.debian.org/  Temporary failure resolving", "retry"),
    ],
)
def test_rules(pm, log, action):
    assert recover.classify(pm, log) == (action, "regola")


def test_apt_rule_not_allowed_for_dnf():
    assert recover.classify("dnf", "dpkg was interrupted")[0] == "none"


def test_unknown_pm():
    assert recover.classify("pacman", "Could not get lock") == ("none", "gestore sconosciuto")


def test_unknown_error_without_internal_llm_never_calls_out():
    post, calls = answer('{"action": "retry"}')
    assert recover.classify("apt", "boh", cfg(EXTERNAL), post) == ("none", "nessuna regola")
    assert calls == []  # il log è un dato del nodo: mai a un servizio esterno


def test_internal_llm_chooses_from_catalog():
    post, calls = answer('Ecco: {"action": "clean_cache", "reason": "x"}')
    log = "§" * 10000
    assert recover.classify("apt", log, cfg(EXTERNAL, INTERNAL), post) == ("clean_cache", "interno")
    ((url, body),) = calls
    assert url == "http://ollama/v1/chat/completions"
    user = body["messages"][1]["content"]
    assert "Allowed actions: retry, wait_lock" in user and user.count("§") == 4000


@pytest.mark.parametrize(
    "content", ['{"action": "dpkg_configure"}', "non JSON", '{"action": "rm -rf"}']
)
def test_invalid_llm_answer_is_none(content):
    post, _ = answer(content)
    assert recover.classify("dnf", "boh", cfg(INTERNAL), post)[0] == "none"


def test_node_data_must_be_bool():
    with pytest.raises(config.ConfigError, match="node_data"):
        cfg({**INTERNAL, "node_data": "sì"})


def test_cli_prints_only_the_action(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("E: Could not get lock /var/lib/dpkg/lock"))
    code = cli.main(["recover-action", "--config", "examples/config.example.yaml", "--pm", "apt"])
    out = capsys.readouterr()
    assert code == 0 and out.out == "wait_lock\n"
    assert "recupero: wait_lock (regola)" in out.err
