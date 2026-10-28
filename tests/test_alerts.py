"""Test del modulo alerts: notify, webhook e gestione errori (ADR-0019)."""

from unittest.mock import MagicMock

import pytest

from sage import config
from sage.alerts import notify
from tests.conftest import base_config


class FakeKube:
    """KubeApi finta che registra le chiamate."""

    namespace = "sage"

    def __init__(self):
        self.calls = []  # (node, reason, message)

    def post_event(self, node, reason, message):
        self.calls.append((node, reason, message))


def test_notify_without_webhook_only_post_event():
    cfg = base_config()
    kube = FakeKube()
    notify(cfg, kube, "w1", "SageQuarantine", "messaggio")
    assert kube.calls == [("w1", "SageQuarantine", "messaggio")]


def test_notify_with_webhook_calls_post():
    cfg = base_config(alerts={"webhook_url": "https://hooks.example/x"})
    kube = FakeKube()
    post = MagicMock()
    notify(cfg, kube, "w1", "SageQuarantine", "messaggio", post=post)
    assert kube.calls == [("w1", "SageQuarantine", "messaggio")]
    post.assert_called_once_with(
        "https://hooks.example/x",
        {"source": "sage", "node": "w1", "reason": "SageQuarantine", "message": "messaggio"},
    )


def test_notify_post_error_does_not_raise():
    cfg = base_config(alerts={"webhook_url": "https://hooks.example/x"})
    kube = FakeKube()

    def failing_post(url, body):
        raise RuntimeError("connessione fallita")

    notify(cfg, kube, "w1", "SageQuarantine", "messaggio", post=failing_post)
    assert kube.calls == [("w1", "SageQuarantine", "messaggio")]


def test_notify_invalid_webhook_url_raises():
    with pytest.raises(config.ConfigError):
        base_config(alerts={"webhook_url": "ftp://x"})
