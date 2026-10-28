"""Notifica degli avvisi di SAGE: eventi Kubernetes e webhook HTTP (ADR-0019)."""

from __future__ import annotations

import json
import logging
import urllib.request

from sage.config import Config
from sage.kube import KubeApi

log = logging.getLogger(__name__)


def notify(
    cfg: Config,
    kube: KubeApi,
    node: str,
    reason: str,
    message: str,
    post=None,
) -> None:
    """Invia un avviso via evento Kubernetes e, se configurato, via webhook HTTP.

    Il parametro `post` (per i test) se fornito sostituisce l'invio HTTP:
    post(url, body_dict).
    """
    try:
        kube.post_event(node, reason, message)
    except Exception:  # noqa: BLE001 (un avviso perso non ferma il controllore)
        log.warning("evento per %s (%s) non creato", node, reason, exc_info=True)
    if cfg.alerts.webhook_url and post is not None:
        body = {
            "source": "sage",
            "node": node,
            "reason": reason,
            "message": message,
        }
        try:
            post(cfg.alerts.webhook_url, body)
        except Exception:  # noqa: BLE001
            log.warning("webhook per %s (%s): errore", node, reason)
    elif cfg.alerts.webhook_url:
        body = json.dumps(
            {
                "source": "sage",
                "node": node,
                "reason": reason,
                "message": message,
            }
        ).encode()
        req = urllib.request.Request(
            cfg.alerts.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception:  # noqa: BLE001
            log.warning("webhook per %s (%s): errore", node, reason)
