"""Percorsi di playbook e policy: dall'ambiente nell'immagine, dalla repo in sviluppo."""

from __future__ import annotations

import os
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def ansible_dir() -> Path:
    return Path(os.environ.get("SAGE_ANSIBLE_DIR", _REPO / "ansible"))


def policy_dir() -> Path:
    return Path(os.environ.get("SAGE_POLICY_DIR", _REPO / "policy"))


def opa_bin() -> str:
    return os.environ.get("SAGE_OPA_BIN", "opa")


def workdir() -> Path:
    return Path(os.environ.get("SAGE_WORKDIR", "/tmp/sage"))
