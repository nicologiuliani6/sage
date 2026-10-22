"""Dati sintetici condivisi: nodi, report del collector, configurazioni."""

import os
import shutil
from pathlib import Path

import pytest

from sage import config

# OPA locale per i test d'integrazione: SAGE_OPA_BIN o `opa` nel PATH.
OPA = os.environ.get("SAGE_OPA_BIN") or shutil.which("opa")
needs_opa = pytest.mark.skipif(not OPA, reason="binario opa non disponibile")
if OPA:
    os.environ["SAGE_OPA_BIN"] = OPA
os.environ.setdefault("SAGE_POLICY_DIR", str(Path(__file__).parents[1] / "policy"))


def base_config(**overrides):
    raw = {
        "ssh": {"user": "admin", "key_path": "/chiave"},
        "llm": {
            "endpoints": [{"name": "primario", "base_url": "http://llm/v1", "model": "m"}],
        },
        "groups": [
            {
                "name": "worker",
                "selector": "sage.io/group=worker",
                "order": 1,
                "kernel": "auto",
                "canary": "w1",
                "allow_remove": True,
                "allow_mitigate": True,
            },
            {
                "name": "master",
                "selector": "node-role.kubernetes.io/control-plane",
                "order": 2,
                "kernel": "auto",
            },
        ],
        "policy": {
            "protected_packages": ["glibc", "systemd"],
            "idle_scans_required": 2,
            "idle_days_required": 0,
        },
    }
    raw.update(overrides)
    return config.parse(raw)


def kernel_facts(loaded=(), available=("algif_aead",), blocked=()):
    modules = {"sctp": {"dir": "net/sctp", "state": "available"}}
    for m in available:
        modules[m] = {"dir": "crypto", "state": "available"}
    for m in loaded:
        modules[m] = {"dir": "crypto", "state": "loaded"}
    return {
        "release": "5.14.0-500.el9.x86_64",
        "modules": modules,
        "install_blocked": list(blocked),
        "blacklisted": [],
        "sysctl": {"kernel.modules_disabled": 0},
    }


def package(
    advisories,
    idle=False,
    running=(),
    listening=(),
    units=None,
    removal=None,
    privileged=(),
    installed=("0:1.0-1.el9",),
):
    return {
        "advisories": advisories,
        "context": {
            "installed": list(installed),
            "has_libraries": False,
            "libraries_loaded": [],
            "has_binaries": True,
            "binaries_running": list(running),
            "listening": list(listening),
            "units": units or {},
            "privileged_files": list(privileged),
            "required_by": [],
            "idle": idle,
            "removal_also_removes": removal,
        },
    }


def advisory(adv_id, cves, severity="Important"):
    return {
        "id": adv_id,
        "severity": severity,
        "fixed_version": "1.1-1.el9",
        "cves": cves,
        "issued": "2026-01-01",
    }


def report(packages, kernel=None):
    return {
        "schema_version": 2,
        "node": {
            "hostname": "h",
            "role": "worker",
            "os": {"name": "Rocky Linux", "version": "9.4"},
            "arch": "x86_64",
        },
        "kernel": kernel or kernel_facts(),
        "packages": packages,
    }


@pytest.fixture
def cfg():
    return base_config()
