"""remediate.yml eseguito davvero in locale, con un `dnf` finto e senza API Kubernetes.

Copre il rollback (anche quando dnf fallisce a metà) e la modalità leggera. Serve
ansible-playbook con la collection kubernetes.core: altrimenti il test viene saltato.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ANSIBLE_DIR = Path(__file__).parents[1] / "ansible"

FAKE_DNF = """#!/bin/bash
echo "$*" >> "$FAKE_STATE/calls"
case "$*" in
  "-q history info last")
    id=41; [ -f "$FAKE_STATE/after" ] && id=42
    echo "Transaction ID : $id" ;;
  "-y upgrade --advisory"*)
    if [ -n "$FAKE_DEPSOLVE_FAIL" ]; then echo "Error: Problem: cannot install both"; exit 1; fi
    touch "$FAKE_STATE/after"
    if [ -n "$FAKE_FAIL_UPDATE" ]; then echo "Error: scriptlet failed"; exit 1; fi
    echo "Complete!" ;;
  "-y remove --noautoremove"*) touch "$FAKE_STATE/after"; echo "Removed" ;;
  "needs-restarting -r") exit 0 ;;
  "-y history undo 42") touch "$FAKE_STATE/undone" ;;
  *) echo "chiamata inattesa: $*"; exit 3 ;;
esac
"""


def _collection_available() -> bool:
    if not shutil.which("ansible-playbook"):
        return False
    out = subprocess.run(
        ["ansible-galaxy", "collection", "list", "kubernetes.core"],
        capture_output=True,
        text=True,
    )
    return "kubernetes.core" in out.stdout


pytestmark = pytest.mark.skipif(
    not _collection_available(), reason="ansible-playbook o kubernetes.core non disponibili"
)


def run_playbook(tmp_path, fail_update=False, depsolve_fail=False, **overrides):
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    dnf = bin_dir / "dnf"
    dnf.write_text(FAKE_DNF)
    dnf.chmod(0o755)
    denylist = tmp_path / "sage-denylist.conf"
    variables = {
        "sage_node_name": "w1",
        "sage_kube": False,
        "sage_update_advisories": ["RLSA-2026:1"],
        "sage_denylist_modules": ["algif_aead"],
        "sage_denylist_file": str(denylist),
        "ansible_become": False,
        **overrides,
    }
    vars_file = tmp_path / "vars.json"
    vars_file.write_text(json.dumps(variables))
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_STATE=str(state))
    if fail_update:
        env["FAKE_FAIL_UPDATE"] = "1"
    if depsolve_fail:
        env["FAKE_DEPSOLVE_FAIL"] = "1"
    proc = subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "remediate.yml",
            "-e",
            f"@{vars_file}",
        ],
        cwd=ANSIBLE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    calls = (state / "calls").read_text().splitlines() if (state / "calls").exists() else []
    content = denylist.read_text() if denylist.exists() else ""
    return proc, calls, content, (state / "undone").exists()


def test_success_applies_advisories_and_blocks_module(tmp_path):
    proc, calls, denylist, undone = run_playbook(tmp_path)
    assert proc.returncode == 0, proc.stdout
    assert "-y upgrade --advisory=RLSA-2026:1" in calls
    assert "needs-restarting -r" in calls
    assert denylist.splitlines() == ["install algif_aead /bin/false", "blacklist algif_aead"]
    assert not undone


def test_failure_mid_transaction_rolls_back(tmp_path):
    proc, calls, denylist, undone = run_playbook(tmp_path, fail_update=True)
    assert proc.returncode != 0
    assert undone and calls[-1] == "-y history undo 42"
    assert "rollback eseguito" in proc.stdout
    assert denylist == ""


def test_depsolve_failure_changes_nothing(tmp_path):
    """dnf si ferma prima di installare (dipendenze): nessun rollback, nodo in servizio."""
    proc, calls, denylist, undone = run_playbook(tmp_path, depsolve_fail=True)
    assert proc.returncode != 0
    assert not undone and not any("history undo" in c for c in calls)
    assert "senza modificare il nodo" in proc.stdout
    assert denylist == ""


def test_light_mode_never_checks_reboot(tmp_path):
    proc, calls, denylist, _ = run_playbook(tmp_path, sage_light=True, sage_update_advisories=[])
    assert proc.returncode == 0, proc.stdout
    assert "needs-restarting -r" not in calls
    assert not any("upgrade" in c for c in calls)
    assert "install algif_aead /bin/false" in denylist


def test_removal(tmp_path):
    proc, calls, _, _ = run_playbook(
        tmp_path,
        sage_update_advisories=[],
        sage_remove_packages=["cockpit-ws"],
        sage_denylist_modules=[],
    )
    assert proc.returncode == 0, proc.stdout
    assert "-y remove --noautoremove cockpit-ws" in calls


# ------------------------------------------------------------ apt e zypper

FAKE_APT = """#!/bin/bash
echo "apt-get $*" >> "$FAKE_STATE/calls"
case "$*" in
  "-y install --only-upgrade"*)
    if [ -n "$FAKE_LOCK_ONCE" ] && [ ! -f "$FAKE_STATE/locked" ]; then
      touch "$FAKE_STATE/locked"
      echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42"; exit 100
    fi
    if [ -n "$FAKE_DEPSOLVE_FAIL" ]; then echo "E: Unable to correct problems"; exit 100; fi
    touch "$FAKE_STATE/after"
    if [ -n "$FAKE_FAIL_UPDATE" ]; then echo "E: dpkg returned an error"; exit 100; fi
    echo "Setting up openssl" ;;
  "-y remove"*) echo "Removing" ;;
  "-y install --allow-downgrades"*) touch "$FAKE_STATE/undone" ;;
  *) echo "chiamata inattesa: $*"; exit 3 ;;
esac
"""

FAKE_ZYPPER = """#!/bin/bash
echo "zypper $*" >> "$FAKE_STATE/calls"
case "$*" in
  "-n install -t patch"*)
    if [ -n "$FAKE_DEPSOLVE_FAIL" ]; then echo "Problem: nothing provides foo"; exit 4; fi
    touch "$FAKE_STATE/after"
    if [ -n "$FAKE_FAIL_UPDATE" ]; then echo "Installation aborted"; exit 8; fi
    echo "done" ;;
  "needs-rebooting") exit 0 ;;
  "-n install --oldpackage"*) touch "$FAKE_STATE/undone" ;;
  *) echo "chiamata inattesa: $*"; exit 3 ;;
esac
"""

# Istantanea delle versioni: cambia solo dopo un aggiornamento fallito a metà (così il
# caso riuscito non chiede un riavvio, che in locale non si può fare).
FAKE_SNAPSHOT = """#!/bin/bash
echo "libc=2.36-9"
if [ -f "$FAKE_STATE/after" ] && [ -n "$FAKE_FAIL_UPDATE" ]; then
  echo "openssl=3.0.15-1"
else
  echo "openssl=3.0.11-1"
fi
"""


def run_other(tmp_path, pm, fail_update=False, depsolve_fail=False, lock_once=False, **overrides):
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    fakes = (
        {"apt-get": FAKE_APT, "dpkg-query": FAKE_SNAPSHOT}
        if pm == "apt"
        else {"zypper": FAKE_ZYPPER, "rpm": FAKE_SNAPSHOT}
    )
    for name, script in fakes.items():
        (bin_dir / name).write_text(script)
        (bin_dir / name).chmod(0o755)
    variables = {
        "sage_node_name": "w1",
        "sage_kube": False,
        "sage_package_manager": pm,
        "sage_update_advisories": ["SUSE-2026-1"] if pm == "zypper" else ["DSA-1"],
        "sage_update_packages": ["openssl", "libssl3"],
        "sage_denylist_modules": [],
        "sage_denylist_file": str(tmp_path / "denylist.conf"),
        "ansible_become": False,
        **overrides,
    }
    vars_file = tmp_path / "vars.json"
    vars_file.write_text(json.dumps(variables))
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_STATE=str(state))
    if fail_update:
        env["FAKE_FAIL_UPDATE"] = "1"
    if depsolve_fail:
        env["FAKE_DEPSOLVE_FAIL"] = "1"
    if lock_once:
        env["FAKE_LOCK_ONCE"] = "1"
    proc = subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            "remediate.yml",
            "-e",
            f"@{vars_file}",
        ],
        cwd=ANSIBLE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    calls = (state / "calls").read_text().splitlines() if (state / "calls").exists() else []
    return proc, calls, (state / "undone").exists()


def test_apt_updates_packages(tmp_path):
    proc, calls, undone = run_other(tmp_path, "apt")
    assert proc.returncode == 0, proc.stdout
    assert calls == [
        "apt-get -y install --only-upgrade -o Dpkg::Options::=--force-confdef "
        "-o Dpkg::Options::=--force-confold openssl libssl3"
    ]
    assert not undone


def test_apt_failure_mid_update_restores_versions(tmp_path):
    proc, calls, undone = run_other(tmp_path, "apt", fail_update=True)
    assert proc.returncode != 0
    assert undone and calls[-1] == "apt-get -y install --allow-downgrades openssl=3.0.11-1"
    assert "rollback eseguito" in proc.stdout


def test_apt_depsolve_failure_changes_nothing(tmp_path):
    proc, calls, undone = run_other(tmp_path, "apt", depsolve_fail=True)
    assert proc.returncode != 0
    assert not undone and "senza modificare il nodo" in proc.stdout


def test_apt_removal(tmp_path):
    proc, calls, _ = run_other(
        tmp_path,
        "apt",
        sage_update_advisories=[],
        sage_update_packages=[],
        sage_remove_packages=["telnet"],
    )
    assert proc.returncode == 0, proc.stdout
    assert calls == ["apt-get -y remove telnet"]


def test_zypper_installs_patches(tmp_path):
    proc, calls, undone = run_other(tmp_path, "zypper")
    assert proc.returncode == 0, proc.stdout
    assert calls == ["zypper -n install -t patch SUSE-2026-1", "zypper needs-rebooting"]
    assert not undone


def test_zypper_failure_mid_update_restores_versions(tmp_path):
    proc, calls, undone = run_other(tmp_path, "zypper", fail_update=True)
    assert proc.returncode != 0
    assert undone and calls[-1] == "zypper -n install --oldpackage openssl=3.0.11-1"


def test_unknown_package_manager_is_refused(tmp_path):
    proc, calls, _ = run_other(tmp_path, "apt", sage_package_manager="pacman")
    assert proc.returncode != 0 and calls == []
    assert "senza modificare il nodo" in proc.stdout


def test_apt_lock_held_is_recovered_without_rollback(tmp_path):
    """unattended-upgrades tiene il lock: sage recover-action sceglie wait_lock (regola
    fissa, nessun LLM) e il secondo tentativo riesce, senza rollback."""
    config_path = ANSIBLE_DIR.parent / "examples" / "config.example.yaml"
    proc, calls, undone = run_other(
        tmp_path, "apt", lock_once=True, sage_config_path=str(config_path)
    )
    assert proc.returncode == 0, proc.stdout
    assert len([c for c in calls if "--only-upgrade" in c]) == 2
    assert not undone
