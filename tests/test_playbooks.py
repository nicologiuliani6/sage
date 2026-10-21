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
  "-y upgrade-minimal"*)
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


def run_playbook(tmp_path, fail_update=False, **overrides):
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
    assert "-y upgrade-minimal --advisory=RLSA-2026:1" in calls
    assert "needs-restarting -r" in calls
    assert denylist.splitlines() == ["install algif_aead /bin/false", "blacklist algif_aead"]
    assert not undone


def test_failure_mid_transaction_rolls_back(tmp_path):
    proc, calls, denylist, undone = run_playbook(tmp_path, fail_update=True)
    assert proc.returncode != 0
    assert undone and calls[-1] == "-y history undo 42"
    assert "rollback eseguito" in proc.stdout
    assert denylist == ""


def test_light_mode_never_checks_reboot(tmp_path):
    proc, calls, denylist, _ = run_playbook(tmp_path, sage_light=True, sage_update_advisories=[])
    assert proc.returncode == 0, proc.stdout
    assert "needs-restarting -r" not in calls
    assert not any("upgrade-minimal" in c for c in calls)
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
