from pathlib import Path

from sage import __version__
from sage.cli import main

EXAMPLE = Path(__file__).parents[1] / "examples" / "config.example.yaml"


def test_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_check_config_ok(capsys):
    assert main(["check-config", "--config", str(EXAMPLE)]) == 0
    assert "configurazione valida" in capsys.readouterr().out


def test_check_config_invalid(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("groups: []\n")
    assert main(["check-config", "--config", str(bad)]) == 1
    assert "ssh" in capsys.readouterr().err


def test_scan_outside_cluster_fails_clearly(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "nessuno"))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["scan", "--config", str(EXAMPLE), "--dry-run"]) == 1
    assert "API Kubernetes" in capsys.readouterr().err
