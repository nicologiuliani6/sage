"""Test del collector con output di dnf/rpm sintetici (nessun dato reale)."""

import importlib.util
from pathlib import Path

import pytest

COLLECTOR = Path(__file__).parents[1] / "ansible" / "files" / "collect_node.py"

UPDATEINFO_LIST = """\
RLSA-2025:0001  Moderate/Sec.  NetworkManager-1:1.48.10-5.el9_5.x86_64
RLSA-2026:0002  Moderate/Sec.  NetworkManager-1:1.54.3-5.el9_8.x86_64
RLSA-2026:0003  Critical/Sec.  cockpit-ws-344-2.el9_7.x86_64
RLSA-2026:0004  Critical/Sec.  libexample-4.23.5-10.el9_8.x86_64
not an advisory line
"""

UPDATEINFO_INFO = """\
===============================================================================
  Critical: libexample security update
===============================================================================
  Update ID: RLSA-2026:0004
       Type: security
    Updated: 2026-05-02 10:11:12
       Bugs: 111 - something
           : 222 - title mentioning CVE-2099-0001
       CVEs: CVE-2026-1111
           : CVE-2026-2222
Description: text mentioning CVE-2099-9999
           : more text
   Severity: Critical
===============================================================================
  Critical: cockpit security update
===============================================================================
  Update ID: RLSA-2026:0003
    Updated: 2026-02-01 00:00:00
       CVEs: CVE-2026-3333
   Severity: Critical
"""

FILES = {
    "libexample": "/usr/lib64/libexample.so.2\n",
    "cockpit-ws": (
        "/usr/libexec/cockpit-ws\n"
        "/usr/lib/systemd/system/cockpit.socket\n"
        "/usr/lib/systemd/system/cockpit.service\n"
    ),
    "NetworkManager": (
        "/usr/sbin/NetworkManager\n/usr/lib/systemd/system/NetworkManager.service\n"
    ),
}


def fake_run(cmd):
    if cmd[:4] == ["dnf", "-q", "updateinfo", "list"]:
        return UPDATEINFO_LIST
    if cmd[:4] == ["dnf", "-q", "updateinfo", "info"]:
        return UPDATEINFO_INFO
    if cmd[:2] == ["rpm", "-q"] and "--whatrequires" in cmd:
        if cmd[-1] == "libexample":
            return "dependent-pkg-2.9.4-6.el9_4.x86_64\n"
        return f"no package requires {cmd[-1]}\n"
    if cmd[:2] == ["rpm", "-q"]:
        return "0:1.0-1.el9\n"
    if cmd[:2] == ["rpm", "-ql"]:
        return FILES[cmd[-1]]
    if cmd[0] == "ss":
        return 'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("NetworkManager",pid=42,fd=3))\n'
    if cmd[0] == "systemctl":
        return "".join(("active" if "Network" in unit else "inactive") + "\n" for unit in cmd[2:])
    return ""


@pytest.fixture
def report(monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("collect_node", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "run", fake_run)
    monkeypatch.setattr(mod, "running_state", lambda: ({"42": "/usr/sbin/NetworkManager"}, set()))
    mod.main()
    import json

    return json.loads(capsys.readouterr().out)


def test_summary(report):
    assert report["summary"] == {"advisories": 4, "packages": 3, "cves": 3}


def test_cves_only_from_cve_field(report):
    adv = report["packages"]["libexample"]["advisories"][0]
    assert adv["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert adv["issued"] == "2026-05-02 10:11:12"


def test_running_service_context(report):
    ctx = report["packages"]["NetworkManager"]["context"]
    assert ctx["binaries_running"] == ["/usr/sbin/NetworkManager"]
    assert ctx["listening"] == ["udp 68"]
    assert ctx["units"] == {"NetworkManager.service": "active"}


def test_idle_service_context(report):
    ctx = report["packages"]["cockpit-ws"]["context"]
    assert ctx["binaries_running"] == []
    assert ctx["listening"] == []
    assert set(ctx["units"].values()) == {"inactive"}
    assert ctx["has_libraries"] is False  # cockpit.socket non è una libreria


def test_library_dependency(report):
    ctx = report["packages"]["libexample"]["context"]
    assert ctx["has_libraries"] is True
    assert ctx["libraries_loaded"] == []
    assert ctx["required_by"] == ["dependent-pkg"]
