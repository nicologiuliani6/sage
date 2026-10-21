"""Test del collector con output di dnf/rpm sintetici (nessun dato reale)."""

import importlib.util
import json
from pathlib import Path

import pytest

COLLECTOR = Path(__file__).parents[1] / "ansible" / "files" / "collect_node.py"

UPDATEINFO_LIST = """\
RLSA-2025:0001  Moderate/Sec.  NetworkManager-1:1.48.10-5.el9_5.x86_64
RLSA-2026:0002  Moderate/Sec.  NetworkManager-1:1.54.3-5.el9_8.x86_64
RLSA-2026:0003  Critical/Sec.  cockpit-ws-344-2.el9_7.x86_64
RLSA-2026:0004  Critical/Sec.  libexample-4.23.5-10.el9_8.x86_64
RLSA-2026:0005  Important/Sec. kernel-core-5.14.0-600.el9.x86_64
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
    "kernel-core": "/lib/modules/5.14.0-500.el9.x86_64/vmlinuz\n",
}

REMOVE_COCKPIT = """\
Dependencies resolved.
================================================================================
 Package          Architecture   Version           Repository         Size
================================================================================
Removing:
 cockpit-ws       x86_64         344-2.el9         @appstream         1.2 M

Transaction Summary
================================================================================
Remove  1 Package

Freed space: 1.2 M
Operation aborted.
"""

MODPROBE_CONFIG = """\
blacklist floppy
install algif_aead /bin/false
install usb-storage /bin/true
alias net-pf-38 af_alg
"""

KERNEL_FILES = {
    "/lib/modules/5.14.0-500.el9.x86_64/modules.dep": (
        "kernel/net/sctp/sctp.ko.xz: kernel/lib/libcrc32c.ko.xz\n"
        "kernel/crypto/algif_aead.ko.xz:\n"
        "kernel/drivers/usb/storage/usb-storage.ko.xz:\n"
    ),
    "/lib/modules/5.14.0-500.el9.x86_64/modules.builtin": "kernel/fs/ext4/ext4.ko\n",
    "/proc/modules": "sctp 450560 0 - Live 0x0\nnf_tables 300000 1 - Live 0x0\n",
    "/proc/sys/kernel/modules_disabled": "0\n",
    "/proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
    "/proc/sys/user/max_user_namespaces": "63000\n",
    "/etc/os-release": 'NAME="Rocky Linux"\nVERSION_ID="9.4"\n',
}


def fake_run(cmd):
    if cmd[:4] == ["dnf", "-q", "updateinfo", "list"]:
        return UPDATEINFO_LIST
    if cmd[:4] == ["dnf", "-q", "updateinfo", "info"]:
        return UPDATEINFO_INFO
    if cmd[:2] == ["dnf", "remove"]:
        return REMOVE_COCKPIT if cmd[-1] == "cockpit-ws" else "Error: no match\n"
    if cmd[:2] == ["rpm", "-q"] and "--whatrequires" in cmd:
        if cmd[-1] == "libexample":
            return "dependent-pkg-2.9.4-6.el9_4.x86_64\n"
        return f"no package requires {cmd[-1]}\n"
    if cmd[:2] == ["rpm", "-q"] and "FILECAPS" in cmd[3]:
        if cmd[-1] == "NetworkManager":
            return "-rwsr-xr-x||/usr/sbin/nm-helper\n-rwxr-xr-x||/usr/sbin/NetworkManager\n"
        return "-rwxr-xr-x||/usr/bin/whatever\n"
    if cmd[:2] == ["rpm", "-q"]:
        return "0:1.0-1.el9\n"
    if cmd[:2] == ["rpm", "-ql"]:
        return FILES[cmd[-1]]
    if cmd[0] == "ss":
        return 'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("NetworkManager",pid=42,fd=3))\n'
    if cmd[:2] == ["systemctl", "is-active"]:
        return "".join(("active" if "Network" in u else "inactive") + "\n" for u in cmd[2:])
    if cmd[:2] == ["systemctl", "is-enabled"]:
        return "".join(("enabled" if "Network" in u else "disabled") + "\n" for u in cmd[2:])
    if cmd[:2] == ["modprobe", "--showconfig"]:
        return MODPROBE_CONFIG
    return ""


@pytest.fixture
def collector():
    spec = importlib.util.spec_from_file_location("collect_node", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def report(collector, monkeypatch, capsys):
    monkeypatch.setattr(collector, "run", fake_run)
    monkeypatch.setattr(collector, "read_file", lambda p: KERNEL_FILES.get(p, ""))
    monkeypatch.setattr(
        collector, "running_state", lambda: ({"42": "/usr/sbin/NetworkManager"}, set())
    )
    monkeypatch.setattr(collector.platform, "release", lambda: "5.14.0-500.el9.x86_64")
    monkeypatch.setattr(collector.platform, "machine", lambda: "x86_64")
    collector.main()
    return json.loads(capsys.readouterr().out)


def test_summary(report):
    assert report["schema_version"] == 2
    assert report["summary"] == {"advisories": 5, "packages": 4, "cves": 3}
    assert report["node"]["os"] == {"name": "Rocky Linux", "version": "9.4"}


def test_cves_only_from_cve_field(report):
    adv = report["packages"]["libexample"]["advisories"][0]
    assert adv["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert adv["issued"] == "2026-05-02 10:11:12"


def test_running_service_context(report):
    ctx = report["packages"]["NetworkManager"]["context"]
    assert ctx["binaries_running"] == ["/usr/sbin/NetworkManager"]
    assert ctx["listening"] == ["udp 68"]
    assert ctx["units"] == {"NetworkManager.service": {"active": "active", "enabled": "enabled"}}
    assert ctx["privileged_files"] == ["/usr/sbin/nm-helper"]
    assert ctx["idle"] is False
    assert ctx["removal_also_removes"] is None  # non inattivo: niente simulazione


def test_idle_service_is_removal_candidate(report):
    ctx = report["packages"]["cockpit-ws"]["context"]
    assert ctx["idle"] is True
    assert ctx["has_libraries"] is False  # cockpit.socket non è una libreria
    assert ctx["removal_also_removes"] == []


def test_failed_removal_simulation_is_none(report):
    ctx = report["packages"]["libexample"]["context"]
    assert ctx["idle"] is True
    assert ctx["removal_also_removes"] is None
    assert ctx["required_by"] == ["dependent-pkg"]


def test_kernel_never_simulated_for_removal(report):
    assert report["packages"]["kernel-core"]["context"]["removal_also_removes"] is None


def test_kernel_facts(report):
    k = report["kernel"]
    assert k["release"] == "5.14.0-500.el9.x86_64"
    assert k["modules"]["sctp"] == {"dir": "net/sctp", "state": "loaded"}
    assert k["modules"]["algif_aead"] == {"dir": "crypto", "state": "available"}
    assert k["modules"]["ext4"] == {"dir": "fs/ext4", "state": "builtin"}
    assert k["modules"]["usb_storage"]["dir"] == "drivers/usb/storage"
    assert k["modules"]["nf_tables"] == {"dir": None, "state": "loaded"}
    assert k["install_blocked"] == ["algif_aead", "usb_storage"]
    assert k["blacklisted"] == ["floppy"]
    assert k["sysctl"]["kernel.modules_disabled"] == 0


@pytest.mark.parametrize(
    "output, expected",
    [
        (REMOVE_COCKPIT, []),
        (
            REMOVE_COCKPIT.replace(
                "\nTransaction Summary",
                "Removing dependent packages:\n cockpit   noarch  344  @appstream  1 M\n"
                "\nTransaction Summary",
            ),
            ["cockpit"],
        ),
        ("Error: Problem: The operation would result in removing protected packages", None),
        ("No match for argument: cockpit-ws", None),
    ],
)
def test_parse_remove_simulation(collector, output, expected):
    assert collector.parse_remove_simulation(output, "cockpit-ws") == expected
