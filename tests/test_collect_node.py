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


RPM_PROVIDES = """\
NetworkManager|NetworkManager
libnm-helper|libnm-helper.so.1()(64bit)
openssh-server|openssh-server
openssl-libs|libcrypto.so.3()(64bit)
"""
RPM_FILES = """\
NetworkManager|/usr/sbin/NetworkManager
NetworkManager|/usr/lib/systemd/system/NetworkManager.service
openssh-server|/usr/sbin/sshd
openssh-server|/usr/lib/systemd/system/sshd.service
bash|/bin/sh
cockpit-ws|/usr/lib/systemd/system/cockpit.socket
glibc|/lib64/libc.so.6
"""
RPM_REQUIRES = """\
NetworkManager|libnm-helper.so.1()(64bit)
NetworkManager|/bin/sh
NetworkManager|rpmlib(PayloadIsZstd)
openssh-server|libcrypto.so.3()(64bit)
bash|(none)
"""
UNITS_ACTIVE = """\
NetworkManager.service loaded active running Network Manager
sshd.service loaded active running OpenSSH server daemon
kubelet.service loaded active running kubelet
"""
UNITS_ENABLED = "getty@.service enabled enabled\nsshd.service enabled enabled\n"
UNIT_FILES = {
    "NetworkManager.service": (
        "/usr/lib/systemd/system/NetworkManager.service",
        "/usr/sbin/NetworkManager",
    ),
    "sshd.service": ("/usr/lib/systemd/system/sshd.service", "/usr/sbin/sshd"),
    "kubelet.service": ("/etc/systemd/system/kubelet.service", "/usr/local/bin/kubelet"),
}


def systemctl_show(units):
    """Come systemd: le proprietà del servizio (ExecStart) prima di quelle della unit."""
    blocks = []
    for unit in units:
        fragment, exe = UNIT_FILES.get(unit, ("", ""))
        exec_start = f"{{ path={exe} ; argv[]={exe} ; }}" if exe else ""
        blocks.append(f"ExecStart={exec_start}\nId={unit}\nFragmentPath={fragment}\n")
    return "\n".join(blocks)


def rpm_iterate(qf, rows):
    """rpm rifiuta un valore singolo dentro [] se non è scritto %{=TAG}."""
    if "[%{NAME}" in qf:
        return "error: array iterator used with different sized arrays\n"
    return rows


def fake_run(cmd):
    if cmd[:2] == ["rpm", "-qa"]:
        qf = cmd[3]
        if "PROVIDENAME" in qf:
            return rpm_iterate(qf, RPM_PROVIDES)
        if "FILENAMES" in qf:
            return rpm_iterate(qf, RPM_FILES)
        if "REQUIRENAME" in qf:
            return rpm_iterate(qf, RPM_REQUIRES)
        return "\n".join(
            ["NetworkManager", "libnm-helper", "openssh-server", "openssl-libs", "bash"]
            + ["cockpit-ws", "glibc", ""]
        )
    if cmd[:2] == ["systemctl", "list-units"]:
        return UNITS_ACTIVE
    if cmd[:2] == ["systemctl", "list-unit-files"]:
        return UNITS_ENABLED
    if cmd[:2] == ["systemctl", "show"]:
        return systemctl_show(
            [
                c
                for c in cmd[2:]
                if not c.startswith("-")
                and "=" not in c
                and c not in ("Id", "FragmentPath", "ExecStart")
            ]
        )
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
    if cmd[:2] == ["rpm", "-q"] and "SOURCERPM" in cmd[3]:
        sources = {"cockpit-ws": "cockpit-344-2.el9", "kernel-core": "kernel-5.14.0-500.el9"}
        return sources.get(cmd[-1], cmd[-1] + "-1.0-1.el9") + ".src.rpm\n"
    if cmd[:2] == ["rpm", "-q"] and "FILECAPS" in cmd[3]:
        if cmd[-1] == "NetworkManager":
            return "-rwsr-xr-x||/usr/sbin/nm-helper\n-rwxr-xr-x||/usr/sbin/NetworkManager\n"
        # Pacchetto senza tag FILECAPS: rpm scrive "(none)" (comportamento reale di rpm).
        return "-rwxr-xr-x|(none)|/usr/bin/whatever\n"
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
    mod._merged = [("/bin/", "/usr/bin/"), ("/lib64/", "/usr/lib64/")]  # come Rocky 9
    return mod


def run_collector(collector, monkeypatch, capsys, argv=()):
    monkeypatch.setattr(collector, "run", fake_run)
    monkeypatch.setattr(collector, "read_file", lambda p: KERNEL_FILES.get(p, ""))
    monkeypatch.setattr(
        collector,
        "running_state",
        lambda: ({"42": "/usr/sbin/NetworkManager"}, {"/usr/lib64/libc.so.6"}, 3),
    )
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    monkeypatch.setattr(collector.platform, "release", lambda: "5.14.0-500.el9.x86_64")
    monkeypatch.setattr(collector.platform, "machine", lambda: "x86_64")
    collector.main(list(argv))
    return json.loads(capsys.readouterr().out)


@pytest.fixture
def report(collector, monkeypatch, capsys):
    return run_collector(collector, monkeypatch, capsys)


def test_summary(report):
    assert report["schema_version"] == 4
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


def test_privileged_files_parsing(collector):
    out = (
        "-rwsr-xr-x|(none)|/usr/bin/sudo\n"
        "-rwxr-sr-x||/usr/bin/write\n"
        "-rwxr-xr-x|cap_net_raw=ep|/usr/bin/ping\n"
        "-rwxr-xr-x|(none)|/usr/bin/acl\n"
        "-rwxr-xr-x||/usr/lib64/libacl.so.1\n"
        "riga senza separatori\n"
    )
    assert collector.parse_privileged(out) == [
        "/usr/bin/ping",
        "/usr/bin/sudo",
        "/usr/bin/write",
    ]


def test_node_profile(report):
    profile = report["profile"]
    assert profile["units"] == ["NetworkManager.service", "kubelet.service", "sshd.service"]
    # Dipendenze risolte in memoria, anche tramite un file (/bin/sh); rpmlib() ignorato.
    assert profile["required"] == {
        "NetworkManager": "NetworkManager.service",
        "bash": "NetworkManager.service",
        "libnm-helper": "NetworkManager.service",
        "openssh-server": "sshd.service",
        "openssl-libs": "sshd.service",
    }
    assert profile["unit_files"] == 3 and profile["seeds"] == 2
    assert profile["container_processes"] == 3
    assert profile["process_scan_ok"] is True
    assert profile["extra"] == [] and profile["extra_missing"] == []
    assert report["packages"]["NetworkManager"]["context"]["needed_by"] == "NetworkManager.service"
    assert report["packages"]["cockpit-ws"]["context"]["needed_by"] is None


def test_extra_services_keep_packages_needed(collector, monkeypatch, capsys):
    report = run_collector(
        collector, monkeypatch, capsys, ["--extra", "cockpit-ws, backup.service,ghost"]
    )
    profile = report["profile"]
    ctx = report["packages"]["cockpit-ws"]["context"]
    assert ctx["needed_by"] == "cockpit-ws (aggiunto)"
    assert ctx["idle"] is False and ctx["removal_also_removes"] is None
    assert profile["extra"] == ["backup.service", "cockpit-ws", "ghost"]
    assert profile["extra_missing"] == ["backup.service", "ghost"]  # inesistenti: segnalati


def test_container_processes_are_ignored(collector, tmp_path):
    def proc(pid, exe, maps, cgroup):
        d = tmp_path / pid
        d.mkdir()
        (d / "exe").symlink_to(exe)
        (d / "maps").write_text(f"7f00-7f01 r-xp 00000000 fd:00 1 {maps}\n")
        (d / "cgroup").write_text(cgroup)

    proc("1", "/usr/lib/systemd/systemd", "/usr/lib64/libc.so.6", "0::/init.scope\n")
    # Servizio con PrivateTmp: namespace suo, ma file del nodo. Va contato.
    proc(
        "10", "/usr/sbin/chronyd", "/usr/lib64/libcrypto.so.3", "0::/system.slice/chronyd.service\n"
    )
    proc(
        "20",
        "/usr/bin/python3",
        "/usr/lib64/libssl.so.3",
        "0::/kubepods.slice/kubepods-burstable.slice/kubepods-pod1.slice/cri-containerd-a.scope\n",
    )
    exes, mapped, skipped = collector.running_state(str(tmp_path))
    assert sorted(exes.values()) == ["/usr/lib/systemd/systemd", "/usr/sbin/chronyd"]
    assert "/usr/lib64/libssl.so.3" not in mapped  # libreria del container, non del nodo
    assert "/usr/lib64/libcrypto.so.3" in mapped
    assert skipped == 1


def test_parse_args(collector):
    assert collector.parse_args(["--extra", "a, b,,c"]) == ["a", "b", "c"]
    assert collector.parse_args([]) == []


def test_source_package(report, collector):
    assert report["packages"]["cockpit-ws"]["context"]["source"] == "cockpit"
    assert report["packages"]["kernel-core"]["context"]["source"] == "kernel"
    assert report["packages"]["NetworkManager"]["context"]["source"] == "NetworkManager"
    assert collector.source_name("glibc-2.34-100.el9_4.2.src.rpm\n") == "glibc"
    assert collector.source_name("(none)\n") is None
    assert collector.source_name("") is None


def test_merged_paths(collector, tmp_path):
    """rpm scrive /lib64/libc.so.6, il kernel /usr/lib64/libc.so.6: è lo stesso file."""
    (tmp_path / "usr" / "lib64").mkdir(parents=True)
    (tmp_path / "lib64").symlink_to("usr/lib64")
    (tmp_path / "etc").mkdir()
    assert collector.merged_prefixes(str(tmp_path)) == [("/lib64/", "/usr/lib64/")]
    assert collector.canonical("/lib64/libc.so.6") == "/usr/lib64/libc.so.6"
    assert collector.canonical("/bin/sh") == "/usr/bin/sh"
    assert collector.canonical("/usr/lib64/libc.so.6") == "/usr/lib64/libc.so.6"


def test_library_listed_under_lib64_is_loaded(collector, monkeypatch):
    monkeypatch.setattr(
        collector,
        "run",
        lambda cmd: "/lib64/libc.so.6\n/usr/sbin/ldconfig\n" if cmd[:2] == ["rpm", "-ql"] else "",
    )
    ctx = collector.package_context("glibc", {}, {"/usr/lib64/libc.so.6"}, {})
    assert ctx["libraries_loaded"] == ["/usr/lib64/libc.so.6"]
    assert ctx["idle"] is False


def test_unreliable_process_scan_never_idle(collector, monkeypatch, capsys):
    monkeypatch.setattr(collector, "run", fake_run)
    monkeypatch.setattr(collector, "read_file", lambda p: KERNEL_FILES.get(p, ""))
    monkeypatch.setattr(collector, "running_state", lambda: ({}, set(), 0))
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    collector.main([])
    report = json.loads(capsys.readouterr().out)
    assert report["profile"]["process_scan_ok"] is False
    assert not any(p["context"]["idle"] for p in report["packages"].values())


def test_unit_paths_order_and_templates(collector, monkeypatch):
    out = (
        "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; }\n"
        "Id=sshd.service\nFragmentPath=/usr/lib/systemd/system/sshd.service\n\n"
        "Id=chronyd.timer\nFragmentPath=\n\n"
        "ExecStart={ path=/bin/sh ; argv[]=/bin/sh -c x ; }\nId=other.service\n"
    )
    monkeypatch.setattr(collector, "run", lambda cmd: out)
    monkeypatch.setattr(
        collector.os.path, "exists", lambda p: p == "/usr/lib/systemd/system/getty@.service"
    )
    paths = collector.unit_paths({"sshd.service", "chronyd.timer", "getty@tty1.service"})
    assert paths["sshd.service"] == ["/usr/lib/systemd/system/sshd.service", "/usr/sbin/sshd"]
    assert paths["chronyd.timer"] == []
    assert paths["getty@tty1.service"] == ["/usr/lib/systemd/system/getty@.service"]
    assert "other.service" not in paths  # non chiesta
