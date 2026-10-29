"""Test del collector con output di dnf/rpm sintetici (nessun dato reale)."""

import fnmatch
import importlib.util
import json
import os
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
        return FILES.get(cmd[-1], "")
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
    monkeypatch.setattr(collector.shutil, "which", lambda n: "/usr/bin/dnf" if n == "dnf" else None)
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
    assert report["schema_version"] == 5
    assert report["summary"] == {"advisories": 5, "packages": 4, "cves": 3}
    assert report["node"]["os"]["name"] == "Rocky Linux"
    assert report["node"]["os"]["version"] == "9.4"
    assert report["node"]["package_manager"] == "dnf"


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
    ctx = collector.package_context(collector.Dnf(), "glibc", {}, {"/usr/lib64/libc.so.6"}, {})
    assert ctx["libraries_loaded"] == ["/usr/lib64/libc.so.6"]
    assert ctx["idle"] is False


def test_unreliable_process_scan_never_idle(collector, monkeypatch, capsys):
    monkeypatch.setattr(collector, "run", fake_run)
    monkeypatch.setattr(collector, "read_file", lambda p: KERNEL_FILES.get(p, ""))
    monkeypatch.setattr(collector, "running_state", lambda: ({}, set(), 0))
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    monkeypatch.setattr(collector.shutil, "which", lambda n: "/usr/bin/dnf" if n == "dnf" else None)
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


# ------------------------------------------------------------ apt (Debian, Ubuntu)

# Righe reali di `apt-get -s dist-upgrade` (Debian 12, Ubuntu 24.04), con dati finti.
APT_SIMULATION = """\
NOTE: This is only a simulation!
Inst base-files [12.4+deb12u1] (12.4+deb12u15 Debian:12.15/oldstable [amd64])
Inst libc6 [2.36-9+deb12u1] (2.36-9+deb12u14 Debian:12.15/oldstable [amd64])
Inst perl-base [5.36.0-7] (5.36.0-7+deb12u4 Debian-Security:12/oldstable-security [amd64])
Inst libssl3t64 [3.0.13-0ubuntu3] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, \
Ubuntu:24.04/noble-security [amd64])
Inst linux-image-6.1.0-40-amd64 (6.1.153-1 Debian-Security:12/oldstable-security [amd64])
Conf libc6 (2.36-9+deb12u14 Debian:12.15/oldstable [amd64])
"""

DPKG_ROWS = "".join(
    "\t".join(row) + "\n"
    for row in [
        [
            "ii ",
            "libc6",
            "2.36-9+deb12u1",
            "glibc",
            "2.36-9+deb12u1",
            "libgcc-s1, libc-bin (= 2.36)",
            "",
            "",
        ],
        [
            "ii ",
            "perl-base",
            "5.36.0-7",
            "perl",
            "5.36.0-7",
            "libc6 (>= 2.35), libcrypt1 (>= 1:4.1.0)",
            "dpkg (>= 1.17.17)",
            "perlapi-5.36.0",
        ],
        ["ii ", "base-files", "12.4+deb12u1", "", "", "", "", ""],
        [
            "ii ",
            "openssh-server",
            "1:9.2p1-2",
            "openssh",
            "1:9.2p1-2",
            "libc6 (>= 2.36), perl-base | perl:any",
            "",
            "ssh-server",
        ],
        ["rc ", "removed-pkg", "1.0", "", "", "", "", ""],
    ]
)

DPKG_LISTS = {
    "/var/lib/dpkg/info/libc6:amd64.list": "/.\n/lib/x86_64-linux-gnu/libc.so.6\n",
    "/var/lib/dpkg/info/perl-base.list": "/.\n/usr/bin/perl\n",
    "/var/lib/dpkg/info/base-files.list": "/.\n/etc/debian_version\n",
    "/var/lib/dpkg/info/openssh-server.list": (
        "/.\n/usr/sbin/sshd\n/lib/systemd/system/ssh.service\n"
    ),
}

DEBIAN_OS = (
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
    'VERSION_ID="12"\nID=debian\n'
)


def test_parse_apt_simulation(collector):
    found = collector.parse_apt_simulation(APT_SIMULATION)
    assert found["perl-base"] == (
        "5.36.0-7",
        "5.36.0-7+deb12u4",
        "Debian-Security:12/oldstable-security",
        True,
    )
    # Correzione arrivata con un rilascio intermedio: tenuta, la decide OSV.
    assert found["libc6"][3] is False
    assert found["libssl3t64"][2] == "Ubuntu:24.04/noble-security"
    assert "linux-image-6.1.0-40-amd64" not in found  # pacchetto nuovo, non aggiornamento


def test_parse_dpkg_database(collector):
    db = collector.parse_dpkg_database(DPKG_ROWS)
    assert set(db) == {"libc6", "perl-base", "base-files", "openssh-server"}
    assert db["libc6"]["source"] == "glibc"
    assert db["base-files"]["source"] == "base-files"  # senza campo Source
    assert db["perl-base"]["requires"] == {"libc6", "libcrypt1", "dpkg"}
    assert db["openssh-server"]["requires"] == {"libc6", "perl-base", "perl"}
    assert db["openssh-server"]["provides"] == {"openssh-server", "ssh-server"}


def test_apt_ecosystem(collector):
    assert collector.apt_ecosystem({"id": "debian", "version": "12", "lts": False}) == "Debian:12"
    ubuntu = {"id": "ubuntu", "version": "24.04", "lts": True}
    assert collector.apt_ecosystem(ubuntu) == "Ubuntu:24.04:LTS"
    assert collector.apt_ecosystem({"id": "ubuntu", "version": "24.10", "lts": False}) == (
        "Ubuntu:24.10"
    )
    assert collector.apt_ecosystem({"id": "linuxmint", "version": "22", "lts": False}) == ""


@pytest.mark.parametrize(
    "output, expected",
    [
        ("NOTE: simulation\nRemv telnet [0.17+2.4-2]\n", []),
        ("Remv libfoo [1]\nRemv foo-tools [1]\n", ["foo-tools"]),
        ("WARNING: The following essential packages will be removed.\nRemv libfoo [1]\n", None),
        ("E: Unable to locate package libfoo\n", None),
    ],
)
def test_parse_apt_remove_simulation(collector, output, expected):
    name = "telnet" if "telnet" in output else "libfoo"
    assert collector.parse_apt_remove_simulation(output, name) == expected


def apt_run(cmd):
    if cmd[0] == "dpkg-query":
        return DPKG_ROWS
    if cmd[:2] == ["apt-get", "update"]:
        return ""
    if cmd[:2] == ["apt-get", "-s"] and cmd[-1] == "dist-upgrade":
        return APT_SIMULATION
    if cmd[:2] == ["apt-get", "-s"] and "remove" in cmd:
        return f"Remv {cmd[-1]} [1]\n"
    return fake_run(cmd) if cmd[0] in ("systemctl", "ss", "modprobe") else ""


def test_debian_node(collector, monkeypatch, capsys):
    files = dict(KERNEL_FILES, **DPKG_LISTS)
    files["/etc/os-release"] = DEBIAN_OS
    monkeypatch.setattr(collector, "run", apt_run)
    monkeypatch.setattr(collector, "read_file", lambda p: files.get(p, ""))
    monkeypatch.setattr(
        collector.glob,
        "glob",
        lambda pattern: sorted(p for p in DPKG_LISTS if fnmatch.fnmatch(p, pattern)),
    )
    monkeypatch.setattr(
        collector,
        "running_state",
        lambda: ({"7": "/usr/bin/perl"}, {"/usr/lib/x86_64-linux-gnu/libc.so.6"}, 0),
    )
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    monkeypatch.setattr(collector, "privileged_from_disk", lambda files: [])
    monkeypatch.setattr(
        collector.shutil,
        "which",
        lambda n: f"/usr/bin/{n}" if n in ("apt-get", "dpkg-query") else None,
    )
    monkeypatch.setattr(collector, "_merged", [("/lib/", "/usr/lib/")])
    collector.main([])
    report = json.loads(capsys.readouterr().out)
    assert report["node"]["package_manager"] == "apt"
    assert report["node"]["os"]["id"] == "debian"
    pkgs = report["packages"]
    assert set(pkgs) == {"base-files", "libc6", "perl-base", "libssl3t64"}
    perl = pkgs["perl-base"]
    assert perl["advisories"][0]["lookup"] == {
        "ecosystem": "Debian:12",
        "source": "perl",
        "installed": "5.36.0-7",
        "fixed": "5.36.0-7+deb12u4",
        "security": True,
    }
    assert perl["advisories"][0]["id"] == "oldstable-security:perl:5.36.0-7+deb12u4"
    assert perl["context"]["binaries_running"] == ["/usr/bin/perl"]
    assert perl["context"]["source"] == "perl"
    assert perl["context"]["installed"] == ["5.36.0-7"]
    # libc6 elencata in /lib, caricata da /usr/lib (usrmerge): in uso
    assert pkgs["libc6"]["context"]["libraries_loaded"] == ["/usr/lib/x86_64-linux-gnu/libc.so.6"]
    assert pkgs["libc6"]["context"]["required_by"] == ["openssh-server", "perl-base"]
    assert report["profile"]["process_scan_ok"] is True


# ------------------------------------------------------------ zypper (SUSE)

# Formato reale di `zypper --xmlout list-patches` (openSUSE Leap 15.6), con dati finti.
ZYPPER_PATCHES = """<?xml version='1.0'?>
<stream>
<message type="warning">Repository metadata expired</message>
<update-status version="0.6">
<update-list>
<update kind="patch" name="openSUSE-SLE-15.6-2026-101" edition="1" arch="noarch"
 status="needed" category="security" severity="important" pkgmanager="false"
 restart="false" interactive="false"><summary>Security update for libexample</summary>
<description>* CVE-2026-1111: overflow</description><license/>
<issue-date time_t="1718004848" text="2026-06-10T07:34:08Z"/>
<issue-list><issue type="bugzilla" id="1225690"><title>VUL-0</title></issue>
<issue type="cve" id="CVE-2026-1111"><title>x</title></issue>
<issue type="cve" id="CVE-2026-2222"><title>x</title></issue></issue-list></update>
<update kind="patch" name="openSUSE-2026-7" edition="1" arch="noarch" status="needed"
 category="recommended" severity="low"><summary>Recommended</summary></update>
<update kind="patch" name="openSUSE-2026-8" edition="1" arch="noarch" status="not-needed"
 category="security" severity="low"><summary>Già applicata</summary></update>
</update-list>
</update-status>
</stream>
"""

ZYPPER_PATCH_INFO = """\
Name        : openSUSE-SLE-15.6-2026-101
Status      : needed
Category    : security
Provides    : patch:openSUSE-SLE-15.6-2026-101 = 1
Conflicts   : [5]
    srcpackage:libexample < 4.23.5-150600.3.1
    libexample.x86_64 < 4.23.5-150600.3.1
    libexample.noarch < 4.23.5-150600.3.1
    libexample-devel.x86_64 < 4.23.5-150600.3.1
    libexample-lang < 4.23.5-150600.3.1
"""


def test_parse_zypper_patches(collector):
    patches = collector.parse_zypper_patches(ZYPPER_PATCHES)
    assert patches == {
        "openSUSE-SLE-15.6-2026-101": {
            "severity": "Important",
            "cves": ["CVE-2026-1111", "CVE-2026-2222"],
            "issued": "2026-06-10T07:34:08Z",
        }
    }
    assert collector.parse_zypper_patches("non xml") == {}


def test_parse_zypper_patch_info(collector):
    assert collector.parse_zypper_patch_info(ZYPPER_PATCH_INFO) == {
        "libexample": "4.23.5-150600.3.1",
        "libexample-devel": "4.23.5-150600.3.1",
        "libexample-lang": "4.23.5-150600.3.1",
    }


@pytest.mark.parametrize(
    "output, expected",
    [
        (
            "Reading installed packages...\nResolving package dependencies...\n\n"
            "The following 2 packages are going to be REMOVED:\n  libexample libexample-tools\n\n"
            "2 packages to remove.\n",
            ["libexample-tools"],
        ),
        (
            "The following package is going to be REMOVED:\n  libexample\n\n1 package to remove.\n",
            [],
        ),
        ("Problem: 1: This request will break your system!\n conflicting requests\n", None),
        ("No provider of 'libexample' found.\nNothing to do.\n", None),
    ],
)
def test_parse_zypper_remove_simulation(collector, output, expected):
    assert collector.parse_zypper_remove_simulation(output, "libexample") == expected


def test_suse_node(collector, monkeypatch, capsys):
    def zypper_run(cmd):
        if cmd[:2] == ["zypper", "-n"] and "list-patches" in cmd:
            return ZYPPER_PATCHES
        if cmd[:2] == ["zypper", "-n"] and "info" in cmd:
            return ZYPPER_PATCH_INFO
        if cmd[0] == "zypper":
            return ""
        if cmd[:2] == ["rpm", "-qa"] and cmd[3] == "%{NAME}\\n":
            return "libexample\nlibexample-lang\nglibc\n"
        if cmd[:2] == ["rpm", "-ql"]:
            return "/usr/lib64/libexample.so.2\n"
        return fake_run(cmd)

    files = dict(KERNEL_FILES)
    files["/etc/os-release"] = 'NAME="openSUSE Leap"\nVERSION_ID="15.6"\nID="opensuse-leap"\n'
    monkeypatch.setattr(collector, "run", zypper_run)
    monkeypatch.setattr(collector, "read_file", lambda p: files.get(p, ""))
    monkeypatch.setattr(collector, "running_state", lambda: ({}, {"/usr/lib64/libc.so.6"}, 0))
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    monkeypatch.setattr(
        collector.shutil, "which", lambda n: "/usr/bin/zypper" if n == "zypper" else None
    )
    collector.main([])
    report = json.loads(capsys.readouterr().out)
    assert report["node"]["package_manager"] == "zypper"
    # solo i pacchetti installati, con le CVE della patch
    assert set(report["packages"]) == {"libexample", "libexample-lang"}
    adv = report["packages"]["libexample"]["advisories"][0]
    assert adv["id"] == "openSUSE-SLE-15.6-2026-101"
    assert adv["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert adv["fixed_version"] == "4.23.5-150600.3.1"


def test_low_priority_reexecs_once_with_ionice(collector, monkeypatch):
    calls = []
    monkeypatch.delenv("SAGE_LOW_PRIORITY", raising=False)
    monkeypatch.setattr(collector.os, "nice", lambda n: calls.append(("nice", n)))
    monkeypatch.setattr(collector.shutil, "which", lambda n: "/usr/bin/ionice")
    monkeypatch.setattr(collector.os, "execv", lambda path, args: calls.append((path, args[:4])))
    collector.low_priority()
    assert calls[0] == ("nice", 19)
    assert calls[1] == ("/usr/bin/ionice", ["/usr/bin/ionice", "-t", "-c", "3"])
    calls.clear()
    collector.low_priority()  # già rilanciato: niente secondo exec
    assert calls == []


def test_newest_kernel_differs(collector, tmp_path):
    old, new = tmp_path / "vmlinuz-6.1.0-26-amd64", tmp_path / "vmlinuz-6.1.0-40-amd64"
    rescue = tmp_path / "vmlinuz-0-rescue-abc"
    for i, f in enumerate((old, new, rescue)):
        f.write_text("")
        collector.os.utime(f, (1000 + i, 1000 + i))
    assert collector.newest_kernel_differs("6.1.0-26-amd64", str(tmp_path))
    assert not collector.newest_kernel_differs("6.1.0-40-amd64", str(tmp_path))
    assert not collector.newest_kernel_differs("6.1.0-26-amd64", str(tmp_path / "vuota"))


def test_reboot_required_file(collector, monkeypatch):
    files = {"/var/run/reboot-required.pkgs": "linux-image-6.1.0-40-amd64\nlibc6\n"}
    monkeypatch.setattr(collector.os.path, "exists", lambda p: p == "/var/run/reboot-required")
    monkeypatch.setattr(collector, "read_file", lambda p: files.get(p, ""))
    monkeypatch.setattr(collector, "newest_kernel_differs", lambda r: False)
    status = collector.reboot_status(collector.Apt(), "6.1.0-26-amd64")
    assert status == {
        "required": True,
        "reasons": ["reboot-required: libc6, linux-image-6.1.0-40-amd64"],
    }


@pytest.mark.parametrize(
    ("os_release", "kind"),
    [
        ('ID=rhcos\nNAME="Red Hat Enterprise Linux CoreOS"', "rhcos"),
        ("ID=fedora\nVARIANT_ID=coreos", "coreos"),
        ("ID=flatcar", "flatcar"),
        ("ID=bottlerocket", "bottlerocket"),
        ('ID=opensuse-microos\nNAME="openSUSE MicroOS"', "opensuse-microos"),
        ("ID=debian", None),
        ('ID=sles\nNAME="SLES"', None),
    ],
)
def test_immutable_systems_are_refused(collector, monkeypatch, capsys, os_release, kind):
    monkeypatch.setattr(collector.os.path, "exists", lambda p: False)
    info = collector.parse_os_release(os_release)
    assert collector.immutable(info) == kind
    if kind:
        monkeypatch.setattr(collector, "read_file", lambda path: os_release)
        assert collector.main([]) == 2
        assert "immutabile" in json.loads(capsys.readouterr().out)["error"]


def test_ostree_booted_is_immutable(collector, monkeypatch):
    monkeypatch.setattr(collector.os.path, "exists", lambda p: p == "/run/ostree-booted")
    assert collector.immutable({"ID": "centos"}) == "rpm-ostree"


def test_report_has_unused_section(report):
    # nel finto nodo nessun pacchetto senza CVE passa la simulazione di rimozione
    assert report["unused"] == {}
    assert "scripts_read" in report["profile"]


def test_cron_and_scripts_reference_binaries(collector):
    texts = [
        ("/etc/cron.d/backup", "0 3 * * * root /usr/bin/curl -s https://x\n"),
        ("/usr/local/bin/job.sh", "#!/bin/sh\nrsync -a /a /b\nfoo-figlet\n"),
    ]
    assert collector.referenced_by(["/usr/bin/curl"], texts) == ["/etc/cron.d/backup"]
    assert collector.referenced_by(["/usr/bin/rsync"], texts) == ["/usr/local/bin/job.sh"]
    assert collector.referenced_by(["/usr/bin/figlet"], texts) == []  # "foo-figlet" è un altro


def test_script_texts_skip_compiled_binaries(collector, tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "SCRIPT_GLOBS", ())
    (tmp_path / "s.sh").write_text("curl x\n")
    (tmp_path / "bin").write_bytes(b"\x7fELF\x00\x00curl")
    texts = collector.script_texts([str(tmp_path / "s.sh"), str(tmp_path / "bin")])
    assert [p for p, _ in texts] == [str(tmp_path / "s.sh")]


def test_disk_usage_atime_and_noatime(collector, tmp_path):
    f = tmp_path / "tool"
    f.write_text("x")
    os.utime(f, (1_700_000_000, 1_600_000_000))
    relatime = collector.mount_options("1 0 0:1 / / rw,relatime - ext4 x rw\n")
    when, reliable = collector.disk_usage([str(f), str(tmp_path / "missing")], relatime)
    assert when == "2023-11-14T22:13:20+00:00" and reliable is True
    noatime = collector.mount_options(f"1 0 0:1 / {tmp_path} rw,noatime - xfs x rw\n")
    assert collector.disk_usage([str(f)], noatime)[1] is False
    assert collector.disk_usage([], noatime) == (None, True)


def test_is_idle_needs_no_boot_files_no_references_and_reliable_atime(collector):
    ctx = {"binaries_running": [], "libraries_loaded": [], "listening": [], "units": {}}
    assert collector.is_idle(ctx) is True
    assert collector.is_idle({**ctx, "boot_files": True}) is False
    assert collector.is_idle({**ctx, "referenced_by": ["/etc/cron.d/x"]}) is False
    assert collector.is_idle({**ctx, "atime_reliable": False}) is False


def test_unused_candidates_only_leaves_outside_services(collector):
    class Pm:
        def removable(self, name):
            return name != "base-pkg"

    db = {
        "installed": {"app", "libdep", "figlet", "base-pkg", "linux-image-6.1", "svc"},
        "requires": {"app": {"libdep"}, "figlet": set()},
        "provides": {"libdep": {"libdep"}},
        "owners": {},
    }
    got = collector.unused_candidates(Pm(), db, {"svc": "svc.service"}, {"app"})
    assert got == ["figlet"]  # libdep serve ad app, svc a un servizio, app ha CVE


def test_apt_base_packages_never_removable(collector, monkeypatch):
    out = {
        "dpkg-query -W -f ${Package}\\t${Essential}\\t${Protected}\\t${Priority}\\n": (
            "bash\tyes\t\trequired\napt\t\tyes\timportant\nfiglet\t\t\toptional\n"
        )
    }
    monkeypatch.setattr(collector, "run", lambda cmd: out.get(" ".join(cmd), ""))
    monkeypatch.setattr(collector.glob, "glob", lambda p: [])
    apt = collector.Apt()
    apt.database()
    assert not apt.removable("bash") and not apt.removable("apt") and apt.removable("figlet")


def test_used_right_after_boot_is_boot_package(collector):
    booted = collector.boot_time("cpu 1 2 3\nbtime 1700000000\nprocesses 9\n")
    assert booted == 1_700_000_000
    assert collector.used_at_boot("2023-11-14T22:20:00+00:00", booted) is True  # 7 min dopo
    assert collector.used_at_boot("2023-11-15T22:13:20+00:00", booted) is False  # un giorno dopo
    # letto nelle 24 ore prima dell'avvio: con relatime la lettura all'avvio non si vede
    assert collector.used_at_boot("2023-11-14T10:00:00+00:00", booted) is True
    assert collector.used_at_boot("2023-11-12T10:00:00+00:00", booted) is False  # 2 giorni prima
    assert collector.used_at_boot(None, booted) is False
    assert collector.used_at_boot("2023-11-14T22:20:00+00:00", None) is False


def test_reading_docs_is_not_use(collector, monkeypatch, tmp_path):
    doc = tmp_path / "changelog.gz"
    doc.write_text("x")
    monkeypatch.setattr(collector, "DOC_PREFIXES", (str(tmp_path) + "/",))
    assert collector.disk_usage([str(doc)], []) == (None, True)
