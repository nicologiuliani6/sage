#!/usr/bin/env python3
"""SAGE collector: gira su un nodo (come root) e stampa un JSON con advisory di
sicurezza, CVE e contesto di ogni pacchetto vulnerabile, più i dati del kernel
che servono a verificare le condizioni di sfruttabilità.

Solo libreria standard: deve girare sul Python 3.9 di Rocky Linux 9.
"""

import glob
import json
import os
import platform
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 2
EXEC_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/")
UNIT_DIRS = ("/usr/lib/systemd/system/", "/etc/systemd/system/")
# Stati di `systemctl is-enabled` per cui una unit può partire da sola.
AUTOSTART_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect")
MODULE_SUFFIX = re.compile(r"\.ko(\.xz|\.zst|\.gz)?$")
BLOCK_COMMANDS = ("/bin/false", "/usr/bin/false", "/bin/true", "/usr/bin/true")
ENV = dict(os.environ, LC_ALL="C", LANG="C")


def run(cmd):
    """Esegue un comando e restituisce stdout (stringa vuota se fallisce)."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
            env=ENV,
        )
        return res.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def os_release():
    info = {}
    for line in read_file("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v.strip('"')
    return {"name": info.get("NAME", ""), "version": info.get("VERSION_ID", "")}


def node_role():
    if os.path.exists("/etc/kubernetes/manifests/kube-apiserver.yaml"):
        return "control_plane"
    if os.path.exists("/etc/kubernetes/kubelet.conf"):
        return "worker"
    return "unknown"


# ---------------------------------------------------------------- advisory


def split_nevra(nevra):
    """'NetworkManager-1:1.48.10-5.el9_5.x86_64' -> (nome, '1:1.48.10-5.el9_5', arch)"""
    base, _, arch = nevra.rpartition(".")
    name, version, release = base.rsplit("-", 2)
    return name, version + "-" + release, arch


def security_advisories():
    """advisory -> {severity, packages: {nome: versione_fix}}"""
    advisories = {}
    for line in run(["dnf", "-q", "updateinfo", "list", "--security"]).splitlines():
        parts = line.split()
        if len(parts) != 3 or "/Sec" not in parts[1]:
            continue
        adv, sev, nevra = parts
        try:
            name, fixed, _ = split_nevra(nevra)
        except ValueError:
            continue
        entry = advisories.setdefault(adv, {"severity": sev.split("/")[0], "packages": {}})
        entry["packages"][name] = fixed
    return advisories


def advisory_details():
    """advisory -> {cves, issued} da 'dnf updateinfo info --security'."""
    details, current, in_cves = {}, None, False
    for line in run(["dnf", "-q", "updateinfo", "info", "--security"]).splitlines():
        key, sep, value = line.partition(":")
        key = key.strip()
        if sep and key == "Update ID":
            current = details.setdefault(value.strip(), {"cves": [], "issued": ""})
            in_cves = False
            continue
        if current is None:
            continue
        if sep and key in ("Updated", "Issued"):
            current["issued"] = value.strip()
            in_cves = False
        elif sep and key == "CVEs":
            in_cves = True
            current["cves"] += re.findall(r"CVE-\d{4}-\d+", value)
        elif sep and key and not key.startswith("CVE"):
            in_cves = False
        elif in_cves:
            current["cves"] += re.findall(r"CVE-\d{4}-\d+", line)
    for d in details.values():
        d["cves"] = sorted(set(d["cves"]))
    return details


# ---------------------------------------------------------------- contesto


def running_state():
    """Eseguibili in esecuzione e file mappati in memoria da tutti i processi."""
    exes, mapped = {}, set()
    for proc in glob.glob("/proc/[0-9]*"):
        pid = proc.rsplit("/", 1)[1]
        try:
            exe = os.readlink(proc + "/exe")
            exes[pid] = exe.replace(" (deleted)", "")
        except OSError:
            pass
        try:
            with open(proc + "/maps") as f:
                for line in f:
                    parts = line.split(None, 5)
                    if len(parts) == 6 and parts[5].startswith("/"):
                        mapped.add(parts[5].strip().replace(" (deleted)", ""))
        except OSError:
            pass
    return exes, mapped


def listening_exes(exes):
    """Eseguibile -> lista di 'proto porta' su cui è in ascolto."""
    result = {}
    for line in run(["ss", "-tulnpH"]).splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        port = local.rsplit(":", 1)[-1]
        for pid in re.findall(r"pid=(\d+)", line):
            exe = exes.get(pid)
            if exe:
                result.setdefault(exe, set()).add(proto + " " + port)
    return {k: sorted(v) for k, v in result.items()}


def unit_states(units):
    """unit -> {active, enabled}"""
    if not units:
        return {}
    names = sorted(units)
    active = run(["systemctl", "is-active"] + names).splitlines()
    enabled = run(["systemctl", "is-enabled"] + names).splitlines()
    result = {}
    for i, name in enumerate(names):
        result[name] = {
            "active": active[i] if i < len(active) else "unknown",
            "enabled": enabled[i] if i < len(enabled) else "unknown",
        }
    return result


def privileged_files(name):
    """File setuid, setgid o con capability: sfruttabili da un utente locale anche se
    nessun processo li sta usando."""
    out = run(["rpm", "-q", "--qf", "[%{FILEMODES:perms}|%{FILECAPS}|%{FILENAMES}\\n]", name])
    found = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        perms, caps, path = parts
        setid = len(perms) == 10 and (perms[3] in "sS" or perms[6] in "sS")
        if setid or caps.strip():
            found.append(path)
    return sorted(found)


def is_idle(ctx):
    if ctx["binaries_running"] or ctx["libraries_loaded"] or ctx["listening"]:
        return False
    for state in ctx["units"].values():
        if state["active"] == "active" or state["enabled"] in AUTOSTART_STATES:
            return False
    return True


def parse_remove_simulation(output, name):
    """Pacchetti che `dnf remove` toglierebbe oltre a `name`; None se dnf si rifiuta."""
    if re.search(r"^(Error|Problem)", output, re.MULTILINE) or "protected packages" in output:
        return None
    removed, in_section = set(), False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Removing") and stripped.endswith(":"):
            in_section = True
            continue
        if not stripped or stripped.startswith(("Transaction Summary", "=")):
            in_section = False
            continue
        if in_section and line.startswith(" "):
            removed.add(stripped.split()[0])
    if name not in removed:
        return None
    return sorted(removed - {name})


def removal_simulation(name):
    out = run(["dnf", "remove", "--assumeno", "--noautoremove", name])
    return parse_remove_simulation(out, name)


def package_context(name, exes, mapped, listening):
    installed = run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", name]).splitlines()
    files = run(["rpm", "-ql", name]).splitlines()
    fileset = set(files)
    libs = [f for f in files if re.search(r"\.so(\.|$)", os.path.basename(f))]
    binaries = [f for f in files if f.startswith(EXEC_DIRS)]
    units = {
        os.path.basename(f)
        for f in files
        if f.startswith(UNIT_DIRS) and f.endswith((".service", ".socket"))
    }
    required_by = sorted(
        {
            line.rsplit("-", 2)[0]
            for line in run(["rpm", "-q", "--whatrequires", name]).splitlines()
            if line and "no package requires" not in line
        }
    )
    ctx = {
        "installed": installed,
        "has_libraries": bool(libs),
        "libraries_loaded": sorted(f for f in libs if f in mapped),
        "has_binaries": bool(binaries),
        "binaries_running": sorted({e for e in exes.values() if e in fileset}),
        "listening": sorted({p for exe, ps in listening.items() if exe in fileset for p in ps}),
        "units": unit_states(units),
        "privileged_files": privileged_files(name),
        "required_by": required_by,
    }
    ctx["idle"] = is_idle(ctx)
    # La simulazione di rimozione serve solo per i pacchetti inattivi (è lenta).
    if ctx["idle"] and not name.startswith("kernel"):
        ctx["removal_also_removes"] = removal_simulation(name)
    else:
        ctx["removal_also_removes"] = None
    return ctx


# ---------------------------------------------------------------- kernel


def module_entry(path):
    """'kernel/net/sctp/sctp.ko.xz' -> ('sctp', 'net/sctp')"""
    rel = path.split(":", 1)[0].strip()
    if rel.startswith("kernel/"):
        rel = rel[len("kernel/") :]
    name = MODULE_SUFFIX.sub("", os.path.basename(rel)).replace("-", "_")
    return name, os.path.dirname(rel)


def kernel_modules(release):
    base = "/lib/modules/" + release
    modules = {}
    for line in read_file(base + "/modules.dep").splitlines():
        if line.strip():
            name, directory = module_entry(line)
            modules[name] = {"dir": directory, "state": "available"}
    for line in read_file(base + "/modules.builtin").splitlines():
        if line.strip():
            name, directory = module_entry(line)
            modules[name] = {"dir": directory, "state": "builtin"}
    for line in read_file("/proc/modules").splitlines():
        name = line.split(" ", 1)[0].replace("-", "_")
        if name in modules:
            modules[name]["state"] = "loaded"
        else:
            modules[name] = {"dir": None, "state": "loaded"}
    return modules


def module_blocks():
    """Moduli bloccati: `install X /bin/false` (blocco totale) e `blacklist X`."""
    install_blocked, blacklisted = set(), set()
    for line in run(["modprobe", "--showconfig"]).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "install" and parts[2] in BLOCK_COMMANDS:
            install_blocked.add(parts[1].replace("-", "_"))
        elif len(parts) == 2 and parts[0] == "blacklist":
            blacklisted.add(parts[1].replace("-", "_"))
    return sorted(install_blocked), sorted(blacklisted)


def sysctl(path):
    value = read_file("/proc/sys/" + path).strip()
    return int(value) if value.lstrip("-").isdigit() else None


def kernel_facts():
    release = platform.release()
    install_blocked, blacklisted = module_blocks()
    return {
        "release": release,
        "modules": kernel_modules(release),
        "install_blocked": install_blocked,
        "blacklisted": blacklisted,
        "sysctl": {
            "kernel.modules_disabled": sysctl("kernel/modules_disabled"),
            "kernel.unprivileged_bpf_disabled": sysctl("kernel/unprivileged_bpf_disabled"),
            "user.max_user_namespaces": sysctl("user/max_user_namespaces"),
        },
    }


# ---------------------------------------------------------------- main


def main():
    advisories = security_advisories()
    details = advisory_details()
    exes, mapped = running_state()
    listening = listening_exes(exes)

    packages = {}
    for adv_id, adv in advisories.items():
        det = details.get(adv_id, {})
        for name, fixed in adv["packages"].items():
            pkg = packages.setdefault(name, {"advisories": []})
            pkg["advisories"].append(
                {
                    "id": adv_id,
                    "severity": adv["severity"],
                    "fixed_version": fixed,
                    "cves": det.get("cves", []),
                    "issued": det.get("issued", ""),
                }
            )
    for name, pkg in packages.items():
        pkg["advisories"].sort(key=lambda a: a["id"])
        pkg["context"] = package_context(name, exes, mapped, listening)

    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "node": {
                    "hostname": socket.gethostname(),
                    "role": node_role(),
                    "os": os_release(),
                    "arch": platform.machine(),
                },
                "kernel": kernel_facts(),
                "summary": {
                    "advisories": len(advisories),
                    "packages": len(packages),
                    "cves": len(
                        {c for p in packages.values() for a in p["advisories"] for c in a["cves"]}
                    ),
                },
                "packages": dict(sorted(packages.items())),
            }
        )
    )


if __name__ == "__main__":
    sys.exit(main())
