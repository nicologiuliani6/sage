#!/usr/bin/env python3
"""SAGE collector: gira su un nodo (come root) e stampa un JSON con
advisory di sicurezza, CVE e contesto di ogni pacchetto vulnerabile.

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

SCHEMA_VERSION = 1
EXEC_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/")


def run(cmd):
    """Esegue un comando e restituisce stdout (stringa vuota se fallisce)."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=600,
        )
        return res.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def os_release():
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    info[k] = v.strip('"')
    except OSError:
        pass
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
    if not units:
        return {}
    out = run(["systemctl", "is-active"] + sorted(units)).splitlines()
    return dict(zip(sorted(units), out))


def package_context(name, exes, mapped, listening):
    installed = run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", name]).splitlines()
    files = run(["rpm", "-ql", name]).splitlines()
    fileset = set(files)
    libs = [f for f in files if re.search(r"\.so(\.|$)", os.path.basename(f))]
    binaries = [f for f in files if f.startswith(EXEC_DIRS)]
    units = {
        os.path.basename(f)
        for f in files
        if f.startswith(("/usr/lib/systemd/system/", "/etc/systemd/system/"))
        and f.endswith((".service", ".socket"))
    }
    running = sorted({e for e in exes.values() if e in fileset})
    ports = sorted({p for exe, ps in listening.items() if exe in fileset for p in ps})
    required_by = sorted(
        {
            line.rsplit("-", 2)[0]
            for line in run(["rpm", "-q", "--whatrequires", name]).splitlines()
            if line and "no package requires" not in line
        }
    )
    return {
        "installed": installed,
        "has_libraries": bool(libs),
        "libraries_loaded": sorted(f for f in libs if f in mapped),
        "has_binaries": bool(binaries),
        "binaries_running": running,
        "listening": ports,
        "units": unit_states(units),
        "required_by": required_by,
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
                    "kernel": platform.release(),
                },
                "summary": {
                    "advisories": len(advisories),
                    "packages": len(packages),
                    "cves": len(
                        {c for p in packages.values() for a in p["advisories"] for c in a["cves"]}
                    ),
                },
                "packages": dict(sorted(packages.items())),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    sys.exit(main())
