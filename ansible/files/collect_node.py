#!/usr/bin/env python3
"""SAGE collector: gira su un nodo (come root) e stampa un JSON con advisory di
sicurezza, CVE e contesto di ogni pacchetto vulnerabile, più i dati del kernel
che servono a verificare le condizioni di sfruttabilità.

Tre famiglie di gestori di pacchetti, stesso JSON in uscita (ADR-0017):
- dnf (RHEL, Rocky, Alma, Oracle, Fedora, Amazon Linux 2023): advisory di updateinfo;
- zypper (SLES, openSUSE): patch di sicurezza, l'equivalente delle advisory;
- apt (Debian, Ubuntu): aggiornamenti dal repository di sicurezza. apt non sa a quali
  CVE corrispondono: SAGE le cerca dopo, fuori dal nodo (vedi `lookup`).

Solo libreria standard, Python 3.9 o successivo.
"""

import glob
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 5
# Processi dei container: i loro file sono nell'immagine, non nei pacchetti del nodo.
CONTAINER_CGROUPS = ("kubepods", "/docker/", "docker-", "libpod-", "crio-", "cri-containerd-")
UNIT_TYPES = "service,socket,timer"
EXEC_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/")
UNIT_DIRS = ("/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/systemd/system/")
# Stati di `systemctl is-enabled` per cui una unit può partire da sola.
AUTOSTART_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect")
MODULE_SUFFIX = re.compile(r"\.ko(\.xz|\.zst|\.gz)?$")
BLOCK_COMMANDS = ("/bin/false", "/usr/bin/false", "/bin/true", "/usr/bin/true")
ENV = dict(os.environ, LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")
# Pacchetti del kernel: non si rimuovono e non si simula la loro rimozione.
KERNEL_PREFIXES = ("kernel", "linux-image-", "linux-modules-")
# Cartelle che su Rocky 9 (e Debian 12, Ubuntu) sono collegamenti (usrmerge): rpm elenca
# /lib64/libc.so.6, il
# kernel in /proc/<pid>/maps scrive /usr/lib64/libc.so.6. Si confrontano i percorsi reali.
MERGED_DIRS = ("/bin", "/sbin", "/lib", "/lib64")
_merged = None


def merged_prefixes(root=""):
    """'/lib64/' -> '/usr/lib64/' per le cartelle che sono collegamenti simbolici."""
    found = []
    for d in MERGED_DIRS:
        if os.path.islink(root + d):
            target = os.path.realpath(root + d)[len(root) :]
            found.append((d + "/", target.rstrip("/") + "/"))
    return found


def canonical(path):
    """Percorso come lo vede il kernel: '/lib64/libc.so.6' -> '/usr/lib64/libc.so.6'."""
    global _merged
    if _merged is None:
        _merged = merged_prefixes()
    for prefix, target in _merged:
        if path.startswith(prefix):
            return target + path[len(prefix) :]
    return path


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


def parse_os_release(text):
    info = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v.strip().strip('"')
    return info


def os_release():
    info = parse_os_release(read_file("/etc/os-release"))
    return {
        "name": info.get("NAME", ""),
        "version": info.get("VERSION_ID", ""),
        "id": info.get("ID", ""),
        "id_like": info.get("ID_LIKE", ""),
        "lts": "LTS" in info.get("VERSION", ""),
    }


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


def parse_updateinfo_list(out):
    """advisory -> {severity, packages: {nome: versione_fix}} da 'dnf updateinfo list'."""
    advisories = {}
    for line in out.splitlines():
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


def parse_updateinfo_info(out):
    """advisory -> {cves, issued} da 'dnf updateinfo info --security'."""
    details, current, in_cves = {}, None, False
    for line in out.splitlines():
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


def merge_advisories(advisories, details):
    """Lista per pacchetto: nome -> [{id, severity, fixed_version, cves, issued}]."""
    packages = {}
    for adv_id, adv in advisories.items():
        det = details.get(adv_id, {})
        for name, fixed in adv["packages"].items():
            packages.setdefault(name, []).append(
                {
                    "id": adv_id,
                    "severity": adv["severity"],
                    "fixed_version": fixed,
                    "cves": det.get("cves", []),
                    "issued": det.get("issued", ""),
                }
            )
    return packages


APT_INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.*?)(?: \[[^\]]*\])?\)")


def parse_apt_simulation(out):
    """Aggiornamenti di `apt-get -s dist-upgrade`: nome -> (installata, nuova, origine,
    dal repository di sicurezza?).

    Si tengono tutti, non solo quelli del repository di sicurezza: Debian pubblica molte
    correzioni di sicurezza nei rilasci intermedi (es. libc6 da "bookworm", non da
    "bookworm-security"). Quali correggono davvero delle CVE lo dice OSV, dopo."""
    found = {}
    for line in out.splitlines():
        m = APT_INST.match(line)
        if not m:
            continue
        name, old, new, origins = m.groups()
        if not old:
            continue  # pacchetto nuovo (es. un kernel), non un aggiornamento
        names = [o.strip() for o in origins.split(",") if o.strip()]
        security = [o for o in names if "-security" in o]
        origin = (security or names or [""])[0]
        found[name.split(":", 1)[0]] = (old, new, origin, bool(security))
    return found


def apt_ecosystem(os_info):
    """Nome dell'ecosistema OSV della release: 'Debian:12', 'Ubuntu:24.04:LTS'."""
    if os_info["id"] == "debian":
        return "Debian:" + os_info["version"].split(".")[0]
    if os_info["id"] == "ubuntu":
        return "Ubuntu:" + os_info["version"] + (":LTS" if os_info["lts"] else "")
    return ""


def parse_zypper_patches(xml_text):
    """Patch di sicurezza da 'zypper --xmlout list-patches': nome -> {severity, cves, issued}.

    Le CVE sono negli elementi <issue type="cve">; i pacchetti di ogni patch arrivano da
    'zypper info -t patch' (parse_zypper_patch_info)."""
    import xml.etree.ElementTree as ET

    patches = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return patches
    for upd in root.iter("update"):
        if upd.get("kind", "patch") != "patch" or upd.get("category") != "security":
            continue
        if upd.get("status", "needed") not in ("needed", "applicable"):
            continue
        cves = sorted(
            {
                i.get("id", "")
                for i in upd.iter("issue")
                if re.match(r"CVE-\d{4}-\d+$", i.get("id", ""))
            }
        )
        issued = upd.find("issue-date")
        patches[upd.get("name")] = {
            "severity": (upd.get("severity") or "").capitalize(),
            "cves": cves,
            "issued": issued.get("text", "") if issued is not None else "",
        }
    return patches


ZYPPER_ARCH = r"(?:\.(?:noarch|x86_64|aarch64|i586|i686|s390x|ppc64le))?"
ZYPPER_CONFLICT = re.compile(r"([A-Za-z0-9_.+-]+?)" + ZYPPER_ARCH + r" < (\S+)")


def parse_zypper_patch_info(out):
    """Pacchetti di una patch: righe 'nome < versione' della sezione Conflicts."""
    packages, in_conflicts = {}, False
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Conflicts"):
            in_conflicts = True
            rest = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if not rest:
                continue
            stripped = rest
        elif in_conflicts and line and not line[0].isspace():
            in_conflicts = False
        if not in_conflicts:
            continue
        m = ZYPPER_CONFLICT.match(stripped)
        if m and not stripped.startswith("srcpackage:"):
            packages[m.group(1)] = m.group(2)
    return packages


# ---------------------------------------------------------------- contesto


def in_container(proc):
    """Il processo gira in un container (pod Kubernetes, Docker, Podman, CRI-O)?

    Si guarda il cgroup e non il mount namespace: molti servizi di systemd hanno un
    namespace proprio (PrivateTmp) ma usano i file del nodo.
    """
    cgroup = read_file(proc + "/cgroup")
    return any(marker in cgroup for marker in CONTAINER_CGROUPS)


def running_state(proc_root="/proc"):
    """Eseguibili in esecuzione e file mappati in memoria dai processi del nodo.

    Restituisce anche quanti processi dei container sono stati esclusi.
    """
    exes, mapped, skipped = {}, set(), 0
    for proc in glob.glob(proc_root + "/[0-9]*"):
        pid = proc.rsplit("/", 1)[1]
        if in_container(proc):
            skipped += 1
            continue
        try:
            exe = os.readlink(proc + "/exe")
            exes[pid] = canonical(exe.replace(" (deleted)", ""))
        except OSError:
            pass
        try:
            with open(proc + "/maps") as f:
                for line in f:
                    parts = line.split(None, 5)
                    if len(parts) == 6 and parts[5].startswith("/"):
                        mapped.add(canonical(parts[5].strip().replace(" (deleted)", "")))
        except OSError:
            pass
    return exes, mapped, skipped


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


def privileged_from_disk(files):
    """File setuid, setgid o con capability, letti dal disco (dpkg non li registra)."""
    found = []
    for path in files:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        setid = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
        caps = False
        try:
            caps = bool(os.getxattr(path, "security.capability", follow_symlinks=False))
        except (OSError, AttributeError):
            pass
        if setid or caps:
            found.append(path)
    return sorted(found)


def parse_privileged(out):
    """Righe "permessi|capability|percorso" di rpm. Se il pacchetto non ha il tag FILECAPS,
    rpm scrive "(none)" per ogni file: non è una capability."""
    found = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        perms, caps, path = parts
        setid = len(perms) == 10 and (perms[3] in "sS" or perms[6] in "sS")
        if setid or caps.strip() not in ("", "(none)"):
            found.append(path)
    return sorted(found)


def is_idle(ctx, scan_ok=True):
    if ctx.get("needed_by"):
        return False  # serve a un servizio del nodo: mai inattivo
    if not scan_ok:
        return False  # lettura dei processi non affidabile: nel dubbio in uso
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


def parse_apt_remove_simulation(output, name):
    """Come sopra per `apt-get -s remove`: righe 'Remv pacchetto [versione]'. None se apt
    si rifiuta o toglierebbe un pacchetto essenziale."""
    if re.search(r"^E:", output, re.MULTILINE) or "essential packages" in output.lower():
        return None
    removed = {
        line.split()[1].split(":", 1)[0]
        for line in output.splitlines()
        if line.startswith("Remv ") and len(line.split()) > 1
    }
    if name not in removed:
        return None
    return sorted(removed - {name})


def parse_zypper_remove_simulation(output, name):
    """Come sopra per `zypper remove --dry-run`: elenco dopo 'The following N package(s)
    are going to be REMOVED:'. None se zypper si rifiuta."""
    if re.search(r"^(Problem|Error)", output, re.MULTILINE):
        return None
    removed, in_section = set(), False
    for line in output.splitlines():
        if re.match(r"The following .* (is|are) going to be REMOVED:", line.strip()):
            in_section = True
            continue
        if in_section:
            if not line.strip():
                in_section = False
                continue
            removed.update(line.split())
    if name not in removed:
        return None
    return sorted(removed - {name})


def source_name(out):
    """'glibc-2.34-100.el9_4.2.src.rpm' -> 'glibc' (pacchetto sorgente, comune ai
    sottopacchetti come glibc-common o glibc-langpack-en)."""
    first = out.splitlines()[0].strip() if out.strip() else ""
    if not first.endswith(".src.rpm"):
        return None
    parts = first[: -len(".src.rpm")].rsplit("-", 2)
    return parts[0] if len(parts) == 3 and parts[0] else None


def is_kernel_package(name):
    return name.startswith(KERNEL_PREFIXES)


def package_context(pm, name, exes, mapped, listening, needed_by=None, scan_ok=True):
    files = [canonical(f) for f in pm.files(name) if f.startswith("/")]
    fileset = set(files)
    libs = [f for f in files if re.search(r"\.so(\.|$)", os.path.basename(f))]
    binaries = [f for f in files if f.startswith(EXEC_DIRS)]
    units = {
        os.path.basename(f)
        for f in files
        if f.startswith(UNIT_DIRS) and f.endswith((".service", ".socket"))
    }
    ctx = {
        "installed": pm.installed_versions(name),
        "has_libraries": bool(libs),
        "libraries_loaded": sorted(f for f in libs if f in mapped),
        "has_binaries": bool(binaries),
        "binaries_running": sorted({e for e in exes.values() if e in fileset}),
        "listening": sorted({p for exe, ps in listening.items() if exe in fileset for p in ps}),
        "units": unit_states(units),
        "privileged_files": pm.privileged(name, files),
        "required_by": pm.required_by(name),
        "source": pm.source(name),
        # Servizio del nodo (o voce aggiunta) che ha bisogno di questo pacchetto.
        "needed_by": needed_by,
    }
    ctx["idle"] = is_idle(ctx, scan_ok)
    # La simulazione di rimozione serve solo per i pacchetti inattivi (è lenta).
    if ctx["idle"] and not is_kernel_package(name):
        ctx["removal_also_removes"] = pm.removal(name)
    else:
        ctx["removal_also_removes"] = None
    return ctx


# ---------------------------------------------------------------- gestori di pacchetti


class Rpm:
    """Database rpm: comune a dnf e zypper."""

    name = "rpm"

    def database(self):
        """Tre letture del database rpm: chi fornisce cosa, chi possiede quale file, chi
        richiede cosa. Le dipendenze si risolvono poi in memoria.

        Dentro [] rpm itera sugli array: il nome, che è un solo valore, va scritto %{=NAME}
        (ripetuto a ogni riga). Con %{NAME} rpm si rifiuta ("different sized arrays") per
        ogni pacchetto con più di un file, e il profilo resta vuoto.
        """
        provides, owners, requires = {}, {}, {}
        for line in run(["rpm", "-qa", "--qf", "[%{=NAME}|%{PROVIDENAME}\\n]"]).splitlines():
            name, _, cap = line.partition("|")
            if cap and cap != "(none)":
                provides.setdefault(cap, set()).add(name)
        for line in run(["rpm", "-qa", "--qf", "[%{=NAME}|%{FILENAMES}\\n]"]).splitlines():
            name, _, path = line.partition("|")
            if path.startswith("/"):
                owners.setdefault(canonical(path), set()).add(name)
        for line in run(["rpm", "-qa", "--qf", "[%{=NAME}|%{REQUIRENAME}\\n]"]).splitlines():
            name, _, cap = line.partition("|")
            if cap and cap != "(none)" and not cap.startswith("rpmlib("):
                requires.setdefault(name, set()).add(cap)
        installed = set(run(["rpm", "-qa", "--qf", "%{NAME}\\n"]).split())
        self.db = {"provides": provides, "owners": owners, "requires": requires}
        self.db["installed"] = installed
        return self.db

    def installed_versions(self, name):
        return run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", name]).splitlines()

    def files(self, name):
        return run(["rpm", "-ql", name]).splitlines()

    def privileged(self, name, files):
        out = run(["rpm", "-q", "--qf", "[%{FILEMODES:perms}|%{FILECAPS}|%{FILENAMES}\\n]", name])
        return parse_privileged(out)

    def required_by(self, name):
        return sorted(
            {
                line.rsplit("-", 2)[0]
                for line in run(["rpm", "-q", "--whatrequires", name]).splitlines()
                if line and "no package requires" not in line
            }
        )

    def source(self, name):
        return source_name(run(["rpm", "-q", "--qf", "%{SOURCERPM}\n", name]))


class Dnf(Rpm):
    name = "dnf"

    def security_updates(self, os_info):
        return merge_advisories(
            parse_updateinfo_list(run(["dnf", "-q", "updateinfo", "list", "--security"])),
            parse_updateinfo_info(run(["dnf", "-q", "updateinfo", "info", "--security"])),
        )

    def removal(self, name):
        out = run(["dnf", "remove", "--assumeno", "--noautoremove", name])
        return parse_remove_simulation(out, name)


class Zypper(Rpm):
    name = "zypper"

    def security_updates(self, os_info):
        run(["zypper", "-n", "--gpg-auto-import-keys", "-q", "refresh"])
        patches = parse_zypper_patches(
            run(["zypper", "-n", "--xmlout", "-q", "list-patches", "--category", "security"])
        )
        advisories, details = {}, {}
        for patch, info in patches.items():
            out = run(["zypper", "-n", "-q", "info", "-t", "patch", patch])
            advisories[patch] = {
                "severity": info["severity"],
                "packages": {
                    pkg: version
                    for pkg, version in parse_zypper_patch_info(out).items()
                    if pkg in self.db["installed"]
                },
            }
            details[patch] = {"cves": info["cves"], "issued": info["issued"]}
        return merge_advisories(advisories, details)

    def removal(self, name):
        out = run(["zypper", "-n", "remove", "--dry-run", "--no-clean-deps", name])
        return parse_zypper_remove_simulation(out, name)


def parse_deps(text):
    """'libc6 (>= 2.34), libssl3 | libssl1.1, perl:any' -> {'libc6', 'libssl3', ...}.
    Le alternative contano tutte: più dipendenze vuol dire meno pacchetti "inutilizzati"."""
    names = set()
    for part in re.split(r"[,|]", text):
        name = part.strip().split(" ", 1)[0].split(":", 1)[0]
        if name:
            names.add(name)
    return names


# Campi separati da tabulazioni: "|" compare nelle dipendenze alternative ("a | b").
DPKG_FIELDS = "\\t".join(
    [
        "${db:Status-Abbrev}",
        "${Package}",
        "${Version}",
        "${source:Package}",
        "${source:Version}",
        "${Depends}",
        "${Pre-Depends}",
        "${Provides}",
    ]
)
DPKG_FIELDS += "\\n"


def parse_dpkg_database(out):
    """Righe di dpkg-query -> pacchetti installati con versione, sorgente e dipendenze."""
    packages = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 8 or not parts[0].startswith("ii"):
            continue
        status, name, version, src, src_version, depends, pre, provides = parts
        packages[name] = {
            "version": version,
            "source": src or name,
            "source_version": src_version or version,
            "requires": parse_deps(depends) | parse_deps(pre),
            "provides": parse_deps(provides) | {name},
        }
    return packages


class Apt:
    name = "apt"

    def database(self):
        self.packages = parse_dpkg_database(run(["dpkg-query", "-W", "-f", DPKG_FIELDS]))
        provides, owners, requires = {}, {}, {}
        for name, info in self.packages.items():
            for cap in info["provides"]:
                provides.setdefault(cap, set()).add(name)
            requires[name] = set(info["requires"])
        for path in glob.glob("/var/lib/dpkg/info/*.list"):
            name = os.path.basename(path)[: -len(".list")].split(":", 1)[0]
            for line in read_file(path).splitlines():
                if line.startswith("/") and line != "/.":
                    owners.setdefault(canonical(line), set()).add(name)
        self.db = {"provides": provides, "owners": owners, "requires": requires}
        self.db["installed"] = set(self.packages)
        return self.db

    def security_updates(self, os_info):
        run(["apt-get", "update", "-qq"])
        out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"])
        ecosystem = apt_ecosystem(os_info)
        packages = {}
        for name, (old, new, origin, security) in parse_apt_simulation(out).items():
            info = self.packages.get(name, {})
            source = info.get("source", name)
            packages[name] = [
                {
                    # Segnaposto: SAGE lo sostituisce con DSA/DLA/USN e le CVE (lookup).
                    "id": origin.split("/", 1)[-1] + ":" + source + ":" + new,
                    "severity": "",
                    "fixed_version": new,
                    "cves": [],
                    "issued": "",
                    "lookup": {
                        "ecosystem": ecosystem,
                        "source": source,
                        "installed": info.get("source_version", old),
                        "fixed": new,
                        # Dal repository di sicurezza: resta anche se OSV non risponde.
                        "security": security,
                    },
                }
            ]
        return packages

    def installed_versions(self, name):
        version = self.packages.get(name, {}).get("version")
        return [version] if version else []

    def files(self, name):
        listed = glob.glob("/var/lib/dpkg/info/" + name + ".list")
        listed += glob.glob("/var/lib/dpkg/info/" + name + ":*.list")
        lines = []
        for path in listed:
            lines += [x for x in read_file(path).splitlines() if x != "/."]
        return lines

    def privileged(self, name, files):
        return privileged_from_disk(files)

    def required_by(self, name):
        caps = self.packages.get(name, {}).get("provides", {name})
        return sorted(
            other
            for other, info in self.packages.items()
            if other != name and info["requires"] & caps
        )

    def source(self, name):
        return self.packages.get(name, {}).get("source")

    def removal(self, name):
        out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "remove", name])
        return parse_apt_remove_simulation(out, name)


def package_manager():
    """Il gestore di pacchetti del nodo, o None se non è tra quelli supportati."""
    if shutil.which("dnf"):
        return Dnf()
    if shutil.which("zypper"):
        return Zypper()
    if shutil.which("apt-get") and shutil.which("dpkg-query"):
        return Apt()
    return None


# ---------------------------------------------------------------- profilo del nodo


def required_closure(seeds, db):
    """Pacchetti richiesti dai semi, anche indirettamente: pacchetto -> origine."""
    origin = dict(seeds)
    queue = list(seeds)
    while queue:
        pkg = queue.pop()
        for cap in sorted(db["requires"].get(pkg, ())):
            found = db["provides"].get(cap) or (
                db["owners"].get(canonical(cap)) if cap.startswith("/") else None
            )
            for provider in sorted(found or ()):
                if provider not in origin:
                    origin[provider] = origin[pkg]
                    queue.append(provider)
    return origin


def node_units():
    """Unit attive o abilitate (servizi, socket, timer): quello che il nodo esegue."""
    units = set()
    listed = run(
        [
            "systemctl",
            "list-units",
            "--type=" + UNIT_TYPES,
            "--state=active",
            "--no-legend",
            "--plain",
        ]
    )
    for line in listed.splitlines():
        if line.split():
            units.add(line.split()[0])
    enabled = run(
        ["systemctl", "list-unit-files", "--type=" + UNIT_TYPES, "--state=enabled", "--no-legend"]
    )
    for line in enabled.splitlines():
        name = line.split()[0] if line.split() else ""
        if name and "@." not in name:
            units.add(name)
    return units


def unit_paths(units):
    """unit -> file della unit ed eseguibili di ExecStart.

    `systemctl show` separa le unit con una riga vuota e non stampa le proprietà
    nell'ordine chiesto (ExecStart arriva prima di Id): si legge un blocco alla volta.
    Il file della unit si cerca anche direttamente nelle cartelle di systemd, così un
    output inatteso di systemctl non svuota il profilo.
    """
    paths = {}
    if not units:
        return paths
    names = sorted(units)
    out = run(["systemctl", "show", "-p", "Id", "-p", "FragmentPath", "-p", "ExecStart"] + names)
    for block in re.split(r"\n\s*\n", out):
        props = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props.setdefault(key, []).append(value)
        unit = (props.get("Id") or [""])[0]
        if unit not in units:
            continue
        files = paths.setdefault(unit, [])
        files += [canonical(v) for v in props.get("FragmentPath", []) if v.startswith("/")]
        for value in props.get("ExecStart", []):
            files += [canonical(p) for p in re.findall(r"path=(\S+)", value)]
    for unit in names:
        # 'getty@tty1.service' viene dal modello 'getty@.service'
        base = re.sub(r"@[^.]*\.", "@.", unit)
        for d in UNIT_DIRS:
            for name in {unit, base}:
                if os.path.exists(d + name):
                    paths.setdefault(unit, []).append(d + name)
    return paths


def node_profile(extra, db):
    """Servizi del nodo, pacchetti che servono a farli girare e voci aggiunte a mano.

    `extra`: unit o pacchetti dichiarati in configurazione (servizi fuori da Kubernetes
    che devono restare, anche se in quel momento non girano).
    """
    units = node_units()
    missing = []
    extra_packages = []
    for item in extra:
        if item in db["installed"]:
            extra_packages.append(item)
        elif "." in item:
            units.add(item)
        else:
            missing.append(item)
    seeds = {}
    paths = unit_paths(units)
    for unit, files in sorted(paths.items()):
        for path in files:
            for pkg in sorted(db["owners"].get(path, ())):
                seeds.setdefault(pkg, unit)
    # Unit aggiunte a mano ma inesistenti sul nodo: segnalate, non ignorate in silenzio.
    missing += [u for u in sorted(units) if u in extra and not paths.get(u)]
    for pkg in extra_packages:
        seeds.setdefault(pkg, pkg + " (aggiunto)")
    required = required_closure(seeds, db)
    return {
        "unit_files": sum(1 for files in paths.values() if files),
        "seeds": len(seeds),
        "units": sorted(units),
        "extra": sorted(extra),
        "extra_missing": sorted(set(missing)),
        "installed_packages": len(db["installed"]),
        "required": dict(sorted(required.items())),
    }


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


def parse_args(argv):
    """--extra a,b,c: servizi o pacchetti aggiuntivi del nodo."""
    extra = []
    for i, arg in enumerate(argv):
        if arg == "--extra" and i + 1 < len(argv):
            extra = [x.strip() for x in argv[i + 1].split(",") if x.strip()]
    return extra


def main(argv=None):
    extra = parse_args(sys.argv[1:] if argv is None else argv)
    pm = package_manager()
    if pm is None:
        print(json.dumps({"error": "gestore di pacchetti non supportato (dnf, zypper, apt)"}))
        return 2
    os_info = os_release()
    db = pm.database()
    updates = pm.security_updates(os_info)
    exes, mapped, container_processes = running_state()
    listening = listening_exes(exes)
    profile = node_profile(extra, db)
    profile["container_processes"] = container_processes
    # Controllo di coerenza: qualche file in uso dai processi del nodo deve appartenere a
    # un pacchetto (almeno la libc). Se no, la lettura non è affidabile e nessun pacchetto
    # viene dichiarato inattivo.
    profile["process_scan_ok"] = any(f in db["owners"] for f in mapped)

    packages = {}
    for name, advisories in updates.items():
        packages[name] = {"advisories": sorted(advisories, key=lambda a: a["id"])}
        packages[name]["context"] = package_context(
            pm,
            name,
            exes,
            mapped,
            listening,
            profile["required"].get(name),
            profile["process_scan_ok"],
        )
    advisory_ids = {a["id"] for p in packages.values() for a in p["advisories"]}

    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "node": {
                    "hostname": socket.gethostname(),
                    "role": node_role(),
                    "os": os_info,
                    "package_manager": pm.name,
                    "arch": platform.machine(),
                },
                "kernel": kernel_facts(),
                "profile": profile,
                "summary": {
                    "advisories": len(advisory_ids),
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
