"""kubectl, helm e ssh finti per provare l'installer senza un cluster.

Un solo script, invocato tramite collegamenti con il nome del comando. Lo stato sta
in un file JSON (variabile FAKE_STATE). Ogni nodo finto ha una home: i comandi SSH
di installazione e rimozione della chiave vengono eseguiti davvero lì, così si prova
anche il loro shell. Solo libreria standard: gira anche con Python 3.9.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE = Path(os.environ["FAKE_STATE"])


def load():
    return json.loads(STATE.read_text())


def save(state):
    STATE.write_text(json.dumps(state, indent=1))


def out(obj):
    print(json.dumps(obj) if not isinstance(obj, str) else obj)
    return 0


def fail(msg, code=1):
    print(msg, file=sys.stderr)
    return code


# ------------------------------------------------------------------ kubectl


def node_doc(state, name):
    n = state["nodes"][name]
    capacity = {"cpu": "4"}
    if n.get("gpus"):
        capacity["nvidia.com/gpu"] = str(n["gpus"])
    return {
        "metadata": {"name": name, "labels": state["labels"].get(name, {})},
        "spec": {},
        "status": {
            "addresses": [{"type": "InternalIP", "address": n["ip"]}],
            "capacity": capacity,
            "conditions": [{"type": "Ready", "status": "True"}],
            "nodeInfo": {"osImage": n.get("os", "Rocky Linux 9.4"), "kernelVersion": "5.14"},
        },
    }


def kubectl(args):
    state = load()
    state["calls"].append(["kubectl"] + args)
    save(state)
    clean, i = [], 0
    while i < len(args):
        if args[i] in ("--context", "-n"):
            i += 2
            continue
        clean.append(args[i])
        i += 1
    a = clean
    if a[:2] == ["config", "current-context"]:
        return out("fake")
    if a[:2] == ["get", "--raw"]:
        return out({"gitVersion": "v1.34.3"})
    if a[:2] == ["auth", "can-i"]:
        return out("yes")
    if a[:2] == ["auth", "whoami"]:
        return out("fake-admin")
    if a[:2] == ["get", "nodes"]:
        return out({"items": [node_doc(state, n) for n in state["nodes"]]})
    if a[:3] == ["get", "svc", "kubernetes"]:
        return out("10.96.0.1")
    if a[:2] == ["get", "secret"]:
        secret = state["secrets"].get(a[2])
        if secret is None:
            return fail(f'secrets "{a[2]}" not found')
        return out(secret)
    if a[:2] == ["get", "namespace"]:
        ns = state["namespace"]
        return out(ns) if ns else fail("not found")
    if a[:3] == ["create", "-f", "-"]:
        text = sys.stdin.read()
        if text.lstrip().startswith("{"):
            state["namespace"] = json.loads(text)
        else:  # Job di controllo in YAML (dal modello del chart)
            name = text.split("name: ", 1)[1].split()[0]
            assert "sage.io/role: scan" in text
            state["jobs"].append(name)
        save(state)
        return out("created")
    if a[:2] == ["create", "configmap"]:
        state.setdefault("flags", []).append(a[2])
        if a[2].endswith("-scan-now"):  # il controllore finto avvia subito il controllo
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state.setdefault("scan_jobs", []).append({"name": "sage-scan-1", "created": stamp})
        save(state)
        return out("configmap created")
    if a[0] == "apply":
        doc = json.loads(sys.stdin.read())
        store = "configmaps" if doc["kind"] == "ConfigMap" else "secrets"
        state[store][doc["metadata"]["name"]] = doc
        save(state)
        return out("applied")
    if a[:2] == ["get", "configmap"] and a[2].endswith("-scan-template"):
        job = "apiVersion: batch/v1\nkind: Job\nmetadata:\n  labels:\n    sage.io/role: scan\n"
        return out({"data": {"job.yaml": job}})
    if a[:2] == ["get", "configmap"]:
        cm = state["configmaps"].get(a[2])
        return out(cm) if cm else fail(f'configmaps "{a[2]}" not found')
    if a[:2] == ["label", "node"]:
        labels = state["labels"].setdefault(a[2], {})
        spec = a[3]
        if spec.endswith("-"):
            labels.pop(spec[:-1], None)
        else:
            key, value = spec.split("=", 1)
            labels[key] = value
        save(state)
        return out("labeled")
    if a[:2] == ["create", "job"]:
        state["jobs"].append(a[3])
        save(state)
        return out("job created")
    if a[:2] == ["get", "pods"]:
        return out({"items": [{"status": {"phase": "Succeeded", "containerStatuses": []}}]})
    if a[0] == "logs":
        return out("riepilogo del giro (finto)")
    if a[:2] == ["get", "job"]:
        return out({"status": {"succeeded": 1}})
    if a[:2] == ["get", "jobs"]:
        if "sage.io/role=scan" in a:
            items = [
                {"metadata": {"name": j["name"], "creationTimestamp": j["created"]}}
                for j in state.get("scan_jobs", [])
            ]
            return out({"items": items})
        return out({"items": []})
    if a[:2] == ["rollout", "status"]:
        return out("deployment successfully rolled out")
    if a[0] == "port-forward":
        return out("Forwarding from 127.0.0.1")  # in realtà resta aperto fino a Ctrl+C
    if a[0] == "delete":
        state["deleted"].append(a[1:])
        store = {"secret": "secrets", "configmap": "configmaps"}.get(a[1])
        if store:
            state[store].pop(a[2], None)
        save(state)
        return 0
    return fail(f"kubectl finto: comando inatteso {a}", 3)


# ------------------------------------------------------------------ helm


def helm(args):
    state = load()
    state["calls"].append(["helm"] + args)
    save(state)
    if args[0] == "status":
        if state["helm"] is None:
            return fail("Error: release: not found")
        return out({"version": state["helm"]["revision"]})
    if args[:2] == ["get", "values"]:
        return out(state["helm"]["values"])
    if args[0] == "history":
        return out([{"revision": state["helm"]["revision"], "status": "deployed"}])
    if args[:2] == ["upgrade", "--install"]:
        values_file = args[args.index("-f") + 1]
        state["revision"] = state.get("revision", 0) + 1
        state["helm"] = {
            "chart": args[3],
            "values": json.loads(Path(values_file).read_text()),
            "description": args[args.index("--description") + 1],
            "revision": state["revision"],
        }
        save(state)
        return out("Release installata")
    if args[0] == "uninstall":
        state["helm"] = None
        save(state)
        return out("release uninstalled")
    return fail(f"helm finto: comando inatteso {args}", 3)


# ------------------------------------------------------------------ ssh


def public_blob(key_path):
    line = subprocess.run(
        ["ssh-keygen", "-y", "-f", key_path], capture_output=True, text=True, check=True
    ).stdout
    return line.split()[1]


def ssh(args):
    key, rest, i = None, [], 0
    while i < len(args):
        if args[i] in ("-o", "-p"):
            i += 2
            continue
        if args[i] == "-i":
            key = args[i + 1]
            i += 2
            continue
        rest.append(args[i])
        i += 1
    target, command = rest[0], rest[1]
    ip = target.split("@", 1)[1]
    state = load()
    node = next((n for n in state["nodes"].values() if n["ip"] == ip), None)
    if node is None:
        return fail(f"ssh: connect to host {ip} port 22: No route to host", 255)
    home = Path(state["homes"]) / ip
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    auth = home / ".ssh" / "authorized_keys"
    if key:
        allowed = auth.exists() and public_blob(key) in auth.read_text()
    else:
        allowed = node.get("admin", True)
    if not allowed:
        return fail(f"{target}: Permission denied (publickey,gssapi-keyex).", 255)
    if "SAGE-CHECK" in command:
        print("SAGE-CHECK:" + "".join(" " + p for p in node.get("problems", [])))
        return 0
    env = dict(os.environ, HOME=str(home))
    return subprocess.run(["sh", "-c", command], env=env).returncode


def main():
    name = Path(sys.argv[0]).name
    handler = {"kubectl": kubectl, "helm": helm, "ssh": ssh}[name]
    return handler(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
