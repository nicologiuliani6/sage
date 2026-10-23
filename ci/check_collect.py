"""Controlla il JSON del collector girato in un container (ci/distros.sh).

Uso: python3 ci/check_collect.py <nome> <gestore atteso> < output
Stampa un'annotazione con il riepilogo; esce con 1 se il JSON non va.
"""

import json
import sys


def fail(name: str, why: str, text: str) -> None:
    tail = text[-1500:].replace("%", "%25").replace("\n", "%0A")
    print(f"::error title=collector {name}::{why}%0A{tail}")
    sys.exit(1)


def main() -> None:
    name, pm = sys.argv[1], sys.argv[2]
    text = sys.stdin.read()
    try:
        report = json.loads(text)
    except json.JSONDecodeError:
        fail(name, "output non JSON", text)
    if "error" in report:
        fail(name, report["error"], text)
    node = report["node"]
    if node.get("package_manager") != pm:
        fail(name, f"gestore {node.get('package_manager')} invece di {pm}", text)
    profile = report["profile"]
    if profile["installed_packages"] < 50:
        fail(name, "database dei pacchetti quasi vuoto", text)
    packages = report["packages"]
    for pkg, entry in packages.items():
        ctx = entry["context"]
        if not entry["advisories"] or not ctx["installed"]:
            fail(name, f"{pkg}: advisory o versione installata mancanti", text)
        if pm == "apt" and not entry["advisories"][0].get("lookup", {}).get("ecosystem"):
            fail(name, f"{pkg}: ecosistema OSV mancante", text)
    sample = next(iter(sorted(packages.items())), None)
    summary = (
        f"{node['os']['name']} {node['os']['version']}: {len(packages)} pacchetti da "
        f"aggiornare, {profile['installed_packages']} installati, "
        f"{len(report['kernel']['modules'])} moduli"
    )
    if sample:
        summary += f"%0Aesempio {sample[0]}: {json.dumps(sample[1]['advisories'][0])[:600]}"
    print(f"::notice title=collector {name}::{summary}")


if __name__ == "__main__":
    main()
