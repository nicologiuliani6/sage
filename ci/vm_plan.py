"""Piano per la prova su VM Debian (ci/vm_debian.sh): report del collector + OSV vero.

Uso: uv run python ci/vm_plan.py <report.json> <cartella di uscita>
Scrive plan.json (pacchetti e advisory da aggiornare) e stampa un riepilogo.
"""

import json
import sys
from pathlib import Path

from sage import osv
from sage.config import SourcesConfig

# Mai usati per la prova del rollback: se il rollback andasse male, la VM non si userebbe più.
CRITICAL = ("libc", "linux-", "systemd", "dpkg", "apt", "libapt", "base-", "init", "udev")


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2])
    listed = len(report["packages"])
    kept = osv.enrich({"vm": report}, SourcesConfig())
    packages = report["packages"]
    advisories = sorted({a["id"] for p in packages.values() for a in p["advisories"]})
    cves = sorted({c for p in packages.values() for a in p["advisories"] for c in a["cves"]})
    named = [a for a in advisories if a.startswith(osv.ADVISORY_PREFIXES)]
    if not packages or not cves:
        print(f"::error title=vm debian::OSV: {kept} pacchetti su {listed}, {len(cves)} CVE")
        sys.exit(1)
    leaf = [n for n in sorted(packages) if not n.startswith(CRITICAL)]
    (out / "plan.json").write_text(
        json.dumps({"packages": sorted(packages), "advisories": advisories, "leaf": leaf})
    )
    print(
        f"aggiornamenti disponibili {listed}, con vulnerabilità note {len(packages)}, "
        f"advisory {len(named)} (es. {', '.join(named[:3])}), CVE {len(cves)}"
    )


if __name__ == "__main__":
    main()
