"""Scrive nell'installer i dati di una release: immagine, chart e Helm con i checksum.

Uso: python3 ci/stamp_installer.py SORGENTE DESTINAZIONE chiave=valore...
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

MARKER = "# sage-install:release"
REQUIRED = ("version", "image", "chart_url", "chart_sha256")


def stamp(source: str, data: dict[str, str]) -> str:
    if not all(isinstance(k, str) and isinstance(v, str) and v for k, v in data.items()):
        raise ValueError("solo coppie chiave=valore di stringhe non vuote")
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise ValueError(f"mancano: {', '.join(missing)}")
    if "@sha256:" not in data["image"]:
        raise ValueError("l'immagine va indicata per digest (repo@sha256:...)")
    if "chart_b64" in data:
        chart = base64.b64decode(data["chart_b64"], validate=True)
        if hashlib.sha256(chart).hexdigest() != data["chart_sha256"]:
            raise ValueError("chart_b64 non corrisponde a chart_sha256")
    lines = source.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.rstrip().endswith(MARKER)]
    if len(hits) != 1:
        raise ValueError(f"il marcatore {MARKER!r} deve comparire una volta sola")
    payload = json.dumps(data, sort_keys=True, ensure_ascii=True)
    lines[hits[0]] = f"RELEASE: dict = {payload}  {MARKER}\n"
    return "".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    source, target, *pairs = argv
    data = dict(p.split("=", 1) for p in pairs)
    Path(target).write_text(stamp(Path(source).read_text(), data))
    Path(target).chmod(0o755)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
