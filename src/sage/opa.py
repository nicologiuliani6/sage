"""Chiamata a OPA: una sola valutazione per tutte le coppie (nodo, pacchetto)."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from sage import paths


class OpaError(RuntimeError):
    pass


def decide(items: list[dict[str, Any]], config_data: dict[str, Any]) -> list[dict[str, str]]:
    if not items:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "input.json"
        data_path = Path(tmp) / "data.json"
        input_path.write_text(json.dumps({"items": items}))
        data_path.write_text(json.dumps({"sage": {"config": config_data}}))
        cmd = [
            paths.opa_bin(),
            "eval",
            "--format",
            "json",
            "--data",
            str(paths.policy_dir()),
            "--data",
            str(data_path),
            "--input",
            str(input_path),
            "data.sage.batch.results",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise OpaError(proc.stderr.strip() or proc.stdout.strip())
    try:
        results = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise OpaError(f"risposta di OPA inattesa: {exc}") from exc
    if len(results) != len(items):
        raise OpaError("OPA ha restituito un numero di decisioni diverso dagli input")
    return results
