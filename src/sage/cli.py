"""Riga di comando di SAGE: un solo eseguibile per tutti i passi."""

from __future__ import annotations

import argparse
import sys

from sage import __version__, config

NOT_YET = {
    "scan": "M2",
    "analyze": "M5",
    "remediate": "M6",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="stampa la versione")

    check = sub.add_parser("check-config", help="valida un file di configurazione")
    check.add_argument("--config", required=True, help="percorso del file YAML")

    for name in NOT_YET:
        p = sub.add_parser(name, help=f"(milestone {NOT_YET[name]})")
        p.add_argument("--config", required=True, help="percorso del file YAML")
        p.add_argument("--dry-run", action="store_true", help="non modifica nulla")

    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "check-config":
        try:
            cfg = config.load(args.config)
        except (OSError, config.ConfigError) as exc:
            print(exc, file=sys.stderr)
            return 1
        mode = "solo regole deterministiche" if cfg.llm.safe_mode_only else "con LLM"
        print(f"configurazione valida: {len(cfg.groups)} gruppi, {mode}")
        return 0

    print(
        f"'{args.command}' non ancora implementato (milestone {NOT_YET[args.command]})",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
