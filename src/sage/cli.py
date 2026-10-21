"""Riga di comando di SAGE: un solo eseguibile per tutti i passi."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from sage import __version__, config

log = logging.getLogger("sage")


def _release() -> str:
    return os.environ.get("SAGE_RELEASE", "sage")


def cmd_check_config(args: argparse.Namespace) -> int:
    try:
        cfg = config.load(args.config)
    except (OSError, config.ConfigError) as exc:
        print(exc, file=sys.stderr)
        return 1
    mode = "solo regole deterministiche" if cfg.llm.safe_mode_only else "con LLM"
    print(f"configurazione valida: {len(cfg.groups)} gruppi, {mode}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from sage import act, opa, paths, report, sources
    from sage.analyze import Analyzer
    from sage.collect import collect
    from sage.inventory import assign_groups
    from sage.kube import Kube
    from sage.llm import LlmChain

    cfg = config.load(args.config)
    kube = Kube()
    release = _release()
    now = datetime.now(ZoneInfo(cfg.timezone))

    nodes = kube.list_nodes()
    groups, warnings = assign_groups(nodes, cfg.groups)
    targets = [n for n in nodes if groups.get(n.name)]
    reports = collect(targets, cfg, paths.workdir() / "scan")
    warnings += [
        f"nodo {n.name} non raggiunto: escluso da questo giro"
        for n in targets
        if n.name not in reports
    ]

    state = kube.read_json(f"{release}-state") or {}
    cache = kube.read_json(f"{release}-llm-cache") or {}
    kev = sources.fetch_kev(cfg.sources)
    all_cves = sorted(
        {
            c
            for r in reports.values()
            for p in r.get("packages", {}).values()
            for a in p.get("advisories", [])
            for c in a.get("cves", [])
        }
    )
    epss = sources.fetch_epss(cfg.sources, all_cves)
    chain = LlmChain(cfg.llm)
    analyzer = Analyzer(
        cfg, chain, lambda cve: sources.fetch_cve_record(cfg.sources, cve), opa.decide, now
    )
    analysis = analyzer.run(reports, groups, state.get("idle", {}), cache, kev, epss)
    state["idle"] = analysis.idle
    kube.write_json(f"{release}-llm-cache", analysis.cache)

    plans = act.build_plans(analysis.decisions, groups, now)
    resumed = []
    if kube.pop_flag(f"{release}-resume") and state.get("halted"):
        resumed = [f"ondate sbloccate su richiesta (era: {state.get('halt_reason')})"]
        act.resume(state)
    messages = resumed + act.step(
        cfg, kube, chain, release, nodes, groups, plans, state, now, args.dry_run
    )
    kube.write_json(f"{release}-state", state)

    plan_dicts = {n: p.to_dict() for n, p in plans.items()}
    data = report.to_json(analysis, plan_dicts, messages, warnings, now, args.dry_run)
    data["vex"] = report.openvex(analysis, reports, now)
    kube.write_json(f"{release}-report", data)
    print(report.summary(analysis, groups, plan_dicts, messages, warnings, args.dry_run))
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    from sage import paths, remediate
    from sage.kube import Kube

    cfg = config.load(args.config)
    plan = json.loads(base64.b64decode(args.plan))
    return remediate.run(cfg, Kube(), args.node, plan, paths.workdir() / "remediate")


def cmd_resume(args: argparse.Namespace) -> int:
    from sage import act
    from sage.kube import Kube

    kube = Kube()
    name = f"{_release()}-state"
    state = kube.read_json(name) or {}
    if not state.get("halted"):
        print("SAGE non è fermo: niente da sbloccare")
        return 0
    reason = state.get("halt_reason")
    failed = act.resume(state)
    kube.write_json(name, state)
    print(f"sbloccato (era: {reason}); nodi riportati in attesa: {', '.join(failed) or 'nessuno'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="stampa la versione")

    p = sub.add_parser("check-config", help="valida un file di configurazione")
    p.add_argument("--config", required=True)

    p = sub.add_parser("scan", help="raccoglie, analizza, decide e fa avanzare le ondate")
    p.add_argument("--config", required=True)
    p.add_argument("--dry-run", action="store_true", help="nessuna modifica ai nodi")

    p = sub.add_parser("remediate", help="esegue il piano su un nodo (usato dai Job)")
    p.add_argument("--config", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--plan", required=True, help="piano in JSON codificato base64")

    sub.add_parser("resume", help="sblocca le ondate dopo un errore controllato a mano")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "version":
        print(__version__)
        return 0
    handlers = {
        "check-config": cmd_check_config,
        "scan": cmd_scan,
        "remediate": cmd_remediate,
        "resume": cmd_resume,
    }
    from sage.kube import KubeUnavailable

    try:
        return handlers[args.command](args)
    except (config.ConfigError, KubeUnavailable) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
