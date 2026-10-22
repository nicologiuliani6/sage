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


def set_log_level(cfg: config.Config) -> None:
    logging.getLogger().setLevel(logging.DEBUG if cfg.log_level == "debug" else logging.INFO)


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
    """Controllo completo: raccolta, analisi, decisioni, report. Nessuna modifica ai nodi:
    le remediation le avvia il controllore (`sage controller`)."""
    from sage.kube import Kube

    cfg = config.load(args.config)
    set_log_level(cfg)
    return full_scan(cfg, Kube(), _release(), args.dry_run)


def track_urgent(analysis, previous: dict, now: datetime) -> dict:
    """Quando è stata trovata ogni CVE grave ancora da sistemare: 'nodo|pacchetto' -> ora."""
    current = {}
    for node, decisions in analysis.decisions.items():
        for d in decisions:
            if d.priority == "act" and d.action in ("update", "remove", "mitigate"):
                key = f"{node}|{d.package}"
                current[key] = previous.get(key) or now.isoformat()
    return current


def full_scan(cfg: config.Config, kube, release: str, dry_run: bool) -> int:
    from sage import act, opa, paths, report, sources
    from sage.analyze import Analyzer
    from sage.collect import collect
    from sage.inventory import assign_groups
    from sage.llm import LlmChain

    now = datetime.now(ZoneInfo(cfg.timezone))
    log.info("giro %s (%s)", "in simulazione" if dry_run else "REALE", cfg.timezone)

    nodes = kube.list_nodes()
    groups, warnings = assign_groups(nodes, cfg.groups)
    targets = [n for n in nodes if groups.get(n.name)]
    log.info("nodi nel cluster: %d, gestiti da SAGE: %d", len(nodes), len(targets))
    reports = collect(targets, cfg, paths.workdir() / "scan")
    log.info("raccolta completata: %d nodi su %d", len(reports), len(targets))
    warnings += [
        f"nodo {n.name} non raggiunto: escluso da questo giro"
        for n in targets
        if n.name not in reports
    ]

    state = kube.read_json(f"{release}-state") or {}
    state["last_scan"] = now.isoformat()
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
    log.info(
        "catalogo KEV: %s", f"{len(kev)} CVE sfruttate" if kev is not None else "non disponibile"
    )
    epss = sources.fetch_epss(cfg.sources, all_cves)
    log.info("EPSS: %d CVE su %d", len(epss), len(all_cves))
    chain = LlmChain(cfg.llm)
    analyzer = Analyzer(
        cfg,
        chain,
        lambda cve: sources.fetch_cve_record(cfg.sources, cve),
        opa.decide,
        now,
        save_cache=lambda c: kube.write_json(f"{release}-llm-cache", c),
    )
    analysis = analyzer.run(reports, groups, state.get("idle", {}), cache, kev, epss)
    state["idle"] = analysis.idle
    # Le CVE gravi dei nodi non raggiunti restano con la loro data di scoperta.
    previous = state.get("urgent", {})
    state["urgent"] = {
        **{k: v for k, v in previous.items() if k.split("|", 1)[0] not in reports},
        **track_urgent(analysis, previous, now),
    }
    kube.write_json(f"{release}-llm-cache", analysis.cache)
    if state["urgent"]:
        log.info(
            "CVE gravi da sistemare entro %d ore: %d pacchetti",
            cfg.policy.urgent_deadline_hours,
            len(state["urgent"]),
        )

    log.info("analisi completata, chiamate LLM: %d", chain.calls)
    plans = act.build_plans(analysis.decisions, groups)
    messages: list[str] = []
    kube.write_json(f"{release}-state", state)

    plan_dicts = {n: p.to_dict() for n, p in plans.items()}
    data = report.to_json(analysis, plan_dicts, messages, warnings, now, dry_run)
    data["vex"] = report.openvex(analysis, reports, now)
    data["profiles"] = {node: r.get("profile") for node, r in reports.items()}
    kube.write_json(f"{release}-report", data)
    log.info("report salvato in %s-report", release)
    print(report.summary(analysis, groups, plan_dicts, messages, warnings, dry_run, reports))
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    from sage import paths, remediate
    from sage.kube import Kube

    cfg = config.load(args.config)
    set_log_level(cfg)
    plan = json.loads(base64.b64decode(args.plan))
    return remediate.run(cfg, Kube(), args.node, plan, paths.workdir() / "remediate")


def cmd_resume(args: argparse.Namespace) -> int:
    from sage.kube import Kube

    Kube().set_flag(f"{_release()}-resume")
    print("richiesta inviata: il controllore riprende al prossimo passo")
    return 0


def cmd_controller(args: argparse.Namespace) -> int:
    from sage import controller
    from sage.kube import Kube

    cfg = config.load(args.config)
    set_log_level(cfg)
    controller.run(controller.Controller(cfg, Kube(), _release(), args.dry_run))
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from sage import dashboard
    from sage.kube import Kube

    refresh = max(dashboard.MIN_REFRESH, args.refresh)
    source = dashboard.Source(Kube(), _release(), args.config, ttl=refresh)
    dashboard.serve(source, args.bind, args.port, refresh)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sage", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="stampa la versione")

    p = sub.add_parser("check-config", help="valida un file di configurazione")
    p.add_argument("--config", required=True)

    p = sub.add_parser("scan", help="controllo completo: raccoglie, analizza, decide, report")
    p.add_argument("--config", required=True)
    p.add_argument("--dry-run", action="store_true", help="nessuna modifica ai nodi")

    p = sub.add_parser(
        "controller", help="loop sempre acceso: controllo, remediation nodo per nodo, pausa"
    )
    p.add_argument("--config", required=True)
    p.add_argument("--dry-run", action="store_true", help="nessuna modifica ai nodi")

    p = sub.add_parser("remediate", help="esegue il piano su un nodo (usato dai Job)")
    p.add_argument("--config", required=True)
    p.add_argument("--node", required=True)
    p.add_argument("--plan", required=True, help="piano in JSON codificato base64")

    sub.add_parser("resume", help="riprende dopo un errore, una volta controllato il nodo")

    p = sub.add_parser("dashboard", help="dashboard web di sola lettura")
    p.add_argument("--config", required=True)
    p.add_argument("--bind", default="127.0.0.1", help="indirizzo (predefinito solo locale)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument(
        "--refresh", type=int, default=5, help="secondi tra un aggiornamento e l'altro (min. 2)"
    )

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.command == "version":
        print(__version__)
        return 0
    handlers = {
        "check-config": cmd_check_config,
        "scan": cmd_scan,
        "controller": cmd_controller,
        "remediate": cmd_remediate,
        "resume": cmd_resume,
        "dashboard": cmd_dashboard,
    }
    from sage.kube import KubeUnavailable

    try:
        return handlers[args.command](args)
    except (config.ConfigError, KubeUnavailable) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
