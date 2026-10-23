"""Configurazione di SAGE.

Tutto ciò che dipende dall'ambiente (gruppi di nodi, utente SSH, endpoint LLM,
pacchetti protetti) arriva da qui. Il codice non contiene valori di uno
specifico cluster: i campi obbligatori mancanti sono un errore, non un default.
I soli default presenti sono valori prudenti e indipendenti dall'ambiente
(es. gli URL pubblici di CISA, FIRST e del CVE Program).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

KERNEL_MODES = ("auto", "manual")
DRAIN_MODES = ("evict", "wait-empty")
LOG_LEVELS = ("info", "debug")
# Nome di una unit systemd o di un pacchetto.
SERVICE_RE = re.compile(r"^[A-Za-z0-9@._:+-]{1,128}$")


class ConfigError(ValueError):
    """Configurazione non valida: il messaggio elenca tutti i problemi trovati."""


@dataclass(frozen=True)
class SshConfig:
    user: str
    key_path: str
    known_hosts_path: str | None = None
    proxy_jump: str | None = None
    port: int = 22


@dataclass(frozen=True)
class LlmEndpoint:
    name: str
    base_url: str
    model: str
    api_key_env: str | None = None
    # Gruppo di nodi che ospita questo endpoint (per la regola requires_fallback).
    hosted_in_group: str | None = None


@dataclass(frozen=True)
class LlmConfig:
    endpoints: tuple[LlmEndpoint, ...] = ()
    timeout_seconds: int = 60
    max_calls_per_run: int = 100
    min_interval_seconds: float = 0.0

    @property
    def safe_mode_only(self) -> bool:
        """Senza endpoint SAGE usa solo le regole deterministiche."""
        return not self.endpoints


@dataclass(frozen=True)
class NodeGroup:
    name: str
    selector: str
    order: int
    # Primo nodo del gruppo nel giro: se qualcosa va storto, si ferma lì.
    canary: str | None = None
    # auto: il kernel si aggiorna nel giro come il resto; manual: mai in automatico.
    kernel: str = "auto"
    drain: str = "evict"
    drain_timeout_seconds: int = 1800
    allow_remove: bool = False
    allow_mitigate: bool = False
    requires_fallback: bool = False
    health_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyConfig:
    protected_packages: tuple[str, ...] = ()
    protected_modules: tuple[str, ...] = ()
    # Un pacchetto è "inutilizzato" solo se nessun processo lo usa da almeno tanti controlli
    # consecutivi E da almeno tanti giorni: con il controllore in loop i controlli sono
    # frequenti, e gli strumenti usati a mano o di notte vanno visti per un periodo lungo.
    idle_scans_required: int = 3
    idle_days_required: int = 7
    epss_attend_threshold: float = 0.1
    # Entro quante ore dalla scoperta una CVE grave (priorità act) deve essere sistemata.
    urgent_deadline_hours: int = 6


@dataclass(frozen=True)
class SourcesConfig:
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://api.first.org/data/v1/epss"
    cve_api_url: str = "https://cveawg.mitre.org/api/cve"
    # Debian e Ubuntu: advisory e CVE degli aggiornamenti di sicurezza (ADR-0017).
    osv_url: str = "https://api.osv.dev/v1"
    timeout_seconds: int = 30


@dataclass(frozen=True)
class ControllerConfig:
    """Il controllore gira in loop: controllo completo, remediation nodo per nodo, pausa."""

    # Attesa tra la fine di un giro e l'inizio del successivo (0 = subito).
    pause_minutes: int = 30
    # Ogni quanti secondi il controllore guarda lo stato dei Job.
    poll_seconds: int = 30


@dataclass(frozen=True)
class Config:
    ssh: SshConfig
    llm: LlmConfig
    groups: tuple[NodeGroup, ...]
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    sources: SourcesConfig = field(default_factory=SourcesConfig)
    # Fuso orario degli orari nel report e nei log.
    timezone: str = "UTC"
    # Dettaglio del log: "info" (fasi e avanzamento) o "debug" (anche ogni CVE e la cache).
    log_level: str = "info"
    # Servizi (unit systemd) o pacchetti fuori da Kubernetes che un nodo deve tenere:
    # nome del nodo -> elenco. Contano come necessari anche quando non girano.
    extra_services: dict[str, tuple[str, ...]] = field(default_factory=dict)
    controller: ControllerConfig = field(default_factory=ControllerConfig)

    def group(self, name: str) -> NodeGroup | None:
        return next((g for g in self.groups if g.name == name), None)

    def to_policy_data(self) -> dict[str, Any]:
        """Parte della configurazione passata a OPA come documento `data`."""
        return {"protected_packages": list(self.policy.protected_packages)}


def load(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return parse(raw)


def parse(raw: dict[str, Any]) -> Config:
    errors: list[str] = []

    if not isinstance(raw, dict):
        raise ConfigError("la configurazione deve essere un oggetto YAML")

    ssh = _parse_ssh(raw.get("ssh"), errors)
    llm = _parse_llm(raw.get("llm") or {}, errors)
    groups = _parse_groups(raw.get("groups"), errors)
    policy = _parse_policy(raw.get("policy") or {}, errors)
    sources = _parse_sources(raw.get("sources") or {}, errors)
    timezone = raw.get("timezone", "UTC")
    try:
        ZoneInfo(str(timezone))
    except (ZoneInfoNotFoundError, ValueError):
        errors.append(f"timezone: fuso orario sconosciuto ({timezone!r}), es. 'Europe/Rome'")
        timezone = "UTC"

    log_level = raw.get("log_level", "info")
    if log_level not in LOG_LEVELS:
        errors.append(f"log_level: uno tra {', '.join(LOG_LEVELS)}")
        log_level = "info"

    extra_services = _parse_extra_services(raw.get("extra_services"), errors)
    controller = _parse_controller(raw.get("controller") or {}, errors)

    group_names = {g.name for g in groups}
    for ep in llm.endpoints:
        if ep.hosted_in_group and ep.hosted_in_group not in group_names:
            errors.append(f"llm.endpoints '{ep.name}'.hosted_in_group: gruppo inesistente")

    if errors:
        raise ConfigError("configurazione non valida:\n- " + "\n- ".join(errors))
    return Config(
        ssh=ssh,
        llm=llm,
        groups=groups,
        policy=policy,
        sources=sources,
        timezone=str(timezone),
        log_level=log_level,
        extra_services=extra_services,
        controller=controller,
    )


# ------------------------------------------------------------------ helper


def _require_str(obj: dict[str, Any], key: str, where: str, errors: list[str]) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}.{key}: obbligatorio (stringa non vuota)")
        return ""
    return value.strip()


def _int(obj: dict, key: str, default: int, where: str, errors: list[str], minimum: int) -> int:
    value = obj.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        errors.append(f"{where}.{key}: intero >= {minimum}")
        return default
    return value


def _number(obj: dict, key: str, default: float, where: str, errors: list[str]) -> float:
    value = obj.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        errors.append(f"{where}.{key}: numero >= 0")
        return default
    return float(value)


def _str_list(obj: dict, key: str, where: str, errors: list[str]) -> tuple[str, ...]:
    value = obj.get(key) or []
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        errors.append(f"{where}.{key}: lista di stringhe")
        return ()
    return tuple(value)


def _url(value: str, where: str, errors: list[str]) -> None:
    if value and not value.startswith(("http://", "https://")):
        errors.append(f"{where}: deve iniziare con http:// o https://")


# ------------------------------------------------------------------ sezioni


def _parse_ssh(raw: Any, errors: list[str]) -> SshConfig:
    if not isinstance(raw, dict):
        errors.append("ssh: sezione obbligatoria")
        return SshConfig(user="", key_path="")
    return SshConfig(
        user=_require_str(raw, "user", "ssh", errors),
        key_path=_require_str(raw, "key_path", "ssh", errors),
        known_hosts_path=raw.get("known_hosts_path") or None,
        proxy_jump=raw.get("proxy_jump") or None,
        port=_int(raw, "port", 22, "ssh", errors, 1),
    )


def _parse_llm(raw: dict[str, Any], errors: list[str]) -> LlmConfig:
    endpoints: list[LlmEndpoint] = []
    names: set[str] = set()
    for i, ep in enumerate(raw.get("endpoints") or []):
        where = f"llm.endpoints[{i}]"
        if not isinstance(ep, dict):
            errors.append(f"{where}: deve essere un oggetto")
            continue
        name = _require_str(ep, "name", where, errors)
        base_url = _require_str(ep, "base_url", where, errors)
        model = _require_str(ep, "model", where, errors)
        _url(base_url, f"{where}.base_url", errors)
        if name in names:
            errors.append(f"{where}.name: '{name}' duplicato")
        names.add(name)
        endpoints.append(
            LlmEndpoint(
                name=name,
                base_url=base_url.rstrip("/"),
                model=model,
                api_key_env=ep.get("api_key_env") or None,
                hosted_in_group=ep.get("hosted_in_group") or None,
            )
        )
    where = "llm"
    return LlmConfig(
        endpoints=tuple(endpoints),
        timeout_seconds=_int(raw, "timeout_seconds", 60, where, errors, 1),
        max_calls_per_run=_int(raw, "max_calls_per_run", 100, where, errors, 0),
        min_interval_seconds=_number(raw, "min_interval_seconds", 0.0, where, errors),
    )


def _parse_groups(raw: Any, errors: list[str]) -> tuple[NodeGroup, ...]:
    if not isinstance(raw, list) or not raw:
        errors.append("groups: serve almeno un gruppo (i nodi senza gruppo non vengono toccati)")
        return ()
    groups: list[NodeGroup] = []
    names: set[str] = set()
    orders: set[int] = set()
    for i, g in enumerate(raw):
        where = f"groups[{i}]"
        if not isinstance(g, dict):
            errors.append(f"{where}: deve essere un oggetto")
            continue
        name = _require_str(g, "name", where, errors)
        selector = _require_str(g, "selector", where, errors)
        order = g.get("order")
        if isinstance(order, bool) or not isinstance(order, int):
            errors.append(f"{where}.order: obbligatorio (intero, i gruppi si aggiornano in ordine)")
            order = -1
        elif order in orders:
            errors.append(f"{where}.order: {order} già usato da un altro gruppo")
        orders.add(order)
        if name in names:
            errors.append(f"{where}.name: '{name}' duplicato")
        names.add(name)

        kernel = g.get("kernel", "auto")
        if kernel == "window":
            kernel = "auto"  # configurazioni precedenti: la finestra di manutenzione non c'è più
        if kernel not in KERNEL_MODES:
            errors.append(f"{where}.kernel: uno tra {', '.join(KERNEL_MODES)}")
        drain = g.get("drain", "evict")
        if drain not in DRAIN_MODES:
            errors.append(f"{where}.drain: uno tra {', '.join(DRAIN_MODES)}")
        health_urls = _str_list(g, "health_urls", where, errors)
        for url in health_urls:
            _url(url, f"{where}.health_urls", errors)

        groups.append(
            NodeGroup(
                name=name,
                selector=selector,
                order=order,
                canary=g.get("canary") or None,
                kernel=kernel,
                drain=drain,
                drain_timeout_seconds=_int(g, "drain_timeout_seconds", 1800, where, errors, 60),
                allow_remove=bool(g.get("allow_remove", False)),
                allow_mitigate=bool(g.get("allow_mitigate", False)),
                requires_fallback=bool(g.get("requires_fallback", False)),
                health_urls=health_urls,
            )
        )
    return tuple(sorted(groups, key=lambda grp: grp.order))


def _parse_controller(raw: Any, errors: list[str]) -> ControllerConfig:
    if not isinstance(raw, dict):
        errors.append("controller: deve essere un oggetto")
        return ControllerConfig()
    where = "controller"
    return ControllerConfig(
        pause_minutes=_int(raw, "pause_minutes", 30, where, errors, 0),
        poll_seconds=_int(raw, "poll_seconds", 30, where, errors, 5),
    )


def _parse_extra_services(raw: Any, errors: list[str]) -> dict[str, tuple[str, ...]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append("extra_services: oggetto nodo -> elenco di servizi o pacchetti")
        return {}
    result = {}
    for node, items in raw.items():
        where = f"extra_services.{node}"
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            errors.append(f"{where}: elenco di nomi")
            continue
        bad = [i for i in items if not SERVICE_RE.match(i)]
        if bad:
            errors.append(f"{where}: nomi non validi: {', '.join(bad)}")
            continue
        result[str(node)] = tuple(items)
    return result


def _parse_policy(raw: dict[str, Any], errors: list[str]) -> PolicyConfig:
    where = "policy"
    threshold = _number(raw, "epss_attend_threshold", 0.1, where, errors)
    if threshold > 1:
        errors.append("policy.epss_attend_threshold: tra 0 e 1")
    return PolicyConfig(
        protected_packages=_str_list(raw, "protected_packages", where, errors),
        protected_modules=_str_list(raw, "protected_modules", where, errors),
        idle_scans_required=_int(raw, "idle_scans_required", 3, where, errors, 1),
        idle_days_required=_int(raw, "idle_days_required", 7, where, errors, 0),
        epss_attend_threshold=threshold,
        urgent_deadline_hours=_int(raw, "urgent_deadline_hours", 6, where, errors, 1),
    )


def _parse_sources(raw: dict[str, Any], errors: list[str]) -> SourcesConfig:
    defaults = SourcesConfig()
    values = {}
    for key in ("kev_url", "epss_url", "cve_api_url", "osv_url"):
        value = raw.get(key, getattr(defaults, key))
        if not isinstance(value, str) or not value:
            errors.append(f"sources.{key}: stringa non vuota")
            value = getattr(defaults, key)
        _url(value, f"sources.{key}", errors)
        values[key] = value.rstrip("/")
    values["timeout_seconds"] = _int(raw, "timeout_seconds", 30, "sources", errors, 1)
    return SourcesConfig(**values)
