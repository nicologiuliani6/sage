"""Configurazione di SAGE.

Tutto ciò che dipende dall'ambiente (gruppi di nodi, utente SSH, endpoint LLM,
pacchetti protetti) arriva da qui. Il codice non contiene valori di uno
specifico cluster: i campi obbligatori mancanti sono un errore, non un default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KERNEL_MODES = ("auto", "window", "manual")
DRAIN_MODES = ("evict", "wait-empty")
WINDOW_RE = re.compile(
    r"^(mon|tue|wed|thu|fri|sat|sun)(,(mon|tue|wed|thu|fri|sat|sun))* "
    r"([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$"
)


class ConfigError(ValueError):
    """Configurazione non valida: il messaggio elenca tutti i problemi trovati."""


@dataclass(frozen=True)
class SshConfig:
    user: str
    key_path: str
    known_hosts_path: str | None = None


@dataclass(frozen=True)
class LlmEndpoint:
    name: str
    base_url: str
    model: str
    api_key_env: str | None = None
    # True per endpoint esterni: al modello arrivano solo dati minimizzati.
    minimize_data: bool = True


@dataclass(frozen=True)
class LlmConfig:
    endpoints: tuple[LlmEndpoint, ...] = ()
    timeout_seconds: int = 60

    @property
    def safe_mode_only(self) -> bool:
        """Senza endpoint SAGE usa solo le regole deterministiche."""
        return not self.endpoints


@dataclass(frozen=True)
class NodeGroup:
    name: str
    selector: str
    order: int
    concurrency: int = 1
    canary: str | None = None
    kernel: str = "window"
    drain: str = "evict"
    allow_remove: bool = False
    window: str | None = None
    requires_fallback: bool = False


@dataclass(frozen=True)
class PolicyConfig:
    protected_packages: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    ssh: SshConfig
    llm: LlmConfig
    groups: tuple[NodeGroup, ...]
    policy: PolicyConfig = field(default_factory=PolicyConfig)

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

    if errors:
        raise ConfigError("configurazione non valida:\n- " + "\n- ".join(errors))
    assert ssh is not None
    return Config(ssh=ssh, llm=llm, groups=groups, policy=policy)


def _require_str(obj: dict[str, Any], key: str, where: str, errors: list[str]) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}.{key}: obbligatorio (stringa non vuota)")
        return ""
    return value.strip()


def _parse_ssh(raw: Any, errors: list[str]) -> SshConfig | None:
    if not isinstance(raw, dict):
        errors.append("ssh: sezione obbligatoria")
        return SshConfig(user="", key_path="")
    return SshConfig(
        user=_require_str(raw, "user", "ssh", errors),
        key_path=_require_str(raw, "key_path", "ssh", errors),
        known_hosts_path=raw.get("known_hosts_path") or None,
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
        if base_url and not base_url.startswith(("http://", "https://")):
            errors.append(f"{where}.base_url: deve iniziare con http:// o https://")
        if name in names:
            errors.append(f"{where}.name: '{name}' duplicato")
        names.add(name)
        endpoints.append(
            LlmEndpoint(
                name=name,
                base_url=base_url,
                model=model,
                api_key_env=ep.get("api_key_env") or None,
                minimize_data=bool(ep.get("minimize_data", True)),
            )
        )
    timeout = raw.get("timeout_seconds", 60)
    if not isinstance(timeout, int) or timeout <= 0:
        errors.append("llm.timeout_seconds: intero positivo")
        timeout = 60
    return LlmConfig(endpoints=tuple(endpoints), timeout_seconds=timeout)


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
        if not isinstance(order, int):
            errors.append(f"{where}.order: obbligatorio (intero, i gruppi si aggiornano in ordine)")
            order = -1
        elif order in orders:
            errors.append(f"{where}.order: {order} già usato da un altro gruppo")
        orders.add(order)
        if name in names:
            errors.append(f"{where}.name: '{name}' duplicato")
        names.add(name)

        concurrency = g.get("concurrency", 1)
        if not isinstance(concurrency, int) or concurrency < 1:
            errors.append(f"{where}.concurrency: intero >= 1")
            concurrency = 1
        kernel = g.get("kernel", "window")
        if kernel not in KERNEL_MODES:
            errors.append(f"{where}.kernel: uno tra {', '.join(KERNEL_MODES)}")
        drain = g.get("drain", "evict")
        if drain not in DRAIN_MODES:
            errors.append(f"{where}.drain: uno tra {', '.join(DRAIN_MODES)}")
        window = g.get("window") or None
        if window is not None and not WINDOW_RE.match(window):
            errors.append(f"{where}.window: formato 'sat 02:00-06:00' o 'sat,sun 02:00-06:00'")
        if kernel == "window" and window is None:
            errors.append(f"{where}.window: obbligatoria se kernel è 'window'")
        requires_fallback = bool(g.get("requires_fallback", False))

        groups.append(
            NodeGroup(
                name=name,
                selector=selector,
                order=order,
                concurrency=concurrency,
                canary=g.get("canary") or None,
                kernel=kernel,
                drain=drain,
                allow_remove=bool(g.get("allow_remove", False)),
                window=window,
                requires_fallback=requires_fallback,
            )
        )
    return tuple(sorted(groups, key=lambda grp: grp.order))


def _parse_policy(raw: dict[str, Any], errors: list[str]) -> PolicyConfig:
    protected = raw.get("protected_packages") or []
    if not isinstance(protected, list) or not all(isinstance(p, str) for p in protected):
        errors.append("policy.protected_packages: lista di nomi o pattern (es. 'kernel*')")
        protected = []
    return PolicyConfig(protected_packages=tuple(protected))
