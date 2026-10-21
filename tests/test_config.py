from pathlib import Path

import pytest

from sage import config

EXAMPLE = Path(__file__).parents[1] / "examples" / "config.example.yaml"


def minimal(**overrides):
    raw = {
        "ssh": {"user": "admin", "key_path": "/etc/sage/ssh/id_ed25519"},
        "groups": [{"name": "workers", "selector": "role=worker", "order": 1, "kernel": "auto"}],
    }
    raw.update(overrides)
    return raw


def test_example_config_is_valid():
    cfg = config.load(EXAMPLE)
    orders = [g.order for g in cfg.groups]
    assert orders == sorted(orders)  # i gruppi tornano in ordine di ondata
    assert not cfg.llm.safe_mode_only


def test_minimal_config_runs_in_safe_mode():
    cfg = config.parse(minimal())
    assert cfg.llm.safe_mode_only
    assert cfg.groups[0].concurrency == 1


@pytest.mark.parametrize(
    "raw, fragment",
    [
        ({"groups": [{"name": "w", "selector": "s", "order": 1, "kernel": "auto"}]}, "ssh"),
        (minimal(ssh={"user": "", "key_path": "/k"}), "ssh.user"),
        (minimal(groups=[]), "groups"),
        (minimal(groups=[{"name": "w", "selector": "s", "kernel": "auto"}]), "order"),
        (
            minimal(groups=[{"name": "w", "selector": "s", "order": 1, "kernel": "sometimes"}]),
            "kernel",
        ),
        (minimal(groups=[{"name": "w", "selector": "s", "order": 1}]), "window"),
        (
            minimal(
                groups=[
                    {
                        "name": "w",
                        "selector": "s",
                        "order": 1,
                        "kernel": "window",
                        "window": "saturday night",
                    }
                ]
            ),
            "window",
        ),
        (
            minimal(
                groups=[
                    {"name": "a", "selector": "s", "order": 1, "kernel": "auto"},
                    {"name": "b", "selector": "s", "order": 1, "kernel": "auto"},
                ]
            ),
            "già usato",
        ),
        (
            minimal(llm={"endpoints": [{"name": "x", "base_url": "ftp://x", "model": "m"}]}),
            "base_url",
        ),
    ],
)
def test_invalid_configs_are_rejected(raw, fragment):
    with pytest.raises(config.ConfigError) as exc:
        config.parse(raw)
    assert fragment in str(exc.value)


def test_all_errors_reported_together():
    with pytest.raises(config.ConfigError) as exc:
        config.parse({"groups": [{"name": "w"}]})
    message = str(exc.value)
    assert "ssh" in message and "selector" in message and "order" in message


def test_policy_data_comes_from_config():
    cfg = config.parse(minimal(policy={"protected_packages": ["glibc", "kernel*"]}))
    assert cfg.to_policy_data() == {"protected_packages": ["glibc", "kernel*"]}


def test_helm_values_example_contains_valid_config():
    import yaml

    values = yaml.safe_load((EXAMPLE.parent / "values.example.yaml").read_text())
    raw = values["config"]
    raw["ssh"].setdefault("key_path", "/etc/sage/ssh/id_ed25519")  # default del chart
    cfg = config.parse(raw)
    assert [g.name for g in cfg.groups] == ["worker", "master"]
