import json

import pytest

from sage import config, llm


def chain_cfg(**extra):
    raw = {
        "ssh": {"user": "u", "key_path": "/k"},
        "groups": [
            {"name": "w", "selector": "a=b", "order": 1, "kernel": "auto"},
            {"name": "gpu-llm", "selector": "a=c", "order": 2, "kernel": "auto"},
        ],
        "llm": {
            "endpoints": [
                {
                    "name": "locale",
                    "base_url": "http://locale/v1",
                    "model": "m",
                    "hosted_in_group": "gpu-llm",
                },
                {
                    "name": "groq",
                    "base_url": "https://groq/v1",
                    "model": "m",
                    "api_key_env": "GROQ_API_KEY",
                },
            ],
            **extra,
        },
    }
    return config.parse(raw).llm


GOOD = {
    "conditions": [{"type": "kernel_module", "module": "algif-aead", "reason": "file in crypto/"}],
    "mitigation": {"type": "module_denylist", "module": "algif_aead"},
    "summary": "bug in algif_aead",
}


def answer(data):
    return {"choices": [{"message": {"content": json.dumps(data)}}]}


def test_parse_valid_and_normalizes_module():
    out = llm.parse_response("```json\n" + json.dumps(GOOD) + "\n```")
    assert out["conditions"][0]["module"] == "algif_aead"
    assert out["mitigation"] == {"type": "module_denylist", "module": "algif_aead"}


@pytest.mark.parametrize(
    "bad",
    [
        "niente json",
        {"conditions": "no"},
        {"conditions": [{"type": "magia"}]},
        {"conditions": [{"type": "kernel_module"}]},
        {"conditions": [{"type": "kernel_module", "module": "../../etc"}]},
        {"conditions": [], "mitigation": {"type": "rm -rf"}},
        {"conditions": [{"type": "component_in_use"}] * 6},
    ],
)
def test_parse_rejects_invalid(bad):
    text = bad if isinstance(bad, str) else json.dumps(bad)
    with pytest.raises(llm.LlmError):
        llm.parse_response(text)


def test_prompt_contains_only_public_cve_data():
    msg = llm.user_message(
        "CVE-2026-1", "kernel-core", {"description": "bug", "program_files": ["a/b.c"]}, "Low"
    )
    assert "CVE-2026-1" in msg and "a/b.c" in msg and "<cve_data>" in msg
    for forbidden in ("ansible_host", "hostname", "192.0.2", "listening"):
        assert forbidden not in msg


def test_fallback_to_next_endpoint_and_api_key():
    seen = []

    def post(url, body, headers, timeout):
        seen.append((url, headers.get("Authorization")))
        if "locale" in url:
            raise OSError("nodo GPU in manutenzione")
        return answer(GOOD)

    chain = llm.LlmChain(chain_cfg(), env={"GROQ_API_KEY": "segreto"}, post=post)
    result, ep = chain.ask("CVE-2026-1", "kernel-core", None, "Low")
    assert ep.name == "groq" and result["conditions"][0]["module"] == "algif_aead"
    assert seen == [
        ("http://locale/v1/chat/completions", None),
        ("https://groq/v1/chat/completions", "Bearer segreto"),
    ]


def test_invalid_answer_also_falls_back():
    def post(url, body, headers, timeout):
        return answer({"conditions": [{"type": "magia"}]}) if "locale" in url else answer(GOOD)

    _, ep = llm.LlmChain(chain_cfg(), env={}, post=post).ask("CVE-1", "kernel", None, "")
    assert ep.name == "groq"


def test_all_endpoints_down_returns_none():
    def post(*a):
        raise OSError("giù")

    assert llm.LlmChain(chain_cfg(), env={}, post=post).ask("CVE-1", "p", None, "") is None


def test_budget_limits_calls():
    chain = llm.LlmChain(chain_cfg(max_calls_per_run=2), env={}, post=lambda *a: answer(GOOD))
    assert chain.ask("CVE-1", "p", None, "") and chain.ask("CVE-2", "p", None, "")
    assert chain.ask("CVE-3", "p", None, "") is None
    assert chain.calls == 2


def test_min_interval_between_calls():
    slept = []
    chain = llm.LlmChain(
        chain_cfg(min_interval_seconds=2),
        env={},
        post=lambda *a: answer(GOOD),
        sleep=slept.append,
    )
    chain.ask("CVE-1", "p", None, "")
    chain.ask("CVE-2", "p", None, "")
    assert len(slept) == 1 and 0 < slept[0] <= 2


def test_fallback_available_ignores_endpoints_hosted_in_group():
    statuses = {"http://locale/v1/models": 200, "https://groq/v1/models": 500}
    chain = llm.LlmChain(chain_cfg(), env={}, get_status=lambda url, h, t: statuses[url])
    assert chain.fallback_available("w") is True  # il locale va bene: non è nel gruppo w
    assert chain.fallback_available("gpu-llm") is False  # il locale è nel gruppo, groq è giù
    statuses["https://groq/v1/models"] = 200
    assert chain.fallback_available("gpu-llm") is True


def test_no_endpoints_means_no_budget():
    cfg = config.parse(
        {
            "ssh": {"user": "u", "key_path": "/k"},
            "groups": [{"name": "w", "selector": "a", "order": 1, "kernel": "auto"}],
        }
    ).llm
    chain = llm.LlmChain(cfg, env={})
    assert not chain.budget_left() and chain.primary is None
