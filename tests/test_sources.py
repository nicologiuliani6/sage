from sage import sources
from sage.config import SourcesConfig

RECORD = {
    "containers": {
        "cna": {
            "descriptions": [
                {"lang": "es", "value": "otra"},
                {"lang": "en", "value": "crypto: algif_aead - fix out-of-bounds write"},
            ],
            "affected": [
                {"programFiles": ["crypto/algif_aead.c"]},
                {"programFiles": ["crypto/algif_aead.c", "crypto/af_alg.c"]},
                {"versions": []},
            ],
            "metrics": [],
        },
        "adp": [
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [
                    {"cvssV3_1": {"vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "options": [
                                    {"Exploitation": "poc"},
                                    {"Automatable": "no"},
                                    {"Technical Impact": "total"},
                                ]
                            },
                        }
                    },
                ],
            }
        ],
    }
}


def test_extract_record():
    r = sources.extract_record(RECORD)
    assert r["description"].startswith("crypto: algif_aead")
    assert r["program_files"] == ["crypto/af_alg.c", "crypto/algif_aead.c"]
    assert r["attack_vector"] == "local"
    assert r["ssvc"] == {"exploitation": "poc", "automatable": "no", "technical impact": "total"}


def test_extract_record_without_data():
    r = sources.extract_record({})
    assert r == {
        "description": "",
        "program_files": [],
        "cvss_vector": None,
        "attack_vector": None,
        "ssvc": {},
    }


def test_attack_vector_parsing():
    assert sources.attack_vector("CVSS:4.0/AV:N/AC:L") == "network"
    assert sources.attack_vector("AV:A/AC:L") == "adjacent"
    assert sources.attack_vector("CVSS:3.1/AC:L") is None
    assert sources.attack_vector(None) is None


def test_kev_unavailable_returns_none(monkeypatch):
    def boom(url, timeout):
        raise OSError("rete giù")

    monkeypatch.setattr(sources, "http_json", boom)
    assert sources.fetch_kev(SourcesConfig()) is None


def test_kev_and_epss(monkeypatch):
    calls = []

    def fake(url, timeout):
        calls.append(url)
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": "CVE-2026-0001"}, {"other": 1}]}
        return {"data": [{"cve": "CVE-2026-0001", "epss": "0.42"}]}

    monkeypatch.setattr(sources, "http_json", fake)
    assert sources.fetch_kev(SourcesConfig()) == {"CVE-2026-0001"}
    cves = [f"CVE-2026-{i:04d}" for i in range(1, 121)]
    assert sources.fetch_epss(SourcesConfig(), cves) == {"CVE-2026-0001": 0.42}
    assert len(calls) == 1 + 3  # KEV + 120 CVE a blocchi di 50
