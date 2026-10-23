"""Debian e Ubuntu: dagli aggiornamenti di sicurezza alle advisory e alle CVE (dati finti)."""

import pytest

from sage import osv
from sage.config import SourcesConfig


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("1.0", "1.0", 0),
        ("1.0-1", "1.0-2", -1),
        ("1:1.0", "2.0", 1),  # l'epoca vince
        ("1.0~rc1", "1.0", -1),  # la tilde viene prima di tutto
        ("1.0", "1.0+deb12u1", -1),
        ("3.0.11-1~deb12u2", "3.0.15-1~deb12u1", -1),
        ("2.36-9+deb12u8", "2.36-9+deb12u10", -1),
        ("1.2a", "1.2+", -1),  # lettere prima dei simboli
        ("1.10", "1.9", 1),
        ("0001.2", "1.2", 0),
        ("2.35-0ubuntu3.8", "2.35-0ubuntu3.10", -1),
        ("1.0-1", "1.0-1build1", -1),
    ],
)
def test_compare_versions(a, b, expected):
    assert osv.compare_versions(a, b) == expected
    assert osv.compare_versions(b, a) == -expected


ECO = "Debian:12"


def vuln(vid, fixed, aliases=(), upstream=(), name="openssl", eco=ECO):
    return {
        "id": vid,
        "aliases": list(aliases),
        "upstream": list(upstream),
        "published": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": eco, "name": name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                ],
            }
        ],
    }


LOOKUP = {
    "ecosystem": ECO,
    "source": "openssl",
    "installed": "3.0.11-1~deb12u2",
    "fixed": "3.0.15-1~deb12u1",
}


def test_advisories_for_picks_fixes_between_installed_and_new():
    vulns = [
        vuln("DSA-0001-1", "3.0.13-1~deb12u1", upstream=["CVE-2026-0001", "CVE-2026-0002"]),
        vuln("DEBIAN-CVE-2026-0002", "3.0.13-1~deb12u1"),  # già nell'advisory
        vuln("DEBIAN-CVE-2026-0003", "3.0.15-1~deb12u1"),  # senza advisory
        vuln("DEBIAN-CVE-2026-0004", "3.0.11-1~deb12u1"),  # già corretta prima
        vuln("DEBIAN-CVE-2026-0005", "3.0.16-1~deb12u1"),  # corretta solo più avanti
        vuln("DEBIAN-CVE-2026-0006", "3.0.13-1", name="openssl", eco="Debian:11"),
        vuln("DSA-0002-1", "3.0.14-1~deb12u1", name="altro"),
    ]
    advisories, loose = osv.advisories_for(LOOKUP, vulns)
    assert [a["id"] for a in advisories] == ["DSA-0001-1"]
    assert advisories[0]["cves"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert advisories[0]["fixed_version"] == "3.0.15-1~deb12u1"
    assert loose == ["CVE-2026-0003"]


def test_ubuntu_severity_and_aliases():
    v = vuln("USN-7000-1", "3.0.15-1", aliases=["CVE-2026-0009"], eco="Ubuntu:24.04:LTS")
    v["severity"] = [{"type": "Ubuntu", "score": "high"}]
    lookup = dict(
        LOOKUP, ecosystem="Ubuntu:24.04:LTS", installed="3.0.13-0ubuntu1", fixed="3.0.15-1"
    )
    advisories, loose = osv.advisories_for(lookup, [v])
    assert advisories[0]["severity"] == "High" and advisories[0]["cves"] == ["CVE-2026-0009"]
    assert loose == []


def report_with_placeholder():
    placeholder = {
        "id": "bookworm-security:openssl:3.0.15-1~deb12u1",
        "severity": "",
        "fixed_version": "3.0.15-1~deb12u1",
        "cves": [],
        "issued": "",
        "lookup": dict(LOOKUP, security=True),
    }
    other = {
        "id": "bookworm:hello:2.10-4",
        "severity": "",
        "fixed_version": "2.10-4",
        "cves": [],
        "issued": "",
        "lookup": dict(LOOKUP, source="hello", installed="2.10-3", fixed="2.10-4", security=False),
    }
    return {
        "n1": {
            "packages": {
                "libssl3": {"advisories": [placeholder], "context": {}},
                "hello": {"advisories": [other], "context": {}},
            }
        }
    }


def fake_osv(monkeypatch, ids_by_source, vulns, posted=None):
    def post(url, body, timeout):
        if posted is not None:
            posted.append(body)
        return {
            "results": [
                {"vulns": [{"id": i} for i in ids_by_source.get(q["package"]["name"], [])]}
                for q in body["queries"]
            ]
        }

    monkeypatch.setattr(osv, "_post_json", post)
    monkeypatch.setattr(osv, "http_json", lambda url, timeout: vulns[url.rsplit("/", 1)[1]])


def test_enrich_replaces_placeholder_and_drops_plain_updates(monkeypatch):
    posted = []
    vulns = {
        "DSA-0001-1": vuln("DSA-0001-1", "3.0.13-1~deb12u1", upstream=["CVE-2026-0001"]),
        "DEBIAN-CVE-2026-0003": vuln("DEBIAN-CVE-2026-0003", "3.0.15-1~deb12u1"),
    }
    fake_osv(monkeypatch, {"openssl": list(vulns)}, vulns, posted)
    reports = report_with_placeholder()
    assert osv.enrich(reports, SourcesConfig()) == 1
    packages = reports["n1"]["packages"]
    assert "hello" not in packages  # aggiornamento normale, nessuna vulnerabilità corretta
    advisories = packages["libssl3"]["advisories"]
    assert [a["id"] for a in advisories] == [
        "DSA-0001-1",
        "bookworm-security:openssl:3.0.15-1~deb12u1",
    ]
    assert advisories[1]["cves"] == ["CVE-2026-0003"]
    # A OSV solo pacchetto sorgente, release e versione
    assert posted == [
        {
            "queries": [
                {"package": {"ecosystem": ECO, "name": "hello"}, "version": "2.10-3"},
                {"package": {"ecosystem": ECO, "name": "openssl"}, "version": "3.0.11-1~deb12u2"},
            ]
        }
    ]


def test_point_release_fix_is_kept(monkeypatch):
    """Correzione di sicurezza arrivata con un rilascio intermedio (non da -security)."""
    vulns = {"DEBIAN-CVE-2026-0007": vuln("DEBIAN-CVE-2026-0007", "2.10-4", name="hello")}
    fake_osv(monkeypatch, {"hello": list(vulns)}, vulns)
    reports = report_with_placeholder()
    osv.enrich(reports, SourcesConfig())
    assert reports["n1"]["packages"]["hello"]["advisories"][0]["cves"] == ["CVE-2026-0007"]


def test_enrich_without_osv_keeps_only_security_repo(monkeypatch):
    def down(url, body, timeout):
        raise OSError("rete giù")

    monkeypatch.setattr(osv, "_post_json", down)
    reports = report_with_placeholder()
    assert osv.enrich(reports, SourcesConfig()) == 1
    packages = reports["n1"]["packages"]
    assert list(packages) == ["libssl3"]
    assert packages["libssl3"]["advisories"][0]["cves"] == []  # niente CVE: si aggiorna


def test_unreadable_vulnerability_keeps_the_update(monkeypatch):
    def broken(url, timeout):
        raise OSError("timeout")

    fake_osv(monkeypatch, {"hello": ["DEBIAN-CVE-2026-0008"]}, {})
    monkeypatch.setattr(osv, "http_json", broken)
    reports = report_with_placeholder()
    osv.enrich(reports, SourcesConfig())
    assert "hello" in reports["n1"]["packages"]  # nel dubbio si aggiorna


def test_enrich_only_advisory_drops_placeholder(monkeypatch):
    vulns = {"DSA-1": vuln("DSA-1", "3.0.15-1~deb12u1", upstream=["CVE-2026-0001"])}
    fake_osv(monkeypatch, {"openssl": ["DSA-1"]}, vulns)
    reports = report_with_placeholder()
    osv.enrich(reports, SourcesConfig())
    advisories = reports["n1"]["packages"]["libssl3"]["advisories"]
    assert [a["id"] for a in advisories] == ["DSA-1"]
