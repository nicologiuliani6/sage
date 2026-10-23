"""Righe del profilo nel riepilogo (dati sintetici)."""

from sage.report import profile_lines


def node(profile, packages=None):
    return {"profile": profile, "packages": packages or {}}


def test_profile_ok():
    lines = profile_lines(
        node(
            {
                "units": ["a.service"],
                "required": {"pkg": "a.service"},
                "installed_packages": 10,
                "process_scan_ok": True,
            },
            {"pkg": {"context": {"needed_by": "a.service"}}, "other": {"context": {}}},
        )
    )
    assert lines[0] == "   profilo: 1 servizi del nodo, 1 pacchetti necessari su 10 installati"
    assert not any("ATTENZIONE" in line for line in lines)
    assert lines[-1].endswith("(1): other")


def test_profile_warnings():
    lines = profile_lines(node({"units": ["a.service"], "required": {}, "process_scan_ok": False}))
    assert any("lettura dei processi non affidabile" in line for line in lines)
    assert any("profilo non utilizzabile" in line for line in lines)


def test_no_profile():
    assert profile_lines({}) == []


def test_purl_per_distro():
    from sage.report import purl

    rocky = {"node": {"os": {"id": "rocky", "version": "9.4"}, "arch": "x86_64"}}
    assert purl("openssl", "1:3.0.7-27.el9", rocky) == (
        "pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4"
    )
    debian = {
        "node": {
            "os": {"id": "debian", "version": "12"},
            "arch": "x86_64",
            "package_manager": "apt",
        }
    }
    assert purl("openssh-server", "1:9.2p1-2", debian) == (
        "pkg:deb/debian/openssh-server@1:9.2p1-2?arch=amd64&distro=debian-12"
    )
