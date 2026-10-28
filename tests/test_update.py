"""Aggiornamento automatico di SAGE (ADR-0021)."""

import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from sage import update
from tests.conftest import base_config

REL = [
    {"tag_name": "v0.8.1", "assets": []},
    {"tag_name": "v0.9.0", "assets": []},
    {"tag_name": "v1.0.0", "assets": []},
    {"tag_name": "v0.9.1", "prerelease": True, "assets": []},
    {"tag_name": "nightly", "assets": []},
]


@pytest.mark.parametrize(
    ("channel", "skipped", "expected"),
    [
        ("minor", [], "v0.9.0"),  # mai la versione maggiore da solo, niente pre-release
        ("patch", [], "v0.8.1"),
        ("off", [], None),
        ("minor", ["v0.9.0"], "v0.8.1"),  # una versione fallita non si riprova
    ],
)
def test_pick_release(channel, skipped, expected):
    picked = update.pick_release(REL, "0.8.0", channel, skipped)
    assert (picked or {}).get("tag_name") == expected


def test_dev_build_never_updates():
    assert update.pick_release(REL, "copia locale", "minor", []) is None


class FakeKube:
    def __init__(self):
        self.store = {"sage-report": {"generated_at": "2026-10-28T10:00:00+00:00"}}
        self.flags, self.history = [], []

    def read_json(self, name):
        return self.store.get(name)

    def write_json(self, name, data):
        self.store[name] = data

    def set_flag(self, name):
        self.flags.append(name)

    def append_text(self, name, key, text):
        self.history.append(text)

    def read_lease(self, name):
        return self.store.get("lease")


def setup(monkeypatch, *, verified=True, works=True):
    cfg = base_config(self_update={"repository": "owner/sage", "channel": "minor"})
    kube = FakeKube()
    calls = []
    monkeypatch.setenv("SAGE_VERSION", "0.8.0")
    monkeypatch.setattr(
        update, "_get", lambda url, timeout=60: b'[{"tag_name": "v0.8.1", "assets": []}]'
    )

    def verify(workdir, assets, repository, chart):
        if not verified:
            raise RuntimeError("firma non valida")
        return workdir / chart

    def helm(*args):
        calls.append(args[0])
        out = '[{"revision": 7, "status": "deployed"}]' if args[0] == "history" else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    monkeypatch.setattr(update, "verify", verify)
    monkeypatch.setattr(update, "helm", helm)
    monkeypatch.setattr(update, "wait_for_work", lambda kube, release, since: works)
    return cfg, kube, calls


def test_unsigned_release_is_refused_and_nothing_changes(monkeypatch):
    cfg, kube, calls = setup(monkeypatch, verified=False)
    assert update.run(cfg, kube, "sage", "sage") == 1
    assert "upgrade" not in calls
    assert [i["tag"] for i in kube.store["sage-update"]["skipped"]] == ["v0.8.1"]
    assert "rifiutato" in kube.history[0]


def test_update_kept_only_if_sage_works(monkeypatch):
    cfg, kube, calls = setup(monkeypatch)
    assert update.run(cfg, kube, "sage", "sage") == 0
    assert calls == ["history", "upgrade"]
    assert kube.store["sage-update"]["last"] == {"version": "0.8.1", "ok": True}
    assert '"user": "sage (automatico)"' in kube.history[0]


def test_sage_that_does_not_work_is_rolled_back(monkeypatch):
    cfg, kube, calls = setup(monkeypatch, works=False)
    assert update.run(cfg, kube, "sage", "sage") == 1
    assert calls == ["history", "upgrade", "rollback"]
    assert [i["tag"] for i in kube.store["sage-update"]["skipped"]] == ["v0.8.1"]


def test_off_or_without_repository_does_nothing(monkeypatch):
    cfg = base_config(self_update={"channel": "off", "repository": "owner/sage"})
    assert update.run(cfg, FakeKube(), "sage", "sage") == 0
    assert update.run(base_config(), FakeKube(), "sage", "sage") == 0


class Clock:
    """Tempo finto: ogni sleep avanza l'orologio, niente attese vere."""

    def __init__(self):
        self.t = 0.0

    def sleep(self, seconds):
        self.t += seconds

    def __call__(self):
        return self.t


def proof(kube, before="2026-10-28T10:00:00+00:00"):
    clock = Clock()
    return update.wait_for_work(kube, "sage", before, sleep=clock.sleep, clock=clock), clock.t


def alive():
    now = datetime.now(UTC)
    return {"renew_time": now.isoformat()}, {
        "cycle": {"started": (now + timedelta(seconds=1)).isoformat()}
    }


def test_proof_waits_as_long_as_the_new_sage_works():
    """Un controllo lungo (cluster grande, LLM lento) non è un guasto: si aspetta."""
    kube = FakeKube()
    kube.store["lease"], kube.store["sage-controller"] = alive()
    calls = {"n": 0}

    def read_json(name):
        if name == "sage-report":
            calls["n"] += 1
            # Report nuovo solo dopo 2 ore di controllo.
            done = calls["n"] > 240
            return {
                "generated_at": "2026-10-28T12:00:00+00:00" if done else "2026-10-28T09:00:00+00:00"
            }
        return kube.store.get(name)

    kube.read_json = read_json
    ok, waited = proof(kube)
    assert ok and waited > 2 * 3600
    assert kube.flags == ["sage-scan-now"]


def test_proof_fails_fast_if_no_cycle_starts():
    kube = FakeKube()
    kube.store["lease"] = alive()[0]
    kube.store["sage-controller"] = {"cycle": {"started": "2026-10-01T00:00:00+00:00"}}
    ok, waited = proof(kube)
    assert not ok and waited <= update.START_TIMEOUT + 60


def test_proof_fails_if_the_controller_stops_renewing_the_lease():
    kube = FakeKube()
    lease, kube.store["sage-controller"] = alive()
    kube.store["lease"] = {"renew_time": "2026-10-01T00:00:00+00:00"}
    ok, waited = proof(kube)
    assert not ok and waited <= update.START_TIMEOUT + 60


def test_a_rolled_back_version_is_retried_after_some_days():
    now = datetime.now(UTC)
    state = {"skipped": ["v0.8.0"]}  # formato vecchio: non blocca più per sempre
    assert update._skipped(state, now) == []
    update._skip(state, "v0.10.0", now)
    assert update._skipped(state, now) == ["v0.10.0"]
    assert update._skipped(state, now + timedelta(days=update.SKIP_DAYS + 1)) == []


def test_verify_refuses_missing_signature_and_wrong_checksum(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="non firmata"):
        update.verify(
            tmp_path, {"SHA256SUMS": "u", "sage-0.8.1.tgz": "u"}, "owner/sage", "sage-0.8.1.tgz"
        )
    files = {
        "SHA256SUMS": b"0" * 64 + b"  sage-0.8.1.tgz\n",
        "SHA256SUMS.sigstore.json": b"{}",
        "sage-0.8.1.tgz": b"chart",
    }
    monkeypatch.setattr(update, "_get", lambda url, timeout=60: files[url])
    cosign = []
    monkeypatch.setattr(
        update.subprocess,
        "run",
        lambda cmd, **kw: cosign.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""),
    )
    with pytest.raises(RuntimeError, match="checksum"):
        update.verify(tmp_path, {n: n for n in files}, "owner/sage", "sage-0.8.1.tgz")
    identity = cosign[0][cosign[0].index("--certificate-identity-regexp") + 1]
    assert identity.startswith(r"^https://github\.com/owner/sage/\.github/workflows/publish\.yml")
