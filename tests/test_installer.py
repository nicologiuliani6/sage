"""Test dell'installer con dati sintetici.

Scritti con unittest e senza dipendenze, così la CI li esegue anche con Python 3.9
(il Python dei master): `python -m unittest tests.test_installer`.
"""

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


inst = load(ROOT / "installer" / "sage_install.py", "sage_install")
stamp = load(ROOT / "ci" / "stamp_installer.py", "stamp_installer")

DIGEST = "sha256:" + "a" * 64
IMAGE = "registry.example/owner/sage@" + DIGEST


def node(
    name,
    ip="192.0.2.10",
    os_image="Rocky Linux 9.4 (Blue Onyx)",
    cp=False,
    gpus=0,
    ready=True,
    labels=None,
):
    lab = dict(labels or {})
    if cp:
        lab["node-role.kubernetes.io/control-plane"] = ""
    capacity = {"cpu": "4"}
    if gpus:
        capacity["nvidia.com/gpu"] = str(gpus)
    return {
        "metadata": {"name": name, "labels": lab},
        "spec": {},
        "status": {
            "addresses": [{"type": "InternalIP", "address": ip}] if ip else [],
            "capacity": capacity,
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "nodeInfo": {"osImage": os_image, "kernelVersion": "5.14.0"},
        },
    }


CLUSTER = {
    "items": [
        node("w2", "192.0.2.12"),
        node("w1", "192.0.2.11"),
        node("cp1", "192.0.2.1", cp=True),
        node("g1", "192.0.2.21", gpus=2),
        node("u1", "192.0.2.31", os_image="Ubuntu 24.04 LTS"),
        node("x1", None),
    ]
}


class NodesAndGroups(unittest.TestCase):
    def test_parse_nodes(self):
        nodes = inst.parse_nodes(CLUSTER)
        self.assertEqual([n.name for n in nodes], ["cp1", "g1", "u1", "w1", "w2", "x1"])
        by = {n.name: n for n in nodes}
        self.assertTrue(by["cp1"].control_plane)
        self.assertEqual(by["g1"].gpus, 2)
        self.assertIn("OS non supportato", by["u1"].problem)
        self.assertEqual(by["x1"].problem, "senza InternalIP")
        self.assertIsNone(by["w1"].problem)
        self.assertIn("GPU x2", by["g1"].label(4))

    def test_proposal(self):
        nodes = [n for n in inst.parse_nodes(CLUSTER) if not n.problem]
        groups, assignment = inst.propose_groups(nodes)
        self.assertEqual(
            [(g.name, g.order, g.kernel) for g in groups],
            [("worker", 1, "auto"), ("gpu", 2, "manual"), ("master", 3, "window")],
        )
        self.assertEqual(groups[0].canary, "w1")  # canary solo se il gruppo ha più nodi
        self.assertIsNone(groups[1].canary)
        self.assertEqual(groups[2].window, inst.DEFAULT_WINDOW)
        self.assertEqual(assignment, {"w1": "worker", "w2": "worker", "g1": "gpu", "cp1": "master"})

    def test_normalize_drops_empty_groups_and_stale_canary(self):
        groups = [
            inst.Group("a", 5, canary="n1"),
            inst.Group("b", 2),
            inst.Group("c", 9, canary="n3"),
        ]
        assignment = {"n1": "b", "n2": "a", "n3": "c"}
        result = inst.normalize_groups(groups, assignment)
        self.assertEqual([(g.name, g.order) for g in result], [("b", 1), ("a", 2), ("c", 3)])
        self.assertIsNone(next(g for g in result if g.name == "a").canary)
        self.assertEqual(next(g for g in result if g.name == "c").canary, "n3")
        self.assertEqual(inst.normalize_groups(groups, {"n1": "b"})[0].name, "b")

    def test_group_roundtrip_keeps_unknown_fields(self):
        raw = {
            "name": "gpu",
            "selector": "something-else",
            "order": 2,
            "kernel": "manual",
            "drain": "wait-empty",
            "health_urls": ["http://h/health"],
        }
        cfg = inst.Group.from_config(raw).to_config()
        self.assertEqual(cfg["selector"], "sage.io/group=gpu")
        self.assertEqual(cfg["drain"], "wait-empty")
        self.assertEqual(cfg["health_urls"], ["http://h/health"])
        self.assertNotIn("window", cfg)


class Values(unittest.TestCase):
    def make(self, base=None, **kw):
        groups, _ = inst.propose_groups(inst.parse_nodes({"items": CLUSTER["items"][:4]}))
        args = dict(
            release="sage",
            image=IMAGE,
            pull_secret=None,
            schedule="0 */6 * * *",
            timezone="Europe/Rome",
            suspend=False,
            ssh_user="admin",
            ssh_port=22,
            llm={"endpoints": []},
            llm_secret=False,
            groups=groups,
            proxy=[],
        )
        args.update(kw)
        return inst.build_values(base or {}, **args)

    def test_new_install_is_dry_run(self):
        v = self.make()
        self.assertTrue(v["dryRun"])
        self.assertEqual(
            v["image"], {"repository": "registry.example/owner/sage", "digest": DIGEST, "tag": ""}
        )
        self.assertEqual(v["secrets"], {"ssh": "sage-ssh", "llm": ""})
        self.assertEqual(v["config"]["ssh"], {"user": "admin"})
        self.assertEqual(
            [g["selector"] for g in v["config"]["groups"]],
            ["sage.io/group=worker", "sage.io/group=gpu", "sage.io/group=master"],
        )
        self.assertIn("glibc", v["config"]["policy"]["protected_packages"])

    def test_existing_values_are_kept(self):
        base = {
            "dryRun": False,
            "resources": {"limits": {"memory": "2Gi"}},
            "extraEnv": [{"name": "FOO", "value": "1"}, {"name": "HTTPS_PROXY", "value": "x"}],
            "config": {
                "policy": {"protected_packages": ["solo-questo"]},
                "llm": {"timeout_seconds": 9},
            },
        }
        proxy = inst.proxy_env("http://proxy.example:3128", ["192.0.2.1"], "10.96.0.1")
        v = self.make(
            base, proxy=proxy, ssh_port=2222, llm_secret=True, llm={"endpoints": [inst.GROQ]}
        )
        self.assertFalse(v["dryRun"])  # il passaggio al vivo non si perde riconfigurando
        self.assertEqual(v["resources"], {"limits": {"memory": "2Gi"}})
        self.assertEqual(v["config"]["policy"]["protected_packages"], ["solo-questo"])
        self.assertEqual(v["config"]["llm"]["timeout_seconds"], 9)
        self.assertEqual(v["config"]["ssh"]["port"], 2222)
        self.assertEqual(v["secrets"]["llm"], "sage-llm")
        names = [e["name"] for e in v["extraEnv"]]
        self.assertEqual(names, ["FOO", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"])
        self.assertEqual(v["extraEnv"][1]["value"], "http://proxy.example:3128")
        self.assertIn("10.96.0.1", v["extraEnv"][3]["value"])
        self.assertEqual(base["config"]["policy"]["protected_packages"], ["solo-questo"])

    def test_config_is_valid_for_sage(self):
        try:
            from sage import config
        except Exception:  # Python 3.9: il pacchetto sage richiede 3.12
            self.skipTest("pacchetto sage non importabile con questo Python")
        v = self.make(llm={"endpoints": [inst.GROQ], "min_interval_seconds": 2.5})
        raw = dict(v["config"])
        raw["ssh"] = dict(raw["ssh"], key_path="/etc/sage/ssh/id_ed25519")
        cfg = config.parse(raw)
        self.assertEqual([g.name for g in cfg.groups], ["worker", "gpu", "master"])

    def test_helm_renders_installer_values(self):
        helm = shutil.which("helm")
        if not helm:
            self.skipTest("helm non disponibile")
        v = self.make()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "values.json"
            path.write_text(json.dumps(v))
            out = subprocess.run(
                [helm, "template", "sage", str(ROOT / "chart" / "sage"), "-f", str(path)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("kind: CronJob", out.stdout)

    def test_images(self):
        self.assertEqual(
            inst.split_image("reg.example:5000/ns/sage:1.2")["repository"],
            "reg.example:5000/ns/sage",
        )
        self.assertEqual(inst.split_image("reg.example:5000/ns/sage:1.2")["tag"], "1.2")
        with self.assertRaises(inst.Fail):
            inst.split_image("reg.example:5000/ns/sage")
        self.assertEqual(inst.image_ref({"image": inst.split_image(IMAGE)}), IMAGE)
        self.assertEqual(inst.parse_image(IMAGE), ("registry.example", "owner/sage", DIGEST))
        self.assertEqual(
            inst.parse_image("python:3.12"), ("registry-1.docker.io", "library/python", "3.12")
        )
        self.assertEqual(inst.parse_image("localhost:5000/sage@" + DIGEST)[0], "localhost:5000")


class FakeResponse:
    def __init__(self, body=b"{}"):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return self.body


def http_error(code, headers=None):
    return urllib.error.HTTPError("https://x", code, "err", headers or {}, None)


class Registry(unittest.TestCase):
    CHALLENGE = {"WWW-Authenticate": 'Bearer realm="https://r.example/token",service="r.example"'}

    def opener(self, manifest_after_token):
        calls = []

        def fake(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            calls.append(url)
            if "/token" in url:
                return FakeResponse(json.dumps({"token": "t"}).encode())
            if req.get_header("Authorization"):
                if manifest_after_token == 200:
                    return FakeResponse()
                raise http_error(manifest_after_token)
            raise http_error(401, self.CHALLENGE)

        return fake, calls

    def test_public_after_anonymous_token(self):
        fake, calls = self.opener(200)
        self.assertEqual(inst.image_access(IMAGE, fake), "public")
        self.assertIn("service=r.example", calls[1])

    def test_private(self):
        fake, _ = self.opener(403)
        self.assertEqual(inst.image_access(IMAGE, fake), "private")

    def test_network_error_is_unknown(self):
        def fake(req, timeout=None):
            raise urllib.error.URLError("no route")

        self.assertTrue(inst.image_access(IMAGE, fake).startswith("unknown"))


class LlmProbe(unittest.TestCase):
    def probe(self, fake):
        with mock.patch.object(inst.urllib.request, "urlopen", fake):
            return inst.llm_probe("https://llm.example/v1", "k", "m1")

    def test_sends_user_agent_and_key(self):
        seen = {}

        def fake(req, timeout=None):
            seen.update(req.header_items())
            return FakeResponse(json.dumps({"data": [{"id": "m1"}]}).encode())

        self.assertIsNone(self.probe(fake))
        # urllib normalizza i nomi: "User-agent". Senza, Cloudflare risponde 403.
        self.assertTrue(seen["User-agent"].startswith("sage-install/"))
        self.assertEqual(seen["Authorization"], "Bearer k")

    def test_errors(self):
        for code, text in ((401, "chiave rifiutata"), (403, "accesso negato"), (500, "HTTP 500")):

            def fake(req, timeout=None, code=code):
                raise http_error(code)

            self.assertIn(text, self.probe(fake))

        def other_models(req, timeout=None):
            return FakeResponse(json.dumps({"data": [{"id": "m2"}]}).encode())

        self.assertIn("es. m2", self.probe(other_models))


class Selection(unittest.TestCase):
    KEYS = ["cp1", "w1", "w2", "u1"]

    def test_text_selection(self):
        enabled = {0, 1, 2}
        self.assertEqual(inst.parse_selection("", self.KEYS, enabled), enabled)
        self.assertEqual(inst.parse_selection("tutti", self.KEYS, enabled), enabled)
        self.assertEqual(inst.parse_selection("1,3", self.KEYS, enabled), {0, 2})
        self.assertEqual(inst.parse_selection("2-3", self.KEYS, enabled), {1, 2})
        self.assertEqual(inst.parse_selection("w1 CP1", self.KEYS, enabled), {0, 1})
        for bad in ("5", "3-1", "boh", "4"):
            with self.assertRaises(ValueError):
                inst.parse_selection(bad, self.KEYS, enabled)

    def test_checklist_keys(self):
        c = inst.Checklist(["cp1", "w1", "u1"], {0, 1, 2}, {2: "OS non supportato"})
        self.assertEqual(c.selected, {0, 1})  # i disabilitati non partono selezionati
        self.assertTrue(c.all_on())
        c.key("space")  # su "Tutti": deseleziona tutto
        self.assertEqual(c.selected, set())
        self.assertFalse(c.key("enter"))  # almeno un nodo
        self.assertIn("almeno", c.message)
        c.key("down")
        c.key("space")
        self.assertEqual(c.selected, {0})
        c.key("down")
        c.key("down")
        c.key("space")
        self.assertIn("non selezionabile", c.message)
        self.assertEqual(c.selected, {0})
        c.key("a")
        self.assertEqual(c.selected, {0, 1})
        c.key("up")
        c.key("up")
        c.key("up")
        c.key("up")  # dalla prima riga si torna in fondo
        self.assertEqual(c.cursor, 3)
        self.assertTrue(c.key("enter"))

    def test_checklist_render_scrolls_and_fits(self):
        labels = [f"nodo-{i:03d} " + "x" * 200 for i in range(50)]
        c = inst.Checklist(labels, set(), {})
        for _ in range(30):
            c.key("down")
        lines = c.lines(80, 12)
        rows = [r for r in lines if isinstance(r, tuple)]
        self.assertEqual(len(lines), 12)
        self.assertTrue(all(len(r[0]) <= 80 for r in rows))
        current = [r[0] for r in rows if r[1]]
        self.assertEqual(len(current), 1)
        self.assertIn("nodo-029", current[0])
        self.assertTrue(lines[1][0].startswith("  [ ]"))  # "Tutti" è fuori dalla vista

    def test_header_shows_all(self):
        c = inst.Checklist(["a", "b"], {0, 1}, {})
        self.assertTrue(c.lines(80, 10)[1][0].startswith("> [x] Tutti"))
        c.key("n")
        self.assertTrue(c.lines(80, 10)[1][0].startswith("> [ ] Tutti"))
        c.key("down")
        c.key("space")
        self.assertTrue(c.lines(80, 10)[1][0].startswith("  [-] Tutti"))

    def test_menu(self):
        m = inst.Menu(["a", "b", "c"], 1)
        m.key("down")
        self.assertTrue(m.key("enter"))
        self.assertEqual(m.cursor, 2)
        m.key("1")
        self.assertEqual(m.cursor, 0)


class RemoteCommands(unittest.TestCase):
    PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests0000000000000000000000000 sage@x"

    def shell(self, home, command):
        env = dict(os.environ, HOME=str(home))
        return subprocess.run(["sh", "-c", command], env=env, capture_output=True, text=True)

    def test_install_is_idempotent_and_remove_is_precise(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".ssh").mkdir()
            keys = home / ".ssh" / "authorized_keys"
            keys.write_text("ssh-rsa AAAAOTHER admin@pc")  # senza a capo finale
            keys.chmod(0o600)
            for _ in range(2):
                self.assertEqual(self.shell(home, inst.install_key_command(self.PUB)).returncode, 0)
            text = keys.read_text()
            self.assertEqual(text.count("sage@x"), 1)
            self.assertIn("ssh-rsa AAAAOTHER admin@pc\n", text)
            # Rimozione: la chiave si riconosce dal blob, anche senza commento.
            public_no_comment = " ".join(self.PUB.split()[:2])
            self.assertEqual(
                self.shell(home, inst.remove_key_command(public_no_comment)).returncode, 0
            )
            lines = [line for line in keys.read_text().splitlines() if line]
            self.assertEqual(lines, ["ssh-rsa AAAAOTHER admin@pc"])
            self.assertEqual(oct(keys.stat().st_mode & 0o777), oct(0o600))  # permessi intatti

    def test_install_creates_ssh_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.shell(tmp, inst.install_key_command(self.PUB)).returncode, 0)
            self.assertIn("sage@x", (Path(tmp) / ".ssh" / "authorized_keys").read_text())

    def test_check(self):
        out = self.shell(tempfile.gettempdir(), inst.CHECK_COMMAND)
        self.assertIsNotNone(inst.parse_check(out.stdout))
        self.assertEqual(inst.parse_check("motd\nSAGE-CHECK:"), [])
        self.assertEqual(
            inst.parse_check("SAGE-CHECK: sudo python"),
            ["sudo senza password non disponibile", "manca python3 >= 3.9"],
        )
        self.assertIsNone(inst.parse_check("Permission denied"))

    def test_quoting(self):
        self.assertEqual(shlex.split(inst.install_key_command(self.PUB))[0], "umask")
        with self.assertRaises(inst.Fail):
            inst.key_blob("non-una-chiave")

    def test_ssh_errors(self):
        self.assertEqual(
            inst.explain_ssh_error("x: Permission denied (publickey)."), "accesso negato"
        )
        changed = (
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n"
            "Host key verification failed."
        )
        self.assertIn("chiave host", inst.explain_ssh_error(changed))
        self.assertIn("non raggiungibile", inst.explain_ssh_error("connect: No route to host"))


class Stamp(unittest.TestCase):
    DATA = {
        "version": "0.1.0",
        "image": IMAGE,
        "chart_url": "https://example.invalid/sage-0.1.0.tgz",
        "chart_sha256": "b" * 64,
    }

    def test_stamped_installer_carries_release(self):
        source = (ROOT / "installer" / "sage_install.py").read_text()
        stamped = stamp.stamp(source, self.DATA)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sage-install.py"
            path.write_text(stamped)
            module = load(path, "sage_install_stamped")
            out = subprocess.run(
                [sys.executable, str(path), "--version"], capture_output=True, text=True
            )
        self.assertEqual(module.RELEASE, self.DATA)
        self.assertEqual(out.stdout.strip(), "0.1.0")
        self.assertEqual(len(stamped.splitlines()), len(source.splitlines()))

    def test_rejects_bad_data(self):
        source = (ROOT / "installer" / "sage_install.py").read_text()
        with self.assertRaises(ValueError):
            stamp.stamp(source, dict(self.DATA, image="registry.example/owner/sage:latest"))
        with self.assertRaises(ValueError):
            stamp.stamp(source, {"version": "0.1.0"})
        with self.assertRaises(ValueError):
            stamp.stamp("niente marcatore", self.DATA)


class Misc(unittest.TestCase):
    def test_no_proxy_and_names(self):
        value = inst.no_proxy(["192.0.2.2", "192.0.2.1", "192.0.2.2"], "10.96.0.1")
        self.assertEqual(
            value, "localhost,127.0.0.1,.svc,.cluster.local,10.96.0.1,192.0.2.1,192.0.2.2"
        )
        self.assertEqual(inst.env_name("vllm-gpu"), "VLLM_GPU_API_KEY")
        self.assertTrue(inst.WINDOW_RE.match("sat,sun 01:00-05:00"))
        self.assertFalse(inst.WINDOW_RE.match("sabato 01:00-05:00"))
        self.assertEqual(
            inst.parse_www_authenticate('Bearer realm="https://a/t",scope="s"'),
            {"realm": "https://a/t", "scope": "s"},
        )

    def test_args(self):
        args = inst.parse_args(["--release", "sage-test", "--namespace", "x"])
        self.assertEqual((args.release, args.namespace), ("sage-test", "x"))
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            inst.parse_args(["--release", "Non_Valido"])


class Interactive(unittest.TestCase):
    """Passi interattivi con risposte scritte (liste numerate, senza terminale)."""

    def setUp(self):
        args = inst.parse_args(["--no-tui"])
        self.installer = inst.Installer(args, inst.UI(tui=False, color=False))
        self.addCleanup(shutil.rmtree, self.installer.tmp, True)

    def answer(self, answers, fn, secrets=()):
        answers, secrets = list(answers), list(secrets)
        with (
            mock.patch("builtins.input", lambda prompt="": answers.pop(0)),
            mock.patch.object(inst.getpass, "getpass", lambda prompt="": secrets.pop(0)),
            mock.patch("builtins.print"),
        ):
            result = fn()
        self.assertEqual((answers, secrets), ([], []), "risposte non usate")
        return result

    def test_edit_groups(self):
        nodes = [n for n in inst.parse_nodes(CLUSTER) if not n.problem]
        groups, assignment = inst.propose_groups(nodes)
        answers = [
            "2",
            "1",
            "2",  # sposta cp1 nel gruppo gpu
            "3",
            "1",  # modifica il gruppo worker...
            "4",
            "2",
            "sun 01:00-03:00",  # ...kernel nella finestra
            "5",
            "2",  # ...due nodi alla volta
            "6",  # ...rimozioni attive
            "1",  # fatto
            "1",  # i gruppi vanno bene
        ]
        result = self.answer(answers, lambda: self.installer.edit_groups(groups, assignment, nodes))
        by = {g.name: g for g in result}
        self.assertNotIn("master", by)  # rimasto vuoto: tolto
        self.assertEqual(assignment["cp1"], "gpu")
        self.assertEqual(by["worker"].kernel, "window")
        self.assertEqual(by["worker"].window, "sun 01:00-03:00")
        self.assertEqual(by["worker"].concurrency, 2)
        self.assertTrue(by["worker"].allow_remove)

    def test_groq_with_backup_endpoint_in_cluster(self):
        groups = [inst.Group("worker", 1), inst.Group("gpu", 2)]
        answers = [
            "1",  # Groq
            "",  # modello predefinito
            "s",  # aggiungo una riserva
            "2",  # endpoint compatibile
            "vllm-gpu",
            "http://vllm.example:8000/v1",
            "modello-locale",
            "3",  # gira su un nodo del gruppo gpu
            "n",  # niente altre riserve
        ]
        probe = mock.patch.object(inst, "llm_probe", return_value=None)
        with probe:
            llm, keys = self.answer(
                answers,
                lambda: self.installer.configure_llm({}, groups),
                secrets=["chiave-groq", "chiave-vllm"],
            )
        names = [e["name"] for e in llm["endpoints"]]
        self.assertEqual(names, ["groq", "vllm-gpu"])
        self.assertEqual(llm["min_interval_seconds"], inst.GROQ_MIN_INTERVAL)
        self.assertEqual(keys, {"GROQ_API_KEY": "chiave-groq", "VLLM_GPU_API_KEY": "chiave-vllm"})
        self.assertEqual(llm["endpoints"][1]["hosted_in_group"], "gpu")
        self.assertTrue(groups[1].requires_fallback)

    def test_wrong_model_can_be_changed(self):
        problems = ["il modello openai/gpt-oss-120b non è tra quelli disponibili (es. altro)", None]
        with mock.patch.object(inst, "llm_probe", side_effect=problems):
            llm, keys = self.answer(
                ["1", "", "s", "altro", "n"],
                lambda: self.installer.configure_llm({}, []),
                secrets=["chiave-groq"],
            )
        self.assertEqual(llm["endpoints"][0]["model"], "altro")
        self.assertEqual(keys, {"GROQ_API_KEY": "chiave-groq"})

    def test_keep_current_llm(self):
        current = {"endpoints": [dict(inst.GROQ)], "min_interval_seconds": 3}
        llm, keys = self.answer(["1"], lambda: self.installer.configure_llm(current, []))
        self.assertEqual((llm, keys), ({"endpoints": [inst.GROQ]}, {}))

    def test_custom_schedule(self):
        cron = self.answer(["4", "15 2 * * *"], lambda: self.installer.choose_schedule(None))
        self.assertEqual(cron, "15 2 * * *")
        cron = self.answer([""], lambda: self.installer.choose_schedule("15 2 * * *"))
        self.assertEqual(cron, "15 2 * * *")


# ------------------------------------------------------------------ prova completa


@unittest.skipUnless(shutil.which("ssh-keygen"), "serve ssh-keygen")
class EndToEnd(unittest.TestCase):
    """Installer completo contro kubectl, helm e ssh finti (tests/fake_cluster.py)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        script = bin_dir / "fake_cluster.py"
        script.write_text(
            f"#!{sys.executable}\n" + (ROOT / "tests" / "fake_cluster.py").read_text()
        )
        script.chmod(0o755)
        for name in ("kubectl", "helm", "ssh"):
            (bin_dir / name).symlink_to(script)
        self.state = self.tmp / "state.json"
        self.write_state(
            {
                "nodes": {
                    "cp1": {"ip": "192.0.2.1"},
                    "w1": {"ip": "192.0.2.11"},
                    "w2": {"ip": "192.0.2.12"},
                    "w3": {"ip": "192.0.2.13", "admin": False},
                    "u1": {"ip": "192.0.2.31", "os": "Ubuntu 24.04 LTS"},
                },
                "labels": {"cp1": {"node-role.kubernetes.io/control-plane": ""}},
                "secrets": {},
                "namespace": None,
                "helm": None,
                "jobs": [],
                "deleted": [],
                "calls": [],
                "homes": str(self.tmp / "homes"),
            }
        )
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        env.update(PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_STATE=str(self.state))
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        access = mock.patch.object(inst, "image_access", return_value="public")
        access.start()
        self.addCleanup(access.stop)

    def write_state(self, state):
        self.state.write_text(json.dumps(state))

    def read_state(self):
        return json.loads(self.state.read_text())

    def run_installer(self, answers, args=()):
        answers = list(answers)
        output = []

        def fake_input(prompt=""):
            output.append(prompt)
            if not answers:
                raise AssertionError("risposte finite, ultima domanda: " + prompt)
            return answers.pop(0)

        with mock.patch("builtins.input", fake_input), mock.patch("builtins.print"):
            code = inst.main(["--no-tui", "--image", IMAGE, *args])
        self.assertEqual(answers, [], "risposte non usate")
        return code, output

    def test_install_reconfigure_live_uninstall(self):
        # Prima installazione: w3 non accetta le credenziali dell'amministratore.
        code, prompts = self.run_installer(
            [
                "",  # nodi: quelli proposti (tutti i supportati)
                "admin",  # utente SSH
                "2",  # w3 non accetta le credenziali: escludilo
                "",  # gruppi: vanno bene
                "3",  # nessun LLM
                "",  # ogni 6 ore
                "Europe/Rome",
                "",  # nessun proxy
                "",  # giri automatici attivi
                "",  # procedo
                "",  # primo giro subito
            ]
        )
        self.assertEqual(code, 0, prompts)
        state = self.read_state()
        values = state["helm"]["values"]
        self.assertTrue(values["dryRun"])
        self.assertFalse(values["suspend"])
        self.assertEqual(values["image"]["digest"], DIGEST)
        self.assertEqual(values["config"]["ssh"]["user"], "admin")
        self.assertEqual(values["timeZone"], "Europe/Rome")
        self.assertEqual([g["name"] for g in values["config"]["groups"]], ["worker", "master"])
        labels = {n: lab.get("sage.io/group") for n, lab in state["labels"].items()}
        self.assertEqual(labels, {"cp1": "master", "w1": "worker", "w2": "worker"})
        ssh_secret = state["secrets"]["sage-ssh"]["data"]
        self.assertIn("id_ed25519", ssh_secret)
        self.assertEqual(
            state["namespace"]["metadata"]["labels"]["app.kubernetes.io/managed-by"], "sage-install"
        )
        self.assertEqual(len(state["jobs"]), 1)
        keys = (self.tmp / "homes" / "192.0.2.11" / ".ssh" / "authorized_keys").read_text()
        self.assertIn("sage@sage", keys)

        # Riconfigurazione: valori attuali come default, stessa chiave.
        # menu, nodi, utente, gruppi, nessun LLM, frequenza, fuso, proxy, procedo, niente giro
        code, prompts = self.run_installer(["1", "", "", "", "3", "", "", "", "", "n"])
        self.assertEqual(code, 0, prompts)
        state = self.read_state()
        self.assertEqual(
            state["secrets"]["sage-ssh"]["data"]["id_ed25519"], ssh_secret["id_ed25519"]
        )
        self.assertTrue(state["helm"]["values"]["dryRun"])

        # Passaggio al vivo, con conferma esplicita.
        code, _ = self.run_installer(["2", "s"])
        self.assertEqual(code, 0)
        self.assertFalse(self.read_state()["helm"]["values"]["dryRun"])

        # Disinstallazione: chiave tolta dai nodi, etichette rimosse, namespace eliminato.
        code, _ = self.run_installer(["5", "s", ""])
        self.assertEqual(code, 0)
        state = self.read_state()
        self.assertIsNone(state["helm"])
        self.assertTrue(all("sage.io/group" not in lab for lab in state["labels"].values()))
        keys = (self.tmp / "homes" / "192.0.2.11" / ".ssh" / "authorized_keys").read_text()
        self.assertNotIn("sage@sage", keys)
        self.assertIn(["namespace", "sage", "--wait=false"], state["deleted"])


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(hasattr(os, "openpty") and sys.platform.startswith("linux"), "serve un pty")
class Terminal(unittest.TestCase):
    """Lista con le caselle in un terminale vero (pty): frecce, spazio, invio."""

    def run_tui(self, code, keys):
        import pty
        import select as sel

        program = (
            f"import sys; sys.path.insert(0, {str(ROOT / 'installer')!r}); "
            "import sage_install as s; ui = s.UI(tui=True, color=False); " + code
        )
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, "-c", program])
        output = b""
        for chunk in keys:
            time.sleep(0.3)
            os.write(fd, chunk)
        deadline = time.time() + 10
        while time.time() < deadline:
            ready, _, _ = sel.select([fd], [], [], 0.2)
            if ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                output += data
        os.waitpid(pid, 0)
        return output.decode(errors="replace")

    def test_checklist_with_keys(self):
        code = (
            "r = ui.checklist('Nodi:', ['a', 'b', 'c'], ['a', 'b', 'c'], {0, 1, 2}, {}); "
            "print('RISULTATO', sorted(r))"
        )
        # "Tutti" toglie tutto, giù di due, spazio su "b", invio.
        out = self.run_tui(code, [b" ", b"\x1b[B", b"\x1b[B", b" ", b"\r"])
        self.assertIn("RISULTATO [1]", out)
        self.assertIn("[x] Tutti", out)

    def test_menu_with_keys(self):
        code = "print('RISULTATO', ui.choose('Scelta:', ['uno', 'due', 'tre']))"
        out = self.run_tui(code, [b"\x1b[B", b"\x1b[B", b"\x1b[A", b"\r"])
        self.assertIn("RISULTATO 1", out)
