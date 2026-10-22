import pytest

from sage import conditions as c
from tests.conftest import kernel_facts, package

CTX_IDLE = package(
    [], idle=True, units={"x.service": {"active": "inactive", "enabled": "disabled"}}
)["context"]
CTX_ACTIVE = package([], running=["/usr/sbin/x"], listening=["tcp 80"])["context"]
REC_KERNEL = {"program_files": ["crypto/algif_aead.c"], "attack_vector": "local"}
REC_NET = {"attack_vector": "network"}


def km(module="algif_aead"):
    return {"type": "kernel_module", "module": module}


def verify(cond, pkg="kernel-core", ctx=None, kernel=None, record=None, idle=True):
    return c.verify(
        cond, pkg, ctx or CTX_IDLE, kernel or kernel_facts(), record, idle, "da 7 giorni"
    )


# --- kernel_module


def test_loadable_module_is_true_copy_fail_trap():
    # Non caricato ma caricabile su richiesta: NON è sicuro.
    assert verify(km(), record=REC_KERNEL).state == "true"


def test_blocked_module_is_false_with_mitigation_justification():
    check = verify(km(), record=REC_KERNEL, kernel=kernel_facts(blocked=["algif_aead"]))
    assert check.state == "false"
    assert check.justification == c.MITIGATIONS_EXIST


def test_modules_disabled_is_false():
    kernel = kernel_facts()
    kernel["sysctl"]["kernel.modules_disabled"] = 1
    assert verify(km(), record=REC_KERNEL, kernel=kernel).state == "false"


def test_loaded_or_builtin_is_true():
    assert (
        verify(km(), record=REC_KERNEL, kernel=kernel_facts(loaded=["algif_aead"])).state == "true"
    )
    kernel = kernel_facts()
    kernel["modules"]["algif_aead"]["state"] = "builtin"
    assert verify(km(), record=REC_KERNEL, kernel=kernel).state == "true"


@pytest.mark.parametrize(
    "cond, pkg, record, why",
    [
        (km("inesistente"), "kernel-core", REC_KERNEL, "assente"),
        (km(), "kernel-core", {"program_files": []}, "non noti"),
        (km(), "kernel-core", None, "non noti"),
        (km("sctp"), "kernel-core", REC_KERNEL, "non contiene"),  # modulo sbagliato per i file
        (km(), "openssl", REC_KERNEL, "non kernel"),
    ],
)
def test_kernel_module_unverifiable(cond, pkg, record, why):
    check = verify(cond, pkg=pkg, record=record, kernel=kernel_facts(blocked=["algif_aead"]))
    assert check.state == "unknown" and why in check.evidence


def test_module_dir_matches_subdirectories():
    assert c.module_matches_files("drivers/net/ice", ["drivers/net/ice/base/x.c"])
    assert not c.module_matches_files("drivers/net/ice", ["drivers/net/iceberg/x.c"])
    assert not c.module_matches_files(None, ["a/b.c"])


# --- network_service


def test_network_service_idle_confirmed_is_false():
    check = verify({"type": "network_service"}, pkg="cockpit-ws", record=REC_NET)
    assert check.state == "false" and check.justification == c.NOT_IN_EXECUTE_PATH


def test_network_service_idle_not_yet_confirmed_is_unknown():
    assert (
        verify({"type": "network_service"}, pkg="x", record=REC_NET, idle=False).state == "unknown"
    )


def test_network_service_active_or_enabled_is_true():
    assert (
        verify({"type": "network_service"}, pkg="x", ctx=CTX_ACTIVE, record=REC_NET).state == "true"
    )
    enabled = package([], units={"x.socket": {"active": "inactive", "enabled": "enabled"}})[
        "context"
    ]
    assert verify({"type": "network_service"}, pkg="x", ctx=enabled, record=REC_NET).state == "true"


def test_network_service_requires_network_attack_vector():
    # L'LLM dice "servizio di rete" ma il CVSS dice attacco locale: non ci si fida.
    record = {"attack_vector": "local"}
    assert verify({"type": "network_service"}, pkg="x", record=record).state == "unknown"
    assert verify({"type": "network_service"}, pkg="x", record={}).state == "unknown"


# --- component_in_use


def test_component_unused_is_false():
    assert verify({"type": "component_in_use"}, pkg="x").state == "false"


def test_component_with_setuid_is_unknown():
    ctx = package([], idle=True, privileged=["/usr/bin/sudo"])["context"]
    assert verify({"type": "component_in_use"}, pkg="sudo", ctx=ctx).state == "unknown"


def test_component_in_use_kernel_is_unknown():
    assert verify({"type": "component_in_use"}, pkg="kernel-core").state == "unknown"


def test_unknown_condition_type():
    assert verify({"type": "telepatia"}).state == "unknown"


# --- evaluate


def check(state, j=None):
    return c.Check(state, f"prova {state}", j)


def test_evaluate():
    assert c.evaluate([], False).status == "affected"
    assert c.evaluate([check("true"), check("true")], True).status == "affected"
    out = c.evaluate([check("true"), check("false", "j")], True)
    assert (out.status, out.verified, out.justification) == ("not_affected", True, "j")
    out = c.evaluate([check("true"), check("unknown")], True)
    assert (out.status, out.verified) == ("unknown", False)


# --- mitigazione


MIT = {"type": "module_denylist", "module": "algif_aead"}


def mitigation(**kw):
    args = {
        "mitigation": MIT,
        "package": "kernel-core",
        "kernel": kernel_facts(),
        "record": REC_KERNEL,
        "protected_modules": (),
        "loaded_in_group": set(),
    }
    args.update(kw)
    return c.mitigation_ok(**args)


def test_mitigation_ok():
    assert mitigation()[0] is True


@pytest.mark.parametrize(
    "kw",
    [
        {"mitigation": None},
        {"package": "openssl"},
        {"protected_modules": ("algif_*",)},
        {"kernel": kernel_facts(loaded=["algif_aead"])},
        {"kernel": kernel_facts(blocked=["algif_aead"])},
        {"loaded_in_group": {"algif_aead"}},
        {"record": {"program_files": ["net/sctp/socket.c"]}},
    ],
)
def test_mitigation_refused(kw):
    assert mitigation(**kw)[0] is False


def test_package_needed_by_node_service_is_in_use():
    pkg = package([], idle=True)
    pkg["context"]["needed_by"] = "sshd.service"
    check = c.verify({"type": "component_in_use"}, "openssl-libs", pkg["context"], {}, {}, True, 3)
    assert check.state == "true" and "sshd.service" in check.evidence


@pytest.mark.parametrize(
    "pkg", ["grub2-tools", "shim-x64", "dracut", "microcode_ctl", "linux-firmware"]
)
def test_boot_packages_are_never_unused(pkg):
    for cond in ({"type": "component_in_use"}, {"type": "network_service"}):
        check = verify(cond, pkg=pkg, record=REC_NET)
        assert check.state == "unknown" and "avvio" in check.evidence
