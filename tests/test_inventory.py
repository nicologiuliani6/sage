import os

import pytest
import yaml

from sage import config
from sage.inventory import assign_groups, parse_selector, write_inventory
from sage.kube import Node


def node(name, labels=None, ip="192.0.2.10"):
    return Node(name=name, labels=labels or {}, internal_ip=ip, ready=True, unschedulable=False)


@pytest.mark.parametrize(
    "selector, labels, expected",
    [
        ("sage.io/group=worker", {"sage.io/group": "worker"}, True),
        ("sage.io/group==worker", {"sage.io/group": "worker"}, True),
        ("sage.io/group=worker", {"sage.io/group": "gpu"}, False),
        (
            "node-role.kubernetes.io/control-plane",
            {"node-role.kubernetes.io/control-plane": ""},
            True,
        ),
        ("node-role.kubernetes.io/control-plane", {}, False),
        ("!node-role.kubernetes.io/control-plane", {}, True),
        ("a=1,b!=2", {"a": "1", "b": "3"}, True),
        ("a=1,b!=2", {"a": "1", "b": "2"}, False),
    ],
)
def test_selector(selector, labels, expected):
    assert all(r.matches(labels) for r in parse_selector(selector)) is expected


def test_empty_selector_rejected():
    with pytest.raises(ValueError):
        parse_selector(" , ")


def make_cfg(tmp_path, known_hosts=True, proxy=None, extra=None):
    key = tmp_path / "key"
    key.write_text("chiave-finta")
    os.chmod(key, 0o440)
    kh = tmp_path / "known_hosts"
    if known_hosts:
        kh.write_text("")
    return config.parse(
        {
            "extra_services": extra or {},
            "ssh": {
                "user": "admin",
                "key_path": str(key),
                "known_hosts_path": str(kh),
                "proxy_jump": proxy,
            },
            "groups": [
                {
                    "name": "worker",
                    "selector": "sage.io/group=worker",
                    "order": 1,
                    "kernel": "auto",
                },
                {
                    "name": "master",
                    "selector": "node-role.kubernetes.io/control-plane",
                    "order": 2,
                    "kernel": "auto",
                },
            ],
        }
    )


def test_assign_groups(tmp_path):
    cfg = make_cfg(tmp_path)
    nodes = [
        node("w1", {"sage.io/group": "worker"}),
        node("m1", {"node-role.kubernetes.io/control-plane": ""}),
        node("both", {"sage.io/group": "worker", "node-role.kubernetes.io/control-plane": ""}),
        node("none"),
    ]
    groups, warnings = assign_groups(nodes, cfg.groups)
    assert groups["w1"].name == "worker"
    assert groups["m1"].name == "master"
    assert groups["both"] is None and groups["none"] is None
    assert any("both" in w and "più gruppi" in w for w in warnings)
    assert any("none" in w and "senza gruppo" in w for w in warnings)


def test_inventory(tmp_path):
    cfg = make_cfg(tmp_path, proxy="jump@bastion", extra={"w1": ["backup.service", "nfs-utils"]})
    path, warnings = write_inventory([node("w1"), node("noip", ip=None)], cfg, tmp_path / "w")
    inv = yaml.safe_load(path.read_text())["all"]
    assert inv["hosts"] == {
        "w1": {"ansible_host": "192.0.2.10", "sage_extra_services": ["backup.service", "nfs-utils"]}
    }
    assert inv["vars"]["ansible_user"] == "admin"
    args = inv["vars"]["ansible_ssh_common_args"]
    assert "StrictHostKeyChecking=yes" in args and "ProxyJump=jump@bastion" in args
    key = inv["vars"]["ansible_ssh_private_key_file"]
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"
    assert any("noip" in w for w in warnings)


def test_inventory_without_known_hosts_warns(tmp_path):
    cfg = make_cfg(tmp_path, known_hosts=False)
    path, warnings = write_inventory([node("w1")], cfg, tmp_path / "w")
    assert (
        "accept-new" in yaml.safe_load(path.read_text())["all"]["vars"]["ansible_ssh_common_args"]
    )
    assert any("known_hosts" in w for w in warnings)
