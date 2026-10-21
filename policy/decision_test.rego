package sage.decision_test

import data.sage.decision

config := {"protected_packages": ["glibc", "systemd", "openssh*"]}

idle_context := {
	"binaries_running": [],
	"libraries_loaded": [],
	"listening": [],
	"units": {"cockpit.socket": "inactive"},
}

base := {
	"node": {"group": "worker"},
	"group": {"allow_remove": true, "kernel": "window"},
	"package": {"name": "cockpit-ws", "context": idle_context, "removal_also_removes": []},
	"cves": [{"kev": false, "applicability": {"status": "affected", "verified": true}}],
	"proposal": {"action": "update"},
}

test_default_is_update if {
	decision.action == "update" with input as base with data.sage.config as config
}

test_node_without_group_is_skipped if {
	inp := object.union(object.remove(base, ["node"]), {"node": {}})
	decision.action == "skip" with input as inp with data.sage.config as config
}

test_empty_group_is_skipped if {
	inp := object.union(base, {"node": {"group": ""}})
	decision.action == "skip" with input as inp with data.sage.config as config
}

test_kev_wins_over_not_affected if {
	inp := object.union(base, {"cves": [{"kev": true, "applicability": {"status": "not_affected", "verified": true}}]})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_not_affected_when_all_verified if {
	inp := object.union(base, {"cves": [
		{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
		{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
	]})
	decision.action == "not_affected" with input as inp with data.sage.config as config
}

test_unverified_not_affected_falls_back_to_update if {
	inp := object.union(base, {"cves": [{"kev": false, "applicability": {"status": "not_affected", "verified": false}}]})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_one_affected_cve_blocks_not_affected if {
	inp := object.union(base, {"cves": [
		{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
		{"kev": false, "applicability": {"status": "affected", "verified": true}},
	]})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_remove_when_idle if {
	inp := object.union(base, {"proposal": {"action": "remove"}})
	decision.action == "remove" with input as inp with data.sage.config as config
}

test_no_remove_if_group_forbids if {
	inp := object.union(base, {"proposal": {"action": "remove"}, "group": {"allow_remove": false, "kernel": "window"}})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_no_remove_if_running if {
	ctx := object.union(idle_context, {"binaries_running": ["/usr/libexec/cockpit-ws"]})
	pkg := object.union(base.package, {"context": ctx})
	inp := object.union(base, {"proposal": {"action": "remove"}, "package": pkg})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_no_remove_if_unit_active if {
	ctx := object.union(idle_context, {"units": {"cockpit.socket": "active"}})
	pkg := object.union(base.package, {"context": ctx})
	inp := object.union(base, {"proposal": {"action": "remove"}, "package": pkg})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_no_remove_if_it_drags_other_packages if {
	pkg := object.union(base.package, {"removal_also_removes": ["sssd-common"]})
	inp := object.union(base, {"proposal": {"action": "remove"}, "package": pkg})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_no_remove_if_protected_by_config if {
	pkg := object.union(base.package, {"name": "openssh-server"})
	inp := object.union(base, {"proposal": {"action": "remove"}, "package": pkg})
	decision.action == "update" with input as inp with data.sage.config as config
}

test_mitigate_only_if_verified if {
	ok := object.union(base, {"proposal": {"action": "mitigate", "mitigation": {"verified": true}}})
	decision.action == "mitigate" with input as ok with data.sage.config as config
	ko := object.union(base, {"proposal": {"action": "mitigate", "mitigation": {"verified": false}}})
	decision.action == "update" with input as ko with data.sage.config as config
}

test_kernel_schedule_follows_group if {
	pkg := object.union(base.package, {"name": "kernel-core"})
	win := object.union(base, {"package": pkg})
	decision.schedule == "window" with input as win with data.sage.config as config
	man := object.union(win, {"group": {"allow_remove": true, "kernel": "manual"}})
	decision.schedule == "manual" with input as man with data.sage.config as config
	auto := object.union(win, {"group": {"allow_remove": true, "kernel": "auto"}})
	decision.schedule == "auto" with input as auto with data.sage.config as config
}

test_kernel_never_removed if {
	pkg := object.union(base.package, {"name": "kernel-modules-extra"})
	inp := object.union(base, {"proposal": {"action": "remove"}, "package": pkg})
	decision.action == "update" with input as inp with data.sage.config as config
}
