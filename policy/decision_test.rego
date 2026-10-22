package sage.decision_test

import data.sage.batch
import data.sage.decision

config := {"protected_packages": ["glibc", "systemd", "openssh*"]}

idle_context := {
	"binaries_running": [],
	"libraries_loaded": [],
	"listening": [],
	"units": {"cockpit.socket": {"active": "inactive", "enabled": "disabled"}},
	"removal_also_removes": [],
}

base := {
	"node": {"group": "worker"},
	"group": {"allow_remove": false, "allow_mitigate": false, "kernel": "auto"},
	"kev_available": true,
	"package": {"name": "cockpit-ws", "context": idle_context, "idle_confirmed": true},
	"cves": [{"kev": false, "applicability": {"status": "affected", "verified": true}}],
	"proposal": {},
}

removable := object.union(base, {"group": {"allow_remove": true}})

not_affected_cves := {"cves": [
	{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
	{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
]}

with_pkg(inp, changes) := object.union(inp, {"package": object.union(inp.package, changes)})

with_ctx(inp, changes) := with_pkg(inp, {"context": object.union(inp.package.context, changes)})

act(inp) := a if {
	a := decision.action with input as inp with data.sage.config as config
}

# --- default e nodi senza gruppo

test_default_is_update if act(base) == "update"

test_node_without_group_is_skipped if {
	act(object.union(object.remove(base, ["node"]), {"node": {}})) == "skip"
}

test_empty_group_is_skipped if act(object.union(base, {"node": {"group": ""}})) == "skip"

# --- non affetto

test_not_affected_when_all_verified if act(object.union(base, not_affected_cves)) == "not_affected"

test_not_affected_requires_kev_catalog if {
	act(object.union(object.union(base, not_affected_cves), {"kev_available": false})) == "update"
}

test_kev_wins_over_not_affected if {
	inp := object.union(base, {"cves": [{"kev": true, "applicability": {"status": "not_affected", "verified": true}}]})
	act(inp) == "update"
}

test_unverified_not_affected_falls_back_to_update if {
	inp := object.union(base, {"cves": [{"kev": false, "applicability": {"status": "not_affected", "verified": false}}]})
	act(inp) == "update"
}

test_one_affected_cve_blocks_not_affected if {
	inp := object.union(base, {"cves": [
		{"kev": false, "applicability": {"status": "not_affected", "verified": true}},
		{"kev": false, "applicability": {"status": "unknown", "verified": false}},
	]})
	act(inp) == "update"
}

test_no_cves_means_update if act(object.union(base, {"cves": []})) == "update"

# --- rimozione

test_remove_when_idle_and_allowed if act(removable) == "remove"

test_remove_also_closes_kev if {
	act(object.union(removable, {"cves": [{"kev": true, "applicability": {"status": "affected", "verified": true}}]})) == "remove"
}

test_no_remove_if_group_forbids if act(base) == "update"

test_no_remove_if_not_idle_long_enough if act(with_pkg(removable, {"idle_confirmed": false})) == "update"

test_no_remove_if_running if act(with_ctx(removable, {"binaries_running": ["/usr/libexec/cockpit-ws"]})) == "update"

test_no_remove_if_unit_active if {
	act(with_ctx(removable, {"units": {"cockpit.socket": {"active": "active", "enabled": "disabled"}}})) == "update"
}

test_no_remove_if_unit_enabled if {
	act(with_ctx(removable, {"units": {"cockpit.socket": {"active": "inactive", "enabled": "enabled"}}})) == "update"
}

test_no_remove_if_it_drags_other_packages if act(with_ctx(removable, {"removal_also_removes": ["sssd-common"]})) == "update"

test_no_remove_if_simulation_failed if act(with_ctx(removable, {"removal_also_removes": null})) == "update"

test_no_remove_if_protected_by_config if act(with_pkg(removable, {"name": "openssh-server"})) == "update"

test_kernel_never_removed if act(with_pkg(removable, {"name": "kernel-modules-extra"})) == "update"

# --- mitigazione

mitigable := object.union(base, {
	"group": {"allow_mitigate": true},
	"proposal": {"action": "mitigate", "mitigation": {"verified": true}},
})

test_mitigate_when_verified_and_allowed if act(mitigable) == "mitigate"

test_no_mitigate_if_unverified if {
	act(object.union(mitigable, {"proposal": {"mitigation": {"verified": false}}})) == "update"
}

test_no_mitigate_if_group_forbids if act(object.union(mitigable, {"group": {"allow_mitigate": false}})) == "update"

test_no_mitigate_for_kev if {
	act(object.union(mitigable, {"cves": [{"kev": true, "applicability": {"status": "affected", "verified": true}}]})) == "update"
}

# --- pianificazione del kernel

test_kernel_schedule_follows_group if {
	k := with_pkg(base, {"name": "kernel-core"})
	decision.schedule == "auto" with input as k
	decision.schedule == "manual" with input as object.union(k, {"group": {"kernel": "manual"}})
}

test_userland_schedule_is_auto if decision.schedule == "auto" with input as base

# --- valutazione a blocchi

test_batch_keeps_order if {
	items := [base, removable, object.union(base, not_affected_cves)]
	got := batch.results with input as {"items": items} with data.sage.config as config
	got == [
		{"action": "update", "schedule": "auto"},
		{"action": "remove", "schedule": "auto"},
		{"action": "not_affected", "schedule": "auto"},
	]
}
