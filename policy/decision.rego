# Decisione per una coppia (nodo, pacchetto).
#
# Input (costruito da `sage analyze`):
#   node.group        nome del gruppo del nodo, assente se il nodo non è in nessun gruppo
#   group             parametri del gruppo (allow_remove, kernel, ...)
#   package.name      nome del pacchetto
#   package.context   contesto runtime raccolto dal collector
#   package.removal_also_removes   altri pacchetti che `dnf remove` toglierebbe
#   cves[]            una voce per CVE: kev, applicability.status, applicability.verified
#   proposal          proposta dell'LLM: action, mitigation.verified
#
# Parametri da configurazione (documento data.sage.config):
#   protected_packages   nomi o pattern che non si rimuovono mai
#
# Garanzie fisse, non configurabili:
#   - nel dubbio si aggiorna (fail closed)
#   - una CVE nel catalogo KEV non viene mai dichiarata "non affetto"
#   - "non affetto" solo se verificato sul nodo, per tutte le CVE del pacchetto
package sage.decision

default action := "update"

action := "skip" if {
	not group_known
} else := "update" if {
	some cve in input.cves
	cve.kev == true
} else := "not_affected" if {
	count(input.cves) > 0
	every cve in input.cves {
		cve.applicability.status == "not_affected"
		cve.applicability.verified == true
	}
} else := "remove" if {
	input.proposal.action == "remove"
	input.group.allow_remove == true
	removal_safe
} else := "mitigate" if {
	input.proposal.action == "mitigate"
	input.proposal.mitigation.verified == true
}

default schedule := "auto"

schedule := "manual" if {
	is_kernel
	input.group.kernel == "manual"
} else := "window" if {
	is_kernel
	input.group.kernel == "window"
}

group_known if {
	is_string(input.node.group)
	input.node.group != ""
}

is_kernel if startswith(input.package.name, "kernel")

protected if {
	some pattern in data.sage.config.protected_packages
	glob.match(pattern, [], input.package.name)
}

removal_safe if {
	not protected
	not is_kernel
	ctx := input.package.context
	count(ctx.binaries_running) == 0
	count(ctx.libraries_loaded) == 0
	count(ctx.listening) == 0
	every _, state in ctx.units {
		state != "active"
	}
	count(input.package.removal_also_removes) == 0
}
