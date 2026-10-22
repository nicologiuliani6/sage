# Decisione per una coppia (nodo, pacchetto).
#
# Input (costruito da `sage scan`):
#   node.group                nome del gruppo del nodo (assente o vuoto: nodo senza gruppo)
#   group                     parametri del gruppo: allow_remove, allow_mitigate, kernel
#   kev_available             il catalogo CISA KEV è stato letto in questo giro
#   package.name              nome del pacchetto
#   package.context           contesto raccolto sul nodo (processi, librerie, porte, unit)
#   package.idle_confirmed    inutilizzato da abbastanza scansioni consecutive
#   cves[]                    kev, applicability.status, .verified, .justification
#   proposal                  mitigazione verificata: action = "mitigate", mitigation.verified
#
# Parametri da configurazione (data.sage.config):
#   protected_packages        nomi o pattern che non si rimuovono mai
#
# Garanzie fisse, non configurabili:
#   - nel dubbio si aggiorna (fail closed)
#   - una CVE nel catalogo KEV non è mai "non affetto" né solo mitigata
#   - "non affetto" solo se verificato sul nodo, per tutte le CVE, con il KEV letto
#   - un pacchetto della catena di avvio (bootloader, initramfs, microcodice, firmware) non è
#     mai "non affetto" perché nessun processo lo usa: lo esegue l'avvio del nodo
package sage.decision

default action := "update"

action := "skip" if {
	not group_known
} else := "remove" if {
	input.group.allow_remove == true
	removal_safe
} else := "update" if {
	some cve in input.cves
	cve.kev == true
} else := "not_affected" if {
	input.kev_available == true
	not boot_unused
	count(input.cves) > 0
	every cve in input.cves {
		cve.applicability.status == "not_affected"
		cve.applicability.verified == true
	}
} else := "mitigate" if {
	input.kev_available == true
	input.group.allow_mitigate == true
	input.proposal.action == "mitigate"
	input.proposal.mitigation.verified == true
}

default schedule := "auto"

schedule := "manual" if {
	is_kernel
	input.group.kernel == "manual"
}

group_known if {
	is_string(input.node.group)
	input.node.group != ""
}

is_kernel if startswith(input.package.name, "kernel")

boot_patterns := ["grub2*", "shim*", "dracut*", "microcode_ctl", "*-firmware*", "linux-firmware*"]

is_boot if {
	some pattern in boot_patterns
	glob.match(pattern, ["/"], input.package.name)
}

# "Non affetto" per un pacchetto di avvio solo perché nessun processo lo usa: non vale.
boot_unused if {
	is_boot
	some cve in input.cves
	cve.applicability.justification == "vulnerable_code_not_in_execute_path"
}

autostart := {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect"}

protected if {
	some pattern in data.sage.config.protected_packages
	glob.match(pattern, ["/"], input.package.name)
}

removal_safe if {
	not protected
	not is_kernel
	input.package.idle_confirmed == true
	ctx := input.package.context
	count(ctx.binaries_running) == 0
	count(ctx.libraries_loaded) == 0
	count(ctx.listening) == 0
	every _, unit in ctx.units {
		unit.active != "active"
		not autostart[unit.enabled]
	}
	is_array(ctx.removal_also_removes)
	count(ctx.removal_also_removes) == 0
}
