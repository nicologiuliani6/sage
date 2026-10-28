# Decisioni di architettura (ADR)

Una decisione per file: contesto, decisione, conseguenze. Una decisione superata non si cancella:
si segna come sostituita e se ne scrive una nuova.

| # | Decisione |
|---|---|
| [0001](0001-llm-estrae-condizioni.md) | L'LLM estrae condizioni, il nodo le verifica |
| [0002](0002-ansible-per-le-azioni.md) | Ansible per raccolta e azioni |
| [0003](0003-cronjob-come-orchestratore.md) | CronJob come orchestratore (sostituita dalla 0015) |
| [0004](0004-catena-endpoint-llm.md) | Catena di endpoint LLM, modalità sicura, nessun dato dei nodi al modello |
| [0005](0005-gruppi-di-nodi-e-canary.md) | Gruppi di nodi e canary per gruppo |
| [0006](0006-fonti-cve.md) | Fonti delle CVE |
| [0007](0007-niente-hardcoding.md) | Niente valori specifici di un ambiente nel codice |
| [0008](0008-dipendenze-e-supply-chain.md) | Dipendenze gratuite, open source e pinnate |
| [0009](0009-rimozione-dai-fatti.md) | La rimozione la decide la policy sui fatti, non l'LLM |
| [0010](0010-errori-e-ripresa.md) | Un errore ferma tutto, una persona riprende (in parte sostituita dalla 0019) |
| [0011](0011-installer-interattivo.md) | Un installer interattivo per qualsiasi cluster |
| [0012](0012-storico-delle-modifiche.md) | Storico delle modifiche fatte con l'installer |
| [0013](0013-profilo-del-nodo.md) | Profilo del nodo: servizi, dipendenze, container esclusi |
| [0014](0014-dashboard-sola-lettura.md) | Dashboard web di sola lettura, aperta con port-forward |
| [0015](0015-controllore-in-loop.md) | Un controllore sempre acceso che fa il giro dei nodi |
| [0016](0016-installer-eseguibile-unico.md) | L'installer come eseguibile unico |
| [0017](0017-piu-distribuzioni.md) | Più distribuzioni (dnf, zypper, apt), stesso flusso |
| [0018](0018-ogni-cluster-senza-rompere.md) | SAGE va bene su ogni cluster, senza rompere niente |
| [0019](0019-quarantena-del-nodo.md) | Quarantena del nodo, non fermo del cluster |
| [0021](0021-aggiornamento-automatico.md) | SAGE si aggiorna da solo, solo con release firmate e se lavora |
