# Roadmap

## Fatto

- [x] Configurazione validata senza hardcoding, CI, immagine e chart con dipendenze fissate
- [x] Raccolta dai nodi via SSH: advisory, contesto dei pacchetti, kernel, profilo dei servizi
      ([ADR-0013](adr/0013-profilo-del-nodo.md))
- [x] LLM: catena di endpoint, cache, schema, solo dati pubblici delle CVE
- [x] Verifica delle condizioni sul nodo (moduli, servizi, uso) con controlli di coerenza
- [x] Decisione OPA (fail closed, KEV, rimozione e mitigazione sicure), priorità SSVC, report, VEX
- [x] Remediation per nodo con rollback, stop e ripresa
- [x] Controllore sempre acceso che fa il giro dei nodi, con ripresa dopo un'interruzione e
      scadenza per le CVE gravi ([ADR-0015](adr/0015-controllore-in-loop.md))
- [x] Installer interattivo come eseguibile unico, con storico delle modifiche
      ([ADR-0011](adr/0011-installer-interattivo.md), [ADR-0016](adr/0016-installer-eseguibile-unico.md))
- [x] Più distribuzioni: famiglia RHEL (dnf), SUSE (zypper), Debian e Ubuntu (apt con OSV)
      ([ADR-0017](adr/0017-piu-distribuzioni.md))
- [x] Dashboard web di sola lettura, aggiornata in tempo reale
      ([ADR-0014](adr/0014-dashboard-sola-lettura.md))

## Da fare

### Affidabilità
- [ ] Cluster con 3 master: verifica del giro con quorum etcd
- [ ] Immagine base pinnata per digest
- [ ] Prompt di prova sull'LLM come controllo di salute (oggi: `health_urls`)

### Applicabilità deterministica
- [ ] Livello versione: Red Hat CSAF VEX (`known_not_affected`) per le CVE delle advisory
- [ ] Livello configurazione kernel: file colpiti e configurazione compilata del nodo
- [ ] Integrazione con `certcc-ssvc` per l'albero SSVC completo

### Valutazione
- [ ] Confronto con dnf-automatic (security): quanti aggiornamenti, quanti riavvii evitati
- [ ] Accordo con le decisioni di un esperto su un campione
- [ ] Stabilità delle risposte del modello

### Estensioni
- [ ] Prova end-to-end della remediation su un nodo Debian/Ubuntu e SUSE reale
- [ ] Amazon Linux 2023 (`releasever=latest`), Alpine, Arch
- [ ] Dashboard: azioni operative (spegni, giro, riprendi) con login tramite token Kubernetes
