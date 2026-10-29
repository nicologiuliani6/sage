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
- [x] Nessuna persona necessaria: quarantena del nodo e del gruppo al posto del fermo del
      cluster, recupero automatico da un catalogo chiuso (regole, poi LLM interno), avvisi
      (Eventi e webhook) ([ADR-0019](adr/0019-quarantena-del-nodo.md))
- [x] Robustezza su ogni cluster: errori passeggeri dell'API, control plane stabile prima di
      ogni nodo, drain bloccato da un PDB senza fermare il gruppo, test con kind 1.34 e 1.37
      ([ADR-0018](adr/0018-ogni-cluster-senza-rompere.md))
- [x] Dashboard a pagine con grafici: panoramica, nodi, CVE, giri, salute, log, storico
- [x] Aggiornamento automatico alle release firmate, con rollback se SAGE non lavora
      ([ADR-0021](adr/0021-aggiornamento-automatico.md))

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

### Scala: cluster da 1000 nodi
- [x] Remediation in parallelo per gruppo (`max_unavailable`, avvio graduale, limite per zona,
      master uno alla volta).
- [ ] Remediation in parallelo: controllo della capacità libera del cluster prima di svuotare
      un nodo (oggi la protezione la danno i PodDisruptionBudget).
- [ ] Raccolta più parallela: `forks` di Ansible configurabile, più pod di controllo
- [x] Report e stato oltre il limite di 1 MiB di una ConfigMap: divisi in parti
      (`<nome>-part-N`, fino a 10 ConfigMap, circa 9 MB compressi), letti e scritti in modo
      trasparente; una scrittura a metà non viene mai letta come valida
- [ ] Oltre qualche migliaio di nodi: una risorsa (CRD) per nodo e report su un volume o un
      object storage, fuori da etcd
- [ ] Chiamate all'LLM in parallelo e budget per giro adatto a un server locale veloce
- [ ] Dashboard aggregata per gruppo, con filtri e paginazione

### Estensioni
- [ ] Prova end-to-end della remediation su nodi Debian/Ubuntu e SUSE reali
- [ ] Amazon Linux 2023 (`releasever=latest`), Alpine, Arch
- [ ] Dashboard: azioni operative (spegni, giro, riprendi) con login tramite token Kubernetes
