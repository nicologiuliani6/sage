# Roadmap

## Fatto

- [x] **M0** repo, configurazione validata senza hardcoding, CI, immagine, chart
- [x] **M2** scan nel cluster: inventario dall'API Kubernetes, gruppi, raccolta via SSH
- [x] **M4** livello LLM: catena di endpoint, cache, schema, budget, solo dati pubblici
- [x] **M4** verifica delle condizioni sul nodo (moduli, servizi, uso) con controlli di coerenza
- [x] **M5** decisione OPA (fail closed, KEV, rimozione e mitigazione sicure), priorità, report, VEX
- [x] **M6** remediation a ondate: Job per nodo, canary e osservazione, concorrenza, finestre,
      riserva LLM, rollback, stop e `sage resume`
- [x] Installer interattivo per qualsiasi cluster e release con la CI
      ([ADR-0011](adr/0011-installer-interattivo.md))

## Da fare

### Test sul gemello ([guida](test-gemello.md))
- [ ] Workflow nella repo, prima immagine su GHCR resa pubblica, release v0.1.0
- [ ] Installazione con l'installer dal master
- [ ] Giri in simulazione, lettura delle decisioni
- [ ] Remediation vera sul canary

### Cluster gemello in HA (M1)
- [ ] 3 master con etcd, bastion dedicato
- [ ] Nodo GPU (in attesa: API del modello o server da gestire?)

### Applicabilità deterministica (M3)
- [ ] Livello versione: Red Hat CSAF VEX (`known_not_affected`) per le CVE delle advisory
- [ ] Livello configurazione kernel: file colpiti e configurazione compilata del nodo

### Valutazione (M7)
- [ ] Confronto con dnf-automatic (security): quanti aggiornamenti, quanti riavvii evitati
- [ ] Accordo con le decisioni di un esperto su un campione
- [ ] Stabilità delle risposte del modello

### Miglioramenti
- [ ] Immagine base pinnata per digest
- [ ] Prompt di prova sull'LLM come controllo di salute del gruppo LLM (oggi: `health_urls`)
- [ ] Integrazione con `certcc-ssvc` per l'albero SSVC completo
- [ ] Installer: supporto ai nodi non RHEL (apt) quando la remediation lo avrà
