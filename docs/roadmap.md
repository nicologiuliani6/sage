# Roadmap

## M0: repo, CI, immagine
- [x] Struttura, `pyproject` con dipendenze pinnate (`uv.lock`)
- [x] Configurazione validata, nessun valore hardcoded
- [x] Collector (dal prototipo), compatibile con Python 3.9
- [x] Policy OPA iniziale con test
- [x] Chart Helm con valori obbligatori bloccanti
- [x] CI: test, lint, policy, chart, build immagine, gitleaks
- [ ] Prima immagine su GHCR e digest annotato
- [ ] Immagine base pinnata per digest

## M1: cluster gemello in HA
- [ ] 3 master con etcd, bastion dedicato
- [ ] Nodo GPU (in attesa: API del modello o server da gestire?)
- [ ] Label dei gruppi sui nodi

## M2: scan nel cluster
- [ ] `sage scan`: inventario dall'API Kubernetes, `collect.yml` via SSH
- [ ] Report dei nodi salvati in ConfigMap
- [ ] Chiave SSH dedicata, `known_hosts` gestito

## M3: applicabilità deterministica
- [ ] Livello versione: dati della distribuzione (advisory, Red Hat CSAF VEX)
- [ ] Livello configurazione kernel: file colpiti dalla CVE e configurazione del nodo
- [ ] Collector: config kernel, moduli caricati e disponibili, denylist, sysctl

## M4: livello LLM
- [ ] Estrazione delle condizioni in JSON con schema
- [ ] Verifica delle condizioni sul nodo
- [ ] Catena di endpoint, modalità sicura, cache delle decisioni
- [ ] Minimizzazione dei dati verso endpoint esterni

## M5: decisione (demo)
- [ ] SSVC (certcc-ssvc, CISA Vulnrichment), KEV, EPSS
- [ ] OPA collegata ai dati reali
- [ ] Piano e VEX in sola simulazione

## M6: remediation
- [ ] `remediate.yml`: drain, azioni, riavvio, health check, rollback
- [ ] Job per nodo, ondate per gruppo, canary
- [ ] Regole del gruppo LLM: riserva verificata, prompt di prova

## M7: valutazione
- [ ] Confronto con dnf-automatic (security)
- [ ] Accordo con le decisioni di un esperto
- [ ] Stabilità delle risposte del modello
