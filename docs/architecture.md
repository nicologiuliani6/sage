# Architettura

SAGE decide, per ogni pacchetto vulnerabile di ogni nodo, se la CVE si applica davvero e cosa fare.
Gira dentro il cluster che protegge, senza dipendere da ciò che aggiorna. Nessun processo resta
acceso: ogni giro è un pod che nasce e finisce.

## Flusso

```
sage scan (CronJob, una sola istanza, ogni N ore)
  1. nodi e gruppi     API Kubernetes + label selector della configurazione
  2. raccolta          collect.yml via SSH sui nodi con un gruppo
  3. fonti             CISA KEV, FIRST EPSS, record CVE (CVE Program + arricchimento CISA)
  4. analisi           per pacchetto, CVE dalla più probabile da sfruttare:
                         condizioni dalla cache o dall'LLM (solo dati pubblici della CVE)
                         verifica delle condizioni con i fatti raccolti sul nodo
                         stop anticipato appena ogni nodo è deciso
  5. decisione         OPA: skip | remove | update | not_affected | mitigate
  6. stato e report    ConfigMap: stato delle ondate, cache LLM, report con VEX
  7. ondate            se serve e nessun Job è in corso: un Job di remediation
                         ordine dei gruppi → canary del gruppo → osservazione → resto

sage remediate (Job, mai sul nodo bersaglio)
  remediate.yml: cordon → drain → dnf / rimozione / blocco moduli → riavvio se serve
                 → nodo Ready → (master: apiserver, etcd) → uncordon → controlli di salute
  errore → rollback della transazione dnf, nodo in cordon, ondate ferme fino a `sage resume`
```

## Il ruolo dell'LLM

L'LLM **non decide** che un sistema è al sicuro (ADR-0001). Riceve solo dati pubblici della CVE
(descrizione, file sorgente colpiti, vettore CVSS) e il nome del pacchetto, e restituisce le
condizioni **necessarie** per sfruttarla, scelte da un catalogo chiuso:

| Condizione | Falsa (quindi "non affetto") solo se | Controlli di coerenza |
|---|---|---|
| `kernel_module` | il modulo esiste ma è bloccato (`install /bin/false`) o il caricamento è disabilitato | il modulo deve contenere i file colpiti dalla CVE; un modulo solo "non caricato" conta come sfruttabile (caricamento su richiesta) |
| `network_service` | nessuna porta in ascolto, unit spente e non abilitate da N scansioni | il vettore CVSS deve essere di rete |
| `component_in_use` | nessun processo usa il pacchetto da N scansioni | non vale per pacchetti con file setuid, setgid o con capability |

Se una condizione non è verificabile la CVE conta come applicabile. Le risposte sono validate
contro uno schema e messe in cache per CVE e pacchetto.

## Rimozione e mitigazione

- **Rimozione**: decisa dalla policy sui fatti, non dall'LLM. Pacchetto inutilizzato da
  `idle_scans_required` scansioni, `dnf remove` simulato senza altri pacchetti coinvolti, non
  protetto, gruppo con `allow_remove`.
- **Mitigazione**: blocco di un modulo del kernel proposto dall'LLM e verificato (modulo
  disponibile ma non caricato su nessun nodo del gruppo, coerente con i file colpiti, non
  protetto), gruppo con `allow_mitigate`. Al giro successivo la CVE risulta non affetta.

## Gruppi di nodi

Ogni gruppo (label selector) ha ordine, canary e tempo di osservazione, concorrenza, regola per
il kernel (`auto`, `window`, `manual`), modalità di drain, finestre, permessi di rimozione e
mitigazione, controlli di salute. I nodi fuori da ogni gruppo non vengono mai toccati.

## Alta affidabilità

| Elemento | Meccanismo |
|---|---|
| Control plane | 3 master, quorum etcd 2/3; CronJob e Job gestiti dal controller-manager con leader election |
| Scan | CronJob con `concurrencyPolicy: Forbid`; ogni giro è ripetibile senza effetti doppi |
| Remediation | un Job per nodo, mai sul nodo bersaglio, nessun nuovo tentativo automatico |
| Stato | ConfigMap in etcd |
| LLM | catena di endpoint; modalità sicura senza LLM; il gruppo che ospita l'LLM si tocca solo con una riserva funzionante |
| Emergenza | stessi playbook lanciabili dal bastion con la stessa immagine ([runbook](runbook.md)) |

## Fuori ambito

- kubelet, containerd, etcd: installati da kubespray come binari, si aggiornano con kubespray.
- Immagini dei workload: responsabilità di chi le usa.
- Il controllo di versione sui dati della distribuzione (Red Hat CSAF VEX) e quello sulla
  configurazione del kernel sono previsti (roadmap), non ancora implementati: oggi le versioni
  upstream non vengono mai usate per dichiarare "non affetto".
