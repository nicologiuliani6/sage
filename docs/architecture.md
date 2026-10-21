# Architettura

SAGE decide, per ogni pacchetto vulnerabile di ogni nodo, se la CVE si applica davvero e cosa fare.
Gira dentro il cluster che protegge, senza dipendere da ciò che aggiorna.

## Flusso

```
sage scan (CronJob, una sola istanza, ogni N ore)
  1. collect   ansible-playbook collect.yml su tutti i nodi (SSH)
  2. analyze   per ogni (nodo, pacchetto, CVE):
                 versione       dati della distribuzione (advisory, Red Hat VEX)
                 configurazione il codice vulnerabile è compilato/presente?
                 uso            l'LLM estrae le condizioni, il nodo le verifica
               + KEV, EPSS, SSVC (dati CISA e FIRST)
               → OPA: not_affected | mitigate | remove | update | skip
  3. record    decisioni, VEX e storico in ConfigMap
  4. act       se serve e nessun Job è in corso:
               crea sage-remediate-<nodo> (canary del gruppo → resto → gruppo successivo)

sage-remediate-<nodo> (Job, schedulato su un ALTRO nodo)
  ansible-playbook remediate.yml --limit <nodo>
  cordon → drain → azioni → riavvio se serve → Ready → uncordon → health check
  errore → rollback (dnf history undo), nodo resta cordoned, ondate ferme
```

## Ruolo dell'LLM

L'LLM **non decide** che un sistema è al sicuro. Legge CVE, advisory e fix e restituisce le
**condizioni** che rendono la vulnerabilità sfruttabile, in forma verificabile (es. "modulo X
caricabile", "servizio Y in ascolto"). Le condizioni sono controllate sul nodo; la decisione finale
è di OPA. Senza conferma sul nodo una CVE è considerata applicabile.

Gli endpoint LLM sono una catena configurabile (locale primario, locale secondario, esterno).
Se nessuno risponde SAGE usa solo regole deterministiche e non dichiara mai `not_affected`.
Ogni decisione registra endpoint e modello che l'hanno prodotta.

## Gruppi di nodi

I nodi non sono trattati come uguali. Ogni gruppo (da configurazione, tramite label) ha ordine,
canary, concorrenza, regole per il kernel, modalità di drain e finestre di manutenzione.
I nodi fuori da ogni gruppo non vengono mai toccati.

## Alta affidabilità

| Elemento | Meccanismo |
|---|---|
| Control plane | 3 master, quorum etcd 2/3; CronJob e Job gestiti dal controller-manager con leader election |
| Scan | CronJob con `concurrencyPolicy: Forbid`: al massimo un'istanza, nessuna leader election da gestire |
| Remediation | un Job per nodo, mai sul nodo bersaglio; idempotente, rilanciato altrove se il pod muore |
| Stato | ConfigMap in etcd |
| LLM | catena di endpoint; modalità sicura senza LLM; il nodo che ospita l'LLM si tocca solo con una riserva attiva |
| Emergenza | stessi playbook lanciabili dal bastion con la stessa immagine ([runbook](runbook.md)) |

## Fuori ambito

- kubelet, containerd, etcd: installati da kubespray come binari, si aggiornano con kubespray.
- Immagini dei workload: responsabilità di chi le usa.

Le motivazioni delle scelte sono negli [ADR](adr).
