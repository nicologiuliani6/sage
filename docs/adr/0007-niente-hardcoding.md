# ADR-0007: Niente valori specifici di un ambiente nel codice

Stato: accettata (2026-10-21)

## Contesto

SAGE nasce su un cluster di prova ma deve poter girare in produzione e su qualsiasi cluster.

## Decisione

- Gruppi, utente SSH, endpoint LLM, pacchetti protetti, finestre e orari arrivano dalla
  configurazione (`config.yaml`, generato dai valori del chart).
- I campi obbligatori non hanno default: la validazione di `sage` e il chart Helm falliscono con un
  messaggio chiaro se mancano.
- La policy OPA legge i parametri da `data.sage.config`. Restano fisse nel codice solo le garanzie
  di sicurezza: nel dubbio si aggiorna; una CVE in KEV non è mai `not_affected`; `not_affected` solo
  se verificato.
- Nessun IP, hostname, nome di progetto o utente personale nella repo; inventario dall'API
  Kubernetes; nome dell'immagine derivato dalla repo in CI.
- Dati reali dei nodi mai committati; i test usano dati sintetici.

## Conseguenze

- Ogni nuovo parametro va aggiunto a `config.py` (con validazione), a `examples/config.example.yaml`
  e ai valori del chart.
