# ADR-0009: La rimozione la decide la policy sui fatti, non l'LLM

Stato: accettata (2026-10-21)

## Contesto

Togliere un pacchetto inutilizzato elimina la vulnerabilità e la superficie d'attacco. Ma un
pacchetto può sembrare inutilizzato in un'istantanea (un job notturno, un servizio avviato a
mano) o essere una dipendenza di altro.

## Decisione

La rimozione non è una proposta dell'LLM. La policy OPA la sceglie solo se, sul nodo:

- nessun processo esegue o carica il pacchetto, nessuna porta, unit spente e non abilitate;
- lo stato vale da `idle_scans_required` scansioni consecutive;
- `dnf remove --assumeno --noautoremove` simulato non toglie altri pacchetti (e dnf non rifiuta);
- il pacchetto non è protetto da configurazione né è un kernel;
- il gruppo lo permette (`allow_remove`, disattivato di default).

Una rimozione chiude anche CVE nel catalogo KEV, quindi viene valutata prima dell'aggiornamento.

## Conseguenze

- Al primo giro non si rimuove nulla: servono più scansioni.
- Per riavere un pacchetto rimosso basta reinstallarlo: il giro successivo lo vedrà in uso o lo
  rimetterà nel conteggio.
