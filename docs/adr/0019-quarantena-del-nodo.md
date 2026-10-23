# ADR-0019: Quarantena del nodo, non fermo del cluster

Stato: accettata (2026-10-23). Sostituisce in parte l'ADR-0010.

## Contesto

Con l'ADR-0010 un errore fermava tutto finché una persona non creava `<release>-resume`.
SAGE però deve andare avanti senza persone (ADR-0018): su 1000 nodi un nodo con un pacchetto
rotto non può bloccare gli altri 999 fino a lunedì. Serve fermare la propagazione di un
aggiornamento difettoso, non tutto il resto.

## Decisione

- **Nodo**: una remediation fallita fa rollback (come prima). Se dopo il rollback il nodo è
  sano (Ready e controlli di salute) torna in servizio; altrimenti resta in cordon. In entrambi
  i casi il nodo va in quarantena: si ritenta dopo un'attesa che raddoppia a ogni errore
  (1 ora, 2, 4... fino a 7 giorni). Una remediation riuscita azzera il conteggio.
- **Gruppo**: si ferma per il resto del giro se fallisce il canary, un master, o più di
  `max(1, 10%)` dei nodi del gruppo. Riprova da solo dopo un'attesa che raddoppia allo stesso
  modo. Gli altri gruppi proseguono, nell'ordine di sempre (master per ultimi).
- **Cordon**: SAGE segna i nodi che mette in cordon (annotazione `sage.io/cordoned`). Solo
  quelli può riprendere; un nodo in cordon messo da una persona non viene mai toccato.
- **Infrastruttura**: un Job mai creato o un'API che non risponde non sono errori del nodo:
  il nodo torna in coda (già dalla 0.6.5).
- **A mano**: `halted` resta come interruttore esplicito (Spegni il controllore); la
  ConfigMap `<release>-resume` azzera quarantene e gruppi fermi.

## Conseguenze

- Nessuna persona è necessaria; gli avvisi (Eventi, metriche, webhook) dicono cosa è in
  quarantena e perché.
- Un aggiornamento difettoso arriva al più al canary o al 10% di un gruppo per giro, poi il
  gruppo aspetta sempre di più.
