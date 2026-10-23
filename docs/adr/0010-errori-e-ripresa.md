# ADR-0010: Un errore ferma tutto, una persona riprende

Stato: accettata (2026-10-21), in parte sostituita dalla [0019](0019-quarantena-del-nodo.md)

## Contesto

Una remediation può fallire per motivi diversi: drain bloccato, pacchetto rotto, nodo che non
torna Ready dopo il riavvio. Ripetere automaticamente può peggiorare la situazione o propagarla.

## Decisione

- Il Job di remediation non ha nuovi tentativi (`backoffLimit: 0`).
- Il playbook fa rollback della transazione dnf e dei blocchi dei moduli; se nulla era stato
  modificato rimette il nodo in servizio, altrimenti lo lascia in cordon.
- Un Job fallito, scaduto o scomparso ferma il controllore: nessun altro nodo viene toccato
  (`halted` nello stato, ADR-0015).
- Si riprende solo con un'azione esplicita: la ConfigMap `<release>-resume` (letta e cancellata dal
  controllore al passo successivo) o il comando `sage resume`, che la crea. Il giro continua dal
  nodo dopo; quello fallito viene ritentato al giro successivo.
- Un errore passeggero dell'API Kubernetes non è un errore della remediation. Su cluster con
  etcd lento (VM su storage condiviso) o durante il riavvio di un master l'API dà EOF o
  `etcdserver: request timed out` per decine di secondi. Per questo:
  - cordon, drain e uncordon nel playbook riprovano (fino a due minuti per l'uncordon): un
    uncordon fallito dopo un riavvio riuscito farebbe annullare un aggiornamento buono;
  - un Job la cui creazione non è stata confermata e che non compare nell'elenco non ferma il
    controllore: il nodo non è stato toccato e torna in coda;
  - l'installer ripete `helm upgrade` dopo un errore passeggero, riportando prima la release
    all'ultima revisione buona se era rimasta in `pending-*`.

## Conseguenze

- Una persona controlla sempre il nodo dopo un errore.
- Il rollback dnf non può togliere il kernel in esecuzione: dopo un errore sul kernel può servire
  un riavvio sul kernel precedente (runbook).
