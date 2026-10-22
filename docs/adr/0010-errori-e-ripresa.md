# ADR-0010: Un errore ferma tutto, una persona riprende

Stato: accettata (2026-10-21)

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

## Conseguenze

- Una persona controlla sempre il nodo dopo un errore.
- Il rollback dnf non può togliere il kernel in esecuzione: dopo un errore sul kernel può servire
  un riavvio sul kernel precedente (runbook).
