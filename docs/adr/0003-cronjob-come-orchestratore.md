# ADR-0003: CronJob come orchestratore

Stato: sostituita dall'[ADR-0015](0015-controllore-in-loop.md) (2026-10-22)

## Contesto

Opzioni valutate per far girare la pipeline in modo affidabile anche se un master cade:
script su una VM esterna, operatore dedicato (kopf), Argo Workflows, CronJob nativo.

## Decisione

Un CronJob con `concurrencyPolicy: Forbid`. Le ondate di remediation avanzano di un passo a ogni
esecuzione, leggendo lo stato dei Job precedenti.

## Motivazioni

- Script esterno: punto di rottura unico, fuori dal ciclo di vita del cluster.
- kopf: l'alta affidabilità richiede priorità distinte per replica (con priorità uguali gli operatori
  si bloccano); codice in più da mantenere.
- Argo Workflows: adatto, ma è un componente in più per una pipeline lineare.
- CronJob: gestito dal controller-manager, che ha già la leader election sui master. Con `Forbid`
  esiste al massimo un'istanza. Ogni esecuzione è ripetibile senza effetti doppi.

## Conseguenze

- Il codice deve essere idempotente: ogni passo può essere rieseguito.
- Se la pipeline diventasse complessa (rami, approvazioni), Argo Workflows resta l'evoluzione naturale.
