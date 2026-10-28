# ADR-0004: Catena di endpoint LLM, modalità sicura, nessun dato dei nodi al modello

Stato: accettata (2026-10-21)

## Contesto

L'LLM locale può girare su un nodo GPU dello stesso cluster che SAGE aggiorna. Se SAGE dipende da un
solo endpoint, aggiornando quel nodo resta senza LLM. L'LLM può essere un servizio gestito
esterno, un'API interna o un server GPU da gestire: SAGE non deve dipendere da una scelta.

## Decisione

- Gli endpoint sono una lista ordinata in configurazione, tutti con API compatibile OpenAI
  (vLLM, servizi interni, Groq). Si provano in ordine; una risposta non valida conta come errore.
- **Al modello arrivano solo dati pubblici della CVE e il nome del pacchetto.** La verifica avviene
  nel cluster, quindi nessun dato dei nodi esce, qualunque sia l'endpoint.
- Senza endpoint disponibili: modalità sicura, solo regole deterministiche, mai `not_affected`.
- Budget di chiamate per giro e pausa minima tra chiamate (piani gratuiti). Le risposte vanno in
  cache per CVE e pacchetto; quelle di una riserva vengono richieste di nuovo al primario dopo 24 ore.
- Il gruppo di nodi che ospita un endpoint (`hosted_in_group`) si aggiorna solo se un endpoint
  ospitato altrove risponde (`requires_fallback`); solo in quel caso il drain può ignorare i
  PodDisruptionBudget.

## Conseguenze

- Preferire lo stesso modello su tutti gli endpoint (es. gpt-oss, open-weight Apache 2.0).
- Ogni decisione registra endpoint e modello che l'hanno prodotta.

## Aggiornamento (2026-10-22): limiti di richieste gestiti da SAGE

Il setup non chiede più il numero di richieste al minuto: un servizio adatto a SAGE non deve
averne bisogno, e i piani gratuiti non sono il caso d'uso. Se capita comunque un HTTP 429 (o
503), SAGE aspetta quanto indicato da `Retry-After`, oppure 2, 4 e 8 secondi, e riprova lo stesso
endpoint fino a tre volte. Intanto rallenta le chiamate successive del giro. Le attese sono
limitate (60 secondi l'una, 15 minuti per giro); dopo si passa alla riserva e, senza risposta, la
CVE resta "nel dubbio si aggiorna". `min_interval_seconds` resta disponibile per casi particolari.

## Aggiornamento (2026-10-28): log dei nodi solo agli LLM interni

Con il recupero automatico (ADR-0019) un LLM può ricevere il log di un aggiornamento fallito,
che è un dato del nodo. Lo riceve solo un endpoint con `node_data: true`. Il default è vero per
gli endpoint con `hosted_in_group` (girano su un nodo del cluster) e falso per tutti gli altri:
un servizio esterno non riceve mai dati dei nodi, a meno che qualcuno non lo scriva
esplicitamente nella configurazione. Per le CVE non cambia niente: solo dati pubblici.
