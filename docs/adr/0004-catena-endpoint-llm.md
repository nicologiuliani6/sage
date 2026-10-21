# ADR-0004: Catena di endpoint LLM, modalità sicura, nessun dato dei nodi al modello

Stato: accettata (2026-10-21)

## Contesto

L'LLM locale può girare su un nodo GPU dello stesso cluster che SAGE aggiorna. Se SAGE dipende da un
solo endpoint, aggiornando quel nodo resta senza LLM. Non è ancora noto se l'LLM sarà un'API gestita
da CINECA o un server GPU da gestire. Per il prototipo si usa un servizio esterno (Groq).

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
