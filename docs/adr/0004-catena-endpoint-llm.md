# ADR-0004: Catena di endpoint LLM e modalità sicura

Stato: accettata (2026-10-21)

## Contesto

L'LLM locale può girare su un nodo GPU dello stesso cluster che SAGE aggiorna. Se SAGE dipende da un
solo endpoint, aggiornando quel nodo resta senza LLM. Non è ancora noto se l'LLM sarà un'API gestita
da CINECA o un server GPU da gestire.

## Decisione

- Gli endpoint sono una lista ordinata in configurazione, tutti con API compatibile OpenAI
  (vLLM, servizi interni, Groq). Si provano in ordine.
- Senza endpoint disponibili: modalità sicura, solo regole deterministiche, mai `not_affected`.
- Il gruppo di nodi che ospita l'LLM si aggiorna solo in finestra e solo dopo aver verificato che
  una riserva risponda (`requires_fallback`); il controllo di salute include un prompt di prova.
- Ogni decisione registra endpoint e modello. Quelle prese da una riserva vengono ricontrollate dal
  primario quando torna disponibile.
- Verso endpoint esterni (`minimize_data: true`) non escono IP, hostname o nomi interni.

## Conseguenze

- Preferire lo stesso modello su tutti gli endpoint (es. gpt-oss, open-weight Apache 2.0) per avere
  decisioni coerenti.
- Il free tier degli endpoint esterni ha limiti: la cache delle decisioni e il raggruppamento dei nodi
  con contesto identico riducono le chiamate.
