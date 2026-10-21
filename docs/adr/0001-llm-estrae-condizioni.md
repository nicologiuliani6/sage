# ADR-0001: L'LLM estrae condizioni, il nodo le verifica

Stato: accettata (2026-10-21)

## Contesto

Molte CVE segnalate su un pacchetto non si applicano a un nodo specifico: il codice vulnerabile
non è compilato, il modulo non è caricabile, il servizio è spento, la funzionalità non è usata.
Un LLM sa leggere la descrizione di una CVE e capire quando è sfruttabile, ma può sbagliare o
inventare. Un falso "non affetto" lascia aperta una vulnerabilità.

Esistono trappole note: un modulo non caricato può essere caricato su richiesta da un utente non
privilegiato (es. Copy Fail, CVE-2026-31431, via socket AF_ALG); su un nodo Kubernetes "attaccante
locale" significa qualsiasi pod.

## Decisione

L'LLM non restituisce un verdetto ma un elenco di **condizioni verificabili** in JSON con schema
(es. `kernel_module_loadable`, `service_listening`). SAGE le verifica sul nodo. `not_affected` vale
solo se una condizione necessaria è falsa e verificata; se una condizione non è verificabile, la CVE
è considerata applicabile. Un modulo non caricato conta come sicuro solo se anche bloccato.

## Conseguenze

- Il ruolo dell'LLM è circoscritto e misurabile (estrazione di condizioni).
- Ogni `not_affected` ha una prova (comando e output) registrata nel VEX.
- Serve un catalogo di tipi di condizione che il collector sa verificare; cresce nel tempo.
