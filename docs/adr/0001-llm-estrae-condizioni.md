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

L'LLM non restituisce un verdetto ma un elenco di **condizioni necessarie**, da un catalogo chiuso
(`kernel_module`, `network_service`, `component_in_use`), in JSON validato da schema. SAGE le
verifica sul nodo con controlli di coerenza indipendenti dall'LLM:

- `kernel_module`: il modulo deve contenere i file sorgente colpiti dalla CVE (dal record del CNA
  del kernel). Conta come falsa solo se il modulo è bloccato (`install /bin/false`) o il
  caricamento è disabilitato; "non caricato" non basta.
- `network_service`: accettata solo se il vettore CVSS è di rete.
- `component_in_use`: non accettata per pacchetti con file setuid, setgid o con capability.
- "inutilizzato" deve valere per `idle_scans_required` controlli consecutivi e almeno
  `idle_days_required` giorni, non per un'istantanea (ADR-0013).

`not_affected` vale solo se una condizione è falsa e verificata, per tutte le CVE del pacchetto.
Una condizione non verificabile rende la CVE applicabile.

## Conseguenze

- Il ruolo dell'LLM è circoscritto e misurabile (estrazione di condizioni).
- Ogni `not_affected` ha una prova registrata nel VEX.
- Il catalogo delle condizioni cresce solo insieme a una verifica sul nodo e a un controllo di
  coerenza.
