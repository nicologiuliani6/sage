# ADR-0005: Gruppi di nodi e canary per gruppo

Stato: accettata (2026-10-21); concorrenza, osservazione e finestre tolte dall'[ADR-0015](0015-controllore-in-loop.md)

## Contesto

In produzione i nodi non sono uguali: master, worker CPU, nodi GPU di calcolo, nodi GPU con l'LLM.
Un aggiornamento provato su un nodo CPU non dice nulla su un nodo GPU (es. kernel e driver NVIDIA).
Su nodi HPC il drain può interrompere job di lunga durata.

## Decisione

- I gruppi sono definiti in configurazione tramite label selector; nessun gruppo è implicito.
- Ogni gruppo ha: ordine, canary (il primo nodo del gruppo nel giro), regola per il kernel
  (`auto`, `manual`), modalità di drain (`evict`, `wait-empty`), permessi di rimozione e
  mitigazione.
- La decisione è sempre per nodo; si raggruppano solo nodi con contesto identico per non ripetere
  chiamate all'LLM.
- I nodi fuori da ogni gruppo non vengono mai toccati e vengono segnalati.
- Se nodi dello stesso gruppo divergono (kernel, OS), SAGE lo segnala: il canary non è più
  rappresentativo.

## Conseguenze

- Un cluster di prova dovrebbe avere almeno un nodo per ogni gruppo della produzione.
- I master sono l'ultimo gruppo, uno alla volta, per non perdere il quorum di etcd.

## Aggiornamento (2026-10-28): più nodi insieme

Per i cluster grandi un nodo alla volta non basta. Ogni gruppo ha `max_unavailable` (numero o
percentuale, default 1: il comportamento di prima) e `max_unavailable_per_zone` (0 = nessun
limite, altrimenti per `topology.kubernetes.io/zone`). Il canary va sempre da solo; poi i nodi
insieme crescono con quelli già riusciti (1, 2, 4...) fino al tetto. I master restano uno alla
volta, qualunque sia il valore (quorum di etcd). I gruppi restano in ordine: il successivo parte
quando il precedente ha finito. Un errore ferma il gruppo (ADR-0019): nessun nodo nuovo, quelli
partiti finiscono. I PodDisruptionBudget li rispetta il drain; un drain bloccato da un PDB
mette il nodo in attesa senza fermare il gruppo.
