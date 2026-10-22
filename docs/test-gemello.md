# Guida al primo test sul gemello

Obiettivo: installare SAGE sul cluster di test con l'installer, farlo girare **in simulazione**,
leggere le decisioni e solo alla fine provare una remediation vera sul canary.

## 0. Prerequisiti (una volta sola)

1. Workflow della CI nella repo (`.github/workflows/ci.yml` e `publish.yml`). Al primo push su
   `main` il workflow `publish` pubblica l'immagine su GHCR.
2. Pacchetto `sage` su GHCR **pubblico**: dal profilo GitHub, *Packages → sage → Package
   settings → Change visibility → Public*. In alternativa l'installer crea un pull secret.
3. Release: con la CI verde, dalla pagina *Releases → Draft a new release* con un tag nuovo
   `vX.Y.Z` (o `git tag vX.Y.Z && git push origin vX.Y.Z`). La versione viene dal tag. Il
   workflow `publish` allega alla release `sage-install.py`, il chart e `SHA256SUMS`.
4. Un endpoint LLM compatibile OpenAI con la sua chiave API (sul gemello si usa Groq:
   `https://api.groq.com/openai/v1`). Si può anche partire senza LLM: SAGE usa solo le regole
   deterministiche.

## 1. Installazione

Entra su un master **con agent forwarding**, così l'installer può usare la tua chiave per
installare quella di SAGE sugli altri nodi:

```bash
ssh -A <utente>@<IP del master>
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/sage-install.py
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
python3 sage-install.py
```

L'installer occupa tutto il terminale e fa una domanda per pagina (con `--no-tui` le fa su
righe normali). Le pagine, nell'ordine:

1. **Nodi**: frecce per muoversi, spazio per spuntare, `a` tutti, `n` nessuno, invio per
   confermare. I nodi con un OS non supportato sono visibili ma non selezionabili.
2. **Utente SSH**: propone l'utente con cui sei entrato (sul gemello `rocky`). Crea la chiave
   dedicata, la installa sui nodi e controlla sudo, dnf e python3. Se un nodo rifiuta l'accesso
   puoi riprovare, escluderlo o fermarti.
3. **Gruppi**: la proposta viene da Kubernetes (ruolo control-plane: master; GPU dichiarate:
   gpu; gli altri: worker). Invio la conferma. *Sposta i nodi tra i gruppi* apre una vista a
   colonne, una per gruppo: frecce per muoversi, spazio sposta il nodo nella colonna accanto,
   `c` lo segna come canary. Da *Modifica un gruppo* si cambiano ordine, kernel, finestra,
   parallelismo, rimozioni e mitigazioni.
4. **LLM**: URL dell'endpoint compatibile OpenAI e chiave API (non viene mostrata). L'installer
   legge dall'endpoint l'elenco dei modelli e lo fa scegliere. Si può aggiungere una riserva.
   I limiti di richieste (HTTP 429) li gestisce SAGE da solo: aspetta e riprova.
5. **Frequenza**, fuso orario, eventuale proxy HTTP dei pod.
6. **Riepilogo** e **nota per lo storico** (facoltativa): solo dopo la conferma tocca il
   cluster. Poi può lanciare un primo giro e mostrarne il log.

Ogni modifica fatta con l'installer finisce nello **storico** (ConfigMap `sage-history`): chi,
da quale macchina, con quale utente Kubernetes, quando, cosa è cambiato e la nota. Si consulta
rilanciando l'installer (*Storico delle modifiche*); anche `helm history sage -n sage` riporta
chi ha fatto ogni revisione.

Una nuova installazione è sempre **in simulazione**: nessuna modifica ai nodi.

## 2. Leggere il primo giro

Alla fine del log c'è il riepilogo per nodo: quanti pacchetti per azione, i pacchetti non
"aggiorna" con il motivo, il piano e cosa farebbe la prossima ondata. Il report completo
(decisioni, prove, VEX):

```bash
kubectl -n sage get configmap sage-report -o jsonpath='{.binaryData.data\.json\.gz}' \
  | base64 -d | gunzip | python3 -m json.tool | less
```

Cosa aspettarsi al primo giro:
- quasi tutto `aggiorna`: è normale. Le rimozioni richiedono più scansioni consecutive
  (`idle_scans_required`), e con il budget LLM non tutte le CVE vengono analizzate subito.
- le risposte dell'LLM restano in cache (`sage-llm-cache`): i giri successivi chiamano il modello
  solo per le CVE nuove.

## 3. Qualche giorno in simulazione

Rilancia `python3 sage-install.py` quando vuoi cambiare qualcosa: parte dalla configurazione
attuale. Da provare:
- *Riconfigura → Modifica un gruppo*: attiva rimozioni e mitigazioni sul gruppo worker e guarda
  cosa proporrebbe.
- `dnf install -y cockpit` su un worker, senza avviarlo: dopo `idle_scans_required` giri dovrebbe
  comparire tra le rimozioni.

### Servizi aggiuntivi dei nodi

Il riepilogo di ogni giro mostra, per nodo, i servizi trovati, i pacchetti che servono a farli
girare e quelli con advisory che non servono a nessun servizio. Se un nodo usa qualcosa fuori da
Kubernetes che deve restare (agent di backup, NFS, strumenti di amministrazione), dichiaralo
dall'installer: *Modifica il cluster: servizi aggiuntivi dei nodi* (ADR-0013).

## 4. Prima remediation vera, sul canary

Rilancia l'installer e scegli **Passa al vivo** (chiede conferma), poi **Lancia un giro adesso**.
Nel log: `remediation avviata su <canary>`. Per seguirla:

```bash
kubectl -n sage get jobs -l sage.io/role=remediate
kubectl -n sage logs -f job/<nome-del-job-sage-fix>
```

Il Job gira su un altro nodo: cordon, drain, aggiornamenti, riavvio se serve, attesa del nodo
Ready, uncordon. Il giro successivo vede l'esito e, dopo l'osservazione del canary, passa agli
altri worker; i master per ultimi e il kernel solo nella finestra.

## Se qualcosa va storto

- **Fermare tutto**: installer → *Sospendi i giri*, oppure
  `kubectl -n sage patch cronjob sage-scan -p '{"spec":{"suspend":true}}'`.
- **Tornare alla simulazione**: installer → *Torna alla simulazione*.
- **Remediation fallita**: SAGE ha fatto rollback e lasciato il nodo in cordon. Controlla il
  nodo, `kubectl uncordon <nodo>`, poi sblocca le ondate con
  `kubectl -n sage create configmap sage-resume`: il giro successivo le riprende e cancella la
  ConfigMap.
- **Nessun report da un nodo**: SSH. Rilancia l'installer (*Riconfigura*): ricontrolla accesso,
  sudo e chiavi host di tutti i nodi scelti.
- **Il pod non parte (ErrImagePull)**: pacchetto GHCR ancora privato. Rendilo pubblico o fai
  creare all'installer un pull secret.
- **KEV, EPSS o record CVE non disponibili**: i pod non escono su Internet. Rilancia l'installer
  e indica il proxy. Senza KEV SAGE non dichiara nulla "non affetto" (è voluto).
- **Errori 429 dall'LLM**: SAGE aspetta e riprova da solo. Le CVE rimaste senza risposta
  vengono analizzate ai giri successivi (le risposte restano in cache).
- **Riepilogo con "ATTENZIONE"** nella riga del profilo: il collector non è riuscito a leggere
  processi o servizi del nodo. In quel caso nessun pacchetto viene dichiarato inattivo.
- **Disinstallare**: installer → *Disinstalla SAGE*. Toglie anche la chiave dai nodi e le
  etichette `sage.io/group`.

## Senza installer

Il chart si installa anche a mano: valori d'esempio in `examples/values.example.yaml`, chiave e
`known_hosts` nel Secret `<release>-ssh`, etichette dei gruppi sui nodi.
