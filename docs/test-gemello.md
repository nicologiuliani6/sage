# Guida al primo test sul gemello

Obiettivo: installare SAGE sul cluster di test con l'installer, farlo girare **in simulazione**,
leggere le decisioni e solo alla fine passare al vivo.

SAGE ha un **controllore sempre acceso** (ADR-0015) che fa il giro dei nodi: controllo completo,
poi un nodo alla volta (prima i worker con il canary per primo, poi i master), pausa, da capo.
Ogni remediation gira in un Job su un altro nodo: un nodo non modifica mai se stesso.

## 0. Prerequisiti (una volta sola)

1. Workflow della CI nella repo (`.github/workflows/ci.yml` e `publish.yml`). Al primo push su
   `main` il workflow `publish` pubblica l'immagine su GHCR.
2. Pacchetto `sage` su GHCR **pubblico**: dal profilo GitHub, *Packages → sage → Package
   settings → Change visibility → Public*. In alternativa l'installer crea un pull secret.
3. Release: con la CI verde, dalla pagina *Releases → Draft a new release* con un tag nuovo
   `vX.Y.Z` (o `git tag vX.Y.Z && git push origin vX.Y.Z`). La versione viene dal tag. Il
   workflow `publish` allega alla release l'eseguibile `sage`, `sage-install.py`, il chart e
   `SHA256SUMS`.
4. Un endpoint LLM compatibile OpenAI con la sua chiave API (sul gemello si usa Groq:
   `https://api.groq.com/openai/v1`). Si può anche partire senza LLM: SAGE usa solo le regole
   deterministiche.

## 1. Installazione

Entra su un master **con agent forwarding**, così l'installer può usare la tua chiave per
installare quella di SAGE sugli altri nodi:

```bash
ssh -A <utente>@<IP del master>
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/sage
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sage
./sage
```

Al primo avvio chiede di installarsi come comando di sistema (`/usr/local/bin/sage`): da lì in
poi basta `sage`, e il file scaricato si può cancellare. Se `/tmp` è montata `noexec` (baseline
CIS): `TMPDIR=~/.cache sage`.
Opzioni: `--live` per partire subito in modalità reale (su un'installazione esistente: passa al
vivo), `--reinstall` per rifare l'installazione da zero tenendo storico e cache dell'LLM, `--allow-remove` per permettere la
rimozione dei pacchetti inutilizzati, `--dashboard` per aprire la dashboard, `--resume` per
vedere il giro in corso e seguire il log del lavoro attuale.

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
   `c` lo segna come canary. Da *Modifica un gruppo* si cambiano ordine nel giro, canary, kernel
   (nel giro o solo a mano), rimozioni e mitigazioni.
4. **LLM**: URL dell'endpoint compatibile OpenAI e chiave API (non viene mostrata). L'installer
   legge dall'endpoint l'elenco dei modelli e lo fa scegliere. Si può aggiungere una riserva.
   I limiti di richieste (HTTP 429) li gestisce SAGE da solo: aspetta e riprova.
5. **Pausa tra un giro e il successivo** (oppure controllore spento), fuso orario, eventuale
   proxy HTTP dei pod.
6. **Riepilogo** e **nota per lo storico** (facoltativa): solo dopo la conferma tocca il
   cluster. Poi può lanciare un primo giro e mostrarne il log.

Ogni modifica fatta con l'installer finisce nello **storico** (ConfigMap `sage-history`): chi,
da quale macchina, con quale utente Kubernetes, quando, cosa è cambiato e la nota. Si consulta
rilanciando l'installer (*Storico delle modifiche*); anche `helm history sage -n sage` riporta
chi ha fatto ogni revisione.

Una nuova installazione è sempre **in simulazione**: nessuna modifica ai nodi.

## 2. Leggere il primo giro

### Dalla dashboard

Rilancia l'installer e scegli *Apri la dashboard (sola lettura)*. Dal tuo PC apri un tunnel verso
il master e poi il browser su `http://localhost:8080`:

```bash
ssh -L 8080:localhost:8080 <utente>@<IP del master>
```

In alto gli allarmi, poi quanto manca (nodi senza azioni in sospeso, advisory da applicare, CVE
KEV aperte, CVE gravi con la scadenza), il giro in corso nodo per nodo, una scheda per nodo con i pacchetti e il motivo di ogni
decisione, le CVE ordinate per urgenza e lo storico. Si aggiorna da sola ogni minuto.

### Dal log e dal report

Alla fine del log c'è il riepilogo per nodo: quanti pacchetti per azione, i pacchetti non
"aggiorna" con il motivo e il piano. Il report completo
(decisioni, prove, VEX):

```bash
kubectl -n sage get configmap sage-report -o jsonpath='{.binaryData.data\.json\.gz}' \
  | base64 -d | gunzip | python3 -m json.tool | less
```

Cosa aspettarsi al primo giro:
- quasi tutto `aggiorna`: è normale. "Inutilizzato" (e quindi non affetto o da rimuovere)
  richiede almeno `idle_scans_required` controlli e `idle_days_required` giorni (7), e con i
  limiti dell'LLM non tutte le CVE vengono analizzate subito.
- le risposte dell'LLM restano in cache (`sage-llm-cache`): i giri successivi chiamano il modello
  solo per le CVE nuove.

## 3. Qualche giorno in simulazione

Rilancia `sage` quando vuoi cambiare qualcosa: parte dalla configurazione
attuale. Da provare:
- *Riconfigura → Modifica un gruppo*: attiva rimozioni e mitigazioni sul gruppo worker e guarda
  cosa proporrebbe.
- `dnf install -y cockpit` su un worker, senza avviarlo: dopo `idle_days_required` giorni dovrebbe
  comparire tra le rimozioni.

### Servizi aggiuntivi dei nodi

Il riepilogo di ogni giro mostra, per nodo, i servizi trovati, i pacchetti che servono a farli
girare e quelli con advisory che non servono a nessun servizio. Se un nodo usa qualcosa fuori da
Kubernetes che deve restare (agent di backup, NFS, strumenti di amministrazione), dichiaralo
dall'installer: *Modifica il cluster: servizi aggiuntivi dei nodi* (ADR-0013).

## 4. Al vivo

Rilancia l'installer e scegli **Passa al vivo** (chiede conferma). Dal giro successivo (o subito
con **Lancia un giro adesso**) il controllore sistema i nodi uno alla volta: il canary dei
worker, gli altri worker, poi i master. Per seguire un nodo:

```bash
kubectl -n sage logs deploy/sage-controller -f        # cosa fa il controllore
kubectl -n sage get jobs -l sage.io/role=remediate
kubectl -n sage logs -f job/<nome-del-job-sage-fix>
```

Il Job di un nodo gira su un altro nodo: cordon, drain, aggiornamenti, riavvio se serve, attesa
del nodo Ready, uncordon. Appena finisce, il controllore passa al nodo successivo. Se il nodo da
sistemare è quello del controllore, il drain lo sposta su un altro nodo e il giro riprende da lì.

## Se qualcosa va storto

- **Fermare tutto**: installer → *Spegni il controllore*, oppure
  `kubectl -n sage scale deploy/sage-controller --replicas=0`.
- **Tornare alla simulazione**: installer → *Torna alla simulazione*.
- **Remediation fallita**: SAGE ha fatto rollback e lasciato il nodo in cordon. Controlla il
  nodo, `kubectl uncordon <nodo>`, poi `kubectl -n sage create configmap sage-resume`: il
  controllore riprende dal nodo successivo e cancella la ConfigMap.
- **Controllore fermo** (allarme nella dashboard): `kubectl -n sage logs deploy/sage-controller`.
  Kubernetes lo riavvia da solo se si blocca; riparte dal punto salvato.
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
