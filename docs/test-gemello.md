# Guida al primo test sul gemello

Obiettivo: installare SAGE sul cluster di test con l'installer, farlo girare **in simulazione**,
leggere le decisioni e solo alla fine provare una remediation vera sul canary.

## 0. Prerequisiti (una volta sola)

1. Workflow della CI nella repo (`.github/workflows/ci.yml` e `publish.yml`). Al primo push su
   `main` il workflow `publish` pubblica l'immagine su GHCR.
2. Pacchetto `sage` su GHCR **pubblico**: dal profilo GitHub, *Packages → sage → Package
   settings → Change visibility → Public*. In alternativa l'installer crea un pull secret.
3. Release: con la CI verde, un tag con la versione di `pyproject.toml` e `Chart.yaml`,
   con `git tag v0.1.0 && git push origin v0.1.0` oppure dalla pagina *Releases → Draft a new
   release* (tag nuovo `v0.1.0`). Il workflow `publish` allega alla release `sage-install.py`,
   il chart e `SHA256SUMS`.
4. Una chiave API di Groq (gratuita, da console.groq.com), oppure un altro endpoint compatibile
   OpenAI. Si può anche partire senza LLM: SAGE usa solo le regole deterministiche.

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

L'installer chiede, nell'ordine:

1. **Nodi**: frecce per muoversi, spazio per spuntare, `a` tutti, `n` nessuno, invio per
   confermare. I nodi con un OS non supportato sono visibili ma non selezionabili.
2. **Utente SSH** (sul gemello `rocky`): crea la chiave dedicata, la installa sui nodi e controlla
   sudo, dnf e python3. Se un nodo rifiuta l'accesso puoi riprovare, escluderlo o fermarti.
3. **Gruppi**: proposti in automatico (worker con canary, master per ultimi con il kernel nella
   finestra del sabato notte). Si possono spostare nodi e cambiare canary, kernel, parallelismo,
   rimozioni e mitigazioni.
4. **LLM**: Groq, un endpoint compatibile o nessuno. La chiave non viene mostrata e viene provata
   subito.
5. **Frequenza**, fuso orario, eventuale proxy HTTP dei pod.
6. **Riepilogo**: solo dopo la conferma tocca il cluster. Poi lancia un primo giro e ne mostra
   il log.

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
- **Errori 429 da Groq**: aumenta `config.llm.min_interval_seconds` o abbassa
  `max_calls_per_run` (valori Helm).
- **Disinstallare**: installer → *Disinstalla SAGE*. Toglie anche la chiave dai nodi e le
  etichette `sage.io/group`.

## Senza installer

Il chart si installa anche a mano: valori d'esempio in `examples/values.example.yaml`, chiave e
`known_hosts` nel Secret `<release>-ssh`, etichette dei gruppi sui nodi.
