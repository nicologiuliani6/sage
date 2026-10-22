# Guida operativa

Come installare SAGE su un cluster, metterlo in produzione e tenerlo sotto controllo. Per le
scelte di progetto vedi [architettura](architecture.md) e [ADR](adr); per gli interventi a mano
il [runbook](runbook.md).

## Come lavora

Un **controllore sempre acceso** fa il giro dei nodi
([ADR-0015](adr/0015-controllore-in-loop.md)):

1. controllo completo di tutti i nodi gestiti (pacchetti, servizi, processi, kernel), analisi
   delle CVE e decisione per ogni pacchetto;
2. remediation **un nodo alla volta**: gruppi in ordine (i master per ultimi), il canary per
   primo in ogni gruppo. Ogni nodo viene svuotato, aggiornato, riavviato se serve e rimesso in
   servizio da un Job che gira su un **altro** nodo;
3. pausa (30 minuti per default), poi da capo.

Un errore ferma tutto finché una persona non controlla. Le CVE gravi (KEV o sfruttate
attivamente) hanno una scadenza (6 ore per default) visibile nella dashboard.

## Requisiti

- Cluster Kubernetes con nodi della famiglia RHEL (Rocky, RHEL, AlmaLinux 8 o 9): la
  remediation usa dnf.
- Un master (o una macchina) con `kubectl` da amministratore del cluster e accesso SSH ai nodi
  con un utente che ha sudo senza password. Helm non serve: se manca, l'installer lo scarica
  con il checksum fissato nella release.
- I pod devono raggiungere Internet (direttamente o con un proxy HTTP) per il catalogo CISA KEV,
  EPSS, i record CVE e l'endpoint LLM.
- Un endpoint LLM compatibile OpenAI con la sua chiave (per esempio un servizio gestito o un
  server vLLM interno). Senza LLM SAGE funziona solo con regole deterministiche e non dichiara
  mai "non affetto".

## Installazione in produzione

Entra su un master **con agent forwarding** (`ssh -A`): l'installer usa le tue credenziali per
installare sui nodi la chiave dedicata a SAGE.

```bash
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/sage
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sage
./sage --live --allow-remove
rm sage SHA256SUMS
```

- `--live`: modalità reale da subito. Finito il primo controllo, SAGE inizia ad aggiornare i
  nodi.
- `--allow-remove`: SAGE può anche rimuovere i pacchetti inutilizzati (nessun processo li usa da
  almeno 7 giorni, nessun servizio del nodo ne ha bisogno, `dnf remove` simulato non si porta
  dietro altro, non protetti).
- Al primo avvio l'eseguibile si installa come comando di sistema `/usr/local/bin/sage`: da lì
  in poi basta `sage`.
- Se `/tmp` è montata `noexec` (baseline CIS): `TMPDIR=~/.cache ./sage ...`.

Senza `--live` l'installazione parte **in simulazione**: SAGE decide e scrive cosa farebbe, ma
non tocca i nodi. È il modo consigliato per un primo contatto con un cluster nuovo: si leggono
le decisioni per qualche giro e poi si passa al vivo con `sage --live`.

L'installer occupa il terminale e fa una domanda per pagina (`--no-tui` per domande su righe
normali):

1. **Nodi** da gestire: spazio per spuntare, `a` tutti, invio per confermare. I nodi con un OS
   non supportato sono visibili ma non selezionabili.
2. **Utente SSH**: crea la chiave dedicata a SAGE, la installa sui nodi e controlla sudo, dnf e
   python3.
3. **Gruppi**: proposti da Kubernetes (control-plane: master; nodi con GPU: gpu; gli altri:
   worker). Si possono spostare i nodi tra i gruppi, scegliere il canary, decidere se il kernel
   si aggiorna nel giro o solo a mano, attivare rimozioni e mitigazioni.
4. **LLM**: URL dell'endpoint e chiave (non viene mostrata); il modello si sceglie dall'elenco
   dell'endpoint. Si può aggiungere una riserva. I limiti di richieste (HTTP 429) li gestisce
   SAGE.
5. **Pausa tra un giro e l'altro** (oppure controllore spento), fuso orario, proxy dei pod.
6. **Riepilogo** e nota per lo storico: solo dopo la conferma il cluster viene toccato.

### Prima della produzione

- Un nodo per ogni tipo di hardware o configurazione in un gruppo suo, con il canary: un
  aggiornamento provato su un nodo dice poco su un nodo diverso (ADR-0005).
- Nodi GPU con driver legati al kernel: gruppo con kernel "solo a mano".
- Servizi fuori da Kubernetes che devono restare (agent di backup, NFS, monitoraggio):
  dichiararli con *Modifica il cluster: servizi aggiuntivi dei nodi* (ADR-0013), così non
  vengono mai considerati inutilizzati.
- Snapshot o backup dei nodi prima del primo giro reale.
- Con un solo master, durante il suo riavvio l'API Kubernetes non risponde per qualche minuto.

## Uso quotidiano

| Comando | Cosa fa |
|---|---|
| `sage` | menu: aggiorna, riconfigura, servizi aggiuntivi, vivo o simulazione, accendi o spegni il controllore, giro immediato, dashboard, storico, disinstalla |
| `sage --resume` | segue il giro: stato e log di ogni lavoro, nodo dopo nodo (Ctrl+C esce, il lavoro continua; `--once` per una sola occhiata) |
| `sage --dashboard` | apre la dashboard (port-forward su `localhost:8080`) |
| `sage --live` | passa al vivo un'installazione in simulazione |
| `sage --reinstall --live` | rifà l'installazione da zero, in modalità reale, tenendo storico e cache dell'LLM |

La **dashboard** è di sola lettura ([ADR-0014](adr/0014-dashboard-sola-lettura.md)): allarmi,
giro in corso nodo per nodo, CVE gravi con la scadenza, una scheda per nodo con ogni decisione e
la sua prova, CVE per urgenza, storico, VEX. Da un altro computer:

```bash
ssh -L 8080:localhost:8080 <utente>@<master>
sage --dashboard          # sul master; poi http://localhost:8080 sul tuo computer
```

Ogni modifica fatta con `sage` finisce nello **storico** (ConfigMap `sage-history`): chi, da
quale macchina, con quale utente Kubernetes, quando, cosa è cambiato e perché
([ADR-0012](adr/0012-storico-delle-modifiche.md)).

Il report completo di un controllo (decisioni, prove, VEX):

```bash
kubectl -n sage get configmap sage-report -o jsonpath='{.binaryData.data\.json\.gz}' \
  | base64 -d | gunzip | python3 -m json.tool | less
```

## Se qualcosa va storto

- **Fermare tutto**: `sage`, *Spegni il controllore*. Per tornare a non toccare i nodi:
  *Torna alla simulazione*.
- **Remediation fallita**: SAGE annulla la transazione dnf e si ferma su tutto il cluster. Se il
  nodo era stato modificato resta in cordon. Leggi il log (`sage --resume`), controlla il nodo,
  `kubectl uncordon <nodo>` se serve, poi `kubectl -n sage create configmap sage-resume`: il
  giro continua dal nodo successivo, quello fallito viene ritentato al giro dopo.
- **Controllore fermo** (allarme nella dashboard): `kubectl -n sage logs deploy/sage-controller`.
  Kubernetes lo riavvia da solo; riparte dal punto salvato.
- **Nodo "saltato: advisory ancora presenti"**: dopo una remediation riuscita il controllo vede
  ancora le stesse advisory. SAGE non lo riaggiorna in loop: serve un controllo a mano
  (`dnf updateinfo list --security` sul nodo).
- **Nessun report da un nodo**: problema SSH. `sage`, *Riconfigura*: ricontrolla accesso, sudo e
  chiavi host.
- **Il pod non parte (ErrImagePull)**: immagine privata. Rendila pubblica o fai creare un pull
  secret all'installer.
- **KEV, EPSS o record CVE non disponibili**: i pod non escono su Internet. *Riconfigura* e
  indica il proxy. Senza KEV SAGE non dichiara nulla "non affetto".
- **"ATTENZIONE" nel profilo di un nodo**: il collector non è riuscito a leggere processi o
  servizi. In quel caso nessun pacchetto viene considerato inutilizzato.

Gli interventi a mano più delicati (rollback del kernel, API Kubernetes non disponibile) sono
nel [runbook](runbook.md).

## Senza installer

Il chart si installa anche a mano: valori d'esempio in
[`examples/values.example.yaml`](../examples/values.example.yaml), chiave SSH e `known_hosts`
nel Secret `<release>-ssh`, etichette `sage.io/group=<gruppo>` sui nodi.
