# SAGE

**SSVC-Aware Guarded Engine**: patch management guidato dalle CVE per i nodi di un cluster
Kubernetes. Per ogni pacchetto vulnerabile di ogni nodo SAGE si chiede *"questa CVE ci tocca
davvero?"*, decide cosa fare e lo fa, un nodo alla volta.

| Azione | Quando |
|---|---|
| `update` | la CVE si applica, oppure c'è un dubbio |
| `not_affected` | la CVE non si applica, **verificato sul nodo**: nessun aggiornamento, viene scritto un VEX |
| `mitigate` | si può disattivare ciò che la rende sfruttabile (es. bloccare un modulo del kernel) |
| `remove` | il pacchetto è inutilizzato da giorni, nessun servizio ne ha bisogno e toglierlo non trascina via altro |
| `skip` | il nodo non appartiene a nessun gruppo configurato: non viene toccato |

Un LLM legge i **dati pubblici** della CVE e ne estrae le condizioni di sfruttabilità; il nodo le
**verifica**. L'LLM non può dichiarare "siamo al sicuro" sulla parola e non riceve mai dati dei
nodi. La decisione finale è di una policy OPA con garanzie fisse: nel dubbio si aggiorna, una CVE
nel catalogo CISA KEV non è mai "non affetta".

Un **controllore sempre acceso** fa il giro dei nodi: controllo completo, poi remediation un nodo
alla volta (gruppi in ordine, canary per primo, master per ultimi, mai un nodo che modifica se
stesso), rollback automatico in caso di errore, e da capo.

## Installazione

Da un master del cluster, con `kubectl` da amministratore e agent SSH (`ssh -A`):

```bash
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/sage
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sage
./sage --live --allow-remove
```

Un eseguibile unico, senza dipendenze sul master: fa le domande necessarie (nodi, utente SSH,
gruppi, endpoint LLM), installa SAGE nel cluster e si installa come comando di sistema `sage`.

| Opzione | Effetto |
|---|---|
| `--live` | modalità reale da subito (senza: simulazione, nessuna modifica ai nodi) |
| `--allow-remove` | permette la rimozione dei pacchetti inutilizzati |
| `--reinstall` | rifà l'installazione da zero, tenendo storico e cache dell'LLM |
| `--resume` | segue il giro: stato e log di ogni nodo, uno dopo l'altro, fino a Ctrl+C |
| `--dashboard` | apre la dashboard di sola lettura |

Requisiti, passi dell'installer, uso quotidiano e cosa fare quando qualcosa va storto:
**[guida operativa](docs/guida.md)**.

## Documentazione

- [Guida operativa](docs/guida.md): installazione, produzione, dashboard, problemi
- [Architettura](docs/architecture.md): flusso, ruolo dell'LLM, gruppi, alta affidabilità
- [Decisioni di progetto (ADR)](docs/adr)
- [Runbook](docs/runbook.md): interventi a mano ed emergenze
- [Roadmap](docs/roadmap.md)
- [Configurazione d'esempio](examples/config.example.yaml)

## Principi

- **Nel dubbio si aggiorna.** È una garanzia della policy, non un parametro.
- **Niente hardcoding.** Gruppi, utente SSH, endpoint LLM, pacchetti e moduli protetti arrivano
  dalla configurazione; i campi obbligatori mancanti fanno fallire l'avvio con un errore chiaro.
- **Un nodo alla volta, mai su se stesso.** Ogni remediation gira su un altro nodo; un errore
  ferma tutto finché una persona non controlla.
- **SAGE non dipende da ciò che aggiorna.** L'LLM è una catena di endpoint con riserve; senza
  LLM restano le regole deterministiche.
- **Tracciabilità.** Ogni decisione ha la sua prova, ogni modifica di configurazione finisce in
  uno storico con chi, quando e perché.
- **Solo componenti gratuiti e open source**, con versioni fissate per hash, SHA o digest.

## Struttura

```
src/sage/        SAGE nel cluster: controllo, analisi, controllore, remediation, dashboard
ansible/         raccolta dai nodi e remediation (usati da SAGE e a mano in emergenza)
policy/          policy OPA (Rego) con i test
chart/sage/      chart Helm
installer/       installer (Python 3.9, sola libreria standard; compilato in un eseguibile)
ci/              script della CI e della release (i workflow li chiamano e basta)
examples/        configurazione e valori d'esempio
docs/            guida, architettura, ADR, runbook, roadmap
tests/           test con dati sintetici
```

## Sviluppo

```bash
uv sync
SAGE_OPA_BIN=$(which opa) uv run pytest
uv run ruff check . && uv run ruff format --check .
opa test policy -v
uv run sage check-config --config examples/config.example.yaml
uv run --no-project --python 3.9 python -m unittest tests.test_installer
```

Il collector (`ansible/files/collect_node.py`) gira sui nodi e l'installer sui master con il
Python di sistema: solo libreria standard, compatibili con Python 3.9.

**Release**: con la CI verde, un tag `vX.Y.Z` (da `git push` o dalla pagina *Releases* di
GitHub). La versione viene dal tag. La CI pubblica l'immagine per digest, compila l'installer in
un eseguibile con chart, immagine e checksum già fissati, e allega `sage`, `sage-install.py`
(altre architetture), il chart e `SHA256SUMS`. L'immagine su GHCR va resa pubblica una volta
(*Packages → sage → Package settings*), oppure l'installer crea un pull secret.

## Licenza

Da definire.
