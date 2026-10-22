# SAGE

**SSVC-Aware Guarded Engine**: decide se una CVE tocca davvero un nodo Kubernetes e cosa fare.

Per ogni pacchetto vulnerabile SAGE si chiede *"questa CVE ci tocca?"* e sceglie un'azione:

| Azione | Quando |
|---|---|
| `not_affected` | la CVE non si applica, **verificato sul nodo**: nessun aggiornamento, viene scritto un VEX |
| `mitigate` | si può disattivare ciò che la rende sfruttabile (es. bloccare un modulo del kernel) |
| `remove` | il pacchetto è inutilizzato da più scansioni e toglierlo non trascina via altro |
| `update` | la CVE si applica, oppure c'è un dubbio |
| `skip` | il nodo non appartiene a nessun gruppo configurato: non viene toccato |

Un LLM legge i dati pubblici della CVE e ne estrae le **condizioni** di sfruttabilità; il nodo le
**verifica**. L'LLM non può dichiarare "siamo al sicuro" sulla parola, e nessun dato dei nodi gli
viene inviato. La decisione finale è di OPA. Un controllore sempre acceso fa il giro dei nodi:
controllo completo, poi un nodo alla volta (gruppi in ordine, canary per primo, master per
ultimi, mai un nodo che modifica se stesso), rollback automatico, e da capo
([ADR-0015](docs/adr/0015-controllore-in-loop.md)).

## Installazione

Da un master del cluster (serve `kubectl` con permessi di amministratore), con un solo comando:

```bash
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/sage
curl -fsSLO https://github.com/<owner>/sage/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sage && ./sage
```

Un eseguibile unico, senza Python sul master: al primo avvio si installa come comando di
sistema (`/usr/local/bin/sage`), poi da qualsiasi cartella basta `sage`
([ADR-0016](docs/adr/0016-installer-eseguibile-unico.md)).
Opzioni: `--live` (modalità reale: da subito su una nuova installazione, passaggio al vivo su
una esistente), `--reinstall` (rifà l'installazione da zero, tenendo storico e cache dell'LLM),
`--allow-remove` (rimozione dei pacchetti inutilizzati), `--dashboard` (apre la dashboard),
`--resume` (giro in corso e log del lavoro attuale). Esempio: `sage --reinstall --live`.

L'installer occupa il terminale e fa una domanda per pagina: mostra i nodi e fa scegliere quali
gestire, propone i gruppi dai dati di Kubernetes (modificabili in una vista a colonne), crea e
installa la chiave SSH dedicata, configura l'LLM (qualsiasi endpoint compatibile OpenAI),
installa il chart con Helm e lancia un primo giro in simulazione. Rilanciato, riconfigura, passa
al vivo, spegne il controllore o disinstalla; ogni modifica finisce in uno storico con chi, quando e perché
([ADR-0012](docs/adr/0012-storico-delle-modifiche.md)).
Lo stato si guarda dalla dashboard di sola lettura (installer, *Apri la dashboard*): allarmi,
sicurezza di ogni nodo, giro in corso, CVE gravi con la scadenza, CVE per urgenza
([ADR-0014](docs/adr/0014-dashboard-sola-lettura.md)).
Funziona con nodi della famiglia RHEL (la remediation usa dnf). Dettagli:
[ADR-0011](docs/adr/0011-installer-interattivo.md); passi completi nella
[guida al test](docs/test-gemello.md).

## Stato

Prima versione completa: raccolta, analisi, decisione, report e VEX, controllore con remediation nodo per nodo,
installer. In test sul gemello. Roadmap in [docs/roadmap.md](docs/roadmap.md).

## Principi

- **Niente hardcoding.** Gruppi, utente SSH, endpoint LLM, pacchetti e moduli protetti, finestre
  arrivano dalla configurazione ([esempio](examples/config.example.yaml)). I campi obbligatori
  mancanti fanno fallire l'avvio con un errore chiaro.
- **Nel dubbio si aggiorna.** È una garanzia della policy, non un parametro.
- **Un nodo alla volta, per gruppi.** Canary per gruppo, master per ultimi, kernel nelle finestre.
- **SAGE non dipende da ciò che patcha.** L'LLM è una catena di endpoint con riserve; senza LLM
  SAGE usa solo regole deterministiche.
- **Solo componenti gratuiti e open source**, versioni pinnate per hash, SHA o digest.

Architettura: [docs/architecture.md](docs/architecture.md). Decisioni: [docs/adr](docs/adr).

## Struttura

```
src/sage/        codice Python (comando `sage`: scan, remediate, resume, check-config)
ansible/         collect.yml e remediate.yml (usati da SAGE e a mano in emergenza)
policy/          regole OPA (Rego) e relativi test
chart/sage/      chart Helm: controllore, modelli dei Job di controllo e remediation, dashboard, RBAC
installer/       installer interattivo (un file, Python 3.9 senza dipendenze)
ci/              script della CI e della release (i workflow li chiamano e basta)
examples/        configurazione e valori d'esempio
docs/            architettura, ADR, roadmap, runbook, guida al test
tests/           test Python con dati sintetici
```

## Sviluppo

```bash
uv sync
uv run pytest                      # con `opa` nel PATH (o SAGE_OPA_BIN) girano anche i test d'integrazione
uv run ruff check . && uv run ruff format --check .
opa test policy -v
uv run sage check-config --config examples/config.example.yaml
```

`ansible/files/collect_node.py` gira **sui nodi** e `installer/sage_install.py` **sui master**,
con il Python di sistema (3.9 su Rocky 9): solo libreria standard. I test dell'installer girano
anche con 3.9: `uv run --no-project --python 3.9 python -m unittest tests.test_installer`.

Release: con la CI verde, un tag `vX.Y.Z` (da `git push` o dalla pagina *Releases* di GitHub).
La versione viene dal tag: non serve aggiornarla nei file prima.

## Licenza

Da definire con CINECA.
