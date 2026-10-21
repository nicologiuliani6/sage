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
viene inviato. La decisione finale è di OPA. Le azioni procedono a ondate per gruppi di nodi, con
un canary per gruppo, un nodo alla volta e rollback automatico.

## Stato

Prima versione completa: raccolta, analisi, decisione, report e VEX, remediation a ondate.
Pronta per il test sul gemello: **[guida al test](docs/test-gemello.md)**.
Roadmap in [docs/roadmap.md](docs/roadmap.md).

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
chart/sage/      chart Helm: CronJob, modello del Job di remediation, RBAC
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

`ansible/files/collect_node.py` gira **sui nodi** con il Python di sistema (3.9 su Rocky 9):
solo libreria standard.

## Licenza

Da definire con CINECA.
