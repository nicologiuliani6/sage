# SAGE

**SSVC-Aware Guarded Engine**: decide se una CVE tocca davvero un nodo Kubernetes e cosa fare.

Per ogni pacchetto vulnerabile SAGE si chiede *"questa CVE ci tocca?"* (versione, configurazione,
uso reale sul nodo) e sceglie un'azione:

| Azione | Quando |
|---|---|
| `not_affected` | la CVE non si applica, **verificato sul nodo**: nessun aggiornamento, viene scritto un VEX |
| `mitigate` | la condizione che la rende sfruttabile si può disattivare (es. bloccare un modulo) |
| `remove` | il pacchetto non è usato da nulla e toglierlo non trascina via altro |
| `update` | la CVE si applica, oppure c'è un dubbio |
| `skip` | il nodo non appartiene a nessun gruppo configurato: non viene toccato |

Un LLM legge la CVE e ne estrae le **condizioni** di sfruttabilità; il nodo le **verifica**.
L'LLM non può dichiarare "siamo al sicuro" sulla parola. Le regole finali sono in OPA.

## Stato

Milestone **M0** (repo, CI, configurazione, collector, policy). Vedi [docs/roadmap.md](docs/roadmap.md).

## Principi

- **Niente hardcoding.** Gruppi di nodi, utente SSH, endpoint LLM, pacchetti protetti e finestre di
  manutenzione arrivano dalla configurazione ([esempio](examples/config.example.yaml)). I campi
  obbligatori mancanti fanno fallire l'avvio con un errore chiaro.
- **Nel dubbio si aggiorna.** È una garanzia della policy, non un parametro.
- **Un nodo alla volta, per gruppi.** Canary per gruppo, master per ultimi.
- **SAGE non dipende da ciò che patcha.** L'LLM è una catena di endpoint con riserve; senza LLM
  SAGE usa solo regole deterministiche.
- **Solo componenti gratuiti e open source**, versioni pinnate per hash, SHA o digest.

Architettura completa: [docs/architecture.md](docs/architecture.md). Decisioni di design: [docs/adr](docs/adr).

## Struttura

```
src/sage/        codice Python (comando `sage`)
ansible/         playbook eseguiti da SAGE (e a mano in emergenza)
policy/          regole OPA (Rego) e relativi test
chart/sage/      chart Helm per l'installazione nel cluster
examples/        configurazioni d'esempio
docs/            architettura, ADR, roadmap, runbook
tests/           test Python con dati sintetici
```

## Sviluppo

```bash
uv sync                      # ambiente con dipendenze pinnate (uv.lock)
uv run pytest                # test Python
uv run ruff check .          # lint
opa test policy -v           # test delle policy
uv run sage check-config --config examples/config.example.yaml
```

`ansible/files/collect_node.py` gira **sui nodi** con il Python di sistema (3.9 su Rocky 9):
solo libreria standard.

## Installazione nel cluster

Prerequisiti, creati a mano e mai committati:

```bash
kubectl create namespace sage
# chiave SSH dedicata a SAGE (non quella personale)
kubectl -n sage create secret generic sage-ssh \
  --from-file=id_ed25519=./sage_id_ed25519 --from-file=known_hosts=./known_hosts
# chiavi degli endpoint LLM esterni, se usati
kubectl -n sage create secret generic sage-llm --from-literal=GROQ_API_KEY=...
```

Poi un file di valori locale (non committato) a partire da `chart/sage/values.yaml`:

```bash
helm install sage chart/sage -n sage -f values-local.yaml
```

Il CronJob nasce sospeso (`suspend: true`) e in sola simulazione (`dryRun: true`).

## Licenza

Da definire con CINECA.
