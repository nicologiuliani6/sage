# Istruzioni per lavorare su SAGE

## Regole del progetto

- **Niente hardcoding** (ADR-0007): nessun IP, hostname, utente, nome di progetto o owner nel codice,
  nei test o nei template. Ogni parametro nuovo va in `src/sage/config.py` (con validazione),
  `examples/config.example.yaml` e `chart/sage/values.yaml`. I campi obbligatori non hanno default.
- **Nel dubbio si aggiorna** (fail closed). `not_affected` solo se verificato sul nodo. Una CVE in KEV
  non è mai `not_affected`. Queste garanzie stanno in `policy/decision.rego` e non diventano parametri.
- **Niente dati reali** nella repo: report dei nodi, inventari, chiavi, valori locali. Test con dati
  sintetici.
- **Solo componenti gratuiti e open source**, pinnati: hash in `uv.lock`, Actions per SHA, binari con
  checksum, immagini per digest (ADR-0008).
- `ansible/files/collect_node.py` (sui nodi) e `installer/sage_install.py` (sui master) girano con
  **Python 3.9 e sola libreria standard**. I test dell'installer sono unittest, senza dipendenze.
- La logica della CI sta in `ci/*.sh`: i workflow chiamano solo gli script.
- L'LLM riceve **solo dati pubblici della CVE**: mai dati dei nodi nel prompt (ADR-0004).
- Le condizioni dell'LLM valgono solo con verifica sul nodo e controllo di coerenza (ADR-0001).
- Le espressioni Jinja dei playbook vanno provate con dati finti: niente backslash nei pattern.

## Comandi

```bash
uv sync
SAGE_OPA_BIN=$(which opa) uv run pytest      # senza opa i test d'integrazione vengono saltati
uv run ruff check . && uv run ruff format --check .
opa test policy -v && opa fmt --list --fail policy     # sintassi OPA v1
uv run sage check-config --config examples/config.example.yaml
uv run --no-project --python 3.9 python -m unittest tests.test_installer   # installer con 3.9
helm lint chart/sage -f chart/sage/ci/test-values.yaml
```

## Convenzioni

- Codice e identificatori in inglese; documentazione, messaggi d'errore e commenti in italiano.
- Nei testi non usare il trattino lungo (em dash).
- Ogni decisione di design rilevante diventa un ADR in `docs/adr/`.
- Si lavora su branch con pull request verso `main`.
