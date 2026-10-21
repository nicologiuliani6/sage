# ADR-0008: Dipendenze gratuite, open source e pinnate

Stato: accettata (2026-10-21)

## Contesto

Requisito del progetto: solo componenti gratuiti. A marzo 2026 sono stati compromessi Trivy
(binario v0.69.4 e i tag di trivy-action) e LiteLLM (1.82.7 e 1.82.8 su PyPI); il malware rubava,
tra l'altro, i token dei service account Kubernetes. SAGE ha accesso root ai nodi: una dipendenza
compromessa è un rischio diretto.

## Decisione

- Solo componenti open source e gratuiti (Kubernetes, Ansible, OPA, Python, vLLM o servizi
  compatibili OpenAI). I prodotti commerciali citati nell'analisi restano solo come confronto.
- Dipendenze Python pinnate con hash (`uv.lock`).
- GitHub Actions pinnate per SHA; strumenti scaricati in CI con versione fissa e checksum verificato.
- Immagine usata nel cluster per digest, non per tag.
- Scansione dei segreti (gitleaks) in CI.

## Conseguenze

- Aggiornare una dipendenza è un'azione esplicita (nuovo hash, nuovo checksum), revisionata in PR.
