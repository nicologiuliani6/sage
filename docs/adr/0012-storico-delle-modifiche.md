# ADR-0012: Storico delle modifiche fatte con l'installer

Stato: accettata (2026-10-22)

## Contesto

Su un cluster di produzione più persone possono installare, riconfigurare o passare al vivo
SAGE. Serve sapere sempre chi ha cambiato cosa, quando e perché, anche a distanza di mesi e da
un'altra macchina.

## Decisione

- Ogni azione dell'installer che cambia qualcosa aggiunge una voce allo **storico**:
  installazione, riconfigurazione, passaggio al vivo e ritorno alla simulazione, sospensione e
  riattivazione dei giri, giro manuale, disinstallazione.
- Ogni voce registra: data e ora con fuso, utente del sistema (e quello che ha usato sudo),
  macchina, utente Kubernetes (`kubectl auth whoami`), azione, versione dell'installer, revisione
  di Helm, **modifiche** e una **nota** facoltativa scritta da chi fa la modifica.
- Le modifiche sono le differenze tra i valori Helm prima e dopo (liste confrontate per nome,
  es. `config.groups[worker].kernel: "auto" → "window"`), più i cambi di gruppo dei nodi e gli
  eventi sulle chiavi. I segreti non compaiono mai: solo "chiave API di X: aggiornata".
- Lo storico sta nel cluster, nella ConfigMap `<release>-history` del namespace di SAGE (una
  voce JSON per riga, ultime 1000), così è lo stesso per tutti gli amministratori. Si consulta
  dall'installer. Anche la descrizione di ogni revisione Helm riporta chi e cosa
  (`helm history`).
- Alla disinstallazione lo storico viene salvato in un file locale prima di eliminare il
  namespace.

## Conseguenze

- Chi lavora fuori dall'installer (Helm o kubectl a mano) non lascia voci nello storico: le
  revisioni di Helm restano, ma senza nota né utente del sistema.
- Le azioni di SAGE stesso (remediation) restano nei Job, nello stato e nel report; non sono in
  questo storico.
