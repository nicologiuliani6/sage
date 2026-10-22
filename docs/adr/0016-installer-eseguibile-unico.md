# ADR-0016: L'installer come eseguibile unico

Stato: accettata (2026-10-23)

## Contesto

L'installer è un file Python (ADR-0011) da lanciare con `python3 sage-install.py`. Funziona sui
master con il Python di sistema, ma lascia uno script da interpretare e dipende dalla versione
di Python presente. Si vuole un solo file da scaricare, verificare con il checksum e lanciare.

## Decisione

- Il sorgente resta `installer/sage_install.py`: Python 3.9, sola libreria standard, testato con
  unittest come prima. Per ogni release la CI lo fissa (immagine, chart, Helm) e lo compila con
  **PyInstaller** in un **eseguibile unico** `sage` per linux amd64.
- La compilazione avviene in un container **Rocky Linux 8** (glibc 2.28) fissato per digest, con
  il Python 3.12 dei repository Rocky (pacchetti firmati, con la libreria condivisa che
  PyInstaller richiede): l'eseguibile gira su Rocky e RHEL 8 e 9 e sulle distro recenti.
  PyInstaller e le sue dipendenze hanno versioni e hash fissati (`ci/installer-build.txt`).
  Le immagini manylinux sono state scartate: il loro Python non ha la libreria condivisa.
- La CI prova l'eseguibile in container Rocky Linux 8 e 9 senza nessun programma nel `PATH`
  (quindi senza Python), e con `/tmp` montata `noexec` usando `TMPDIR` (baseline CIS).
- La release pubblica `sage`, `sage-install.py` (per altre architetture) e i checksum.
- **Comando di sistema**: al primo avvio l'eseguibile chiede di installarsi in
  `/usr/local/bin/sage` (`--bin` per un'altra cartella) con `sudo -n install`; se lì c'è già
  una copia diversa la aggiorna. Da quel momento si usa `sage` da qualsiasi cartella.
- Opzioni da riga di comando per i casi frequenti: `--live` (modalità reale da subito),
  `--allow-remove` (rimozioni attive in tutti i gruppi), `--dashboard` (apre subito la
  dashboard), `--resume` (stato del giro e log di quello che SAGE sta facendo adesso). Ogni
  modifica fatta con queste opzioni finisce nello storico come le altre (ADR-0012).

## Conseguenze

- Sui master non serve Python: si scarica, si verifica il checksum e si lancia.
- PyInstaller in modalità file unico estrae il runtime in una cartella temporanea: con `/tmp`
  montata `noexec` va indicata un'altra cartella con `TMPDIR` (es. `TMPDIR=~/.cache`).
- L'eseguibile pesa qualche MB (contiene l'interprete); il checksum resta la verifica.

## Alternative scartate

- **Nuitka**: produce codice C compilato, ma richiede un compilatore e tempi di build lunghi per
  un guadagno che qui non serve.
- **zipapp / shiv**: un solo file, ma richiede comunque Python sul master.
- **Riscrittura in Go**: binario statico senza estrazione, ma due linguaggi da mantenere e tutti
  i test dell'installer da rifare.
