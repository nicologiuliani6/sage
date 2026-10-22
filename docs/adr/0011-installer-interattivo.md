# ADR-0011: Un installer interattivo per qualsiasi cluster, distribuito con le release

Stato: accettata (2026-10-22)

## Contesto

Installare SAGE a mano richiedeva molti passi: chiave SSH, `known_hosts`, etichette sui nodi,
Secret, file di valori, Helm. Ogni passo dipendeva dal cluster ed era facile sbagliarlo. Serve un
solo comando, da lanciare su un master di un cluster qualsiasi, che faccia scegliere i nodi da
gestire e prepari tutto il resto.

## Decisione

- **Un file Python** (`installer/sage_install.py`) con la sola libreria standard e compatibile con
  Python 3.9, lo stesso vincolo del collector: sui master di produzione c'è il Python di sistema,
  non pip. Si lancia da un master o da qualsiasi macchina con `kubectl` da amministratore.
- **A schermo intero, una domanda per pagina**: schermo alternativo del terminale, liste con
  caselle, menu, campi di testo (le chiavi mascherate) e una vista a colonne per spostare i nodi
  tra i gruppi, fatti con `termios` e sequenze ANSI. Alla chiusura ristampa i messaggi nel
  terminale normale. Con `--no-tui` o senza terminale interattivo, domande su righe.
- **Passi**: nodi (i non supportati sono visibili ma non selezionabili), accesso SSH, gruppi
  proposti dai dati di Kubernetes (control-plane: master per ultimi con finestra; GPU: gpu con
  kernel manuale; gli altri: worker), LLM, frequenza, proxy, immagine, riepilogo e conferma.
  Solo dopo la conferma tocca il cluster.
- **LLM generico**: URL e chiave di un endpoint compatibile OpenAI, modello scelto dall'elenco
  che l'endpoint stesso fornisce. Nessun servizio predefinito e nessun limite di richieste da
  impostare (vedi ADR-0004).
- **Storico** di ogni modifica: vedi ADR-0012.
- **Gruppi tramite etichetta**: l'installer mette `sage.io/group=<gruppo>` sui nodi scelti e
  configura ogni gruppo con quel selettore. I nodi senza etichetta non vengono toccati.
- **SSH**: chiave ed25519 dedicata, creata in una cartella temporanea 0700 e salvata solo nel
  Secret. Viene installata sui nodi con le credenziali di chi lancia l'installer (agent SSH),
  poi si verificano con la chiave di SAGE sudo senza password, dnf e python3 >= 3.9. Le chiavi
  host si registrano al primo contatto dal master; una chiave host cambiata richiede una
  conferma esplicita.
- **Rilanciabile**: su un'installazione esistente parte dai valori attuali e offre
  riconfigurazione, passaggio al vivo, sospensione, un giro immediato e disinstallazione (che
  toglie anche la chiave dai nodi e le etichette). Una nuova installazione è sempre in
  simulazione: il vivo è un'azione separata, con conferma.
- **Distribuzione**: per un tag `vX.Y.Z` la CI pubblica una release con l'installer, il chart e
  i checksum. Nell'installer della release la CI scrive l'immagine per digest, URL e sha256 del
  chart e di Helm (letti da get.helm.sh al momento della release). Da una copia della repo
  l'installer usa il chart locale e `--image`.
- **Segreti** con server-side apply: nessuna copia dei dati nell'annotazione last-applied.
- **Logica della CI negli script `ci/*.sh`**: i workflow si limitano a chiamarli, così si
  modificano di rado.

## Conseguenze

- Installare, riconfigurare e disinstallare è lo stesso comando. Il chart resta installabile a
  mano con un file di valori (vedi `examples/values.example.yaml`).
- Per ora solo nodi della famiglia RHEL, perché la remediation usa dnf.
- Il checksum di Helm è quello pubblicato dal progetto Helm al momento della release, come fa lo
  script d'installazione ufficiale. Viene fissato nell'installer di ogni release.
- Il primo contatto SSH dal master si fida delle chiavi host (TOFU), come `ssh-keyscan`.

## Alternative scartate

- **Script bash**: leggere JSON e YAML in modo affidabile e fare le liste con le caselle
  richiede strumenti che sui master possono mancare (jq, whiptail).
- **Python con librerie** (rich, questionary): servirebbe pip sui master.
- **`sage install` dentro l'immagine**: le credenziali per installare la chiave sui nodi sono
  dell'amministratore sul master, non di un pod.
- **`curl | bash`**: niente possibilità di controllare il file prima di eseguirlo. L'installer
  si scarica e poi si lancia, e la release pubblica i checksum.
