# ADR-0014: Dashboard web di sola lettura, aperta con port-forward

Stato: accettata (2026-10-22)

## Contesto

Il riepilogo di ogni giro è nel log del Job e il report completo in una ConfigMap compressa:
per sapere come sta un nodo, se c'è un allarme o a che punto è il giro bisogna
leggere log o decodificare JSON. Serve una vista d'insieme, ma senza aprire un nuovo modo di
modificare il cluster né una nuova superficie d'attacco.

## Decisione

- **Sola lettura**: la dashboard mostra quello che SAGE ha già scritto (report, stato delle
  controllore, storico, Lease, nodi) e non modifica niente. Le azioni restano nell'installer, dove
  ogni modifica finisce nello storico con l'identità di chi la fa (ADR-0012).
- **Nello stesso pacchetto**: `sage dashboard`, server HTTP della libreria standard e una pagina
  statica (HTML, JavaScript e CSS nel pacchetto `sage.web`), nessuna dipendenza nuova e nessuna
  risorsa da Internet. Stessa immagine, un Deployment in più nel chart (`dashboard.enabled`).
- **Accesso tramite Kubernetes**: il server ascolta solo su 127.0.0.1 nel pod e non ha un
  Service. Si apre con `kubectl port-forward` (anche dall'installer, *Apri la dashboard*): chi
  può farlo lo decide l'RBAC del cluster, quindi non serve un login proprio. Le richieste con
  un `Host` diverso da localhost vengono rifiutate (difesa dal DNS rebinding).
- **Permessi minimi**: ServiceAccount proprio con `get` solo sulle ConfigMap del report, dello
  stato, del controllore e dello storico, sul Lease e sul Deployment del controllore (per nome),
  e lettura dei nodi. Non monta la
  chiave SSH né la chiave dell'LLM.
- **Contenuti**: allarmi (SAGE fermo, controllore spento o senza segni di vita, remediation
  fallite, nodi non Ready, CVE KEV aperte, CVE gravi oltre la scadenza,
  profilo non affidabile), avanzamento (nodi senza azioni in
  sospeso, advisory da applicare, nodi già passati nel giro, scadenza delle CVE gravi,
  prossimo giro), una scheda per nodo con il motivo di ogni decisione, le CVE ordinate per
  urgenza con filtri, lo storico e il download del VEX.
- **Tempo reale**: la pagina rilegge lo stato ogni `dashboard.refreshSeconds` (5 s, minimo 2) e
  si ridisegna solo se qualcosa è cambiato, senza chiudere i dettagli aperti. Il server tiene i
  dati per lo stesso intervallo, quindi più schede aperte non moltiplicano le letture dall'API.
  Con la scheda nascosta non legge niente; un indicatore segnala se i dati sono vecchi.
- **Pagina sicura per costruzione**: Content-Security-Policy che permette solo risorse della
  dashboard, nessun HTML costruito dai dati (solo `textContent`), nessuna cache.

## Conseguenze

- Si vede lo stato senza leggere i log; per agire si usa ancora l'installer.
- Un pod in più, leggero (richiesta 10m di CPU e 64 MiB). Si disattiva con
  `dashboard.enabled: false`.
- Senza Ingress la dashboard non è raggiungibile da fuori del cluster, da un altro computer si
  passa da un tunnel SSH verso il master.

## Alternative scartate

- **Gestione dal web**: richiederebbe un login con l'identità dell'utente (token Kubernetes,
  TokenReview e SubjectAccessReview) per tenere affidabile lo storico, e per riconfigurare
  permessi quasi da amministratore nel pod. Possibile più avanti, solo per azioni operative.
- **Plugin per Headlamp**: riusa login e RBAC, ma richiede di installare Headlamp e scrivere il
  plugin in React. Da riconsiderare se il cluster adotta Headlamp.
- **Grafana con metriche**: utile per l'andamento nel tempo, ma serve Prometheus e non mostra
  bene il motivo di ogni decisione.

## Aggiornamento (2026-10-28): pagine, grafici, giri, log e salute

La pagina unica è diventata sette pagine (`#/panoramica`, `#/nodi`, `#/cve`, `#/giri`,
`#/salute`, `#/log`, `#/storico`), sempre una sola pagina statica senza framework. I grafici
(ciambelle, barre impilate) sono SVG costruiti nodo per nodo: niente HTML dai dati, niente stili
inline, colori dei quattro stati riservati e sempre accompagnati da simbolo ed etichetta.

- **Giri**: il controllore salva un riassunto di ogni giro (ultimi 100) nella ConfigMap
  `<release>-cycles`; la dashboard la legge.
- **Salute**: componenti (controllore, API ed etcd da `/readyz`, KEV, età dell'ultimo
  controllo, ogni endpoint LLM con risposte, errori e latenza) e un quadrato per server.
- **Log**: la dashboard può elencare i pod e leggerne i log, ma solo nel namespace di SAGE
  (Role, non ClusterRole) e solo per un pod del rilascio con nome valido: il parametro non è mai
  usato così com'è. I log contengono dati dei nodi: restano nel cluster e li vede solo chi può
  fare il port-forward.
- Un fallimento mostra il suo motivo: `sage remediate` lo scrive nel messaggio di terminazione
  del Job (es. "il nodo non è ripartito dopo il riavvio"), il controllore lo mette nell'esito.
