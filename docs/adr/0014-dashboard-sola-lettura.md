# ADR-0014: Dashboard web di sola lettura, aperta con port-forward

Stato: accettata (2026-10-22)

## Contesto

Il riepilogo di ogni giro è nel log del Job e il report completo in una ConfigMap compressa:
per sapere come sta un nodo, se c'è un allarme o quanto manca alla fine delle ondate bisogna
leggere log o decodificare JSON. Serve una vista d'insieme, ma senza aprire un nuovo modo di
modificare il cluster né una nuova superficie d'attacco.

## Decisione

- **Sola lettura**: la dashboard mostra quello che SAGE ha già scritto (report, stato delle
  ondate, storico, CronJob, nodi) e non modifica niente. Le azioni restano nell'installer, dove
  ogni modifica finisce nello storico con l'identità di chi la fa (ADR-0012).
- **Nello stesso pacchetto**: `sage dashboard`, server HTTP della libreria standard e una pagina
  statica (HTML, JavaScript e CSS nel pacchetto `sage.web`), nessuna dipendenza nuova e nessuna
  risorsa da Internet. Stessa immagine, un Deployment in più nel chart (`dashboard.enabled`).
- **Accesso tramite Kubernetes**: il server ascolta solo su 127.0.0.1 nel pod e non ha un
  Service. Si apre con `kubectl port-forward` (anche dall'installer, *Apri la dashboard*): chi
  può farlo lo decide l'RBAC del cluster, quindi non serve un login proprio. Le richieste con
  un `Host` diverso da localhost vengono rifiutate (difesa dal DNS rebinding).
- **Permessi minimi**: ServiceAccount proprio con `get` solo sulle ConfigMap del report, dello
  stato e dello storico e sul CronJob dello scan (per nome), e lettura dei nodi. Non monta la
  chiave SSH né la chiave dell'LLM.
- **Contenuti**: allarmi (ondate ferme, remediation fallite, nodi non Ready, CVE KEV aperte,
  profilo non affidabile, giri sospesi, report vecchio), avanzamento (nodi senza azioni in
  sospeso, advisory da applicare, rimandi con la prossima finestra, canary in osservazione,
  prossimo giro), una scheda per nodo con il motivo di ogni decisione, le CVE ordinate per
  urgenza con filtri, lo storico e il download del VEX.
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
