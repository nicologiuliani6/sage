# ADR-0015: Un controllore sempre acceso che fa il giro dei nodi

Stato: accettata (2026-10-22). Sostituisce l'ADR-0003 e le parti dell'ADR-0005 su concorrenza,
osservazione del canary e finestre di manutenzione.

## Contesto

Con il CronJob (ADR-0003) ogni esecuzione faceva un controllo completo e un solo passo delle
ondate: il nodo successivo partiva solo al giro dopo, ore più tardi. Con un giro ogni 6 ore e
l'osservazione del canary, quattro nodi richiedevano un giorno e mezzo, più l'attesa della
finestra di manutenzione per il kernel dei master. Una CVE grave trovata a un controllo restava
aperta su alcuni nodi per giorni.

Il modello voluto è più semplice: un controllore sempre acceso fa il giro di tutti i nodi, li
sistema uno dopo l'altro e, finito il giro, ricomincia.

## Decisione

- **Controllore in loop**: un Deployment (`sage controller`, una copia, strategia Recreate).
  Un giro:
  1. controllo completo in un Job (`sage scan`: raccolta, analisi, decisioni, report);
  2. remediation **un nodo alla volta**: gruppi in ordine (i master per ultimi), in ogni
     gruppo il canary per primo. Finito un nodo si passa subito al successivo;
  3. pausa `controller.pause_minutes` (predefinita 30, anche 0), poi da capo.
- **Mai su se stesso**: ogni remediation è un Job con affinità che lo esclude dal nodo
  bersaglio. Se il nodo da sistemare è quello del controllore, il drain lo sposta: il nodo è in
  cordon e Kubernetes ricrea il controllore su un altro nodo.
- **Ripresa dopo un'interruzione**: ogni passo è salvato nella ConfigMap
  `<release>-controller` *prima* di essere eseguito (quale Job di controllo, quale nodo, quale
  Job di remediation). Una copia nuova legge lo stato e riprende: aspetta il Job già avviato,
  non ne crea un secondo, non ricomincia il giro. Un Job di controllo scomparso viene
  rilanciato (fino a 3 volte, poi si passa alla pausa e si riprova al giro dopo); un Job di
  remediation scomparso ferma tutto, perché non si sa in che stato sia il nodo.
- **Un solo controllore attivo**: un Lease (`coordination.k8s.io`) con rinnovo a ogni passo.
  Chi non lo tiene aspetta; chi lo perde esce e viene riavviato. La strategia Recreate evita
  due copie durante un aggiornamento. Allo spegnimento (SIGTERM) il controllore finisce il
  passo in corso e libera il Lease, così la copia nuova parte subito.
- **Control plane stabile prima di intervenire** (aggiornamento del 2026-10-23): prima di ogni
  nodo il controllore legge `/readyz` dell'apiserver (etcd compreso) e controlla che i master
  siano Ready. Parte solo se è tutto sano di fila da `control_plane_stable_seconds` (60 s;
  tre volte tanto prima di un master). Altrimenti il nodo resta in coda e la dashboard
  mostra "in attesa". Vale per qualsiasi cluster: con etcd su dischi lenti, o un master
  appena riavviato, un drain iniziato nel momento sbagliato si blocca a metà e lascia il
  nodo in cordon. In simulazione non si aspetta.
- **Niente attese inutili**: i passi che non lanciano niente (coda pronta, nodo senza niente da
  fare o saltato, remediation appena riuscita) si fanno di fila; si aspetta `poll_seconds`
  solo quando c'è un Job in corso o la pausa.
- **Mai fermo in silenzio**: un controllore bloccato smette di aggiornare il file di battito e
  la livenessProbe lo fa riavviare; un controllore spento o senza rinnovi del Lease è un
  allarme nella dashboard. Un nodo non Ready, in cordon o non raggiunto dal controllo viene
  saltato in quel giro, senza bloccare gli altri.
- **Niente giri a vuoto pericolosi**: se dopo una remediation riuscita il controllo successivo
  chiede esattamente le stesse advisory, il nodo viene saltato (serve un controllo a mano),
  invece di svuotarlo e riavviarlo a ogni giro.
- **Un errore ferma tutto** (ADR-0010 resta valida): remediation fallita o scomparsa, niente
  più nodi finché una persona non controlla e crea la ConfigMap `<release>-resume`.
- **Niente finestra di manutenzione, niente concorrenza, niente osservazione**: il kernel si
  aggiorna nel giro come il resto (`kernel: auto`), o mai in automatico (`kernel: manual`, per
  esempio i nodi GPU). Le configurazioni con `kernel: window` valgono come `auto`.
- **CVE gravi con scadenza**: per ogni pacchetto con priorità act (KEV o sfruttamento attivo)
  si registra quando è stato trovato; la dashboard mostra la scadenza
  (`policy.urgent_deadline_hours`, predefinita 6) e dà un allarme se viene superata.
- **Spento = nessun giro**: `suspend: true` porta il Deployment a 0 copie. Il giro manuale
  dall'installer con il controllore spento fa solo il controllo.

## Conseguenze

- Una CVE trovata a un controllo viene sistemata su tutti i nodi nello stesso giro: con nodi
  da 30-45 minuti l'uno, un cluster piccolo finisce in poche ore.
- Il controllo completo gira in un Job con il suo tempo massimo (`activeDeadlineSeconds`), così
  il controllore resta leggero e il battito non dipende dalla durata delle chiamate all'LLM.
- Durante il riavvio di un master con un solo control plane l'API non risponde: il controllore
  riprova finché torna disponibile (o viene riavviato) e riprende dallo stato.
- Con la pausa a 0 i nodi vengono interrogati in continuo; le risposte dell'LLM restano in
  cache, quindi i giri senza CVE nuove non lo chiamano.

## Alternative scartate

- **CronJob più frequente per far avanzare le ondate**: due CronJob (controllo e avanzamento)
  si sovrappongono senza un lock; uno solo che decide cosa fare a ogni esecuzione è un loop
  spezzato in pezzi, con un ritardo fino all'esecuzione successiva.
- **Operatore con CRD (kopf)**: più codice e una CRD da installare per un loop lineare.
- **Argo Workflows**: un componente in più da installare e mantenere.
