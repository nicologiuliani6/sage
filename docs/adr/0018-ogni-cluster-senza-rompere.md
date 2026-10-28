# ADR-0018: SAGE va bene su ogni cluster, senza rompere niente

Stato: accettata (2026-10-23)

## Contesto

SAGE si installa in cluster già configurati e di tutti i tipi: bare metal o VM, storage locale
o condiviso (Ceph, SAN), uno o più master, bilanciatori dell'API diversi, etcd veloce o lento.
Chi lo installa non deve sistemare il cluster perché SAGE funzioni. Sul cluster Debian di prova
(etcd su Ceph, fsync fino a 18 s) l'API dava EOF e `etcdserver: request timed out` per decine di
secondi durante i controlli e il riavvio di un master: è una condizione normale da reggere, non
un difetto del cluster da correggere prima.

## Decisione

- Le impostazioni di default vanno bene ovunque. Un parametro si aggiunge solo se un valore
  sicuro per tutti non esiste, e il suo default è quello prudente (ADR-0007 per i nomi).
- SAGE non chiede modifiche al cluster per funzionare: niente tuning di etcd, del bilanciatore
  o dello storage. Se un cluster è lento SAGE va più piano (pochi nodi alla volta, attesa del
  control plane stabile), non pretende che sia più veloce.
- Gli errori passeggeri dell'API sono attesi: ogni chiamata a Kubernetes riprova (installer,
  controllore, playbook). Solo un errore che persiste ferma il giro (ADR-0010).
- Sulle operazioni (cordon, drain, riavvio, uncordon) SAGE è prudente: se il cluster non è in
  condizioni di riceverle aspetta o si ferma, non improvvisa. Resta valido "nel dubbio si
  aggiorna" per le decisioni sulle CVE: riguarda cosa fare, non quando farlo.
- Quando una prova su un cluster vero fallisce, la prima domanda è "SAGE dovrebbe reggerlo da
  solo?". La correzione va in SAGE; i consigli per il cluster (per esempio etcd su disco locale)
  vanno nella guida come suggerimenti all'operatore, mai come prerequisiti.

## Conseguenze

- Ogni caso nuovo visto su un cluster vero diventa un test con dati sintetici (CLAUDE.md).
- Alcuni giri durano di più su cluster lenti: è il prezzo di non rompere niente.
