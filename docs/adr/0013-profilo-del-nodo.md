# ADR-0013: Profilo del nodo, processi dei container e servizi aggiuntivi

Stato: accettata (2026-10-22)

## Contesto

Per decidere se un pacchetto è "in uso" SAGE guardava solo il momento della scansione: processi
in esecuzione, librerie caricate, porte in ascolto, unit attive. Il primo test sul gemello ha
mostrato due limiti.

- I processi dei container sono visibili anche dal nodo. Le librerie che usano stanno
  nell'immagine, ma hanno gli stessi percorsi di quelle del nodo (es. `/usr/lib64/libssl.so.3`):
  il pacchetto del nodo sembrava in uso anche quando non lo usava nessuno.
- Un'osservazione istantanea non vede ciò che parte solo ogni tanto (timer, backup notturni).
  Per questo servono più scansioni consecutive prima di dichiarare un pacchetto inutilizzato.

Su un nodo Kubernetes, però, le applicazioni girano nei container: i pacchetti del nodo servono
solo al nodo stesso (kubelet, container runtime, sshd, rete, systemd). Quello che serve si può
quindi calcolare.

## Decisione

- **Processi dei container esclusi**: il collector salta i processi il cui cgroup è di un
  container (`kubepods`, Docker, Podman, CRI-O, containerd). Si guarda il cgroup e non il mount
  namespace, perché molti servizi di systemd hanno un namespace proprio (PrivateTmp) ma usano
  i file del nodo.
- **Profilo del nodo**: a ogni scansione il collector elenca le unit attive o abilitate
  (servizi, socket, timer), risale ai pacchetti che possiedono i loro file e gli eseguibili di
  `ExecStart`, e aggiunge tutte le dipendenze, anche indirette. Il database rpm viene letto tre
  volte (chi fornisce cosa, chi possiede quale file, chi richiede cosa) e le dipendenze si
  risolvono in memoria. Ogni pacchetto necessario porta con sé il servizio da cui deriva
  (`needed_by`).
- Un pacchetto necessario a un servizio del nodo è **in uso** anche se in quel momento non
  gira: la condizione "componente in uso" è vera, non è mai inattivo e non viene mai proposto
  per la rimozione.
- **Servizi aggiuntivi**: per ogni nodo si possono dichiarare unit o pacchetti usati fuori da
  Kubernetes (agent di backup o di monitoraggio, NFS, strumenti di amministrazione):
  `extra_services` in configurazione, gestito dall'installer (*Modifica il cluster*). Entrano
  nel profilo come gli altri servizi. Quelli non trovati sul nodo vengono segnalati.
- Il riepilogo del giro mostra per ogni nodo i servizi, i pacchetti necessari, i processi dei
  container esclusi e i pacchetti con advisory che non servono a nessun servizio.

## Conseguenze

- Meno falsi "in uso" dovuti ai container, e nessun falso "inutilizzato" per i pacchetti che
  servono a un servizio che parte solo ogni tanto.
- I pacchetti fuori dal profilo seguono ancora la regola delle scansioni consecutive: gli
  strumenti usati a mano dagli amministratori non dipendono da nessun servizio. Per tenerli
  sempre si dichiarano tra i servizi aggiuntivi.
- I binari installati fuori da rpm (es. kubelet di kubespray in `/usr/local/bin`) non portano
  dipendenze nel profilo; le librerie che caricano risultano comunque in uso dai processi.
- Un container privilegiato che esegue programmi del nodo (es. con `chroot` sul filesystem
  dell'host) viene escluso come gli altri: caso raro, da dichiarare tra i servizi aggiuntivi.

## Correzioni dopo il primo giro sul gemello (2026-10-22)

Il primo giro con il profilo ha trovato 0 pacchetti necessari su ogni nodo e ha dichiarato
"nessun processo usa il pacchetto" anche per glibc. Due cause, entrambe nel collector:

- **queryformat di rpm**: dentro `[...]` il nome del pacchetto va scritto `%{=NAME}`. Con
  `%{NAME}` rpm rifiuta ogni pacchetto con più di un file o dipendenza, e il database del
  profilo restava quasi vuoto.
- **usrmerge**: su Rocky 9 `/lib64`, `/bin`, `/sbin` e `/lib` sono collegamenti a `/usr`. rpm
  elenca `/lib64/libc.so.6`, il kernel in `/proc/<pid>/maps` scrive `/usr/lib64/libc.so.6`.
  I percorsi ora si confrontano dopo averli ricondotti a quelli reali.

Inoltre, sempre nel senso del fail closed:

- **controllo di coerenza dei processi**: se nessun file usato dai processi del nodo appartiene
  a un pacchetto (almeno la libc dovrebbe), la lettura non è affidabile e nessun pacchetto viene
  dichiarato inattivo (`process_scan_ok` nel profilo, avviso nel riepilogo).
- `systemctl show` stampa ExecStart prima di Id: le unit si leggono a blocchi, e il file della
  unit si cerca anche direttamente nelle cartelle di systemd.
- il riepilogo avvisa se un nodo ha servizi ma nessun pacchetto ricondotto a loro.
