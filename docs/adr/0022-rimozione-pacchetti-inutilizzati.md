# ADR-0022: Rimozione dei pacchetti inutilizzati, anche senza CVE, e uso visto dal disco

Stato: accettata (2026-10-29)

## Contesto

Con `allow_remove` SAGE toglieva un pacchetto solo se era vulnerabile e inutilizzato. Due
problemi, visti su un cluster di prova:

- "Inutilizzato" voleva dire "nessun processo, libreria caricata, porta o unit attiva nei
  controlli". Una fotografia ogni qualche minuto non vede un comando lanciato da un cron per
  due secondi al giorno, né quello chiamato dallo script di un servizio: SAGE poteva togliere
  un pacchetto che uno script usa, e lo script si romperebbe in silenzio.
- Il bootloader, gli hook dell'initramfs, i moduli, i generatori di systemd e gli fsck delle
  partizioni non girano mai come processi: sembravano inutilizzati, e toglierli rompe il riavvio.

Un pacchetto inutilizzato è superficie d'attacco anche senza CVE note oggi.

## Decisione

- **Uso dal disco**: il collector legge l'ultimo accesso (atime) ai file del pacchetto, esclusa
  la documentazione. Con relatime (default di Linux) si aggiorna almeno una volta al giorno:
  un pacchetto è confermato inutilizzato solo se nessun suo file è stato letto negli ultimi
  `idle_days_required` giorni. Su un filesystem `noatime` il dato non c'è: mai inutilizzato.
- **Cron e script**: se un eseguibile del pacchetto è nominato in un cron o in un file dei
  servizi del nodo (unit, script di ExecStart), il pacchetto è in uso.
- **Avvio**: mai inutilizzato un pacchetto con file nelle cartelle dell'avvio (boot, moduli,
  firmware, initramfs, dracut, grub, generatori di systemd, udev, `fsck.*`, rete) né uno letto
  nei 30 minuti dopo l'avvio. La policy rifiuta in più i nomi della catena di avvio.
- **Senza CVE**: con `allow_remove` vengono esaminati anche i pacchetti senza advisory che nessun
  pacchetto installato richiede, non usati dai servizi del nodo, non base del sistema (Debian:
  Essential, Protected, priorità required o important) né kernel. Valgono le stesse condizioni
  della rimozione di un pacchetto vulnerabile (controlli, giorni, simulazione che non trascina
  via altro, pacchetti protetti). Per loro l'unica decisione è "togliere": mai un aggiornamento.
- **Default**: segue `allow_remove` (spento finché non lo si attiva, `--allow-remove`
  nell'installer). Un campo mancante nel report (collector vecchio) non permette rimozioni.

## Conseguenze

- Gli strumenti usati a mano (es. un editor) restano finché qualcuno li usa almeno una volta
  ogni `idle_days_required` giorni; per tenerli comunque: `protected_packages`.
- Un pacchetto appena installato o aggiornato ha un atime recente: si toglie solo dopo
  `idle_days_required` giorni.
- Il controllo legge cron e script del nodo e fa uno `stat` dei file dei candidati: al massimo
  300 pacchetti senza CVE per nodo.

## Aggiornamento (2026-10-29): avvio con relatime e controllo dei pod dopo l'intervento

Prova sul cluster di laboratorio con soglia 0 giorni: SAGE ha tolto `iptables` da tre worker.
kubelet lo usa all'avvio e carica così `nf_conntrack`; dopo il riavvio kube-proxy non partiva e
la rete del cluster (calico) nemmeno, ma il nodo era Ready e la remediation risultava riuscita.

- **relatime**: una lettura all'avvio non aggiorna l'atime se quello vecchio ha meno di un
  giorno. Un accesso tra 24 ore prima dell'avvio e 30 minuti dopo vale come "forse usato
  all'avvio": mai inutilizzato.
- **Dopo l'intervento** non basta il nodo Ready: tutti i pod dei DaemonSet del nodo (kube-proxy,
  rete, storage...) devono tornare pronti entro 10 minuti. Altrimenti è un errore: rollback
  (i pacchetti tolti vengono reinstallati) e, se l'intervento aveva riavviato il nodo, un nuovo
  riavvio per ricaricare i moduli.
