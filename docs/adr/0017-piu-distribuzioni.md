# ADR-0017: Più distribuzioni, stesso flusso

Stato: accettata (2026-10-23)

## Contesto

SAGE nasce per la famiglia RHEL e usa dnf in tre punti: il collector (advisory di sicurezza,
database rpm), la remediation (`dnf upgrade --advisory`, `dnf history undo`) e il controllo
del riavvio (`dnf needs-restarting`). Un cluster reale può avere nodi Debian, Ubuntu o SUSE.
Il resto di SAGE (analisi con l'LLM, policy OPA, piani, controllore, dashboard) non dipende
dalla distro e non deve cambiare.

## Decisione

Cambia solo lo strato del gestore di pacchetti, una famiglia alla volta. Il JSON del nodo, le
decisioni e i piani restano gli stessi.

| | dnf (RHEL, Rocky, Alma, Oracle, Fedora) | zypper (SLES, openSUSE) | apt (Debian, Ubuntu) |
|---|---|---|---|
| Aggiornamenti di sicurezza | advisory di `dnf updateinfo` | patch di sicurezza (`zypper list-patches`) | `apt-get -s dist-upgrade` + OSV |
| CVE | nell'advisory | nella patch (`<issue type="cve">`) | da OSV (DSA, DLA, USN) |
| Database dei pacchetti | rpm | rpm | dpkg (`dpkg-query`, `/var/lib/dpkg/info`) |
| Applicazione | `dnf upgrade --advisory` | `zypper install -t patch` | `apt-get install --only-upgrade` |
| Rollback | `dnf history undo` | versioni precedenti (`--oldpackage`) | versioni precedenti (`--allow-downgrades`) |
| Riavvio | `dnf needs-restarting -r` | `zypper needs-rebooting` | dopo ogni aggiornamento |

- **Il collector** sceglie da solo il gestore (dnf, poi zypper, poi apt) e lo scrive nel JSON
  (`node.package_manager`, schema 5). Il playbook di remediation fa lo stesso: piani e
  controllore non sanno quale distro c'è sotto.
- **Debian e Ubuntu**: apt non sa quali aggiornamenti correggono vulnerabilità né quali. Il
  collector elenca tutti gli aggiornamenti disponibili con pacchetto sorgente e versioni, e
  segna quelli che arrivano dal repository di sicurezza. Debian pubblica molte correzioni nei
  rilasci intermedi (es. libc6 da `bookworm`, non da `bookworm-security`), quindi l'origine
  da sola non basta. Nello scan SAGE chiede a **OSV** (`sources.osv_url`) le vulnerabilità
  della versione installata e tiene quelle corrette dalla versione nuova: advisory DSA, DLA
  e USN con le loro CVE, più le CVE senza advisory. Gli aggiornamenti che non correggono
  niente di noto escono dal piano.
- **A OSV** arrivano solo nome e versione dei pacchetti sorgente e la release della distro,
  mai nomi o indirizzi dei nodi. `osv_url` può puntare a un mirror interno.
- **Fail closed**: se OSV non risponde restano gli aggiornamenti del repository di sicurezza,
  senza CVE, e la policy li aggiorna (senza CVE non si può essere "non affetti"). Se una
  vulnerabilità elencata non si riesce a leggere, il pacchetto resta da aggiornare.
- **Riavvio con apt**: apt non dice quali processi usano librerie vecchie. Dopo un
  aggiornamento il nodo, già svuotato, si riavvia sempre.
- **Rollback con apt e zypper**: non c'è una transazione da annullare. Si salvano le versioni
  prima dell'intervento e, in caso di errore, si reinstallano quelle cambiate. Funziona se il
  repository ha ancora la versione precedente (Debian e Ubuntu tengono quella del rilascio,
  non sempre gli aggiornamenti intermedi): se no il rollback fallisce, viene segnalato e il
  nodo resta in cordon come oggi.
- **Garanzie della policy** per tutte le famiglie: i pacchetti del kernel (`kernel*`,
  `linux-image-*`, `linux-modules-*`) non si rimuovono; quelli della catena di avvio (grub,
  shim, dracut, initramfs-tools, microcodice, firmware) non sono mai "non affetti" perché
  nessun processo li usa.
- **Python sui nodi**: il collector e Ansible (ansible-core 2.17) richiedono Python 3.9 o
  successivo come `python3`. RHEL 8 e SLES 15 hanno il 3.6: serve installare un Python più
  recente e renderlo `python3`, altrimenti l'installer esclude il nodo con un messaggio chiaro.
- **Prove**: oltre ai test con dati sintetici (formati presi dagli output reali), la CI fa
  girare il collector in container Debian, Ubuntu, openSUSE, AlmaLinux e Fedora fissati per
  digest (`ci/distros.sh`) e ne controlla il JSON. Su una **VM Debian** vera (immagine cloud
  datata, KVM sul runner, `ci/vm_debian.sh`) prova tutto il percorso con `remediate.yml`:
  collector, OSV, errore a metà con rollback alla versione di prima, aggiornamento completo
  con riavvio e controllo finale senza più niente da aggiornare.
- **Endpoint LLM nel cluster**: un indirizzo come `http://ollama.<namespace>.svc:11434/v1` si
  risolve solo dai pod. Se dal master non risponde, l'installer lo controlla da un pod
  temporaneo con l'immagine di SAGE (la chiave passa da stdin, il pod viene sempre tolto).

## Conseguenze

- Un cluster con distro miste si gestisce con la stessa configurazione; i gruppi restano
  liberi (una distro per gruppo è comoda ma non obbligatoria).
- Su Debian e Ubuntu la qualità delle CVE dipende da OSV, e ogni aggiornamento porta a un
  riavvio.
- Amazon Linux 2023 blocca i repository alla versione dell'immagine: senza
  `releasever=latest` dnf non vede gli aggiornamenti. Da verificare prima di dichiararlo
  supportato.
- Arch, Alpine e altre famiglie restano fuori: aggiungerle vuol dire scrivere un altro
  gestore nel collector e nel playbook, senza toccare il resto.

## Alternative scartate

- **OSV per tutte le distro**: per RHEL e SUSE le advisory della distro sono già sul nodo, più
  complete e senza chiamate esterne.
- **Scaricare l'intero database OSV** di Debian e Ubuntu a ogni controllo: centinaia di MB ogni
  mezz'ora. Si usa l'API, eventualmente su un mirror.
- **Solo il repository `-security` su Debian**: perde le correzioni dei rilasci intermedi.
