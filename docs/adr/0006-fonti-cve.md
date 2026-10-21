# ADR-0006: Fonti delle CVE

Stato: accettata (2026-10-21)

## Contesto

Si era ipotizzata una doppia scansione (dnf e Trivy) come controprova. Verifiche fatte:

- Per Rocky Linux, Trivy usa le advisory di Rocky stesse: è la stessa fonte di `dnf updateinfo`,
  non una controprova indipendente.
- Trivy Operator non scansiona i pacchetti del sistema operativo dei nodi (feature request aperta).
- Le errata di Rocky hanno avuto ritardi e imprecisioni note (sistema Apollo).
- kubelet, containerd ed etcd installati da kubespray sono binari, invisibili a dnf.

## Decisione

- Pacchetti RPM: advisory della distribuzione via dnf, confrontate con i dati Red Hat (CSAF VEX) per
  lo stato `known_not_affected`.
- CVE del kernel: record del CNA del kernel (file sorgente colpiti) per il controllo di configurazione.
- Contesto di rischio: CISA KEV, CISA Vulnrichment (decision point SSVC), FIRST EPSS.
- Componenti Kubernetes: fuori ambito di SAGE, gestiti con kubespray.

## Conseguenze

- Niente Trivy nel percorso principale. Resta utile per i componenti Kubernetes, in un secondo tempo.
- Le differenze tra fonti vanno registrate: sono un dato utile per la valutazione.
