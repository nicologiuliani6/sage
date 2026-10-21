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

- Pacchetti RPM: advisory della distribuzione via dnf. Il confronto con i dati Red Hat (CSAF VEX,
  stato `known_not_affected`) è previsto ma non ancora implementato.
- Record CVE dal CVE Program: descrizione, vettore CVSS e, per il kernel, i file sorgente colpiti
  (usati per verificare la coerenza delle condizioni sui moduli).
- Contesto di rischio: CISA KEV, CISA Vulnrichment (decision point SSVC), FIRST EPSS.
- Componenti Kubernetes: fuori ambito di SAGE, gestiti con kubespray.

## Conseguenze

- Niente Trivy nel percorso principale. Resta utile per i componenti Kubernetes, in un secondo tempo.
- Le differenze tra fonti vanno registrate: sono un dato utile per la valutazione.
