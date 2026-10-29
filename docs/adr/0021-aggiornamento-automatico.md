# ADR-0021: SAGE si aggiorna da solo, solo con release firmate e se lavora

Stato: accettata (2026-10-28)

## Contesto

SAGE aggiorna i nodi da solo e non deve avere bisogno di una persona (ADR-0018). Restava
indietro proprio lui: ogni correzione arrivava al cluster solo quando qualcuno lanciava `sage`.
Un aggiornamento automatico però è anche il punto più delicato della catena di fornitura: chi
controlla la release controlla un Job con permessi da amministratore.

## Decisione

- **Quando**: il controllore, solo in pausa tra due giri (mai a metà di un nodo), una volta
  ogni `self_update.check_hours` (24) lancia il Job `<release>-update-*`.
- **Cosa**: l'ultima release del canale (`patch`: stessa 0.X; `minor`, il default: stessa
  versione maggiore; `off`). Mai una versione maggiore da sola, mai pre-release, mai una
  versione già fallita.
- **Fiducia**: la CI firma `SHA256SUMS` con cosign keyless (OIDC di GitHub Actions). Il Job
  verifica la firma con identità fissata (`publish.yml` della repo su un tag `v*`, emittente
  GitHub Actions) e poi il checksum del chart, che contiene l'immagine per digest. Senza firma
  valida non si tocca niente. cosign e helm sono nell'immagine, fissati per checksum.
- **Prova che funziona**: dopo `helm upgrade --reset-then-reuse-values --wait`, il Job chiede un
  controllo completo e aspetta un report nuovo **quanto serve** (un controllo su un cluster grande
  o con un LLM solo CPU può durare ore), fino al tempo massimo di un controllo. È un guasto, e si
  torna subito alla revisione di prima con `helm rollback`, solo se il controllore nuovo non
  inizia un giro entro 15 minuti, smette di rinnovare il Lease o il controllo fallisce.
- **Versioni annullate**: non si riprovano per 7 giorni (il guasto poteva essere del cluster),
  poi sì; una versione più nuova si prova subito.
- **Storico**: ogni esito (aggiornato, rifiutato, annullato) finisce in `<release>-history` con
  chi = "sage (automatico)"; lo stato (ultimo controllo, versioni saltate) in
  `<release>-update`.
- **Permessi**: il Job usa un ServiceAccount con `cluster-admin`, perché il chart contiene
  ClusterRole e binding. Esiste solo con il canale diverso da `off`.
- **Repository**: `self_update.repository` lo scrive l'installer da dove viene il suo chart.
  Senza, l'aggiornamento resta spento: chi installa il chart a mano decide da sé.

## Conseguenze

- Una correzione pubblicata arriva a tutti i cluster entro un giorno, senza persone.
- Un aggiornamento che rompe SAGE torna indietro da solo; uno con firma sbagliata non parte.
- Chi non vuole un Job da amministratore mette `channel: off` (installer o valori).

## Aggiornamento (2026-10-29): anche l'immagine, non solo il chart

L'installer fissa l'immagine nei values (`image.digest`) e `--reset-then-reuse-values` la
riportava identica a ogni aggiornamento: cambiava il chart, il codice restava quello vecchio.
Ora la release scrive repository e digest dell'immagine nel `values.yaml` del chart (coperto
dalla firma di `SHA256SUMS`) e l'aggiornamento li passa a helm con `--set`. Una release il cui
chart non fissa l'immagine viene rifiutata.
