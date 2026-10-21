# Guida al primo test sul gemello

Obiettivo: installare SAGE sul cluster di test, farlo girare **in simulazione**, leggere
le decisioni e solo alla fine provare una remediation vera sul canary.

I comandi `kubectl` e `helm` si lanciano da un master (kubespray installa entrambi) o da
una macchina con il kubeconfig del cluster.

## 0. Prerequisiti

- CI applicata (patch `sage-ci.patch`) e workflow `image` verde.
- Digest dell'immagine: nel riepilogo del job `image` su GitHub Actions.
- Pacchetto `sage` su GHCR reso pubblico (*Package settings → Change visibility*),
  oppure un Secret `ghcr-pull` e `imagePullSecrets` nei valori.

## 1. Chiave SSH dedicata

Sul tuo PC (o sul bastion):

```bash
ssh-keygen -t ed25519 -f sage_id_ed25519 -C sage -N ""
```

Installa la chiave pubblica sui nodi. Con l'inventario di kubespray, dalla cartella `kubespray`:

```bash
ansible -i inventory/<nome>/hosts all -b -m ansible.posix.authorized_key \
  -a "user=<utente> key='$(cat sage_id_ed25519.pub)'"
```

Facoltativo ma consigliato: limitare la chiave agli IP del cluster aggiungendo
`key_options='from="<rete dei nodi in CIDR>"'`.

## 2. known_hosts

Le chiavi host vanno lette **dall'interno** del cluster (i pod parlano con gli IP interni):

```bash
ssh <utente>@<IP_MASTER> "ssh-keyscan -t ed25519 $(kubectl get nodes \
  -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')" > known_hosts
```

## 3. Gruppi: etichette sui nodi

```bash
kubectl label node <worker1> <worker2> <worker3> sage.io/group=worker
# i master hanno già node-role.kubernetes.io/control-plane
```

## 4. Namespace e segreti

```bash
kubectl create namespace sage
kubectl -n sage create secret generic sage-ssh \
  --from-file=id_ed25519=sage_id_ed25519 --from-file=known_hosts=known_hosts
kubectl -n sage create secret generic sage-llm --from-literal=GROQ_API_KEY=<chiave>
```

## 5. Valori e installazione

```bash
git clone https://github.com/<owner>/sage.git
cp sage/examples/values.example.yaml ~/values-local.yaml   # fuori dalla repo
# compila: image.repository, image.digest, config.ssh.user, canary
helm install sage sage/chart/sage -n sage -f ~/values-local.yaml
```

Il CronJob nasce sospeso e in simulazione.

## 6. Primo giro, a mano

```bash
kubectl -n sage create job --from=cronjob/sage-scan prova-1
kubectl -n sage logs -f job/prova-1
```

Alla fine del log c'è il riepilogo per nodo: quanti pacchetti per azione, i pacchetti non
"aggiorna" con il motivo, il piano e cosa farebbe la prossima ondata.

Il report completo (decisioni, prove, VEX) sta nella ConfigMap `sage-report`:

```bash
kubectl -n sage get configmap sage-report -o jsonpath='{.binaryData.data\.json\.gz}' \
  | base64 -d | gunzip | python3 -m json.tool | less
```

Cosa aspettarsi al primo giro:
- quasi tutto `aggiorna`: è normale. Le rimozioni richiedono più scansioni consecutive
  (`idle_scans_required`), e con il budget LLM non tutte le CVE vengono analizzate subito.
- le risposte dell'LLM restano in cache (`sage-llm-cache`): i giri successivi chiamano
  il modello solo per le CVE nuove.

## 7. Giri automatici in simulazione

Nel file dei valori `suspend: false`, poi:

```bash
helm upgrade sage sage/chart/sage -n sage -f ~/values-local.yaml
```

Lascia girare qualche giorno. Da provare in questa fase:
- `allow_remove: true` e `allow_mitigate: true` sul gruppo worker: vedi cosa proporrebbe.
- `dnf install -y cockpit` su un worker, senza avviarlo: dopo `idle_scans_required`
  giri dovrebbe comparire tra le rimozioni.

## 8. Prima remediation vera, sul canary

`dryRun: false` e `helm upgrade`, poi un giro a mano:

```bash
kubectl -n sage create job --from=cronjob/sage-scan prova-live-1
kubectl -n sage logs -f job/prova-live-1        # "remediation avviata su <canary>"
kubectl -n sage get jobs -l sage.io/role=remediate
kubectl -n sage logs -f job/<nome-del-job-sage-fix>
```

Il Job gira su un altro nodo: cordon, drain, aggiornamenti, riavvio se serve, attesa del
nodo Ready, uncordon. Il giro successivo vede l'esito e, dopo l'osservazione del canary,
passa agli altri worker; i master per ultimi e il kernel solo nella finestra.

## Se qualcosa va storto

- **Fermare tutto**: `kubectl -n sage patch cronjob sage-scan -p '{"spec":{"suspend":true}}'`
- **Remediation fallita**: SAGE ha fatto rollback e lasciato il nodo in cordon. Controlla il
  nodo, `kubectl uncordon <nodo>`, poi sblocca le ondate con
  `kubectl -n sage create configmap sage-resume`: il giro successivo le riprende e cancella
  la ConfigMap.
- **Nessun report da un nodo**: SSH. Controlla utente, chiave in `authorized_keys`,
  `known_hosts` (rigenerato se il nodo è stato ricreato).
- **KEV, EPSS o record CVE non disponibili**: i pod non escono su Internet. Imposta
  `extraEnv` con il proxy. Senza KEV SAGE non dichiara nulla "non affetto" (è voluto).
- **Errori 429 da Groq**: aumenta `config.llm.min_interval_seconds` o abbassa
  `max_calls_per_run`.
