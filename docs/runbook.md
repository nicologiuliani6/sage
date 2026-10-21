# Runbook

## Fermare SAGE

```bash
kubectl -n <namespace> patch cronjob <release>-scan -p '{"spec":{"suspend":true}}'
kubectl -n <namespace> delete job -l sage.io/role=remediate      # interrompe una remediation
```

## Dopo una remediation fallita

SAGE ha già annullato la transazione dnf (se possibile), tolto i blocchi dei moduli aggiunti e
lasciato il nodo in cordon. Le ondate restano ferme.

1. Leggi il log: `kubectl -n <namespace> logs job/<release>-fix-<nodo>-<data>`
2. Controlla il nodo. Se l'errore era sul kernel, il rollback dnf non può togliere il kernel in
   esecuzione: riavvia sul kernel precedente (`grubby --set-default ...`) se serve.
3. `kubectl uncordon <nodo>`
4. Sblocca le ondate: `kubectl -n <namespace> create configmap <release>-resume`. Il giro
   successivo dello scan riprende le ondate e cancella la ConfigMap. In alternativa, da una
   macchina con kubeconfig: `SAGE_NAMESPACE=<namespace> SAGE_RELEASE=<release> sage resume`.

## Emergenza: API Kubernetes non disponibile

I playbook si lanciano dal bastion con la stessa immagine. Senza API niente cordon e drain
(`sage_kube=false`): svuota il nodo a mano se possibile.

```bash
cp ansible/inventory.example.ini inventory.ini   # compila IP, utente, chiave
mkdir -p out
podman run --rm -it \
  -v "$PWD/inventory.ini:/opt/sage/ansible/inventory.ini:ro" \
  -v "$HOME/.ssh/sage_id_ed25519:/tmp/key:ro" \
  -v "$PWD/out:/out" \
  --entrypoint ansible-playbook <IMMAGINE@DIGEST> \
  -i /opt/sage/ansible/inventory.ini /opt/sage/ansible/collect.yml \
  -e sage_out_dir=/out -e ansible_ssh_private_key_file=/tmp/key

# remediation di un solo nodo
podman run --rm -it ... --entrypoint ansible-playbook <IMMAGINE@DIGEST> \
  -i /opt/sage/ansible/inventory.ini /opt/sage/ansible/remediate.yml --limit <nodo> \
  -e sage_kube=false -e sage_node_name=<nodo> -e '{"sage_update_advisories": ["RLSA-..."]}'
```

## Leggere il report

```bash
kubectl -n <namespace> get configmap <release>-report \
  -o jsonpath='{.binaryData.data\.json\.gz}' | base64 -d | gunzip | python3 -m json.tool
```

Contiene decisioni per nodo e pacchetto con le prove, i piani, i messaggi delle ondate e il
documento OpenVEX (`vex`) con le CVE dichiarate non affette.
