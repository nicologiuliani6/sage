# Runbook

## Emergenza: cluster non disponibile

Se l'API Kubernetes non risponde, SAGE nel cluster non può agire. Gli stessi playbook si lanciano
dal bastion con la stessa immagine.

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
```

Il playbook di remediation (M6) si usa allo stesso modo, sempre con `--limit` su un nodo alla volta.

## Fermare SAGE

```bash
kubectl -n <namespace> patch cronjob <release>-scan -p '{"spec":{"suspend":true}}'
kubectl -n <namespace> delete job -l app.kubernetes.io/component=remediate
```

Un nodo rimasto in cordon dopo un errore va controllato a mano prima di `kubectl uncordon`.
