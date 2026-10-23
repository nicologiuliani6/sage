#!/usr/bin/env bash
# Remediation vera su una VM Debian (ADR-0017), con remediate.yml come in produzione ma
# senza API Kubernetes (sage_kube=false):
#   1. collector sulla VM, poi OSV vero: quali aggiornamenti correggono vulnerabilità;
#   2. errore a metà dell'aggiornamento (un hook di dpkg fallisce una volta): rollback alla
#      versione di prima, il playbook fallisce;
#   3. aggiornamento di tutto il piano: riavvio, nodo di nuovo raggiungibile, niente più da
#      aggiornare al controllo successivo.
# Immagine cloud Debian datata (ha aggiornamenti in sospeso), fissata per checksum.
source "$(dirname "$0")/lib.sh"
W="$TOOLS/vm"
mkdir -p "$W/out"

echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
  | sudo tee /etc/udev/rules.d/99-kvm.rules > /dev/null
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
sudo apt-get install -y -qq qemu-system-x86 qemu-utils cloud-image-utils > /dev/null

curl -fsSL -o "$W/base.qcow2" "$DEBIAN_VM_IMAGE_URL"
echo "${DEBIAN_VM_IMAGE_SHA512}  $W/base.qcow2" | sha512sum -c -
qemu-img create -q -f qcow2 -F qcow2 -b "$W/base.qcow2" "$W/disk.qcow2" 10G
ssh-keygen -q -t ed25519 -N "" -f "$W/key"
cat > "$W/user-data" << EOF2
#cloud-config
users:
  - name: sage
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$W/key.pub")"]
EOF2
cloud-localds "$W/seed.img" "$W/user-data"
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none -daemonize \
  -drive "file=$W/disk.qcow2,if=virtio" -drive "file=$W/seed.img,if=virtio,format=raw" \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
  -serial "file:$W/console.log" -pidfile "$W/qemu.pid"
trap 'kill "$(cat "$W/qemu.pid")" 2> /dev/null || true' EXIT

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
vm() { ssh -i "$W/key" -p 2222 $SSH_OPTS sage@127.0.0.1 "$@"; }
for _ in $(seq 1 60); do vm true 2> /dev/null && break; sleep 5; done
vm true

cat > "$W/inventory.ini" << EOF2
vm ansible_host=127.0.0.1 ansible_port=2222 ansible_user=sage ansible_ssh_private_key_file=$W/key ansible_ssh_common_args='$SSH_OPTS'
EOF2
play() { (cd ansible && uv run ansible-playbook -i "$W/inventory.ini" "$@"); }

# 1. Collector e OSV
play collect.yml -e "sage_out_dir=$W/out" > /dev/null
summary=$(uv run python ci/vm_plan.py "$W/out/vm.json" "$W")
plan() { python3 -c "import json,sys; print(json.dumps(json.load(open('$W/plan.json'))[sys.argv[1]]))" "$1"; }

# 2. Errore a metà: il primo dpkg fallisce dopo aver installato, il rollback deve riuscire.
pkg=$(python3 -c "
import json, subprocess, sys
plan = json.load(open('$W/plan.json'))
for name in plan['leaf']:
    print(name)
" | while read -r name; do
  v=$(vm dpkg-query -W -f='\${Version}' "$name")
  if vm apt-cache madison "$name" | awk -F'|' '{gsub(/ /, "", $2); print $2}' | grep -qxF "$v"; then
    echo "$name"; break
  fi
done)
[ -n "$pkg" ] || { echo "::error title=vm debian::nessun pacchetto con la versione di prima nei repository"; exit 1; }
before=$(vm dpkg-query -W -f='\${Version}' "$pkg")
vm "echo 'DPkg::Post-Invoke {\"if [ ! -e /var/tmp/sage-fail ]; then touch /var/tmp/sage-fail; exit 1; fi\";};' | sudo tee /etc/apt/apt.conf.d/99sage-test > /dev/null"
rc=0
out=$(play remediate.yml -e sage_node_name=vm -e sage_kube=false \
  -e "{\"sage_update_packages\": [\"$pkg\"], \"sage_update_advisories\": [\"test\"]}") || rc=$?
after=$(vm dpkg-query -W -f='\${Version}' "$pkg")
vm sudo rm -f /etc/apt/apt.conf.d/99sage-test
if [ "$rc" -eq 0 ] || ! grep -q "rollback eseguito" <<< "$out" || [ "$after" != "$before" ]; then
  echo "$out" | tail -40
  echo "::error title=vm debian::rollback di $pkg: rc=$rc, versione $before -> $after"
  exit 1
fi

# 3. Aggiornamento completo con riavvio
boot_before=$(vm cat /proc/sys/kernel/random/boot_id)
play remediate.yml -e sage_node_name=vm -e sage_kube=false \
  -e "{\"sage_update_packages\": $(plan packages), \"sage_update_advisories\": $(plan advisories)}" \
  > "$W/remediate.log" || { tail -40 "$W/remediate.log"; exit 1; }
boot_after=$(vm cat /proc/sys/kernel/random/boot_id)
[ "$boot_before" != "$boot_after" ] || { echo "::error title=vm debian::nessun riavvio"; exit 1; }
rm -f "$W/out/vm.json"
play collect.yml -e "sage_out_dir=$W/out" > /dev/null
left=$(python3 -c "
import json
plan = set(json.load(open('$W/plan.json'))['packages'])
report = json.load(open('$W/out/vm.json'))
print(' '.join(sorted(plan & set(report['packages']))))")
[ -z "$left" ] || { echo "::error title=vm debian::ancora da aggiornare: $left"; exit 1; }

echo "::notice title=vm debian::$(vm 'grep PRETTY /etc/os-release') %0A${summary}%0Arollback di $pkg riuscito ($before); aggiornamento completo con riavvio riuscito"
