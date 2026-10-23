#!/usr/bin/env bash
# TEMPORANEO: immagini cloud Debian disponibili e KVM sul runner.
source "$(dirname "$0")/lib.sh"
out="kvm: $(ls -l /dev/kvm 2>&1)%0A"
for rel in bookworm trixie; do
  dirs=$(curl -fsSL "https://cloud.debian.org/images/cloud/$rel/" | grep -o 'href="20[0-9-]*/"' | cut -d'"' -f2 | tail -10 | tr '\n' ' ')
  out+="$rel: $dirs%0A"
  for d in $(echo "$dirs" | tr ' ' '\n' | sed -n '1p;5p'); do
    sum=$(curl -fsSL "https://cloud.debian.org/images/cloud/$rel/$d/SHA512SUMS" | grep "genericcloud-amd64-.*qcow2$" | head -1)
    out+="$rel/$d $sum%0A"
  done
done
echo "::notice title=debian-cloud::${out}"
