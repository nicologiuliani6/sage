#!/usr/bin/env bash
# TEMPORANEO (branch multidistro): prova ci/distros.sh e stampa i digest da fissare.
source "$(dirname "$0")/lib.sh"
bash ci/distros.sh || true
digests=""
for v in DEBIAN12_IMAGE UBUNTU2404_IMAGE UBUNTU2204_IMAGE LEAP156_IMAGE ALMA9_IMAGE FEDORA_IMAGE; do
  img=${!v}
  docker pull -q "$img" > /dev/null 2>&1 || true
  digests+="$v=$(docker inspect --format '{{index .RepoDigests 0}}' "$img" 2>&1)%0A"
done
echo "::notice title=digest::${digests}"
