#!/usr/bin/env bash
# Il collector sui gestori di pacchetti veri (ADR-0017): gira in un container di ogni
# famiglia di distro e il suo JSON viene controllato da ci/check_collect.py.
# Immagini vecchie apposta (hanno aggiornamenti in sospeso), fissate per digest
# (ADR-0008); il Python per il collector si installa dai repository della distro.
source "$(dirname "$0")/lib.sh"

run_collector() {
  local name=$1 image=$2 pm=$3 setup=$4 python=$5 out
  out=$(timeout 900 docker run --rm -v "$PWD/ansible/files:/sage:ro" "$image" \
    sh -c "($setup) > /dev/null 2>&1; $python /sage/collect_node.py") || true
  python3 ci/check_collect.py "$name" "$pm" <<< "$out"
}

APT_PY="apt-get update -qq && apt-get install -y -qq python3-minimal"
run_collector debian-12 "$DEBIAN12_IMAGE" apt "$APT_PY" python3
run_collector ubuntu-24.04 "$UBUNTU2404_IMAGE" apt "$APT_PY" python3
run_collector ubuntu-22.04 "$UBUNTU2204_IMAGE" apt "$APT_PY" python3
# Leap e SLES 15 hanno python3 3.6: il collector usa il python311 dei repository.
run_collector opensuse-leap-15.6 "$LEAP156_IMAGE" zypper \
  "zypper -n --gpg-auto-import-keys refresh && zypper -n install python311" python3.11
run_collector almalinux-9 "$ALMA9_IMAGE" dnf "true" python3
run_collector fedora "$FEDORA_IMAGE" dnf "dnf -y -q install python3" python3
