#!/usr/bin/env bash
# Installer come eseguibile unico per linux amd64 (PyInstaller, ADR-0016): sui master non
# serve Python. Compilato in manylinux2014 (glibc 2.17), poi provato su Rocky Linux 8 e 9
# in container senza Python.
# Uso: ci/installer_bin.sh SORGENTE.py CARTELLA_DI_USCITA  -> CARTELLA/sage-install
source "$(dirname "$0")/lib.sh"
src="$1"
out="$2"
mkdir -p "$out"
work=$(mktemp -d)
cp "$src" "$work/sage-install.py"
cp ci/installer-build.txt "$work/requirements.txt"
cp ci/installer_build_inside.sh "$work/build.sh"
checked docker run --rm -v "$work:/build" "$MANYLINUX_IMAGE" bash /build/build.sh
cp "$work/dist/sage-install" "$out/sage-install"
for image in "$ROCKY9_IMAGE" "$ROCKY8_IMAGE"; do
  # PATH vuoto: nessun Python né altri strumenti a disposizione dell'eseguibile.
  checked docker run --rm -v "$out:/x:ro" "$image" \
    /usr/bin/env -i PATH=/nonexistent /x/sage-install --version
  checked docker run --rm -v "$out:/x:ro" "$image" \
    /usr/bin/env -i PATH=/nonexistent /x/sage-install --help
done
# Master con /tmp montata noexec (baseline CIS): l'eseguibile si estrae altrove con TMPDIR.
checked docker run --rm --tmpfs /tmp:rw,noexec,nosuid -v "$out:/x:ro" "$ROCKY9_IMAGE" \
  /usr/bin/env -i PATH=/nonexistent TMPDIR=/var/tmp /x/sage-install --version
echo "eseguibile: $(du -h "$out/sage-install" | cut -f1), $(/usr/bin/sha256sum "$out/sage-install" | cut -d' ' -f1)"
