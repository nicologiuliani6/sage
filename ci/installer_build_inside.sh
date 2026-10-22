#!/usr/bin/env bash
# Eseguito dentro l'immagine manylinux da ci/installer_bin.sh: compila /build/sage-install.py.
set -euo pipefail
py=/opt/python/cp312-cp312/bin/python
cd /build
$py -m pip install --quiet --no-cache-dir --require-hashes -r requirements.txt 2>&1
$py -m PyInstaller --onefile --clean --noconfirm --log-level WARN --name sage-install sage-install.py 2>&1
chmod 0755 dist/sage-install
