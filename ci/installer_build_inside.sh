#!/usr/bin/env bash
# Eseguito dentro l'immagine Rocky Linux 8 da ci/installer_bin.sh: compila
# /build/sage-install.py. Python 3.12 dei repository Rocky (pacchetti firmati, con la
# libreria condivisa che PyInstaller richiede); PyInstaller con versioni e hash fissati.
set -euo pipefail
dnf -q -y install python3.12 python3.12-pip binutils > /dev/null
cd /build
python3.12 -m venv /venv
/venv/bin/pip install --quiet --no-cache-dir --require-hashes -r requirements.txt 2>&1
/venv/bin/pyinstaller --onefile --clean --noconfirm --log-level WARN --name sage \
  sage-install.py 2>&1
chmod 0755 dist/sage
