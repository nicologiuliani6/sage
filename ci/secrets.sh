#!/usr/bin/env bash
# Nessun segreto nella storia della repo (serve il checkout completo).
source "$(dirname "$0")/lib.sh"
f="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -fsSL -o "$TOOLS/$f" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${f}"
echo "${GITLEAKS_SHA256}  $TOOLS/$f" | sha256sum -c -
tar xzf "$TOOLS/$f" -C "$TOOLS" gitleaks
"$TOOLS/gitleaks" git --redact -v .

# TEMPORANEO (multidistro): output reali dei gestori di pacchetti.
bash ci/discover.sh || true
