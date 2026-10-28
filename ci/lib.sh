# shellcheck shell=bash
# Funzioni comuni degli script della CI. Si usa con `source ci/lib.sh`.
set -Eeuo pipefail
# Su errore, un'annotazione con il comando fallito: si legge anche dall'API (check-runs),
# senza scaricare i log.
trap 'echo "::error title=${0##*/}::comando fallito (exit $?): ${BASH_COMMAND}"' ERR
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=ci/versions.sh
source ci/versions.sh
TOOLS="${RUNNER_TEMP:-$(mktemp -d)}/sage-tools"
mkdir -p "$TOOLS"

install_uv() {
  if ! uv --version 2>/dev/null | grep -q " ${UV_VERSION}"; then
    pipx install --force "uv==${UV_VERSION}"
  fi
}

install_opa() {
  curl -fsSL -o "$TOOLS/opa" \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static"
  echo "${OPA_SHA256}  $TOOLS/opa" | sha256sum -c -
  chmod +x "$TOOLS/opa"
  export SAGE_OPA_BIN="$TOOLS/opa"
}

install_cosign() {
  curl -fsSL -o "$TOOLS/cosign" \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  echo "${COSIGN_SHA256}  $TOOLS/cosign" | sha256sum -c -
  chmod +x "$TOOLS/cosign"
}

install_kind() {
  curl -fsSL -o "$TOOLS/kind" \
    "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64"
  echo "${KIND_SHA256}  $TOOLS/kind" | sha256sum -c -
  chmod +x "$TOOLS/kind"
  export PATH="$TOOLS:$PATH"
}

# Esegue un comando; se fallisce, ne riporta le ultime righe di output in un'annotazione.
checked() {
  local out rc=0
  out=$("$@" 2>&1) || rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ]; then
    local tail
    tail=$(echo "$out" | tail -n 25)
    tail=${tail//'%'/'%25'}
    tail=${tail//$'\n'/'%0A'}
    echo "::error title=${0##*/}::$* (exit $rc)%0A${tail}"
    return "$rc"
  fi
}
