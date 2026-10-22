# shellcheck shell=bash
# Funzioni comuni degli script della CI. Si usa con `source ci/lib.sh`.
set -euo pipefail
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
