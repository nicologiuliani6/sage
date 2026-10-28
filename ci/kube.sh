#!/usr/bin/env bash
# Test di src/sage/kube.py contro un cluster Kubernetes vero (kind).
source "$(dirname "$0")/lib.sh"
install_uv
install_kind
uv sync --frozen --python 3.12

# Funzione per pulire il cluster in caso di errore
cleanup() {
  kind delete cluster --name sage-ci || true
}
trap cleanup EXIT

# Versione minima e massima di Kubernetes supportate (ci/versions.sh).
for image in "$KIND_NODE_MIN" "$KIND_NODE_MAX"; do
  checked kind create cluster --name sage-ci --image "$image" --wait 120s --kubeconfig "$TOOLS/kubeconfig"
  KUBECONFIG="$TOOLS/kubeconfig" SAGE_KUBECONFIG="$TOOLS/kubeconfig" checked uv run pytest -v -rs tests/live \
    | tee "$TOOLS/live.log"
  if grep -q "SKIPPED" "$TOOLS/live.log"; then
    echo "test live saltati: devono girare tutti" && exit 1
  fi
  kind delete cluster --name sage-ci
done