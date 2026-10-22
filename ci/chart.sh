#!/usr/bin/env bash
# Chart Helm: lint, rendering, e niente installazione senza i valori obbligatori.
source "$(dirname "$0")/lib.sh"
helm lint chart/sage -f chart/sage/ci/test-values.yaml
helm template sage chart/sage -f chart/sage/ci/test-values.yaml > /dev/null
if helm template sage chart/sage > /dev/null 2>&1; then
  echo "il chart si installa senza i valori obbligatori" && exit 1
fi
