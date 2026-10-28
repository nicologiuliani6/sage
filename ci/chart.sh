#!/usr/bin/env bash
# Chart Helm: lint, rendering, e niente installazione senza i valori obbligatori.
source "$(dirname "$0")/lib.sh"
helm lint chart/sage -f chart/sage/ci/test-values.yaml
helm template sage chart/sage -f chart/sage/ci/test-values.yaml > /dev/null
if helm template sage chart/sage > /dev/null 2>&1; then
  echo "il chart si installa senza i valori obbligatori" && exit 1
fi
# Con le CA aziendali (caBundle) ogni pod di SAGE (controllore, controllo, remediation,
# aggiornamento) monta la ConfigMap e usa SSL_CERT_FILE.
out=$(helm template sage chart/sage -f chart/sage/ci/test-values.yaml --set caBundle.configMap=sage-ca)
mounts=$(grep -c "mountPath: /etc/sage/ca" <<< "$out")
[ "$mounts" -eq 4 ] || { echo "caBundle montato in $mounts pod invece di 4" && exit 1; }
if helm template sage chart/sage -f chart/sage/ci/test-values.yaml | grep -q SSL_CERT_FILE; then
  echo "SSL_CERT_FILE impostato senza caBundle" && exit 1
fi
