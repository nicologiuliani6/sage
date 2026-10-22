#!/usr/bin/env bash
# Regole OPA: formato (sintassi v1) e test.
source "$(dirname "$0")/lib.sh"
install_opa
"$SAGE_OPA_BIN" fmt --list --fail policy
"$SAGE_OPA_BIN" test policy -v
