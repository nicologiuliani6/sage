# shellcheck shell=bash disable=SC2034
# Il nome non finisce in .env: .gitignore esclude i file .env (segreti locali).
# Versioni e checksum degli strumenti usati dalla CI (ADR-0008).
# Quando aggiorni una versione, aggiorna anche il checksum.
UV_VERSION=0.11.32
OPA_VERSION=1.21.3
OPA_SHA256=add7c9dcf56e1ce1538426a6ee595ea1cc7ee830bbedd4c23219825b02b19a79
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
# Helm che l'installer scarica sui master che non lo hanno. Il checksum viene letto
# da get.helm.sh al momento della release e scritto nell'installer.
HELM_VERSION=v4.3.0
