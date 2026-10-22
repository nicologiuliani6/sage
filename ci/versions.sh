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
# Immagini per compilare l'installer (glibc 2.17: gira su qualsiasi Linux recente) e per
# provarlo su Rocky Linux senza Python. Indice multi-architettura, fissato per digest.
MANYLINUX_IMAGE=quay.io/pypa/manylinux2014_x86_64@sha256:3a591c1109773dbd79f16c038588fd1867d9f2f708b360dab5715852c7f96ef0
ROCKY9_IMAGE=rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
ROCKY8_IMAGE=rockylinux/rockylinux:8@sha256:e8a49c5403b687db05d4d67333fa45808fbe74f36e683cec7abb1f7d0f2338c6
