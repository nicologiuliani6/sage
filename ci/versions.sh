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
# Immagini per compilare l'installer (Rocky 8, glibc 2.28: gira su Rocky e RHEL 8 e 9 e sulle
# distro recenti) e per provarlo. Indice multi-architettura, fissato per digest.
ROCKY9_IMAGE=rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
ROCKY8_IMAGE=rockylinux/rockylinux:8@sha256:e8a49c5403b687db05d4d67333fa45808fbe74f36e683cec7abb1f7d0f2338c6
# Container in cui la CI prova il collector su ogni famiglia di distro (ci/distros.sh).
# Versioni vecchie apposta: hanno aggiornamenti di sicurezza in sospeso.
DEBIAN12_IMAGE=debian:12.1@sha256:eaace54a93d7b69c7c52bb8ddf9b3fcba0c106a497bc1fdbb89a6299cf945c63
UBUNTU2404_IMAGE=ubuntu:noble-20240423@sha256:562456a05a0dbd62a671c1854868862a4687bf979a96d48ae8e766642cd911e8
UBUNTU2204_IMAGE=ubuntu:jammy-20230425@sha256:dfd64a3b4296d8c9b62aa3309984f8620b98d87e47492599ee20739e8eb54fbf
LEAP156_IMAGE=opensuse/leap:15.6@sha256:79be7751205ea84559990fb76b1bec71e38d6fad41c70a4f6c921b803b58f421
ALMA9_IMAGE=almalinux:9.3@sha256:3f0cc7f99b0739908a8d6e4adec37ef47908991dc838dac43d52effe90fec747
FEDORA_IMAGE=fedora:44@sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80
# cluster kind per il contratto con l'API, versione minima e massima supportate
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KIND_NODE_MIN=kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
KIND_NODE_MAX=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
