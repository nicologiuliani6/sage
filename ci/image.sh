#!/usr/bin/env bash
# L'immagine si costruisce e contiene sage, OPA e la collection kubernetes.core.
source "$(dirname "$0")/lib.sh"
checked docker build -t sage:ci .
checked docker run --rm sage:ci version
checked docker run --rm --entrypoint opa sage:ci version
checked docker run --rm --entrypoint ansible-galaxy sage:ci collection list kubernetes.core
# Come nel cluster: utente 10001, radice in sola lettura, /tmp vuota e scrivibile. I playbook
# eseguono task in locale: Ansible deve poter creare le sue cartelle temporanee.
checked docker run --rm --read-only --tmpfs /tmp --entrypoint ansible sage:ci \
  localhost -c local -m ansible.builtin.ping
# Le pagine della dashboard sono nel pacchetto installato (non solo nella repo).
checked docker run --rm --read-only --tmpfs /tmp --entrypoint python sage:ci -c \
  "from importlib import resources; [resources.files('sage.web').joinpath(f).read_bytes() for f in ('index.html', 'app.js', 'style.css')]"
# TEMPORANEO: digest delle immagini di build e di prova dell'installer, da fissare.
for ref in quay.io/pypa/manylinux2014_x86_64:latest rockylinux/rockylinux:9 rockylinux/rockylinux:8; do
  d=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' 2>&1 || true)
  echo "::notice title=digest::$ref $d"
done
