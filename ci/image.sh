#!/usr/bin/env bash
# L'immagine si costruisce e contiene sage, OPA e la collection kubernetes.core.
source "$(dirname "$0")/lib.sh"
checked docker build -t sage:ci .
checked docker run --rm sage:ci version
checked docker run --rm --entrypoint opa sage:ci version
checked docker run --rm --entrypoint ansible-galaxy sage:ci collection list kubernetes.core
