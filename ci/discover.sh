#!/usr/bin/env bash
# TEMPORANEO (branch multidistro): stampa l'output reale dei comandi dei gestori di
# pacchetti nei container di ogni distro, per scrivere e provare i parser del collector.
# I log dei job non si possono scaricare da qui: ogni output va in un'annotazione (max
# 4096 caratteri), leggibile dall'API check-runs.
source "$(dirname "$0")/lib.sh"

note() {
  local title=$1 out
  out=$(cat | head -c 4000)
  out=${out//'%'/'%25'}
  out=${out//$'\r'/'%0D'}
  out=${out//$'\n'/'%0A'}
  echo "::notice title=${title}::${out}"
}

d() { timeout 600 docker run --rm "$1" sh -c "$2" 2>&1 | grep -v "^Unable to find\|Pulling\|Download\|Digest\|Status:\|Pull complete"; }

d ubuntu:noble-20240423 'apt-get update -qq; apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep -E "^Inst" | head -25' | note ubuntu-inst
d debian:12.1 'apt-get update -qq; apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep -E "^Inst" | grep -i secur | head -15; apt-get -s remove less; apt-get -s remove libc6 | tail -5' | note debian-inst-remove
d opensuse/leap:15.6 'zypper -n --gpg-auto-import-keys refresh >/dev/null 2>&1; zypper -n --xmlout list-patches --all --category security | head -c 3500' | note leap-patches-xml
d opensuse/leap:15.6 'zypper -n --gpg-auto-import-keys refresh >/dev/null 2>&1; zypper -n list-patches --all --category security | head -8; zypper -n remove --dry-run --no-clean-deps less; echo rc=$?; zypper -n remove --dry-run --no-clean-deps glibc | tail -8; zypper needs-rebooting; echo needs-rebooting=$?' | note leap-remove
d opensuse/leap:15.6 'zypper -n --gpg-auto-import-keys refresh >/dev/null 2>&1; zypper -n --xmlout list-patches --all --category security | grep -A12 "<update " | sed -n "40,90p"' | note leap-patches-xml-2
d registry.suse.com/bci/bci-base:15.6 'zypper -n lr -u; zypper -n --xmlout list-patches --all --category security | head -c 1500' | note bci-repos
