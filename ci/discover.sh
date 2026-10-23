#!/usr/bin/env bash
# TEMPORANEO (branch multidistro): stampa l'output reale dei comandi dei gestori di
# pacchetti nei container di ogni distro, per scrivere e provare i parser del collector.
# Immagini vecchie apposta: hanno aggiornamenti di sicurezza in sospeso.
source "$(dirname "$0")/lib.sh"

APT='
set -x
cat /etc/os-release | head -3
python3 --version || true
apt-get update -qq
apt list --upgradable 2>/dev/null | head -40
apt-get -s upgrade | grep -E "^Inst" | head -40
dpkg-query -W -f="\${binary:Package}|\${Package}|\${Version}|\${source:Package}|\${source:Version}|\${db:Status-Abbrev}\n" | head -15
apt-cache policy libssl3 openssl libc6 2>/dev/null | head -40
apt-get -s remove --no-auto-remove less | head -20
ls /var/lib/dpkg/info/*.list | head -3
cat /var/lib/dpkg/info/coreutils.list | head -5
dpkg-query -W -f="\${Package}|\${Depends}|\${Pre-Depends}|\${Provides}\n" coreutils libc6 | head
ls -la /lib /bin /sbin /lib64 2>&1 | head
grep -h "^deb\|^URIs\|^Suites" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | head
'

ZYPPER='
set -x
cat /etc/os-release | head -3
python3 --version || true
zypper -n --gpg-auto-import-keys -q refresh || true
zypper -n -q list-patches --category security | head -30
zypper -n --xmlout -q list-patches --category security | head -60
first=$(zypper -n --xmlout -q list-patches --category security | grep -o "name=\"[^\"]*\"" | head -2 | tail -1 | cut -d\" -f2)
echo "PATCH=$first"
zypper -n --xmlout -q info -t patch "$first" | head -80
zypper -n -q info -t patch "$first" | head -60
zypper -n --xmlout -q list-updates | head -30
zypper -n -q remove --dry-run --no-clean-deps less 2>&1 | head -20
zypper needs-rebooting; echo "needs-rebooting rc=$?"
ls -la /lib /bin /lib64 2>&1 | head
'

DNF='
set -x
cat /etc/os-release | head -3
python3 --version || /usr/libexec/platform-python --version || true
dnf -q updateinfo list --security 2>&1 | head -20
dnf -q updateinfo info --security 2>&1 | head -60
dnf needs-restarting -r; echo "needs-restarting rc=$?"
'

run() {
  local image=$1 script=$2
  echo "::group::${image}"
  echo "=== ${image} ==="
  timeout 600 docker run --rm "$image" sh -c "$script" 2>&1 || echo "(uscito con $?)"
  echo "::endgroup::"
}

run debian:12.1 "$APT"
run debian:11.7 "$APT"
run ubuntu:jammy-20230425 "$APT"
run ubuntu:noble-20240423 "$APT"
run opensuse/leap:15.6 "$ZYPPER"
run registry.suse.com/bci/bci-base:15.6 "$ZYPPER"
run almalinux:9.3 "$DNF"
run oraclelinux:9 "$DNF"
run amazonlinux:2023.3.20231218.0 "$DNF"
run fedora:41 "$DNF"
