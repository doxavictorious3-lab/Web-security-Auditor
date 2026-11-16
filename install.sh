#!/usr/bin/env bash
# DOXA Web Security Auditor - dependency installer for Kali Linux / Debian-based systems.
# Usage: ./install.sh [--dry-run] [--no-templates]
set -uo pipefail
DRY=0; TEMPLATES=1
for a in "$@"; do
  case $a in
    --dry-run) DRY=1 ;;
    --no-templates) TEMPLATES=0 ;;
    -h|--help) echo "Usage: $0 [--dry-run] [--no-templates]"; exit 0 ;;
    *) echo "Unknown option: $a" >&2; exit 1 ;;
  esac
done
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIRED=(curl coreutils gawk sed grep openssl)
RECOMMENDED=(jq nmap nikto gobuster whatweb nuclei sslyze dnsutils dirb seclists chromium)

run() { if (( DRY )); then echo "[dry-run] $*"; else echo "+ $*"; "$@"; fi; }

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found: this installer supports Kali/Debian/Ubuntu. Install the packages manually:" >&2
  echo "  ${REQUIRED[*]} ${RECOMMENDED[*]}" >&2
  exit 2
fi
SUDO=""
if (( EUID != 0 )); then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else echo "Run as root or install sudo." >&2; exit 2; fi
fi
run $SUDO apt-get update
missing=()
for p in "${REQUIRED[@]}" "${RECOMMENDED[@]}"; do
  if (( DRY )) || ! dpkg -s "$p" >/dev/null 2>&1; then missing+=("$p"); fi
done
if (( ${#missing[@]} )); then
  # Install one by one so a package that does not exist on this release does not block the rest.
  for p in "${missing[@]}"; do run $SUDO apt-get install -y "$p" || echo "WARNING: could not install $p (module depending on it will be skipped)" >&2; done
else
  echo "All packages already installed."
fi
if (( TEMPLATES )) && command -v nuclei >/dev/null 2>&1; then run nuclei -update-templates || echo "WARNING: nuclei template update failed (needs internet)" >&2; fi
chmod +x "$HERE/doxa.sh" "$HERE/tests/run_tests.sh" 2>/dev/null || true
echo; echo "Done. Verify with:  $HERE/doxa.sh --check-tools"
