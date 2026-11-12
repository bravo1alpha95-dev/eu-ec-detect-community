#!/usr/bin/env bash
# Preflight checks for isolation, tools, and basic environment.
# Read-only except creating reports/ (mode 700). Fails closed on critical issues.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib.sh
source scripts/lib.sh

echo "[preflight] Checking environment for eu-ec-detect-community (owned systems only)"
echo "[preflight] Host: $(hostname) | User: $(id -un) | Date: $(iso_date)"
if [[ $(id -u) -eq 0 ]]; then
  echo "[preflight] WARN: running as root. Prefer least privilege; elevate only where full visibility needs it."
fi

missing=()
for cmd in hostname id date mkdir sed awk getent; do
  command -v "$cmd" >/dev/null || missing+=("$cmd")
done
if (( ${#missing[@]} > 0 )); then
  echo "[preflight] ERROR: Missing required commands: ${missing[*]}"
  exit 1
fi

if ! sed --version 2>/dev/null | grep -q GNU; then
  echo "[preflight] ERROR: GNU sed is required for redaction" >&2
  exit 1
fi

# Checksum tool for baseline integrity (prefer sha256sum, fallback shasum).
if ! command -v sha256sum >/dev/null && ! command -v shasum >/dev/null; then
  echo "[preflight] WARN: neither sha256sum nor shasum found — baseline integrity checks will be limited."
fi

for cmd in ss last lastb ufw; do
  if ! command -v "$cmd" >/dev/null; then
    echo "[preflight] WARN: optional tool missing: $cmd (some checks limited)"
  fi
done

prepare_reports_dir reports
if [[ ! -w reports ]]; then
  echo "[preflight] ERROR: reports/ not writable" >&2
  exit 1
fi

if [[ ! -e .env && ! -L .env ]]; then
  echo "[preflight] WARN: no .env — using .env.example values. Copy and chmod 600 .env for production."
  load_env .env.example || { echo "[preflight] ERROR: cannot load .env.example" >&2; exit 1; }
else
  env_file_ok .env || { echo "[preflight] ERROR: .env must be an owned regular file with mode 600 or 400" >&2; exit 1; }
  load_env .env || { echo "[preflight] ERROR: cannot load .env" >&2; exit 1; }
fi

# Informational only: operators must confirm the host is in authorized scope.
if [[ -n "${EU_SCOPE_CIDR:-}" ]]; then
  echo "[preflight] INFO: Configured EU_SCOPE_CIDR=${EU_SCOPE_CIDR}. Confirm this host is in authorized scope before collection."
else
  echo "[preflight] INFO: EU_SCOPE_CIDR is unset. Set it in .env to document the authorized address range."
fi

if roe_authorized scope/roe.md; then
  echo "[preflight] INFO: ROE Status AUTHORIZED"
else
  echo "[preflight] WARN: ROE not AUTHORIZED or has unfilled (fill) fields — read-only collection only."
fi

echo "[preflight] OK — environment suitable for read-only collection."
