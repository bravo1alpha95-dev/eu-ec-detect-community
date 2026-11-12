#!/usr/bin/env bash
# One-command easy path: preflight + collect + short summary.
# Read-only. Designed to minimize operator workload.
# Usage: ./scripts/easy-run.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Source lib early so helpers like iso_date are available
# shellcheck source=scripts/lib.sh
source scripts/lib.sh
if [[ -e .env || -L .env ]]; then load_env .env; else load_env .env.example; fi

echo "=== Easy Access Monitor Run ==="
echo "Date: $(iso_date)"
echo "Host: $(hostname)"
echo ""

echo "[1/3] Preflight..."
if ! ./scripts/00_preflight.sh; then
  echo "[ERROR] Preflight failed. Fix issues before continuing."
  exit 1
fi
echo ""

echo "[2/3] Collecting access evidence (read-only)..."
./scripts/10_collect.sh
echo ""

echo "[3/3] Summary of latest report:"
# Timestamped names sort chronologically; avoids parsing ls.
shopt -s nullglob
ROLE=$(sanitize_name "${ROLE:-ops}")
EU_HOST=$(sanitize_host)
reports=(reports/"${ROLE}"-access-collect-"${EU_HOST}"-*.txt)
LATEST=""
(( ${#reports[@]} )) && LATEST=${reports[-1]}
if [[ -n "$LATEST" ]]; then
  echo "Latest evidence file: $LATEST"
  echo "--- Key excerpts ---"
  grep -E '^(## |# )' "$LATEST" | head -20 || true
  echo ""
  # Counts only: stdout often ends up in cron mail or CI logs.
  echo "Users with shells: $(awk '/^## Users with login shells/{f=1;next} /^$/{f=0} f' "$LATEST" | wc -l)"
  echo "Listening sockets: $(awk '/^## Listening sockets/{f=1;next} /^$/{f=0} f && /LISTEN|UNCONN/' "$LATEST" | wc -l)"
  echo ""
  echo "Full details in: $LATEST"
  echo "JSON summary (if generated): ${LATEST%.txt}.json"
else
  echo "No report found. Check scripts/10_collect.sh output."
fi

echo ""
echo "=== Done. Review reports/ for evidence. No changes made. ==="
echo "Next: fill scope/roe.md if not done, then consider Wazuh agent for continuous monitoring."
echo "Tip: run scripts/anomaly-checks.sh separately for baseline diffs."
