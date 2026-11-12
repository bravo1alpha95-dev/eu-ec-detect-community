#!/usr/bin/env bash
# Read-only checks for unusual access patterns and unexpected listeners.
# Compares against a simple baseline file if present; otherwise reports current state.
# Safe for owned systems. Output to reports/.
# Baseline normalizes away PIDs and dynamic fields to reduce noise.
# Residual risks: same-user tampering of baseline (store off-host for higher assurance);
# ss output format varies by version/OS — parsing is best-effort and may need tuning.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/lib.sh
source "$ROOT/scripts/lib.sh"
HOST=$(sanitize_host)
TS=$(date +%Y%m%dT%H%M%S)-$$
# Per-host baseline so a shared reports/ dir does not cross-contaminate hosts.
OUT="$ROOT/reports/anomaly-check-${HOST}-${TS}.txt"
BASELINE="$ROOT/reports/baseline-listeners-${HOST}.txt"
prepare_reports_dir "$ROOT/reports"
TMP=$(mktemp "$ROOT/reports/.current-listeners.XXXXXX")
trap 'rm -f "$TMP"' EXIT

command -v ss >/dev/null || { echo "[anomaly] ERROR: ss is required for the listener baseline" >&2; exit 3; }

# Keep only proto, state, and local address:port so PIDs don't show up as changes.
# Prefer headerless (-H) when available. LC_ALL=C for consistent parsing.
normalize_listeners() {
  export LC_ALL=C
  local ss_cmd
  if ss -H -tuln >/dev/null 2>&1; then
    ss_cmd=(ss -H -tuln)
  else
    ss_cmd=(ss -tuln)
  fi
  "${ss_cmd[@]}" | awk '
    # Skip header if present
    NR==1 && ($1 ~ /Netid|State/ || $2 ~ /State/) { next }
    $2 ~ /LISTEN|UNCONN/ {
      local_addr = ""
      for (i = 1; i <= NF; i++) {
        # Local endpoints end in a numeric port (IPv4, bracketed IPv6, or wildcard).
        if ($i ~ /:[0-9]+$/) {
          local_addr = $i
          break
        }
      }
      if (local_addr != "") {
        print $1, $2, local_addr
      }
    }
  ' | sort -u
}

# Atomic write helper for baseline + checksum
write_baseline_atomic() {
  local content_file=$1
  local base=$2
  local sum="${base}.sha256"
  local tmpbase sumtmp hash finalbase
  tmpbase=$(mktemp "${base}.XXXXXX")
  sumtmp=$(mktemp "${sum}.XXXXXX")
  cp -a "$content_file" "$tmpbase"
  finalbase=$(basename "$base")
  if command -v sha256sum >/dev/null 2>&1; then
    hash=$(cd "$(dirname "$tmpbase")" && sha256sum "$(basename "$tmpbase")" | cut -d' ' -f1)
    printf '%s  %s\n' "$hash" "$finalbase" > "$sumtmp"
  elif command -v shasum >/dev/null 2>&1; then
    hash=$(cd "$(dirname "$tmpbase")" && shasum -a 256 "$(basename "$tmpbase")" | cut -d' ' -f1)
    printf '%s  %s\n' "$hash" "$finalbase" > "$sumtmp"
  else
    echo "[anomaly] WARN: cannot create baseline checksum (no sha256 tool)" >&2
    rm -f "$tmpbase" "$sumtmp"
    return 1
  fi
  # Atomic replace: content first, then sum (sum references final name)
  mv -f "$tmpbase" "$base"
  mv -f "$sumtmp" "$sum"
}

# Pin a private report descriptor; errors never append via an attacker-supplied path.
EU_REPORT=$(mktemp "$ROOT/reports/.anomaly.XXXXXX")
exec 3> "$EU_REPORT"
set -E
trap 'echo "!! INCOMPLETE: run aborted at line $LINENO" >&3; echo "[anomaly] ERROR: operational failure; incomplete report: $EU_REPORT" >&2; exit 3' ERR
status=0
{
  echo "# Anomaly Check $(iso_date)"
  echo "# Host: ${HOST} User: $(id -un)"
  echo ""
  echo "## Unexpected listeners check (normalized baseline)"
  # Baselines need the same private, owned regular-file contract as .env.
  if [[ -L "$BASELINE" || -L "${BASELINE}.sha256" ]] ||
     { [[ -e "$BASELINE" ]] && ! env_file_ok "$BASELINE"; } ||
     { [[ -e "${BASELINE}.sha256" ]] && ! env_file_ok "${BASELINE}.sha256"; }; then
    echo "!! UNSAFE BASELINE OR CHECKSUM — require owned regular files with mode 600 or 400, not symlinks."
    status=2
  elif [[ -f "$BASELINE" ]]; then
    # The sidecar only detects edits by other users/tools; an attacker with this account can rewrite both.
    # Residual risk: local privileged or same-user tampering. Store baseline off-host for higher assurance.
    if [[ -f "${BASELINE}.sha256" && ! -L "${BASELINE}.sha256" ]]; then
      if ! verify_checksum "$BASELINE" "${BASELINE}.sha256"; then
        echo "!! BASELINE INTEGRITY CHECK FAILED ($BASELINE.sha256) — treat as possible tampering."
        status=2
      fi
    else
      echo "!! BASELINE EXISTS BUT .sha256 MISSING OR SYMLINK — treat as possible tampering."
      status=2
    fi
    normalize_listeners > "$TMP"
    echo "New or changed listeners (diff on normalized view):"
    if diff -u "$BASELINE" "$TMP"; then
      echo "(no differences)"
    else
      EU_DIFF_STATUS=$?
      if [[ $EU_DIFF_STATUS -ne 1 ]]; then
        echo "!! INCOMPLETE: diff failed with status $EU_DIFF_STATUS" >&3
        echo "[anomaly] ERROR: listener comparison failed; incomplete report: $EU_REPORT" >&2
        exit 3
      fi
      # Preserve the higher integrity status when listeners also changed.
      if [[ $status -eq 0 ]]; then status=1; fi
    fi
  else
    normalize_listeners > "$TMP"
    if write_baseline_atomic "$TMP" "$BASELINE"; then
      echo "No baseline yet. Saved current normalized listeners as baseline (+ .sha256) atomically."
    else
      # Fallback non-atomic if checksum tool missing
      cp -a "$TMP" "$BASELINE"
      echo "No baseline yet. Saved current normalized listeners as baseline (checksum skipped)."
    fi
    echo "To re-baseline after an approved change, delete both files and re-run."
  fi
  echo ""
  echo "## Unusual access pattern indicators (from recent logs, redacted)"
  echo "### Failed / accepted logins (sample)"
  for log in /var/log/auth.log /var/log/secure; do
    if [[ -r "$log" && ! -L "$log" ]]; then
      echo "--- $log ---"
      tail -n 200 "$log" | grep -E 'Failed password|Accepted' | tail -20 | redact || true
    fi
  done
  echo ""
  echo "### Logins starting 00:00-05:59 (from last)"
  # Login time is the first HH:MM on the line (after the weekday/month/day).
  last -n 50 2>/dev/null | awk '
    $1 == "reboot" || $1 == "shutdown" {next}
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9][0-9]?:[0-9][0-9]$/) {
          split($i, t, ":")
          hour = t[1] + 0
          if (hour < 6) print
          break
        }
      }
    }
  ' | redact || true
  echo ""
  echo "## Sudo usage recent (redacted)"
  for log in /var/log/auth.log /var/log/secure; do
    if [[ -r "$log" && ! -L "$log" ]]; then
      grep -E 'sudo:' "$log" | tail -10 | redact || true
    fi
  done
} >&3
mv -f "$EU_REPORT" "$OUT"
trap - ERR
exec 3>&-

echo "[anomaly] wrote $OUT"
case $status in
  0) echo "[anomaly] No listener changes." ;;
  1) echo "[anomaly] Listener changes detected — review $OUT." ;;
  *) echo "[anomaly] Baseline integrity failure — review $OUT." ;;
esac
exit "$status"
