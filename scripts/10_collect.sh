#!/usr/bin/env bash
# Read-only access evidence collection for owned systems.
# Produces timestamped text + JSON summary under reports/.
# Safe: no mutations, redacts sensitive data, fails closed on critical issues.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib.sh
source scripts/lib.sh

if [[ -e .env || -L .env ]]; then load_env .env; else load_env .env.example; fi

HOST=$(sanitize_host)
TS=$(date +%Y%m%dT%H%M%S)-$$
ROLE=$(sanitize_name "${ROLE:-ops}")
OUT="reports/${ROLE}-access-collect-${HOST}-${TS}.txt"
JSON="reports/${ROLE}-access-collect-${HOST}-${TS}.json"
prepare_reports_dir reports

TMPTXT=$(mktemp reports/.collect.XXXXXX)
TMPJSON=$(mktemp reports/.collectjson.XXXXXX)
trap 'rm -f "$TMPTXT" "$TMPJSON"' EXIT
# Incomplete temporary reports are removed, never advertised as successful output.
set -E
trap 'echo "[collect] ERROR: operational failure at line $LINENO; no complete report published" >&2; exit 3' ERR

{
  echo "# Access Evidence Collection $(iso_date)"
  echo "# Host: ${HOST} User: $(id -un) Role: ${ROLE}"
  echo "# Read-only. Redacted excerpts only."
  echo ""

  echo "## Users with login shells"
  getent passwd | awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/ {print $1":"$3":"$7}' | redact || true
  echo ""

  echo "## Groups (sample)"
  getent group | head -50 | redact || true
  echo ""

  echo "## Listening sockets (ss -tuln, headerless preferred)"
  if command -v ss >/dev/null; then
    if ss -H -tuln >/dev/null 2>&1; then
      ss -H -tuln 2>/dev/null | head -100 | redact || true
    else
      ss -tuln 2>/dev/null | head -100 | redact || true
    fi
  else
    echo "(ss not available)"
  fi
  echo ""

  echo "## Recent logins (last -n 30)"
  last -n 30 2>/dev/null | head -40 | redact || echo "(last unavailable)"
  echo ""

  echo "## Failed logins (lastb sample)"
  if command -v lastb >/dev/null; then
    lastb -n 20 2>/dev/null | head -30 | redact || true
  else
    echo "(lastb not available or no permissions)"
  fi
  echo ""

  echo "## Auth log excerpts (redacted, recent)"
  for log in /var/log/auth.log /var/log/secure /var/log/syslog; do
    if [[ -r "$log" && ! -L "$log" ]]; then
      echo "--- $log (tail 100, Failed/Accepted/sudo) ---"
      tail -n 100 "$log" 2>/dev/null | grep -E 'Failed password|Accepted|sudo:|sshd' | tail -30 | redact || true
    fi
  done
  echo ""

  echo "## SSH daemon config (key settings only, if readable)"
  if [[ -r /etc/ssh/sshd_config && ! -L /etc/ssh/sshd_config ]]; then
    grep -iE '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|Port|Protocol)([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null | redact || true
  else
    echo "(sshd_config not readable)"
  fi
  echo ""

  echo "## Sudoers policy (if readable, redacted)"
  if [[ -r /etc/sudoers && ! -L /etc/sudoers ]]; then
    grep -vE '^#|^$' /etc/sudoers 2>/dev/null | head -40 | redact || true
  else
    echo "(sudoers not readable)"
  fi
  echo ""

  echo "## Installed packages related to monitoring/security (sample)"
  if command -v dpkg >/dev/null; then
    dpkg -l 'wazuh*' 'auditd*' 'suricata*' 'rsyslog*' 2>/dev/null | head -20 || true
  elif command -v rpm >/dev/null; then
    rpm -qa 'wazuh*' 'audit*' 'suricata*' 2>/dev/null | head -20 || true
  fi
  echo ""

  echo "## Unattended upgrades / auto-updates status (if present)"
  if command -v apt-config >/dev/null; then
    apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null || true
  fi
  echo ""

  echo "# End of collection. Review before external sharing."
} > "$TMPTXT"

# Simple JSON summary (valid JSON, escaped)
USERS_SHELL=$(getent passwd | awk -F: '$7 ~ /(bash|sh|zsh|ksh|fish)$/ {n++} END {print n+0}')
LISTEN_COUNT=0
if command -v ss >/dev/null; then
  LISTEN_COUNT=$(ss -tuln 2>/dev/null | awk '$2 == "LISTEN" || $2 == "UNCONN" {n++} END {print n+0}') || LISTEN_COUNT=0
fi
ESC_HOST=$(json_escape "$HOST")
ESC_USER=$(json_escape "$(id -un)")
ESC_ROLE=$(json_escape "$ROLE")
ESC_REPORT=$(json_escape "$(basename "$OUT")")
cat > "$TMPJSON" << EOF
{
  "timestamp": "$(iso_date)",
  "host": "$ESC_HOST",
  "user": "$ESC_USER",
  "role": "$ESC_ROLE",
  "report": "$ESC_REPORT",
  "users_with_shells": ${USERS_SHELL},
  "listening_sockets": ${LISTEN_COUNT},
  "notes": "Read-only collection. All sensitive excerpts redacted. Review before sharing."
}
EOF

mv -f "$TMPTXT" "$OUT"
mv -f "$TMPJSON" "$JSON"
chmod 600 "$OUT" "$JSON"

echo "[collect] wrote $OUT"
echo "[collect] wrote $JSON"
exit 0
