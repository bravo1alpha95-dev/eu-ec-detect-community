#!/usr/bin/env bash
# Read-only CIS-style hardening audit for owned Linux systems.
# Checks a subset of common benchmark items and reports PASS / WARN / FAIL:
#   SSH (PermitRootLogin, PasswordAuthentication, Protocol, MaxAuthTries),
#   sudoers NOPASSWD entries, host firewall (ufw, firewalld, nftables),
#   world-writable files in key directories, automatic security updates,
#   auditd, and password aging (/etc/login.defs).
#
# Safe: this script NEVER changes the system. It has no apply mode; CONFIRM is
# ignored. It only reads files and runs status queries (ufw status,
# firewall-cmd --state, nft list ruleset, systemctl is-active/is-enabled).
# Run as root for complete results; unreadable items are reported as WARN.
#
# Output: findings on stdout plus a redacted report and JSON summary under
# reports/ (directory 700, files 600, written under umask 077).
#
# Environment (EU_* naming, all optional):
#   EU_AUDIT_NO_REPORT=yes  print findings only; write nothing to reports/
#   EU_AUDIT_FAIL_ON=fail   exit 2 when any FAIL is found (default: exit 0)
#   EU_AUDIT_ROOT=/path     audit a mounted image or test fixture instead of /
#                           (absolute path; file checks only)
#   EU_AUDIT_MAX_LIST=20    max world-writable paths listed in the report
#
# Exit codes: 0 audit completed, 2 FAIL findings with EU_AUDIT_FAIL_ON=fail,
#             3 operational error (no report published).
# Residual risk: config parsing is best-effort (Match blocks and nested
# includes are not evaluated). Confirm SSH with `sshd -T` as root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib.sh
source scripts/lib.sh

if [[ -e .env || -L .env ]]; then load_env .env; else load_env .env.example; fi

AUDIT_ROOT="${EU_AUDIT_ROOT:-}"
if [[ -n "$AUDIT_ROOT" ]]; then
  if [[ ! "$AUDIT_ROOT" =~ ^/[A-Za-z0-9._/-]*$ || "$AUDIT_ROOT" == *..* || ! -d "$AUDIT_ROOT" || -L "$AUDIT_ROOT" ]]; then
    echo "[hardening] ERROR: EU_AUDIT_ROOT must be an existing absolute directory (safe characters, no ..)" >&2
    exit 3
  fi
  AUDIT_ROOT="${AUDIT_ROOT%/}"
fi
MAX_LIST="${EU_AUDIT_MAX_LIST:-20}"
[[ "$MAX_LIST" =~ ^[0-9]{1,4}$ ]] || MAX_LIST=20
NO_REPORT=no
[[ "${EU_AUDIT_NO_REPORT:-}" == yes ]] && NO_REPORT=yes

HOST=$(sanitize_host)
TS=$(date +%Y%m%dT%H%M%S)-$$
ROLE=$(sanitize_name "${ROLE:-ops}")

FINDINGS=$(mktemp "${TMPDIR:-/tmp}/eu-hardening.XXXXXX")
TMPTXT=""
TMPJSON=""
# Temporary findings and unpublished report files are always removed.
trap 'rm -f "$FINDINGS" ${TMPTXT:+"$TMPTXT"} ${TMPJSON:+"$TMPJSON"}' EXIT
set -E
trap 'echo "[hardening] ERROR: operational failure at line $LINENO; no complete report published" >&2; exit 3' ERR

PASS_N=0 WARN_N=0 FAIL_N=0
# result STATUS SECTION MESSAGE
result() {
  local status=$1 section=$2 msg=$3
  case "$status" in
    PASS) PASS_N=$((PASS_N + 1)) ;;
    WARN) WARN_N=$((WARN_N + 1)) ;;
    FAIL) FAIL_N=$((FAIL_N + 1)) ;;
  esac
  printf '%-4s  %-10s %s\n' "$status" "$section" "$msg" >> "$FINDINGS"
}
detail() { printf '            %s\n' "$1" >> "$FINDINGS"; }

p() { printf '%s%s' "$AUDIT_ROOT" "$1"; }
readable() { [[ -f "$1" && -r "$1" && ! -L "$1" ]]; }

# ---------------------------------------------------------------- SSH
# sshd uses the FIRST value obtained for each keyword. Collect global lines
# (before any Match block) from sshd_config and its Include files, in order.
ssh_lines() {
  local file=$1 depth=${2:-0} line kw rest inc
  readable "$file" || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    kw="${line%%[[:space:]=]*}"
    rest="${line#"$kw"}"
    rest="${rest#"${rest%%[![:space:]=]*}"}"
    kw="${kw,,}"
    if [[ "$kw" == match ]]; then
      break
    elif [[ "$kw" == include && $depth -lt 2 ]]; then
      for inc in $rest; do
        [[ "$inc" == /* ]] || inc="/etc/ssh/$inc"
        [[ "$inc" == *..* ]] && continue
        local f
        for f in $(p "$inc"); do
          [[ -e "$f" ]] && ssh_lines "$f" $((depth + 1))
        done
      done
    else
      printf '%s %s\n' "$kw" "${rest%%[[:space:]]*}"
    fi
  done < "$file"
}

ssh_value() { # keyword (lowercase); prints first value, empty if unset
  awk -v k="$1" '$1 == k {print tolower($2); exit}' <<< "$SSH_CFG"
}

check_ssh() {
  local cfg v
  cfg=$(p /etc/ssh/sshd_config)
  if [[ ! -e "$cfg" ]]; then
    result WARN ssh "sshd_config not found (OpenSSH server not installed?); SSH checks skipped"
    return
  fi
  if ! readable "$cfg"; then
    result WARN ssh "sshd_config not readable as $(id -un); run as root"
    return
  fi
  SSH_CFG=$(ssh_lines "$cfg")

  v=$(ssh_value permitrootlogin)
  case "$v" in
    no) result PASS ssh "PermitRootLogin no" ;;
    yes) result FAIL ssh "PermitRootLogin yes (direct root login allowed; set no)" ;;
    prohibit-password|without-password|forced-commands-only)
      result WARN ssh "PermitRootLogin $v (root key login allowed; CIS recommends no)" ;;
    '') result WARN ssh "PermitRootLogin not set (OpenSSH default prohibit-password; CIS recommends no)" ;;
    *) result WARN ssh "PermitRootLogin has an unrecognized value" ;;
  esac

  v=$(ssh_value passwordauthentication)
  case "$v" in
    no) result PASS ssh "PasswordAuthentication no" ;;
    yes) result WARN ssh "PasswordAuthentication yes (prefer keys; set no where possible)" ;;
    '') result WARN ssh "PasswordAuthentication not set (OpenSSH default yes)" ;;
    *) result WARN ssh "PasswordAuthentication has an unrecognized value" ;;
  esac

  v=$(ssh_value protocol)
  case "$v" in
    '') result PASS ssh "Protocol not set (OpenSSH 7.4+ supports protocol 2 only)" ;;
    2) result PASS ssh "Protocol 2" ;;
    *1*) result FAIL ssh "Protocol includes SSH-1 ($v); remove it" ;;
    *) result WARN ssh "Protocol has an unrecognized value" ;;
  esac

  v=$(ssh_value maxauthtries)
  if [[ -z "$v" ]]; then
    result WARN ssh "MaxAuthTries not set (OpenSSH default 6; CIS recommends 4 or less)"
  elif [[ "$v" =~ ^[0-9]+$ ]] && (( 10#$v <= 4 )); then
    result PASS ssh "MaxAuthTries $v"
  elif [[ "$v" =~ ^[0-9]+$ ]]; then
    result WARN ssh "MaxAuthTries $v (CIS recommends 4 or less)"
  else
    result WARN ssh "MaxAuthTries has an unrecognized value"
  fi
}

# ------------------------------------------------------------ sudoers
check_sudoers() {
  local main dir f files=() details=() hits=0 unreadable=0 n line
  main=$(p /etc/sudoers)
  dir=$(p /etc/sudoers.d)
  if [[ ! -e "$main" && ! -d "$dir" ]]; then
    result WARN sudo "no /etc/sudoers found (sudo not installed?)"
    return
  fi
  [[ -e "$main" ]] && files+=("$main")
  if [[ -d "$dir" && ! -L "$dir" ]]; then
    if [[ -r "$dir" && -x "$dir" ]]; then
      for f in "$dir"/*; do
        [[ -e "$f" ]] || continue
        # sudo skips names ending in ~ or containing a dot.
        case "${f##*/}" in *~|*.*) continue ;; esac
        files+=("$f")
      done
    else
      unreadable=1
    fi
  fi
  for f in "${files[@]}"; do
    if ! readable "$f"; then unreadable=1; continue; fi
    n=$(grep -cE '^[^#]*NOPASSWD[[:space:]]*:' "$f" || true)
    (( n > 0 )) || continue
    hits=$((hits + n))
    details+=("${f#"$AUDIT_ROOT"}: $n NOPASSWD")
    while IFS= read -r line; do
      details+=("  line ${line:0:160}")
    done < <(grep -nE '^[^#]*NOPASSWD[[:space:]]*:' "$f" | head -n 5)
  done
  if (( hits > 0 )); then
    result WARN sudo "$hits NOPASSWD sudoers entries (passwordless sudo; review each one)"
    for line in "${details[@]}"; do detail "$line"; done
    (( unreadable )) && detail "some sudoers files not readable as $(id -un); run as root"
  elif (( unreadable )); then
    result WARN sudo "some sudoers files not readable as $(id -un); run as root"
  else
    result PASS sudo "no NOPASSWD entries in sudoers"
  fi
  return 0
}

# ----------------------------------------------------------- firewall
# Status queries only. Never enable, reload, or add rules.
check_firewall() {
  local out active="" checked=0
  if [[ -n "$AUDIT_ROOT" ]]; then
    result WARN firewall "skipped: live firewall state cannot be read from EU_AUDIT_ROOT"
    return
  fi
  if command -v ufw >/dev/null 2>&1; then
    checked=1
    out=$(ufw status 2>/dev/null || true)
    if grep -qx 'Status: active' <<< "$out"; then active="ufw"; fi
  fi
  if [[ -z "$active" ]] && command -v firewall-cmd >/dev/null 2>&1; then
    checked=1
    out=$(firewall-cmd --state 2>/dev/null || true)
    [[ "$out" == running ]] && active="firewalld"
  fi
  if [[ -z "$active" ]] && command -v nft >/dev/null 2>&1; then
    checked=1
    out=$(nft list ruleset 2>/dev/null || true)
    if grep -qE 'hook[[:space:]]+input' <<< "$out"; then active="nftables (input hook present)"; fi
  fi
  if [[ -n "$active" ]]; then
    result PASS firewall "host firewall active: $active"
  elif (( checked )) && [[ "$(id -u)" -ne 0 ]]; then
    result WARN firewall "no active firewall seen as $(id -un); status queries usually need root"
  elif (( checked )); then
    result FAIL firewall "no active host firewall (ufw inactive, firewalld not running, no nftables input chain)"
  else
    result WARN firewall "none of ufw, firewall-cmd, or nft found; check the firewall another way"
  fi
}

# ------------------------------------------------- world-writable files
check_world_writable() {
  local d dirs=(/etc /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin) found=() path seen_real
  local -A seen=()
  for d in "${dirs[@]}"; do
    path=$(p "$d")
    [[ -d "$path" && ! -L "$path" ]] || continue
    # /bin -> /usr/bin on merged-/usr systems: do not scan the same tree twice.
    seen_real=$(cd "$path" && pwd -P)
    [[ -n "${seen[$seen_real]:-}" ]] && continue
    seen[$seen_real]=1
    while IFS= read -r -d '' f; do
      found+=("${f#"$AUDIT_ROOT"}")
    done < <(find "$path" -xdev \( \( -type f -perm -0002 \) -o \( -type d -perm -0002 ! -perm -1000 \) \) -print0 2>/dev/null || true)
  done
  if (( ${#found[@]} == 0 )); then
    result PASS perms "no world-writable files (or non-sticky world-writable dirs) in ${dirs[*]}"
  else
    result FAIL perms "${#found[@]} world-writable path(s) in key directories"
    local i
    for ((i = 0; i < ${#found[@]} && i < MAX_LIST; i++)); do detail "${found[i]}"; done
    (( ${#found[@]} > MAX_LIST )) && detail "... $(( ${#found[@]} - MAX_LIST )) more"
  fi
  return 0
}

# ------------------------------------------------- automatic updates
check_auto_updates() {
  local f v
  f=$(p /etc/apt/apt.conf.d/20auto-upgrades)
  if [[ -d "$(p /etc/apt)" ]]; then
    v=""
    if [[ -d "$(p /etc/apt/apt.conf.d)" ]]; then
      v=$(cat "$(p /etc/apt/apt.conf.d)"/* 2>/dev/null \
        | sed -nE 's#^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+"([0-9]+)"[[:space:]]*;.*#\1#p' | tail -n 1 || true)
    fi
    if [[ -n "$v" && "$v" != 0 ]]; then
      result PASS updates "unattended-upgrades enabled (Unattended-Upgrade setting $v)"
    elif [[ -n "$v" ]]; then
      result WARN updates "unattended-upgrades disabled (Unattended-Upgrade setting 0)"
    else
      result WARN updates "unattended-upgrades not configured (${f#"$AUDIT_ROOT"} missing or no Unattended-Upgrade setting)"
    fi
    return
  fi
  f=$(p /etc/dnf/automatic.conf)
  if [[ -e "$f" ]]; then
    local timer=""
    if [[ -z "$AUDIT_ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
      for t in dnf-automatic.timer dnf-automatic-install.timer dnf5-automatic.timer; do
        if systemctl is-enabled --quiet "$t" 2>/dev/null; then timer=$t; break; fi
      done
    fi
    if readable "$f" && grep -qiE '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)' "$f" && [[ -n "$timer" || -n "$AUDIT_ROOT" ]]; then
      result PASS updates "dnf-automatic applies updates${timer:+ ($timer enabled)}"
    else
      result WARN updates "dnf-automatic present but not applying updates on a timer"
    fi
    return
  fi
  result WARN updates "no unattended-upgrades or dnf-automatic configuration found"
}

# ------------------------------------------------------------- auditd
check_auditd() {
  local state
  if [[ -n "$AUDIT_ROOT" ]]; then
    if [[ -e "$(p /etc/audit/auditd.conf)" ]]; then
      result WARN auditd "auditd configured in EU_AUDIT_ROOT; service state cannot be read offline"
    else
      result FAIL auditd "auditd not installed (no /etc/audit/auditd.conf)"
    fi
    return
  fi
  if command -v systemctl >/dev/null 2>&1; then
    state=$(systemctl is-active auditd 2>/dev/null || true)
    if [[ "$state" == active ]]; then
      result PASS auditd "auditd service active"
      return
    fi
  fi
  if [[ -e /etc/audit/auditd.conf ]] || command -v auditctl >/dev/null 2>&1; then
    result FAIL auditd "auditd installed but not active${state:+ (systemctl: $state)}"
  else
    result FAIL auditd "auditd not installed"
  fi
}

# ------------------------------------------------------ password aging
check_password_aging() {
  local f max min warn
  f=$(p /etc/login.defs)
  if ! readable "$f"; then
    result WARN aging "/etc/login.defs not found or not readable"
    return
  fi
  max=$(awk '$1 == "PASS_MAX_DAYS" {v = $2} END {print v}' "$f")
  min=$(awk '$1 == "PASS_MIN_DAYS" {v = $2} END {print v}' "$f")
  warn=$(awk '$1 == "PASS_WARN_AGE" {v = $2} END {print v}' "$f")
  if [[ "$max" =~ ^[0-9]+$ ]] && (( 10#$max <= 365 )); then
    result PASS aging "PASS_MAX_DAYS $max"
  else
    result WARN aging "PASS_MAX_DAYS ${max:-unset} (CIS recommends 365 or less)"
  fi
  if [[ "$min" =~ ^[0-9]+$ ]] && (( 10#$min >= 1 )); then
    result PASS aging "PASS_MIN_DAYS $min"
  else
    result WARN aging "PASS_MIN_DAYS ${min:-unset} (CIS recommends 1 or more)"
  fi
  if [[ "$warn" =~ ^[0-9]+$ ]] && (( 10#$warn >= 7 )); then
    result PASS aging "PASS_WARN_AGE $warn"
  else
    result WARN aging "PASS_WARN_AGE ${warn:-unset} (CIS recommends 7 or more)"
  fi
}

check_ssh
check_sudoers
check_firewall
check_world_writable
check_auto_updates
check_auditd
check_password_aging

SUMMARY="PASS=${PASS_N} WARN=${WARN_N} FAIL=${FAIL_N}"
REDACTED=$(redact < "$FINDINGS")
{
  echo "# Hardening audit $(iso_date)"
  echo "# Host: ${HOST} User: $(id -un) Role: ${ROLE}${AUDIT_ROOT:+ Root: EU_AUDIT_ROOT}"
  echo "# Read-only. Nothing was changed. Redacted."
  echo ""
  printf '%s\n' "$REDACTED"
  echo ""
  echo "# Summary: ${SUMMARY}"
}

if [[ "$NO_REPORT" == yes ]]; then
  echo "[hardening] EU_AUDIT_NO_REPORT=yes: no report written"
else
  OUT="reports/${ROLE}-hardening-audit-${HOST}-${TS}.txt"
  JSON="reports/${ROLE}-hardening-audit-${HOST}-${TS}.json"
  prepare_reports_dir reports
  TMPTXT=$(mktemp reports/.hardening.XXXXXX)
  TMPJSON=$(mktemp reports/.hardeningjson.XXXXXX)
  {
    echo "# Hardening audit $(iso_date)"
    echo "# Host: ${HOST} User: $(id -un) Role: ${ROLE}"
    echo "# Read-only. Nothing was changed. Redacted excerpts only; review before sharing."
    echo ""
    printf '%s\n' "$REDACTED"
    echo ""
    echo "# Summary: ${SUMMARY}"
  } > "$TMPTXT"
  cat > "$TMPJSON" << JSONEOF
{
  "timestamp": "$(iso_date)",
  "host": "$(json_escape "$HOST")",
  "user": "$(json_escape "$(id -un)")",
  "role": "$(json_escape "$ROLE")",
  "report": "$(json_escape "$(basename "$OUT")")",
  "pass": ${PASS_N},
  "warn": ${WARN_N},
  "fail": ${FAIL_N},
  "notes": "Read-only hardening audit. Redacted. Review before sharing."
}
JSONEOF
  mv -f "$TMPTXT" "$OUT"
  mv -f "$TMPJSON" "$JSON"
  TMPTXT="" TMPJSON=""
  chmod 600 "$OUT" "$JSON"
  echo "[hardening] wrote $OUT"
  echo "[hardening] wrote $JSON"
fi

if [[ "${EU_AUDIT_FAIL_ON:-}" == fail ]] && (( FAIL_N > 0 )); then
  exit 2
fi
exit 0
