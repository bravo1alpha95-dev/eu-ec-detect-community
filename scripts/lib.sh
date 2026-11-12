#!/usr/bin/env bash
# Shared helpers; sourced by the other scripts, not run directly.
umask 077
# Stable command output and byte-oriented redaction/JSON escaping.
export LC_ALL=C

# Portable ISO-like timestamp (prefers GNU -Is, falls back to common format).
iso_date() {
  if date -Is >/dev/null 2>&1; then
    date -Is
  else
    # BSD/macOS and many others
    date +%Y-%m-%dT%H:%M:%S%z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ
  fi
}

# Parse .env as data (never `source` it): only KEY=value lines with a safe
# value charset are accepted, and nothing is exported to child processes.
# Residual risk: if an attacker controls the account, they can still read .env.
load_env() {
  local file=$1 key val
  if [[ "$file" == .env.example || "$file" == */.env.example ]]; then
    [[ -f "$file" && ! -L "$file" && -O "$file" ]] || return 1
  else
    env_file_ok "$file" || { echo "[env] ERROR: $file must be an owned regular file with mode 600 or 400" >&2; return 1; }
  fi
  while IFS='=' read -r key val || [[ -n "$key" ]]; do
    # Trim leading/trailing whitespace on key
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ -z "$key" || "$key" == \#* || ${#key} -gt 64 || ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && continue
    # Strip trailing inline comments and all whitespace from value; reject dangerous chars
    val="${val%%#*}"
    val="${val//[[:space:]]/}"
    # Reject shell metacharacters that could be dangerous if ever evaluated
    if [[ "$val" =~ [\$\`\;\|\&\<\>\(\)\{\}\[\]\\] ]]; then
      echo "[env] ignoring line with shell metacharacters for key '${key//[^A-Za-z0-9_]/?}' in $file" >&2
      continue
    fi
    if [[ "$key" =~ ^(EU_[A-Z0-9_]+|ROLE)$ && "$val" =~ ^[A-Za-z0-9._/:@+-]*$ && ${#val} -le 256 ]]; then
      printf -v "$key" '%s' "$val"
    else
      echo "[env] ignoring malformed or oversized line for key '${key//[^A-Za-z0-9_]/?}' in $file" >&2
    fi
  done < "$file"
}

# Redaction requires GNU sed (case-insensitive I flag and word boundaries).
# Handles private keys, JWTs, AWS, emails, IPs (v4/v6), hashes, password-like, Azure, generic high-entropy.
# Residual risk: not exhaustive; custom secrets or obfuscated data may leak.
# Always review reports/ before sharing externally.
# Over-redaction preferred.
redact() {
  awk '
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/ {
      print "[PRIVATE KEY REDACTED]"
      inkey = !/-----END [A-Z ]*PRIVATE KEY-----/
      next
    }
    inkey {
      if (/-----END [A-Z ]*PRIVATE KEY-----/) inkey = 0
      next
    }
    { print }
  ' | sed -E \
    -e 's/"([A-Za-z0-9_-]*(password|passwd|token|key|secret|authorization|session|cookie)[A-Za-z0-9_-]*)"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"/"\1":"REDACTED"/Ig' \
    -e 's/(password|passwd|token|key|secret|authorization|session|cookie|api[_-]?key|bearer|credential|auth)[[:space:]]*[=:][[:space:]]*((bearer|basic)[[:space:]]+)?("[^"]*"|'\''[^'\'']*'\''|[^[:space:]",]+)/\1=REDACTED/Ig' \
    -e 's#([a-z][a-z0-9+.-]*://)[^/@[:space:]]+@#\1REDACTED@#Ig' \
    -e '/mysql|mariadb/ s/(^|[[:space:]])-p("[^"]*"|'\''[^'\'']*'\''|[^[:space:]]+)/\1-pREDACTED/g' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/EMAIL_REDACTED/g' \
    -e 's/(^|[^0-9A-Fa-f:])([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}([^0-9A-Fa-f:]|$)/\1MAC_REDACTED\3/g' \
    -e 's/[0-9A-Fa-f:]*::[0-9A-Fa-f:]*([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f:]*::[0-9A-Fa-f:]*|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/IP6_REDACTED/g' \
    -e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/IP_REDACTED/g' \
    -e 's/[0-9A-Fa-f]{32,}/HASH_OR_KEY_REDACTED/g' \
    -e 's#(SHA256|MD5|SHA1):[A-Za-z0-9+/=:]+#\1:FPR_REDACTED#g' \
    -e 's/AKIA[0-9A-Z]{16}/AWS_ACCESS_KEY_REDACTED/g' \
    -e 's/[A-Za-z0-9/+=]{40}/AWS_SECRET_LIKE_REDACTED/g' \
    -e 's/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/JWT_REDACTED/g' \
    -e 's/(-----BEGIN [A-Z ]+-----).*(-----END [A-Z ]+-----)/\1 REDACTED \2/g' \
    -e 's/(sk_live_|sk_test_|rk_live_|rk_test_)[A-Za-z0-9]+/STRIPE_KEY_REDACTED/g' \
    -e 's/(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}/GITHUB_TOKEN_REDACTED/g' \
    -e 's/xox[baprs]-[A-Za-z0-9-]{10,}/SLACK_TOKEN_REDACTED/g' \
    -e 's/(^|[^A-Za-z0-9_])(sk-|rk-|pk_live_|pk_test_)[A-Za-z0-9_-]+/\1STRIPE_OR_SIMILAR_KEY_REDACTED/g' \
    -e 's/[A-Za-z0-9+/]{40,}={0,2}/BASE64_LIKE_REDACTED/g' \
    -e 's/(Bearer|Token|Authorization)[[:space:]]+[A-Za-z0-9._-]{20,}/AUTH_HEADER_REDACTED/Ig' \
    -e 's/(AIza|ya29\.)[A-Za-z0-9_-]{20,}/GOOGLE_KEY_REDACTED/g' \
    -e 's/AccountKey=[A-Za-z0-9+/=]{20,}/AZURE_KEY_REDACTED/g' \
    -e 's/(client_secret|refresh_token)[=:][[:space:]]*[A-Za-z0-9._-]{10,}/\1=REDACTED/Ig' \
    -e 's/(ASIA|AIDA|AROA)[0-9A-Z]{16}/AWS_STS_KEY_REDACTED/g' \
    -e 's/xoxp-[A-Za-z0-9-]+/SLACK_USER_TOKEN_REDACTED/g' \
    -e 's/(discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/DISCORD_WEBHOOK_REDACTED/Ig' \
    -e 's/[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/DISCORD_TOKEN_REDACTED/g' \
    -e 's/(cf_|cloudflare_)[A-Za-z0-9_-]{20,}/CLOUDFLARE_KEY_REDACTED/Ig' \
    -e 's/dop_v1_[A-Za-z0-9]{64}/DIGITALOCEAN_TOKEN_REDACTED/g' \
    -e 's/heroku_[0-9a-f]{32}/HEROKU_KEY_REDACTED/g' \
    -e 's/(api[_-]?key|apikey)[[:space:]]*[=:][[:space:]]*[A-Za-z0-9_-]{20,}/API_KEY_REDACTED/Ig'
  # Note: over-redaction is preferred for external sharing. Review reports/ before external use.
  # Residual: obfuscated, custom, or split secrets may remain. Never share unreviewed reports.
}

# Portable checksum verification (GNU sha256sum or BSD shasum).
# Usage: verify_checksum file expected.sha256
# Returns 0 if ok, non-zero otherwise.
# Assumes sumfile is in same directory as file.
verify_checksum() {
  local file=$1 sumfile=$2
  local filedir sumdir expected actual base
  filedir=$(dirname "$file")
  sumdir=$(dirname "$sumfile")
  base=$(basename "$file")
  if [[ "$filedir" != "$sumdir" ]]; then
    echo "[checksum] ERROR: file and sumfile must be in same directory" >&2
    return 1
  fi
  if [[ ! -f "$file" || ! -f "$sumfile" || -L "$file" || -L "$sumfile" ]]; then
    echo "[checksum] ERROR: missing or symlink file/sum" >&2
    return 1
  fi
  # Hash the requested file, never arbitrary paths named by an untrusted sidecar.
  # Accept only the single record emitted for this baseline (text or binary mode).
  expected=$(< "$sumfile")
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum < "$file") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 < "$file") || return 1
  else
    echo "[checksum] ERROR: no sha256sum or shasum available" >&2
    return 1
  fi
  actual=${actual%% *}
  [[ "$expected" == "$actual  $base" || "$expected" == "$actual *$base" ]]
}

# Every loader validates the same permissions, not only preflight.
env_file_ok() {
  local perms
  [[ -f "$1" && ! -L "$1" && -O "$1" ]] || return 1
  perms=$(stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null) || return 1
  [[ "$perms" == 600 || "$perms" == 400 ]]
}

# Validate existing paths before mkdir/chmod; refuse symlinks (including dangling).
prepare_reports_dir() {
  local dir=$1
  if [[ -L "$dir" || ( -e "$dir" && ! ( -d "$dir" && -O "$dir" ) ) ]]; then
    echo "[eu] ERROR: $dir must be a real directory owned by $(id -un)" >&2
    return 1
  fi
  mkdir -p "$dir" || return 1
  [[ -d "$dir" && ! -L "$dir" && -O "$dir" ]] || return 1
  chmod 700 "$dir"
}

roe_authorized() {
  local roe=$1 f v
  [[ -f "$roe" && ! -L "$roe" ]] || return 1
  [[ $(grep -c '^Status:' "$roe") -eq 1 ]] && grep -qx 'Status: AUTHORIZED' "$roe" && ! grep -q '(fill)' "$roe" || return 1
  for f in 'Authorizer / program' 'Written permission location' 'Window (start / end, timezone)' 'Contact' 'Operator' 'Date'; do
    v=$(awk -v k="- $f:" 'index($0, k) == 1 {n++; v = substr($0, length(k) + 1)} END {gsub(/^[ \t]+|[ \t]+$/, "", v); print v; exit n != 1}' "$roe") || return 1
    case "${v,,}" in '' | tbd | *'(fill)'*) return 1 ;; esac
  done
}

# Consistent hostname sanitization to prevent unexpected characters in filenames/reports.
# Returns sanitized short hostname or INVALID_HOST.
sanitize_host() {
  local h
  h=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")
  h="${h//[^A-Za-z0-9._-]/}"
  h="${h:0:64}"
  if [[ -n "$h" && "$h" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf '%s' "$h"
  else
    echo "[host] WARN: unexpected or empty hostname characters, using INVALID_HOST" >&2
    printf 'INVALID_HOST'
  fi
}

# Sanitize a name component used in filenames (ROLE, etc.) to block path traversal
# and unexpected characters. Defaults to safe fallback. No leading dots, no '..'.
sanitize_name() {
  local n=${1:-ops}
  n="${n//[^A-Za-z0-9._-]/}"
  n="${n:0:32}"
  # Reject empty, starting with ., or containing ..
  if [[ -n "$n" && "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ && "$n" != *..* ]]; then
    printf '%s' "$n"
  else
    echo "[name] WARN: unsafe or empty name component, falling back to 'ops'" >&2
    printf 'ops'
  fi
}

# Escape every JSON control byte; Bash strings cannot contain NUL.
json_escape() {
  local s=$1 out="" c escaped i
  for ((i=0; i<${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      '"') out+='\"' ;;
      \\) out+="\\\\" ;;
      [[:cntrl:]]) printf -v escaped '\\u%04x' "'$c"; out+=$escaped ;;
      *) out+=$c ;;
    esac
  done
  printf '%s' "$out"
}
