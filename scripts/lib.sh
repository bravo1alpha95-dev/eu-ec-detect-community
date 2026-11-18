#!/usr/bin/env bash
# Shared helpers; sourced by the other scripts, not run directly.
umask 077
# Stable command output and byte-oriented redaction/JSON escaping.
export LC_ALL=C

# Portable ISO 8601 UTC timestamp. POSIX date only: GNU `date -Is` does not exist on
# macOS/BSD, and UTC keeps reports from different hosts comparable.
iso_date() {
  date -u +%Y-%m-%dT%H:%M:%SZ
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
    if [[ "$key" =~ ^(EU_[A-Z0-9_]+|ROLE)$ && "$val" =~ ^[A-Za-z0-9._/:@+,-]*$ && ${#val} -le 256 ]]; then
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

# file_mode FILE: octal permission bits, GNU stat (-c) or BSD/macOS stat (-f).
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

# Every loader validates the same permissions, not only preflight.
env_file_ok() {
  local perms
  [[ -f "$1" && ! -L "$1" && -O "$1" ]] || return 1
  perms=$(file_mode "$1") || return 1
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

# ---------- CIDR math and network isolation (IPv4 + IPv6, pure bash) ----------
# Replaces substring/regex matching on `ip route` text, which gave false
# positives (192.0.20.0/24 "matches" the text 192.0.2.) and missed real overlaps
# (10.0.0.0/8 overlaps 10.20.0.0/16 without sharing a text prefix).

# Helpers return results in globals (_EU_BITS, _EU_LEN) instead of $(...) so the
# route/address loops do not fork once per octet.
_EU_NIB=(0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111)

# _eu_hex_bits HEX WIDTH: append HEX (zero-padded to WIDTH bits) to _EU_BITS.
_eu_hex_bits() {
  local h=$1 i
  while (( ${#h} * 4 < $2 )); do h=0$h; done
  for (( i = 0; i < ${#h}; i++ )); do _EU_BITS+=${_EU_NIB[16#${h:i:1}]}; done
}

# _eu_ip_bits ADDR: set _EU_BITS to 32 (IPv4) or 128 (IPv6) bits; non-zero if invalid.
_eu_ip_bits() {
  local a=$1 g i n head tail hex
  local -a hg=() tg=() groups=() v4=()
  _EU_BITS=""
  if [[ "$a" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for i in 1 2 3 4; do
      n=$(( 10#${BASH_REMATCH[i]} ))
      (( n <= 255 )) || return 1
      printf -v hex '%02x' "$n"
      _eu_hex_bits "$hex" 8
    done
    return 0
  fi
  [[ "$a" == *:* && "$a" =~ ^[0-9A-Fa-f:.]+$ && "$a" != *:::* ]] || return 1
  if [[ "$a" =~ ^(.*:)([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    head=${BASH_REMATCH[1]}
    for i in 2 3 4 5; do
      n=$(( 10#${BASH_REMATCH[i]} ))
      (( n <= 255 )) || return 1
      v4+=("$n")
    done
    printf -v a '%s%x:%x' "$head" "$(( v4[0] * 256 + v4[1] ))" "$(( v4[2] * 256 + v4[3] ))"
  fi
  [[ "$a" != *.* ]] || return 1
  if [[ "$a" == *::* ]]; then
    head=${a%%::*}
    tail=${a#*::}
    [[ "$tail" != *::* ]] || return 1
    [[ -z "$head" ]] || IFS=: read -r -a hg <<< "$head"
    [[ -z "$tail" ]] || IFS=: read -r -a tg <<< "$tail"
    n=$(( 8 - ${#hg[@]} - ${#tg[@]} ))
    (( n >= 1 )) || return 1
    groups=("${hg[@]}")
    for (( i = 0; i < n; i++ )); do groups+=(0); done
    groups+=("${tg[@]}")
  else
    [[ "$a" != :* && "$a" != *: ]] || return 1
    IFS=: read -r -a groups <<< "$a"
  fi
  (( ${#groups[@]} == 8 )) || return 1
  for g in "${groups[@]}"; do
    [[ "$g" =~ ^[0-9A-Fa-f]{1,4}$ ]] || { _EU_BITS=""; return 1; }
    _eu_hex_bits "$g" 16
  done
}

# _eu_cidr CIDR: set _EU_LEN and _EU_BITS (a bare address is a host prefix). "default"
# is not accepted here; callers handle it.
_eu_cidr() {
  local c=$1 len
  _eu_ip_bits "${c%%/*}" || return 1
  if [[ "$c" == */* ]]; then
    len=${c#*/}
    [[ "$len" =~ ^[0-9]{1,3}$ ]] || return 1
    len=$(( 10#$len ))
    (( len <= ${#_EU_BITS} )) || return 1
  else
    len=${#_EU_BITS}
  fi
  _EU_LEN=$len
}

# cidr_valid CIDR: 0 if CIDR (or bare address) parses as IPv4 or IPv6.
cidr_valid() { _eu_cidr "$1"; }

# cidr_overlap A B: 0 if the two ranges share any address, 1 if not (or different
# address families), 2 if either is invalid.
cidr_overlap() {
  local a pa p
  _eu_cidr "$1" || return 2
  a=$_EU_BITS pa=$_EU_LEN
  _eu_cidr "$2" || return 2
  (( ${#a} == ${#_EU_BITS} )) || return 1
  p=$(( pa < _EU_LEN ? pa : _EU_LEN ))
  [[ "${a:0:p}" == "${_EU_BITS:0:p}" ]]
}

# cidr_contains NET X: 0 if every address of X (CIDR or bare address) is inside NET.
cidr_contains() {
  local a pa
  _eu_cidr "$1" || return 2
  a=$_EU_BITS pa=$_EU_LEN
  _eu_cidr "$2" || return 2
  (( ${#a} == ${#_EU_BITS} && _EU_LEN >= pa )) || return 1
  [[ "${a:0:pa}" == "${_EU_BITS:0:pa}" ]]
}

# cidr_list_contains LIST X: LIST is comma- or space-separated CIDRs.
cidr_list_contains() {
  local net
  for net in ${1//,/ }; do cidr_contains "$net" "$2" && return 0; done
  return 1
}

# cidr_list_overlaps LIST X: 0 if X overlaps any CIDR in LIST.
cidr_list_overlaps() {
  local net
  for net in ${1//,/ }; do cidr_overlap "$net" "$2" && return 0; done
  return 1
}

# _eu_skip_addr CIDR: loopback, IPv6 link-local and multicast never leave the host/link.
_eu_skip_addr() {
  cidr_contains 127.0.0.0/8 "$1" || cidr_contains ::1/128 "$1" ||
    cidr_contains fe80::/10 "$1" || cidr_contains ff00::/8 "$1" || cidr_contains 224.0.0.0/4 "$1"
}

# Interface names used by common VPN and overlay clients.
EU_VPN_IF_RE='^(tun|tap|wg|tailscale|zt|ppp|ipsec|vti|utun|nordlynx|proton|cscotun|gpd|mullvad|tun2socks)'

# eu_host_addrs: "DEV CIDR" for each address on the host (Linux `ip`); non-zero if unavailable.
eu_host_addrs() {
  command -v ip >/dev/null 2>&1 || return 1
  ip -o addr show 2>/dev/null | awk '$3 == "inet" || $3 == "inet6" {sub(/@.*/, "", $2); print $2, $4}'
}

# eu_routes: "DEST VIA DEV" per route (VIA "-" when directly connected); blackhole,
# unreachable, prohibit and throw routes are dropped because they cannot carry traffic.
eu_routes() {
  command -v ip >/dev/null 2>&1 || return 1
  { ip -4 route show 2>/dev/null; ip -6 route show 2>/dev/null; } | awk '
    function emit(d, line,   i, n, f, via, dev) {
      n = split(line, f, /[ \t]+/); via = "-"; dev = "-"
      for (i = 1; i < n; i++) { if (f[i] == "via") via = f[i + 1]; if (f[i] == "dev") dev = f[i + 1] }
      if (via == "inet6" || via == "inet") { for (i = 1; i < n; i++) if (f[i] == "via") via = f[i + 2] }
      print d, via, dev
    }
    /^[ \t]+nexthop/ { if (dest != "") emit(dest, $0); next }
    {
      t = $1
      if (t ~ /^(blackhole|unreachable|prohibit|throw)$/) { dest = ""; next }
      if (t ~ /^(unicast|local|broadcast|multicast|anycast|nat)$/) { sub(/^[^ \t]+[ \t]+/, ""); }
      dest = $1
      if ($0 ~ / (via|dev) /) emit(dest, $0)
    }'
}

# eu_isolation_check LAB_CIDRS [PROTECTED_CIDRS]: fail-closed lab isolation test.
# Prints one "[isolation] FAIL: ..." line per problem (interface names only; no
# addresses, since stdout often ends up in cron mail or CI logs) and returns 1 if any.
eu_isolation_check() {
  local lab=$1 prot=${2:-} fails=0 in_lab=0 dev cidr dest via net addrs routes
  for net in ${lab//,/ } ${prot//,/ }; do
    cidr_valid "$net" || { echo "[isolation] FAIL: invalid CIDR in EU_LAB_CIDRS/EU_PROTECTED_CIDRS"; return 1; }
  done
  [[ -n "${lab//[, ]/}" ]] || { echo "[isolation] FAIL: no lab CIDRs configured (EU_LAB_CIDRS)"; return 1; }
  addrs=$(eu_host_addrs) || { echo "[isolation] FAIL: cannot list addresses (Linux 'ip' not found); isolation unverified"; return 1; }
  routes=$(eu_routes) || { echo "[isolation] FAIL: cannot list routes (Linux 'ip' not found); isolation unverified"; return 1; }
  while read -r dev cidr; do
    [[ -n "$cidr" ]] || continue
    cidr_valid "$cidr" || { echo "[isolation] FAIL: unparseable address on $dev"; fails=$((fails + 1)); continue; }
    _eu_skip_addr "$cidr" && continue
    if [[ "$dev" =~ $EU_VPN_IF_RE ]]; then
      echo "[isolation] FAIL: VPN/overlay interface $dev is up with an address"; fails=$((fails + 1))
    elif cidr_list_contains "$lab" "${cidr%%/*}"; then
      in_lab=1
    else
      echo "[isolation] FAIL: interface $dev has an address outside the lab CIDRs (LAN/VPN/production leg)"; fails=$((fails + 1))
    fi
  done <<< "$addrs"
  (( in_lab )) || { echo "[isolation] FAIL: no interface address inside the lab CIDRs"; fails=$((fails + 1)); }
  while read -r dest via dev; do
    [[ -n "$dest" ]] || continue
    if [[ "$dev" =~ $EU_VPN_IF_RE ]]; then
      echo "[isolation] FAIL: route via VPN/overlay interface $dev"; fails=$((fails + 1)); continue
    fi
    if [[ "$dest" == default ]]; then
      if [[ "$via" == - ]] || ! cidr_list_contains "$lab" "$via"; then
        echo "[isolation] FAIL: default route on $dev does not use a lab gateway"; fails=$((fails + 1))
      fi
      continue
    fi
    cidr_valid "$dest" || { echo "[isolation] FAIL: unparseable route on $dev"; fails=$((fails + 1)); continue; }
    _eu_skip_addr "$dest" && continue
    if [[ -n "${prot//[, ]/}" ]] && cidr_list_overlaps "$prot" "$dest"; then
      echo "[isolation] FAIL: route on $dev overlaps EU_PROTECTED_CIDRS"; fails=$((fails + 1)); continue
    fi
    if [[ "$via" != - ]] && ! cidr_list_contains "$lab" "$via"; then
      echo "[isolation] FAIL: route on $dev uses a gateway outside the lab CIDRs"; fails=$((fails + 1))
    elif [[ "$via" == - ]] && ! cidr_list_overlaps "$lab" "$dest"; then
      echo "[isolation] FAIL: directly connected non-lab network on $dev"; fails=$((fails + 1))
    fi
  done <<< "$routes"
  (( fails == 0 ))
}

# eu_lab_cidrs: EU_LAB_CIDRS, else the lab subnets from .env (EU_HV_SUBNET,
# EU_DOCKER_SUBNET, EU_AIRGAP_SUBNET). Empty means "not configured", which fails closed.
eu_lab_cidrs() {
  local l=${EU_LAB_CIDRS:-}
  if [[ -z "$l" ]]; then
    # shellcheck disable=SC2086  # load_env limits values to a safe charset; split on purpose
    l=$(printf '%s,' ${EU_HV_SUBNET:-} ${EU_DOCKER_SUBNET:-} ${EU_AIRGAP_SUBNET:-})
    l=${l%,}
  fi
  printf '%s' "$l"
}

# _eu_log_override WHO REASON FAILURES: append one line (no addresses) to
# reports/isolation-override.log (600); a symlinked log is never followed.
_eu_log_override() {
  local log=reports/isolation-override.log
  prepare_reports_dir reports 2>/dev/null || return 0
  [[ -L "$log" || ( -e "$log" && ! -f "$log" ) ]] && { echo "[isolation] WARN: $log is not a regular file; override not logged" >&2; return 0; }
  printf '%s %s user=%s host=%s reason=%s failures=%s\n' "$(iso_date)" "$1" "$(id -un)" \
    "$(sanitize_host 2>/dev/null)" "$2" "$3" >> "$log"
  chmod 600 "$log" 2>/dev/null || true
}

# eu_isolation_gate WHO: fail closed (exit 4) unless the host proves lab isolation.
# Overrides, each announced and appended to reports/isolation-override.log:
#   EU_ENV=prod|production  owned production host; the lab gate does not apply
#   EU_ALLOW_UNISOLATED=1   run on a lab host anyway, despite the failures printed
eu_isolation_gate() {
  local who=$1 out
  case "${EU_ENV:-}" in
    prod|production)
      echo "[$who] INFO: EU_ENV=${EU_ENV}: owned production host; lab isolation gate not applied (logged)."
      _eu_log_override "$who" "EU_ENV=${EU_ENV}" 0
      return 0 ;;
  esac
  if out=$(eu_isolation_check "$(eu_lab_cidrs)" "${EU_PROTECTED_CIDRS:-}"); then
    echo "[$who] INFO: lab isolation verified (CIDR checks on every address and route)."
    return 0
  fi
  printf '%s\n' "$out"
  if [[ "${EU_ALLOW_UNISOLATED:-}" == 1 ]]; then
    echo "[$who] WARN: EU_ALLOW_UNISOLATED=1 — continuing WITHOUT verified isolation (override logged)."
    _eu_log_override "$who" EU_ALLOW_UNISOLATED=1 "$(printf '%s\n' "$out" | grep -c FAIL)"
    return 0
  fi
  echo "[$who] ERROR: isolation check failed; refusing to continue (fail closed)." >&2
  echo "[$who] Fix the interfaces/routes above or EU_LAB_CIDRS; on an owned production host set EU_ENV=prod;" >&2
  echo "[$who] to run anyway set EU_ALLOW_UNISOLATED=1 (logged)." >&2
  exit 4
}

# eu_scope_check WHO: is any host address inside EU_SCOPE_CIDR? Advisory by default;
# EU_FAIL_CLOSED=1 turns a mismatch or an unverifiable scope into exit 4.
eu_scope_check() {
  local who=$1 scope=${EU_SCOPE_CIDR:-} net dev cidr addrs ok=0 msg=""
  if [[ -z "$scope" ]]; then
    echo "[$who] INFO: EU_SCOPE_CIDR is unset. Set it in .env to document the authorized address range."
    [[ "${EU_FAIL_CLOSED:-}" == 1 ]] || return 0
    msg="EU_SCOPE_CIDR is unset"
  else
    for net in ${scope//,/ }; do cidr_valid "$net" || msg="EU_SCOPE_CIDR is not a valid CIDR list"; done
    if [[ -z "$msg" ]]; then
      if addrs=$(eu_host_addrs); then
        while read -r dev cidr; do
          if [[ -n "$cidr" ]] && cidr_valid "$cidr" && ! _eu_skip_addr "$cidr" &&
            cidr_list_contains "$scope" "${cidr%%/*}"; then
            ok=1
          fi
        done <<< "$addrs"
        (( ok )) || msg="no address on this host is inside EU_SCOPE_CIDR"
      else
        msg="cannot list host addresses (Linux 'ip' not found); scope unverified"
      fi
    fi
    if [[ -z "$msg" ]]; then
      echo "[$who] INFO: host has an address inside EU_SCOPE_CIDR."
      return 0
    fi
  fi
  if [[ "${EU_FAIL_CLOSED:-}" == 1 ]]; then
    echo "[$who] ERROR: $msg; EU_FAIL_CLOSED=1, refusing to continue." >&2
    exit 4
  fi
  echo "[$who] WARN: $msg. Confirm this host is in authorized scope (set EU_FAIL_CLOSED=1 to enforce)."
}
