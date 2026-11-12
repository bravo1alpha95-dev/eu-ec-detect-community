#!/usr/bin/env bash
# Apply layer for eu-ec-detect-community.
# Dry-run by default. Mutating steps require BOTH:
#   1. CONFIRM=yes
#   2. scope/roe.md Status: AUTHORIZED
# Safe scaffolding only: Wazuh agent install outline and local config stubs.
# Does not push packages or change firewall/SSH/sudoers without further explicit flags.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib.sh
source scripts/lib.sh

DRY_RUN=1
if [[ "${CONFIRM:-}" == "yes" ]]; then
  DRY_RUN=0
fi

echo "[apply] Mode: $( [[ $DRY_RUN -eq 1 ]] && echo DRY-RUN || echo APPLY )"
echo "[apply] Host: $(hostname) | User: $(id -un) | Date: $(iso_date)"

# ROE gate — hard fail closed for mutations
ROE_OK=0
if roe_authorized scope/roe.md; then
  ROE_OK=1
  echo "[apply] ROE Status: AUTHORIZED"
else
  echo "[apply] ROE Status: not AUTHORIZED (DRAFT, missing, or unfilled (fill) fields)"
fi

if [[ $DRY_RUN -eq 0 && $ROE_OK -eq 0 ]]; then
  echo "[apply] ERROR: CONFIRM=yes given but ROE is not AUTHORIZED. Refusing to mutate."
  echo "[apply] Edit scope/roe.md: fill every (fill) field, set Status: AUTHORIZED, then re-run."
  exit 1
fi

if [[ -L policies || ( -e policies && ! ( -d policies && -O policies ) ) ]]; then
  echo "[apply] ERROR: policies/ must be a real directory owned by $(id -un)" >&2
  exit 1
fi
prepare_reports_dir reports
mkdir -p policies
TS=$(date +%Y%m%dT%H%M%S)-$$
LOG="reports/apply-${TS}.log"
EU_LOG_TMP=$(mktemp reports/.apply.XXXXXX)
trap 'rm -f "$EU_LOG_TMP"' EXIT

{
  echo "# Apply log $TS"
  echo "# dry_run=$DRY_RUN roe_ok=$ROE_OK"
  echo ""

  echo "## Planned actions (Wazuh agent scaffolding)"
  echo "- Check if wazuh-agent is already present"
  echo "- Write a local agent config stub under policies/ (never overwrites existing production config without backup)"
  echo "- Print the official install commands for the operator to run after snapshot"
  echo "- No automatic apt/yum install, no service restart, no firewall change in this version"

  if command -v dpkg >/dev/null 2>&1; then
    echo ""
    echo "## Current wazuh package status (dpkg)"
    dpkg -l 'wazuh*' 2>/dev/null | head -10 || echo "none"
  elif command -v rpm >/dev/null 2>&1; then
    echo ""
    echo "## Current wazuh package status (rpm)"
    rpm -qa 'wazuh*' 2>/dev/null | head -10 || echo "none"
  fi

  STUB="policies/wazuh-agent-local.conf.stub"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo ""
    echo "[DRY-RUN] Would write $STUB"
  else
    if [[ -L "$STUB" || ( -e "$STUB" && ! ( -f "$STUB" && -O "$STUB" ) ) ]]; then
      echo "[apply] ERROR: unsafe stub path $STUB" >&2
      exit 1
    fi
    if [[ -f "$STUB" ]]; then
      cp -a "$STUB" "${STUB}.bak-${TS}"
      echo "[apply] Backed up existing stub"
    fi
    # Same-directory temporary file makes replacement atomic across filesystems.
    tmpstub=$(mktemp "${STUB}.XXXXXX")
    # This block runs in the tee pipeline subshell; the parent trap owns EU_LOG_TMP.
    trap 'rm -f "$tmpstub"' EXIT
    cat > "$tmpstub" << 'EOF'
# Wazuh agent local config stub — eu-ec-detect-community
# Copy relevant blocks into /var/ossec/etc/ossec.conf on the agent after install.
# Manager address must be filled by operator (lab or owned production only).

<ossec_config>
  <client>
    <server>
      <address>REPLACE_WITH_MANAGER_IP_OR_HOSTNAME</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Add FIM, syscheck, and auth log paths as needed -->
</ossec_config>
EOF
    mv -f "$tmpstub" "$STUB"
    echo "[apply] Wrote $STUB"
  fi

  echo ""
  echo "## Operator next steps (manual, after snapshot) — VERIFY ALL EXTERNAL ARTIFACTS"
  echo "CRITICAL SUPPLY-CHAIN WARNING: External downloads are a high-risk vector."
  echo "ALWAYS verify the GPG fingerprint EXACTLY before any use. Prefer offline packages or internal mirrors."
  echo "Do NOT proceed on mismatch. Never pipe install scripts to a shell."
  echo "1. Snapshot the target (recommended name: <hostname>-pre-wazuh-YYYYMMDD)."
  echo "2. On the manager: generate an agent key or use enrollment."
  echo "3. On the agent host (owned only) — ALWAYS verify the GPG fingerprint before trusting the key:"
  echo "   KEY=\$(mktemp) && curl -fsSL -o \"\$KEY\" https://packages.wazuh.com/key/GPG-KEY-WAZUH"
  echo "   gpg --show-keys --with-fingerprint \"\$KEY\""
  echo "   # Compare the fingerprint to the official value in the current Wazuh installation"
  echo "   # documentation (https://documentation.wazuh.com/). This repository does not ship a"
  echo "   # vendor fingerprint — copy it from the vendor, not from a fork or this repo."
  echo "   # If the fingerprint does not match the vendor documentation exactly, DO NOT proceed."
  echo "   # Delete the key, investigate a possible MITM or compromise, and abort."
  echo "   APT: sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \"\$KEY\""
  echo "        echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee /etc/apt/sources.list.d/wazuh.list"
  echo "        sudo apt-get update && sudo apt-get install wazuh-agent=<pinned version matching manager>"
  echo "   RPM: sudo rpm --import \"\$KEY\"; repo file with gpgcheck=1; sudo yum install wazuh-agent-<pinned version>"
  echo "   Pin the same agent version as the manager; never pipe install scripts to a shell."
  echo "   Prefer offline package caches or internal mirrors if available to further reduce external exposure."
  echo "4. Place manager address in the agent config, then systemctl enable --now wazuh-agent."
  echo "5. Confirm in manager dashboard; then enable the custom rules from the eu-wazuh-detections pack (or the examples in policies/wazuh-anomaly-rules.md)."
  echo ""
  echo "[apply] No packages installed, no services restarted, no network changes made."
  echo "[apply] External downloads require manual fingerprint verification to mitigate supply-chain risk. See SECURITY.md."
} | tee "$EU_LOG_TMP"
mv -f "$EU_LOG_TMP" "$LOG"

echo "[apply] Log: $LOG"
echo "[apply] Done. $( [[ $DRY_RUN -eq 1 ]] && echo 'Dry-run only.' || echo 'Apply completed (scaffolding only).' )"
