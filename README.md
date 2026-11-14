# eu-ec-detect-community

Community edition of EmpowerU LLC's defensive access-monitoring and evidence-collection toolkit.

**Purpose:** Baseline and ongoing monitoring of access (users, logins, SSH, sudo, listeners, auth events) on **systems you own**, with structured, redacted evidence suitable for reporting, audit, and anomaly-detection foundations.

**Defensive only. Owned systems only. Read-only by default.** This toolkit does not target third-party systems, and it does not include offensive techniques.

This is a cleaned public-ready snapshot of the operator toolkit. It is not a managed service, a certification, or a substitute for your own authorization and review.

## Related projects

| Project | What it is |
|---|---|
| [eu-wazuh-detections](https://github.com/bravo1alpha95-dev/eu-wazuh-detections) | Wazuh custom rules and a starter dashboard derived from these detections |
| [eu-monitor-installer](https://github.com/bravo1alpha95-dev/eu-monitor-installer) | Docker Compose and Ansible installer (dry-run by default) |
| [eu-security-site](https://github.com/bravo1alpha95-dev/eu-security-site) | Documentation site that links the three tools |

## Standards this toolkit keeps

- Dry-run by default. Collection and preflight are read-only.
- Any mutation requires **both** `CONFIRM=yes` **and** a completed Rules of Engagement (ROE) file with `Status: AUTHORIZED`.
- Scripts are idempotent: re-running a completed apply does not blindly overwrite without a backup.
- Configuration uses `EU_*` names. No secrets are hardcoded. `.env` is parsed as data and is never sourced as a shell script.
- Report directories are mode `700`, report files are mode `600`, and redaction runs before evidence is written.
- Fail closed on ROE, permissions, ownership, and symlinks.

## Quick start

See **[EASY-STEPS.md](EASY-STEPS.md)** for the lowest-effort path.

```bash
cp .env.example .env && chmod 600 .env
# Edit .env: set EU_SCOPE_CIDR to the authorized range of systems you own
# (the 10.0.0.0/24 value in .env.example is a placeholder).
# Edit scope/inventory.md and scope/roe.md for your environment.
# Collection is read-only and does not require AUTHORIZED status.
./scripts/easy-run.sh
```

That single command runs preflight, a full access-evidence collection, and a short summary. Nothing on the host is changed.

Set `Status: AUTHORIZED` in `scope/roe.md` only after every `(fill)` field is completed and you have written authorization to operate on those systems. The apply script (`scripts/20_apply.sh`) refuses to mutate otherwise, even if `CONFIRM=yes` is set.

## What each script does

| Script | Role |
|---|---|
| `scripts/easy-run.sh` | One-command path: preflight + collect + summary |
| `scripts/00_preflight.sh` | Checks tools, permissions, `.env`, and ROE; creates `reports/` |
| `scripts/10_collect.sh` | Read-only evidence collection (users, listeners, logins, SSH/sudo excerpts) |
| `scripts/anomaly-checks.sh` | Compares current listeners to a per-host baseline with a checksum sidecar |
| `scripts/hardening-audit.sh` | Read-only CIS-style hardening audit (SSH, sudoers, firewall, permissions, updates, auditd, password aging) with PASS / WARN / FAIL output |
| `scripts/20_apply.sh` | Dry-run scaffolding for a Wazuh agent; mutates only with `CONFIRM=yes` and a valid ROE |
| `scripts/lib.sh` | Shared helpers: env parsing, redaction, ROE gate, path guards, JSON escaping |

## Hardening audit

`scripts/hardening-audit.sh` checks a subset of common CIS-benchmark-style items and prints one `PASS`, `WARN`, or `FAIL` line per finding. It is **read-only**: it has no apply mode, ignores `CONFIRM`, and only reads files and runs status queries (`ufw status`, `firewall-cmd --state`, `nft list ruleset`, `systemctl is-active` / `is-enabled`). Run it as root for complete results; anything it cannot read is reported as `WARN`, not guessed.

```bash
sudo ./scripts/hardening-audit.sh                     # findings + redacted report in reports/
EU_AUDIT_NO_REPORT=yes ./scripts/hardening-audit.sh   # print only; write nothing
EU_AUDIT_FAIL_ON=fail ./scripts/hardening-audit.sh    # exit 2 if any FAIL (for CI or cron)
```

| Area | PASS | WARN | FAIL |
|---|---|---|---|
| SSH `PermitRootLogin` | `no` | `prohibit-password` and similar, or unset | `yes` |
| SSH `PasswordAuthentication` | `no` | `yes` or unset (OpenSSH default is yes) | — |
| SSH `Protocol` | `2` or unset | unrecognized value | includes `1` |
| SSH `MaxAuthTries` | 4 or less | more than 4, or unset (default 6) | — |
| sudoers `NOPASSWD` | none in `/etc/sudoers` or `/etc/sudoers.d/` | one or more (each listed, redacted) | — |
| Firewall | ufw active, firewalld running, or an nftables `input` hook | tools missing, or not root | none active (as root) |
| World-writable paths in `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin` | none | — | any file, or any directory without the sticky bit |
| Automatic updates | unattended-upgrades or dnf-automatic applying updates | missing or disabled | — |
| auditd | service active | config present but state unknown (`EU_AUDIT_ROOT`) | installed but inactive, or not installed |
| Password aging (`/etc/login.defs`) | `PASS_MAX_DAYS` ≤ 365, `PASS_MIN_DAYS` ≥ 1, `PASS_WARN_AGE` ≥ 7 | otherwise | — |

The report (`reports/<role>-hardening-audit-<host>-<timestamp>.txt`) and its JSON summary (pass, warn, and fail counts) are written under `umask 077` to a `700` directory as `600` files, after redaction, and only once the audit completes. Exit codes: **0** audit completed, **2** FAIL findings with `EU_AUDIT_FAIL_ON=fail`, **3** operational error (no report published).

`EU_AUDIT_ROOT=/mnt/image` audits the files of a mounted image or test fixture instead of `/`; live firewall and service checks are skipped in that mode. SSH parsing follows `Include` files and sshd's first-value-wins rule but does not evaluate `Match` blocks, so confirm SSH with `sudo sshd -T` before acting. This is a subset of CIS items, not a full benchmark or a compliance attestation.

## Evidence handling

- All output goes under `reports/` (gitignored).
- Timestamps, host identity, and redacted excerpts. Report names include the process ID so two runs in the same second do not overwrite each other.
- Do not commit raw evidence. Retain it according to your policy, preferably off-host or on immutable media for authenticity.
- Redaction is best-effort. Always human-review reports before any external sharing.

Anomaly exit codes: **0** no listener changes, **1** changes, **2** integrity failure, **3** operational failure. An interrupted anomaly report remains in a private `reports/.anomaly.*` file with an `INCOMPLETE` marker. Collector failures return **3** and discard temporary outputs rather than publish an incomplete JSON summary.

## Regression checks

Requires Bash, GNU sed, ShellCheck, and Python 3. Run from the repository root:

```bash
for script in scripts/*.sh; do bash -n "$script" || exit; done
shellcheck -x scripts/*.sh
python3 tests/test_regressions.py
python3 tests/test_hardening_audit.py
python3 tests/test_community_hygiene.py
```

Tests use private temporary fixtures and synthetic inputs, including missing or empty `ss`, symlinked output paths, invalid ROE, and secret-redaction examples. The hardening-audit tests run against fixture config trees in `tests/fixtures/hardening/` and stub commands that record their arguments, to confirm the audit never changes a file and only issues status queries. They do not install packages, restart services, download artifacts, or change host policy.

GitHub Actions runs the same checks on every push and pull request.

## License and security

- Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 EmpowerU LLC.
- Vulnerability reports: see [SECURITY.md](SECURITY.md). Use bravo1alpha95@gmail.com.
- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
