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
| `scripts/20_apply.sh` | Dry-run scaffolding for a Wazuh agent; mutates only with `CONFIRM=yes` and a valid ROE |
| `scripts/lib.sh` | Shared helpers: env parsing, redaction, ROE gate, path guards, JSON escaping |

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
```

Tests use private temporary fixtures and synthetic inputs, including missing or empty `ss`, symlinked output paths, invalid ROE, and secret-redaction examples. They do not install packages, restart services, download artifacts, or change host policy.

GitHub Actions runs the same checks on every push and pull request.

## License and security

- Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 EmpowerU LLC.
- Vulnerability reports: see [SECURITY.md](SECURITY.md). Use bravo1alpha95@gmail.com.
- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
