# Security Considerations — eu-ec-detect-community

Defensive toolkit for **owned systems only**. Read-only by default. Residual risks and mitigations below.

## Reporting vulnerabilities

Please report security issues privately to **bravo1alpha95@gmail.com**. Do not open a public issue for a vulnerability, and do not attach production evidence, secrets, or personally identifiable information.

This is a community edition. There is no published SLA for response times. Describe the issue, the affected script or path, and a safe way to reproduce it with synthetic data.

## Design principles

- Fail closed on ROE, permissions, ownership, and symlinks.
- Never source `.env` (parse as data only; strict key charset + length limits + reject shell metacharacters).
- Redact secrets, keys, emails, IPs, tokens (including Azure AccountKey, AWS secret-like and STS keys, Slack tokens, Discord, Cloudflare, and `client_secret` patterns) before writing reports.
- Atomic writes + checksums for baselines where practical.
- Explicit `CONFIRM=yes` + ROE `AUTHORIZED` required for any mutation.
- Filename components (ROLE, host) are sanitized to alphanumeric + limited punctuation to block path traversal.
- Portable timestamps via `iso_date()` to support GNU and BSD date.

## Residual risks (why operators still need to review)

1. **Same-user tampering** of baselines / reports. An attacker with the operator account can rewrite files and checksums. Mitigation: store baselines off-host or on immutable media; monitor report integrity separately.
2. **Parsing fragility** (`ss`, `last`, auth logs). Format varies by OS/version. Best-effort only; tune or replace with structured agents (Wazuh). Numeric hour comparison is used for login time checks.
3. **Supply-chain for Wazuh and any other vendor package**. External key/repo downloads are high risk. Always verify the GPG fingerprint against current official vendor documentation; prefer internal mirrors or offline packages. This repository does not ship vendor fingerprints. Never pipe installers to a shell.
4. **Over-redaction vs under-redaction**. Custom or obfuscated secrets may remain. Always human-review reports before external sharing.
5. **Privilege**. Scripts prefer non-root but some visibility needs elevation. Run with least privilege; elevate only the collector if required.
6. **Env-driven path components**. `ROLE` from `.env` is sanitized at use; still treat `.env` as sensitive (mode 600, owner-only).
7. **Portability**. GNU sed is required by the redaction patterns (checked by preflight). Date formatting has GNU/BSD fallbacks.
8. **JSON injection**. Control bytes representable in Bash strings are escaped in `json_escape()`.

## External attack surface

- No network listeners started by this toolkit.
- No outbound connections in the collection path.
- The apply path only prints operator commands; it does not execute downloads.
- `.env` mode 600, owner-checked, symlink-rejected, shell-metacharacter rejected.
- `reports/` mode 700, owner-checked, symlink-rejected.

## Audit patterns

- Validate path type and ownership **before** chmod or writing. Same-account or root attackers can still race shell-level path checks; use a trusted checkout and protect its parent directory.
- A zero count is data, not a failed match. Socket counting emits one integer from awk; a missing or failing optional `ss` yields zero, not `00`.
- Redaction is still best-effort. Regression fixtures cover single-line PEM, compressed IPv6, quoted/JSON credentials, URL userinfo, and MySQL `-p` passwords, among others.
- Gate checks belong at every entry point. Apply requires `CONFIRM=yes` and one exact `AUTHORIZED` status plus all authorization/contact/sign-off fields, not merely an AUTHORIZED prefix.
- Keep baseline checksums off-host or immutable for authenticity. Local sidecars detect accidental changes, not an attacker controlling the operator account.
- Validate any Wazuh rules with `wazuh-logtest` on the intended Wazuh version before deploying them. This source-only regression suite does not substitute for that integration test or vendor fingerprint verification.
