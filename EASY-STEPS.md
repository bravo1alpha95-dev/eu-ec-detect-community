# Easy Workload Steps — Access Monitoring & Evidence for Owned Systems

Goal: Minimal daily or weekly effort while generating usable evidence and baselines for anomaly, unexpected software, and unusual-access review.

## One-time setup (5–10 minutes)

1. Copy this project to a secure location on an operator host you control (or your workstation).
2. `cd eu-ec-detect-community`
3. `cp .env.example .env && chmod 600 .env`
4. Edit the `EU_*` values in `.env` for your owned environment. Set `EU_SCOPE_CIDR` to your authorized range (the example `10.0.0.0/24` is a placeholder, not a real network you should assume is yours). No API key is used by these scripts.
5. Fill `scope/inventory.md` with the hosts you own and intend to monitor.
6. Open `scope/roe.md`. Fill requester, window, contacts, and every `(fill)` field. Replace the Status line with exactly `Status: AUTHORIZED` only once you confirm these are your owned systems and you have written authorization. Save.
7. Run the easy path (read-only; AUTHORIZED status is not required for collection):
   ```bash
   ./scripts/easy-run.sh
   ```
8. Review the short summary printed and the full file in `reports/`. That is your first evidence baseline.

## Daily / periodic low-effort check

- Run `./scripts/easy-run.sh` whenever you want a fresh snapshot, or schedule it via cron or systemd on the operator host.
- The easy path is fully read-only. It never changes the system.
- Output is timestamped under `reports/` — suitable for audit folders or SIEM ingestion after review.

## Continuous monitoring (recommended next, still low ongoing work)

1. Deploy a Wazuh agent on each owned production host (or start in a lab you own).
   - The manager can live on a dedicated host or the operator.
   - Agents can report auth events, processes, file integrity, and vulnerabilities.
   - Use the companion pack [eu-wazuh-detections](https://github.com/bravo1alpha95-dev/eu-wazuh-detections) for starter custom rules. Those rules have not been tested with `wazuh-logtest` against a live manager in this project.
   - The [eu-monitor-installer](https://github.com/bravo1alpha95-dev/eu-monitor-installer) can copy this toolkit (and optionally the rules) onto a host. It is dry-run by default.
2. Optional: add a network sensor such as Suricata if you have authorized network visibility.
3. For threat-intel enrichment of indicators you already possess (hashes from alerts, and similar), use a separate authorized lookup that reads credentials from environment variables only. Do not hardcode keys.

## Evidence for reporting

- Every run produces:
  - A full text report with redacted auth excerpts, users, listeners, and sudo/SSH settings.
  - A JSON summary.
- Store `reports/` according to your retention policy (noted in your ROE).
- These files are the evidence trail for monitoring, compliance, or incident review. Review them before sharing.

## Desired-state quick checks (manual or later automation)

- SSH root login disabled?
- Password-authentication policy matches intent?
- Unexpected listeners?
- Unattended upgrades present?

Run the collect script; the output already surfaces most of these. Add environment-specific checks in `policies/` as needed.

## Workload reduction tips

- One command (`easy-run.sh`) covers preflight + collect + summary.
- Schedule it (cron or a systemd timer) so you only review exceptions.
- Once Wazuh is running, the agents do the continuous work; you only triage alerts.
- Run `scripts/anomaly-checks.sh` for listener baseline diffs.

## Safety reminders

- Collection is always read-only.
- Any apply (agent-install scaffolding, config change) requires `CONFIRM=yes` **and** ROE `Status: AUTHORIZED` with every `(fill)` field completed.
- Snapshot or backup before mutations.
- Never paste secrets into chat or commit evidence.
- Verify every external package and GPG key against current vendor documentation. This repository does not ship vendor fingerprints.

Start with the one-time setup and one `easy-run.sh`. That gives you immediate evidence with almost no ongoing effort.
