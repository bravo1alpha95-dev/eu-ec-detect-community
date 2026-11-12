# Rules of engagement — template

Copy this file (or edit it in place) for the systems **you own**. The apply scripts treat this file as authorized only when every required field is filled and the Status line is exactly `Status: AUTHORIZED`.

Status: DRAFT — do not run mutating jobs until Status is AUTHORIZED.

## Identity

- Org / env: (fill)
- Project: eu-ec-detect-community
- Authorized CIDR (`EU_SCOPE_CIDR`): (fill, for example 10.0.0.0/24 — replace with your range)
- Focus: Access monitoring, inventory, and evidence collection for reporting and anomaly foundations on **owned systems only**.

## Authorization

- Requester: (fill)
- Authorizer / program: (fill)
- Written permission location: (fill)
- Window (start / end, timezone): (fill)

## In scope

- Assets: (fill — hostnames and addresses of systems you own; user-supplied only)
- Environments: (fill)
- Allowed activity: Read-only collection of access inventory, login history, listeners, auth log excerpts (redacted), and package lists, for monitoring and evidence. Installation of monitoring agents only with explicit CONFIRM=yes and snapshots.

## Out of scope

- Any non-owned systems, third-party tenants, or unscoped scanning.
- Offensive techniques, exploit development, credential dumping, or live probing of unauthorized targets.
- Storage of secrets, full password files, or unredacted sensitive data.

## Emergency stop

- Contact: (fill)
- Condition: Any indication of unauthorized scope or impact — halt immediately.

## Data handling

- Evidence lives in `reports/` (local, mode restricted).
- Retention: (fill — recommend 90 days for operational use, longer for audit if required)
- Redaction: Tokens, passwords, session data, and personal info are stripped or redacted in reports. No full dumps of `/etc/shadow` or private keys.

## Sign-off

- Operator: (fill)
- Date: (fill)

Fill every `(fill)` field and set `Status: AUTHORIZED` before apply steps. The scripts refuse to treat the ROE as authorized while any `(fill)` remains. Collection scripts are read-only and do not require AUTHORIZED status, but they are still only for owned systems.
