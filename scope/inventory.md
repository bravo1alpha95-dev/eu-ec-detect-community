# Inventory — template

List the systems **you own** and intend to monitor. The rows below are placeholders in the documentation range `10.0.0.0/24`. Replace them. Do not copy real third-party addresses into this file if you will publish or share the repository.

Set `EU_SCOPE_CIDR` in `.env` to the authorized range (for example `10.0.0.0/24`).

| Name | Role | Segment | Address | OS | Notes |
|---|---|---|---|---|---|
| ops-01 | ops | 10.0.0.0/24 | 10.0.0.10 | (fill) | example operator host; replace |
| app-01 | app | 10.0.0.0/24 | 10.0.0.20 | (fill) | example application host; replace |

Add or remove rows to match your environment. Keep this inventory consistent with the ROE in-scope list.
