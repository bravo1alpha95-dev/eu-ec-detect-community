# Hardening audit fixtures

Synthetic configuration trees used by `tests/test_hardening_audit.py`. They are
passed to `scripts/hardening-audit.sh` through `EU_AUDIT_ROOT` so tests never read
or change the host's real `/etc`. Addresses use the documentation range
203.0.113.0/24 and `example.com`; nothing here comes from a real system.

- `hardened/` should produce PASS for SSH, sudoers, permissions, updates, and
  password aging (the SSH include file overrides the main file, and the `Match`
  block is ignored).
- `weak/` should produce FAIL for PermitRootLogin, Protocol 1, world-writable
  files (created by the test), and auditd, plus WARN for the rest.
