## What this changes

## How it was tested

- [ ] `bash -n` passes for every `scripts/*.sh`
- [ ] `shellcheck -x scripts/*.sh` passes
- [ ] `python3 tests/test_regressions.py` passes
- [ ] No secrets, real evidence, lab addresses, emails, tokens, or vendor GPG fingerprints are included
- [ ] Dry-run remains the default; `CONFIRM=yes` and a complete ROE are still required for mutations
- [ ] `EU_*` naming is preserved; `.env` is not sourced

## Notes

Use synthetic fixtures only.
