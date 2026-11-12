# Contributing to eu-ec-detect-community

Thank you for helping improve this defensive toolkit. By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## What we accept

- Bug fixes, test coverage, documentation, and defensive improvements.
- Hardening of path guards, redaction, ROE checks, and portability.
- Clear, reproducible reports that use **synthetic** data only.

## What we will not accept

- Offensive techniques, exploit code, credential dumping, or targeting guidance for systems the operator does not own.
- Hardcoded secrets, real evidence, production logs, personal data, or live credentials.
- Changes that weaken the dry-run default, the `CONFIRM=yes` + ROE gate, or fail-closed permission/symlink checks.
- Rewrites of git history, force-pushes to shared branches, or commits that add lab-specific addresses or vendor fingerprints.

## Development setup

```bash
git clone https://github.com/bravo1alpha95-dev/eu-ec-detect-community.git
cd eu-ec-detect-community
# Requires Bash, GNU sed, ShellCheck, and Python 3
for script in scripts/*.sh; do bash -n "$script" || exit; done
shellcheck -x scripts/*.sh
python3 tests/test_regressions.py
```

Keep `EU_*` naming. Do not `source` `.env`. Report directories must remain mode 700 and report files mode 600.

## Pull requests

- Open a PR against `main`. Use the pull-request template.
- Every PR must pass `bash -n`, ShellCheck, and the regression suite (the same checks GitHub Actions runs).
- Prefer a focused change with a short explanation of the bug or improvement and how you reproduced it.
- If you touch redaction, add a regression fixture with synthetic secrets.
- Do not include real IPs, hostnames, emails, tokens, or GPG fingerprints.

## Security issues

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public PR or issue.
