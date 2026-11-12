---
name: Bug report
about: A defensive bug, incorrect guard, or test failure in this toolkit
title: "[bug] "
labels: ["bug"]
---

**What happened**

**What you expected**

**How to reproduce with synthetic data**

Do not attach production evidence, secrets, real addresses, or personal data. Use fixtures.

**Environment**

- OS and Bash version:
- GNU sed present? (`sed --version`):
- Commit SHA:

**Which checks failed**

- [ ] `bash -n scripts/*.sh`
- [ ] `shellcheck -x scripts/*.sh`
- [ ] `python3 tests/test_regressions.py`
