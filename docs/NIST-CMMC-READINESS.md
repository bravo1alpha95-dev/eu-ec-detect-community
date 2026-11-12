# NIST / CMMC readiness checklist (template)

Status: **NOT ASSESSED — NOT CERTIFIED**. This document is a preparation and evidence-tracking framework that operators may use with this toolkit. It is not a claim of conformity, certification, or authorization by EmpowerU LLC or by any user of this software.

## Scope and governing baselines

- Record the legal entity, system boundary, assets, locations, administrators, users, cloud providers, and data flows before assigning any compliance status.
- Determine whether the system processes, stores, or transmits FCI or CUI, with contract/agency confirmation. Do not put real CUI, credentials, or personal data in GitHub issues or evidence attachments.
- CMMC Level 1: 15 FAR 52.204-21 safeguards for FCI, subject to the applicable contract and program requirements.
- CMMC Level 2: 110 requirements in NIST SP 800-171 Rev. 2 under the CMMC program's adopted baseline. Do not silently substitute SP 800-171 Rev. 3.
- NIST SP 800-171 Rev. 3 and NIST CSF 2.0 may be tracked separately for forward-looking improvements; they are not automatic substitutes for the adopted CMMC assessment criteria.
- Use NIST SP 800-171A Rev. 2 assessment objectives and applicable DoD CMMC assessment guides to collect objective-by-objective evidence. Confirm the currently applicable rule, contract language, and assessment pathway before external assertions.

## Evidence-first workflow

For every requirement and assessment objective, record:

1. Control ID and baseline revision; applicability and system-boundary rationale.
2. Implementation owner, technical/policy implementation, affected assets, and inherited/shared responsibility.
3. Evidence identifier, capture timestamp (UTC), source, authorized collector, SHA-256 digest, access controls, retention and off-host integrity protection.
4. Test procedure, result, independent reviewer, review date, exceptions, and remediation owner/due date.
5. Status: NOT ASSESSED / IN PROGRESS / IMPLEMENTED-UNTESTED / VERIFIED / NOT MET / NOT APPLICABLE (with approved rationale).
6. Cross-reference to SSP, POA&M, risk register, change ticket and assessment objective.

**Never mark VERIFIED solely because code exists or a PR claims tests passed.** Verify deployed configuration and operating effectiveness within the defined boundary.

## Control-family coverage checklist (Level 2)

| Family | Example evidence to gather | Initial status |
|---|---|---|
| AC Access Control | identities, MFA, least privilege, authorization reviews, session controls | NOT ASSESSED |
| AT Awareness & Training | training records, role-based awareness | NOT ASSESSED |
| AU Audit & Accountability | event policy, time sync, protected log retention, audit review | NOT ASSESSED |
| CM Configuration Management | inventories, secure baselines, approvals, drift records | NOT ASSESSED |
| IA Identification & Authentication | account lifecycle, MFA, authenticator controls | NOT ASSESSED |
| IR Incident Response | plan, contacts, tabletop, reporting evidence | NOT ASSESSED |
| MA Maintenance | authorized maintenance and remote-access records | NOT ASSESSED |
| MP Media Protection | encryption, sanitization, access and disposal records | NOT ASSESSED |
| PS Personnel Security | screening and termination/transfer procedures | NOT ASSESSED |
| PE Physical Protection | facility access and visitor controls | NOT ASSESSED |
| RA Risk Assessment | risk register, vulnerability assessments and prioritization | NOT ASSESSED |
| CA Security Assessment | SSP, assessments, POA&M and continuous monitoring | NOT ASSESSED |
| SC System & Communications Protection | boundaries, cryptography, segmentation, secure transport | NOT ASSESSED |
| SI System & Information Integrity | patching, malware protection, monitoring and flaw remediation | NOT ASSESSED |

## Toolkit-specific evidence candidates (NOT control satisfaction)

- `scope/roe.md`: authorization workflow, not proof of organizational access-control compliance.
- `scripts/10_collect.sh`, `scripts/anomaly-checks.sh`: potential AU/SI monitoring evidence after validated execution and review.
- `scripts/lib.sh`: potential secure-handling implementation evidence; redaction remains best-effort.
- `scripts/20_apply.sh`: change/authorization guard candidate; verify behavior under failure conditions.
- `tests/test_regressions.py`: test artifacts, not a substitute for operational or assessor evidence.
- `SECURITY.md`: documented limitations; do not interpret prose as proof of implementation.

## Release gates

- [ ] Approved CUI/FCI determination and system boundary/data-flow diagrams.
- [ ] SSP approved and mapped to each applicable assessment objective.
- [ ] Objective-level evidence register with independent verification.
- [ ] CI: Bash syntax, ShellCheck, regressions, secret scanning, dependency review; retain results.
- [ ] Enforce protected default branch, peer review, least-privilege GitHub permissions, and controlled release tags.
- [ ] Test backups and restores; store signed/off-host immutable integrity records as appropriate.
- [ ] Verify logging, incident response exercise, vulnerability remediation, and customer-hosted installation.
- [ ] Review third-party/shared-responsibility dependencies and customer responsibilities.
- [ ] Formal gap assessment, POA&M, authorized risk decisions, and readiness sign-off.
- [ ] Determine required self-assessment or C3PAO assessment pathway under actual contract obligations.

## Evidence handling

Use synthetic fixtures in CI. Keep sensitive evidence in an access-controlled repository outside GitHub source history, with chain-of-custody, retention policy and approved access. Never commit secrets, production logs, CUI, PII, or private keys. Local hashes alone do not establish authenticity against a privileged attacker.

## Authoritative references (verify effective versions and contractual applicability)

- DoD CMMC: https://business.defense.gov/Programs/Cyber-Security-Resources/Cybersecurity-Maturity-Model-Certification/
- DoD CMMC program: https://dodcio.defense.gov/CMMC/
- NIST SP 800-171 Rev. 2: https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final
- NIST SP 800-171 Rev. 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final
- NIST SP 800-171A Rev. 2: https://csrc.nist.gov/pubs/sp/800/171/a/r2/final
- NIST CSF 2.0: https://www.nist.gov/cyberframework

**Decision:** This checklist does not make a system ready for CMMC attestation. Do not attest until the boundary, evidence, applicable assessment objectives, and assessment pathway are independently verified.
