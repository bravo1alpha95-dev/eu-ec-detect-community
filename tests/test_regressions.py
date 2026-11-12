#!/usr/bin/env python3
"""Offline regressions. Copies fixtures into private temporary directories; no installs."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("EU_TEST_ROOT", Path(__file__).resolve().parents[1]))
ENTRYPOINTS = ("00_preflight.sh", "10_collect.sh", "20_apply.sh", "anomaly-checks.sh", "easy-run.sh")


class Regressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="eu-regression-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for folder in ("scripts", "scope"):
            shutil.copytree(ROOT / folder, self.root / folder)
        # Ensure entrypoints are executable in the temp copy (some FS drop the bit)
        for name in ENTRYPOINTS:
            p = self.root / "scripts" / name
            if p.exists():
                p.chmod(0o755)
        shutil.copyfile(ROOT / ".env.example", self.root / ".env.example")
        (self.root / "policies").mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Explicit PATH excludes ss; never rely on the host's listener state.
        for cmd in ("bash dirname date hostname id mkdir chmod mktemp rm mv basename "
                    "awk wc cat sed head sort diff sha256sum cut cp stat grep tee").split():
            (self.bin / cmd).symlink_to(shutil.which(cmd))
        for cmd in ("getent", "last", "lastb", "dpkg", "apt-config"):
            self.stub(cmd, "exit 0")
        self.stub("hostname", "echo eu-test-host")
        self.env = dict(os.environ, PATH=str(self.bin), LC_ALL="C")
        self.env.pop("CONFIRM", None)

    def stub(self, name, body):
        p = self.bin / name
        if p.exists() or p.is_symlink():
            p.unlink()
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(0o700)

    def run_script(self, name, **env):
        return subprocess.run(["/bin/bash", str(self.root / "scripts" / name)],
                              cwd=self.root, env=dict(self.env, **env),
                              text=True, capture_output=True, timeout=15)

    def helper(self, command, data=""):
        return subprocess.run(["/bin/bash", "-c", 'source "$1"; ' + command,
                               "eu-test", str(self.root / "scripts/lib.sh")],
                              input=data, env=self.env, text=True,
                              capture_output=True, timeout=15)

    def authorize(self):
        (self.root / "scope/roe.md").write_text("Status: AUTHORIZED\n" + "\n".join(
            "- " + k + ": test-approved" for k in
            ("Authorizer / program", "Written permission location", "Window (start / end, timezone)",
             "Contact", "Operator", "Date")))

    def test_syntax(self):
        for p in (self.root / "scripts").glob("*.sh"):
            self.assertEqual(subprocess.run(["/bin/bash", "-n", str(p)], capture_output=True).returncode, 0, p.name)

    def test_entrypoints_executable(self):
        for name in ENTRYPOINTS:
            self.assertTrue(os.access(ROOT / "scripts" / name, os.X_OK), name)

    def test_collect_json(self):
        for mode in ("missing", "empty", "listeners", "failed"):
            with self.subTest(mode=mode):
                ss = self.bin / "ss"
                if ss.exists():
                    ss.unlink()
                if mode != "missing":
                    self.stub("ss", {"empty": "exit 0", "failed": "exit 1", "listeners":
                              "printf 'tcp LISTEN 0 10 127.0.0.1:22 0.0.0.0:*\\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\\n'"}[mode])
                result = self.run_script("10_collect.sh")
                self.assertEqual(result.returncode, 0, result.stderr)
                reports = list((self.root / "reports").glob("*.json"))
                parsed = json.loads(max(reports, key=lambda p: p.stat().st_mtime_ns).read_text())
                self.assertEqual(parsed["listening_sockets"], 2 if mode == "listeners" else 0)
                self.assertEqual((self.root / "reports").stat().st_mode & 0o777, 0o700)
                for p in (self.root / "reports").iterdir():
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_symlink_reports_rejected_before_chmod(self):
        target = self.root / "outside"
        target.mkdir(mode=0o755)
        (self.root / "reports").symlink_to(target)
        for name in ENTRYPOINTS[:-1]:
            with self.subTest(name=name):
                target.chmod(0o755)
                result = self.run_script(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.stat().st_mode & 0o777, 0o755)
                self.assertEqual(list(target.iterdir()), [])

    def test_symlink_policy_and_stub_rejected(self):
        self.authorize()
        target = self.root / "outside"
        target.mkdir()
        shutil.rmtree(self.root / "policies")
        (self.root / "policies").symlink_to(target)
        self.assertNotEqual(self.run_script("20_apply.sh", CONFIRM="yes").returncode, 0)
        (self.root / "policies").unlink()
        (self.root / "policies").mkdir()
        sentinel = target / "sentinel"
        sentinel.write_text("sentinel")
        stub = self.root / "policies/wazuh-agent-local.conf.stub"
        stub.symlink_to(sentinel)
        self.assertNotEqual(self.run_script("20_apply.sh", CONFIRM="yes").returncode, 0)
        self.assertTrue(stub.is_symlink())
        self.assertEqual(sentinel.read_text(), "sentinel")

    def test_dry_run_and_roe(self):
        self.assertEqual(self.run_script("20_apply.sh").returncode, 0)
        self.assertEqual(list((self.root / "policies").iterdir()), [])
        self.assertNotEqual(self.run_script("20_apply.sh", CONFIRM="yes").returncode, 0)
        self.authorize()
        self.assertEqual(self.run_script("20_apply.sh", CONFIRM="yes").returncode, 0)
        self.assertTrue((self.root / "policies/wazuh-agent-local.conf.stub").is_file())

    def test_apply_cleanup_success_and_failure(self):
        self.authorize()
        result = self.run_script("20_apply.sh", CONFIRM="yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        reports = self.root / "reports"
        self.assertEqual(len(list(reports.glob("apply-*.log"))), 1)
        self.assertEqual(list(reports.glob(".apply.*")), [])
        policies = self.root / "policies"
        self.assertEqual(list(policies.glob("*.stub.*")), [])
        # Fail after creating the stub tempfile, without touching host paths.
        self.stub("mv", 'case "$1" in -f) case "$2" in policies/*) exit 42 ;; esac ;; esac\n/bin/mv "$@"')
        result = self.run_script("20_apply.sh", CONFIRM="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(reports.glob(".apply.*")), [])
        self.assertEqual(list(policies.glob("*.stub.??????")), [])
        self.assertEqual(len(list(reports.glob("apply-*.log"))), 1)

    def test_checksum_must_cover_requested_baseline(self):
        self.stub("ss", "exit 0")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        reports = self.root / "reports"
        base = reports / "baseline-listeners-eu-test-host.txt"
        unrelated = reports / "unrelated.txt"
        unrelated.write_text("unrelated evidence\n")
        digest = hashlib.sha256(unrelated.read_bytes()).hexdigest()
        Path(str(base) + ".sha256").write_text(digest + "  unrelated.txt\n")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 2)

    def test_baseline_permissions_refused_not_changed(self):
        self.stub("ss", "exit 0")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        base = self.root / "reports/baseline-listeners-eu-test-host.txt"
        for path in (base, Path(str(base) + ".sha256")):
            path.chmod(0o644)
            self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 2)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            path.chmod(0o400)
            self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
            path.chmod(0o600)

    def test_checksum_rejects_extra_or_wrong_records(self):
        base = self.root / "baseline.txt"
        base.write_text("baseline evidence\n")
        digest = hashlib.sha256(base.read_bytes()).hexdigest()
        sidecar = self.root / "baseline.sha256"
        command = 'verify_checksum "' + str(base) + '" "' + str(sidecar) + '"'
        for record in (digest + "  baseline.txt\n", digest + " *baseline.txt\n"):
            sidecar.write_text(record)
            self.assertEqual(self.helper(command).returncode, 0)
        for record in (digest + "  ../baseline.txt\n", digest + "  unrelated.txt\n",
                       digest + "  baseline.txt\n" + digest + "  unrelated.txt\n",
                       "0" * 64 + "  baseline.txt\n"):
            sidecar.write_text(record)
            self.assertNotEqual(self.helper(command).returncode, 0)

    @unittest.skipUnless(shutil.which("shasum"), "shasum fallback not installed")
    def test_checksum_shasum_fallback(self):
        (self.bin / "sha256sum").unlink()
        (self.bin / "shasum").symlink_to(shutil.which("shasum"))
        self.stub("ss", "exit 0")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        base = self.root / "reports/baseline-listeners-eu-test-host.txt"
        base.write_text("tampered fixture\n")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 2)

    def test_baseline_nonregular_paths_refused(self):
        self.stub("ss", "exit 0")
        reports = self.root / "reports"
        reports.mkdir()
        base = reports / "baseline-listeners-eu-test-host.txt"
        for path in (base, Path(str(base) + ".sha256")):
            with self.subTest(path=path.name):
                shutil.rmtree(reports)
                reports.mkdir()
                path.mkdir()
                self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 2)
                self.assertEqual(list(path.iterdir()), [])
                path.rmdir()

    def test_easy_run_summary_uses_current_host(self):
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "ops-access-collect-zz-other-host-20990101T000000-1.txt").write_text("# wrong-host\n")
        result = self.run_script("easy-run.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("# wrong-host", result.stdout)
        self.assertIn("Latest evidence file: reports/ops-access-collect-eu-test-host-", result.stdout)

    def test_roe_exact_status_and_fields(self):
        for roe in ("Status: AUTHORIZED-NO\n", "Status: AUTHORIZED\n", "Status: AUTHORIZED\nStatus: DRAFT\n"):
            (self.root / "scope/roe.md").write_text(roe)
            self.assertNotEqual(self.helper('roe_authorized "' + str(self.root / "scope/roe.md") + '"').returncode, 0, roe)
        self.authorize()
        self.assertEqual(self.helper('roe_authorized "' + str(self.root / "scope/roe.md") + '"').returncode, 0)

    def test_one_line_pem_keeps_following_evidence(self):
        result = self.helper("redact", "-----BEGIN PRIVATE KEY----- fake -----END PRIVATE KEY-----\nafter-evidence\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "[PRIVATE KEY REDACTED]\nafter-evidence\n")

    def test_multiline_pem(self):
        result = self.helper("redact", "before\n-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\nafter\n")
        self.assertEqual(result.stdout, "before\n[PRIVATE KEY REDACTED]\nafter\n")

    def test_ipv6_redaction_and_time_preservation(self):
        for addr in ("2001:db8::1234", "fe80::abcd", "::1", "::", "2001:db8:1:2:3:4:5:6", "::ffff:192.0.2.1"):
            result = self.helper("redact", "[" + addr + "]:443\n")
            self.assertEqual(result.stdout, "[IP6_REDACTED]:443\n", addr)
        self.assertEqual(self.helper("redact", "2026-11-06T12:34:56-0500\n").stdout, "2026-11-06T12:34:56-0500\n")
        self.assertEqual(self.helper("redact", "aa:bb:cc:dd:ee:ff\n").stdout, "MAC_REDACTED\n")

    def test_password_forms(self):
        for text in ('password="synthetic secret"', "password='synthetic secret'", 'mysql -pSYNTHETIC',
                     '{"password": "synthetic secret"}', 'https://user:synthetic@example.invalid/path',
                     'Authorization: Bearer SYNTHETIC'):
            result = self.helper("redact", text + "\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("synthetic", result.stdout.lower(), result.stdout)
            self.assertNotIn("secret", result.stdout.lower(), result.stdout)

    def test_sk_rk_prefix_does_not_mangle_midword(self):
        # Historically (sk-|rk-) matched inside words like network-online.
        result = self.helper("redact", "network-online.service started\nsk-proj-SYNTHETICSECRET\nrk-proj-SYNTHETICSECRET\npk_live_SYNTHETICSECRET\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("network-online.service started", result.stdout)
        self.assertNotIn("SYNTHETICSECRET", result.stdout)
        self.assertIn("STRIPE_OR_SIMILAR_KEY_REDACTED", result.stdout)

    def test_json_escape_controls(self):
        value = 'quotes" backslash\\ newline\n tab\t back\b form\f ctrl' + ''.join(chr(i) for i in range(1, 32)) + ' café ☃'
        result = subprocess.run(
            ["/bin/bash", "-c", 'source "$1"; json_escape "$2"', "eu-test",
             str(self.root / "scripts/lib.sh"), value], env=self.env, capture_output=True, text=True)
        parsed = json.loads('"' + result.stdout + '"')
        self.assertEqual(parsed, value)

    def test_env_permissions_all_entrypoints(self):
        p = self.root / ".env"
        p.write_text("ROLE=ops\n")
        p.chmod(0o644)
        for name in ("00_preflight.sh", "10_collect.sh", "easy-run.sh"):
            self.assertNotEqual(self.run_script(name).returncode, 0, name)
        p.chmod(0o600)
        self.assertEqual(self.run_script("10_collect.sh").returncode, 0)
        p.unlink()
        target = self.root / "env-target"
        target.write_text("ROLE=ops\n")
        target.chmod(0o600)
        p.symlink_to(target)
        self.assertNotEqual(self.run_script("10_collect.sh").returncode, 0)
        p.unlink()
        p.symlink_to(self.root / "missing-env")
        self.assertNotEqual(self.run_script("10_collect.sh").returncode, 0)

    def test_easy_run_date(self):
        result = self.run_script("easy-run.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"Date: [0-9]{4}-[0-9]{2}-[0-9]{2}T")
        self.assertNotIn("command not found", result.stderr)

    def test_baseline_symlink_refused(self):
        self.stub("ss", "exit 0")
        reports = self.root / "reports"
        reports.mkdir()
        target = self.root / "sentinel"
        target.write_text("sentinel")
        baseline = reports / "baseline-listeners-eu-test-host.txt"
        for name in (baseline, Path(str(baseline) + ".sha256")):
            name.symlink_to(target)
            result = self.run_script("anomaly-checks.sh")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertTrue(name.is_symlink())
            self.assertEqual(target.read_text(), "sentinel")
            name.unlink()

    def test_listener_changes_and_operational_failure(self):
        self.stub("ss", "printf 'tcp LISTEN 0 10 127.0.0.1:22 0.0.0.0:*\\n'")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        self.stub("ss", "printf 'tcp LISTEN 0 10 127.0.0.1:23 0.0.0.0:*\\n'")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 1)
        self.stub("ss", "exit 1")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 3)
        self.assertTrue(any("INCOMPLETE" in p.read_text() for p in (self.root / "reports").glob(".anomaly.*")))

    def test_apply_log_symlink_does_not_overwrite_target(self):
        self.stub("date", 'if [[ "$1" == +%Y%m%dT%H%M%S ]]; then echo 20261106T000000; else /bin/date "$@"; fi')
        (self.root / "reports").mkdir()
        sentinel = self.root / "sentinel"
        sentinel.write_text("sentinel")
        result = subprocess.run(["/bin/bash", "-c",
            '/bin/ln -s "$PWD/sentinel" "reports/apply-20261106T000000-$$.log"; /bin/ln -s "$PWD/sentinel" reports/apply-20261106T000000.log; exec /bin/bash scripts/20_apply.sh'],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_text(), "sentinel")

    def test_collect_operational_failure_publishes_no_json(self):
        self.stub("getent", "exit 1")
        result = self.run_script("10_collect.sh")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(list((self.root / "reports").glob("*.json")), [])

    def test_anomaly_missing_ss_is_operational_failure(self):
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 3)

    def test_diff_error_is_not_a_listener_change(self):
        self.stub("ss", "exit 0")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        self.stub("diff", "exit 2")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 3)

    def test_same_second_runs_keep_both_reports(self):
        self.stub("date", 'if [[ "$1" == +%Y%m%dT%H%M%S ]]; then echo 20261106T000000; else /bin/date "$@"; fi')
        for _ in range(2):
            self.assertEqual(self.run_script("10_collect.sh").returncode, 0)
        self.assertEqual(len(list((self.root / "reports").glob("*.json"))), 2)

    def test_sshd_key_matching(self):
        script = (self.root / "scripts/10_collect.sh").read_text()
        match = re.search(r"grep (-i?E) '([^']*PermitRootLogin[^']*)'", script)
        self.assertIsNotNone(match)
        result = subprocess.run(["/bin/grep", match[1], match[2]],
                                input="  permitrootlogin no\nPort 22\nPortForwarding yes\n",
                                text=True, capture_output=True)
        self.assertEqual(result.stdout, "  permitrootlogin no\nPort 22\n")

    def test_reboot_rows_are_not_night_logins(self):
        self.stub("ss", "exit 0")
        self.stub("last", "printf 'reboot system boot Fri Nov 6 01:23\\nshutdown system down Fri Nov 6 02:23\\neu-user pts/0 Fri Nov 6 03:23\\n'")
        result = self.run_script("anomaly-checks.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = next((self.root / "reports").glob("anomaly*.txt")).read_text()
        self.assertNotIn("reboot system", report)
        self.assertNotIn("shutdown system", report)
        self.assertIn("eu-user", report)

    def test_normalized_ipv4_ipv6_and_wildcard_addresses(self):
        rows = ("tcp LISTEN 0 10 127.0.0.1:22 0.0.0.0:*\n"
                "tcp LISTEN 0 10 [2001:db8::1]:443 [::]:*\n"
                "udp UNCONN 0 0 *:53 *:*\n")
        self.stub("ss", "printf '%s' '" + rows + "'")
        self.assertEqual(self.run_script("anomaly-checks.sh").returncode, 0)
        baseline = self.root / "reports/baseline-listeners-eu-test-host.txt"
        self.assertEqual(baseline.read_text(), "tcp LISTEN 127.0.0.1:22\ntcp LISTEN [2001:db8::1]:443\nudp UNCONN *:53\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
