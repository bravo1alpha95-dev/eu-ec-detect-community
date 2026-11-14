#!/usr/bin/env python3
"""Offline tests for scripts/hardening-audit.sh.

Fixture trees under tests/fixtures/hardening/ are copied into private temporary
directories and passed through EU_AUDIT_ROOT, so the host's /etc is never read
for file checks. Live-mode tests use stub commands on an explicit PATH that
record their arguments, to prove only status queries are issued.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("EU_TEST_ROOT", Path(__file__).resolve().parents[1]))
FIXTURES = ROOT / "tests" / "fixtures" / "hardening"
READ_ONLY_CALLS = {
    "ufw status",
    "firewall-cmd --state",
    "nft list ruleset",
    "systemctl is-active auditd",
    # Only reached on dnf-based hosts (no /etc/apt):
    "systemctl is-enabled --quiet dnf-automatic.timer",
    "systemctl is-enabled --quiet dnf-automatic-install.timer",
    "systemctl is-enabled --quiet dnf5-automatic.timer",
}


def tree_digest(path):
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        st = p.lstat()
        h.update(str(p.relative_to(path)).encode())
        h.update(oct(st.st_mode).encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()


class HardeningAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="eu-hardening-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        shutil.copyfile(ROOT / ".env.example", self.root / ".env.example")
        self.fx = Path(self.tmp.name) / "fixtures"
        shutil.copytree(FIXTURES, self.fx)
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        for cmd in ("bash dirname date hostname id mkdir chmod mktemp rm mv basename "
                    "awk wc cat sed head tail sort cut cp stat grep find").split():
            (self.bin / cmd).symlink_to(shutil.which(cmd))
        self.stub("hostname", "echo eu-test-host")
        self.calls = Path(self.tmp.name) / "calls.log"
        self.env = dict(os.environ, PATH=str(self.bin), LC_ALL="C",
                        TMPDIR=str(Path(self.tmp.name)))
        for k in ("CONFIRM", "EU_AUDIT_ROOT", "EU_AUDIT_NO_REPORT", "EU_AUDIT_FAIL_ON"):
            self.env.pop(k, None)

    def stub(self, name, body):
        p = self.bin / name
        if p.exists() or p.is_symlink():
            p.unlink()
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(0o700)

    def recording_stub(self, name, body):
        self.stub(name, f'echo "{name} $*" >> "{self.calls}"\n' + body)

    def run_audit(self, **env):
        return subprocess.run(["/bin/bash", str(self.root / "scripts/hardening-audit.sh")],
                              cwd=self.root, env=dict(self.env, **env),
                              text=True, capture_output=True, timeout=30)

    def offline(self, name, **env):
        return self.run_audit(EU_AUDIT_ROOT=str(self.fx / name), **env)

    def lines(self, out, status, section):
        return [l for l in out.splitlines() if l.startswith(status) and f" {section} " in l]

    def test_syntax_and_executable(self):
        script = ROOT / "scripts" / "hardening-audit.sh"
        self.assertEqual(subprocess.run(["/bin/bash", "-n", str(script)]).returncode, 0)
        self.assertTrue(os.access(script, os.X_OK))

    def test_hardened_fixture_passes(self):
        r = self.offline("hardened", EU_AUDIT_NO_REPORT="yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        for msg in ("PermitRootLogin no", "PasswordAuthentication no", "Protocol 2",
                    "MaxAuthTries 3", "no NOPASSWD entries", "no world-writable files",
                    "unattended-upgrades enabled", "PASS_MAX_DAYS 365",
                    "PASS_MIN_DAYS 1", "PASS_WARN_AGE 14"):
            self.assertTrue(any(l.startswith("PASS") and msg in l for l in out.splitlines()), msg)
        self.assertIn("FAIL=0", out)
        self.assertFalse((self.root / "reports").exists())

    def test_include_wins_and_match_block_ignored(self):
        r = self.offline("hardened", EU_AUDIT_NO_REPORT="yes")
        self.assertEqual(self.lines(r.stdout, "FAIL", "ssh"), [])
        self.assertIn("MaxAuthTries 3", r.stdout)

    def test_weak_fixture_findings(self):
        (self.fx / "weak/etc/cron.d").mkdir()
        bad = self.fx / "weak/etc/cron.d/world-writable"
        bad.write_text("x\n")
        bad.chmod(0o666)
        open_dir = self.fx / "weak/etc/opendir"
        open_dir.mkdir()
        open_dir.chmod(0o777)
        sticky = self.fx / "weak/etc/stickydir"
        sticky.mkdir()
        sticky.chmod(0o1777)
        r = self.offline("weak", EU_AUDIT_NO_REPORT="yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertTrue(self.lines(out, "FAIL", "ssh"))
        self.assertIn("PermitRootLogin yes", out)
        self.assertIn("Protocol includes SSH-1", out)
        self.assertTrue(any("MaxAuthTries 6" in l for l in self.lines(out, "WARN", "ssh")))
        self.assertTrue(any("PasswordAuthentication yes" in l for l in self.lines(out, "WARN", "ssh")))
        self.assertTrue(any("2 NOPASSWD" in l for l in self.lines(out, "WARN", "sudo")))
        perms = self.lines(out, "FAIL", "perms")
        self.assertTrue(perms and "2 world-writable" in perms[0], out)
        self.assertIn("/etc/cron.d/world-writable", out)
        self.assertIn("/etc/opendir", out)
        self.assertNotIn("stickydir", out)
        self.assertTrue(self.lines(out, "FAIL", "auditd"))
        self.assertTrue(any("disabled" in l for l in self.lines(out, "WARN", "updates")))
        self.assertTrue(any("PASS_MAX_DAYS 99999" in l for l in self.lines(out, "WARN", "aging")))
        self.assertIn("FAIL=4", out)

    def test_never_modifies_audited_tree(self):
        for name in ("hardened", "weak"):
            with self.subTest(name=name):
                before = tree_digest(self.fx / name)
                r = self.offline(name, CONFIRM="yes")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(tree_digest(self.fx / name), before)

    def test_report_permissions_json_and_redaction(self):
        r = self.offline("weak")
        self.assertEqual(r.returncode, 0, r.stderr)
        reports = self.root / "reports"
        self.assertEqual(reports.stat().st_mode & 0o777, 0o700)
        files = sorted(reports.iterdir())
        self.assertEqual(len(files), 2, files)
        for p in files:
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertFalse(p.name.startswith("."), "temporary file left behind")
        text = next(p for p in files if p.suffix == ".txt").read_text()
        self.assertNotIn("203.0.113.7", text)
        self.assertNotIn("ops@example.com", text)
        self.assertIn("IP_REDACTED", text)
        summary = json.loads(next(p for p in files if p.suffix == ".json").read_text())
        self.assertEqual((summary["fail"], summary["warn"]), (3, 7))
        self.assertTrue(summary["report"].startswith("ops-hardening-audit-eu-test-host-"))
        self.assertEqual(list(Path(self.env["TMPDIR"]).glob("eu-hardening.*")), [])

    def test_fail_on_exit_code(self):
        self.assertEqual(self.offline("weak", EU_AUDIT_NO_REPORT="yes", EU_AUDIT_FAIL_ON="fail").returncode, 2)
        self.assertEqual(self.offline("hardened", EU_AUDIT_NO_REPORT="yes", EU_AUDIT_FAIL_ON="fail").returncode, 0)

    def test_invalid_audit_root_rejected(self):
        for bad in ("relative/path", str(self.fx) + "/../fixtures", str(self.fx / "missing"), "/tmp;id"):
            with self.subTest(bad=bad):
                r = self.run_audit(EU_AUDIT_ROOT=bad, EU_AUDIT_NO_REPORT="yes")
                self.assertEqual(r.returncode, 3, r.stdout)

    def test_symlink_reports_rejected(self):
        target = Path(self.tmp.name) / "outside"
        target.mkdir(mode=0o755)
        (self.root / "reports").symlink_to(target)
        r = self.offline("hardened")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list(target.iterdir()), [])

    def test_live_mode_uses_status_queries_only(self):
        self.recording_stub("ufw", 'echo "Status: inactive"')
        self.recording_stub("firewall-cmd", 'echo "not running"; exit 252')
        self.recording_stub("nft", 'echo "table inet filter { chain input { type filter hook input priority 0; } }"')
        self.recording_stub("systemctl", 'echo active')
        r = self.run_audit(EU_AUDIT_NO_REPORT="yes", CONFIRM="yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("nftables" in l for l in self.lines(r.stdout, "PASS", "firewall")), r.stdout)
        self.assertTrue(self.lines(r.stdout, "PASS", "auditd"), r.stdout)
        calls = set(self.calls.read_text().splitlines())
        self.assertTrue(calls, "no status queries recorded")
        self.assertLessEqual(calls, READ_ONLY_CALLS, calls)

    def test_live_mode_no_firewall_as_root_fails(self):
        self.recording_stub("ufw", 'echo "Status: inactive"')
        self.stub("id", 'case "$1" in -u) echo 0 ;; -un) echo root ;; *) echo "uid=0(root)" ;; esac')
        r = self.run_audit(EU_AUDIT_NO_REPORT="yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.lines(r.stdout, "FAIL", "firewall"), r.stdout)
        self.assertEqual(set(self.calls.read_text().splitlines()), {"ufw status"})

    def test_live_mode_ufw_active_passes(self):
        self.recording_stub("ufw", 'printf "Status: active\\n\\nTo Action From\\n"')
        r = self.run_audit(EU_AUDIT_NO_REPORT="yes")
        self.assertTrue(any("ufw" in l for l in self.lines(r.stdout, "PASS", "firewall")), r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
