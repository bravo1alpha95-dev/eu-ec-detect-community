#!/usr/bin/env python3
"""Community-edition hygiene: no lab addresses, fingerprints, or repo-local secrets."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Patterns that must not appear in the published tree (except this file's own strings).
# bravo1alpha95@gmail.com is the published vulnerability-report and CoC contact,
# set at the owner's request; it is not a lab leftover.
FORBIDDEN = (
    "172.29.",
    "ec.lab.internal",
    "eu-lab-ec-ops",
    "eu-lab-ec-dns",
    "eu-lab-ec-det",
    "eu-lab-ec-idx",
    "eu-lab-ec-ids",
    "eu-lab-ec-tgt",
    "0DCF CA55",
    "96B3 EE5F",
    "2911 1145",
)
PUBLISHED_CONTACT = "bravo1alpha95@gmail.com"
SKIP_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}


def _text_files():
    for path in ROOT.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield path, text


class Hygiene(unittest.TestCase):
    def test_no_internal_lab_or_secret_markers(self):
        hits = []
        for path, text in _text_files():
            for needle in FORBIDDEN:
                if needle in text:
                    hits.append(f"{path.relative_to(ROOT)}: {needle}")
        self.assertEqual(hits, [], "internal markers present:\n" + "\n".join(hits))

    def test_published_contact_email_is_only_gmail(self):
        """SECURITY.md and the Code of Conduct carry the published contact; no other Gmail addresses."""
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        coc = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
        self.assertIn(PUBLISHED_CONTACT, security)
        self.assertIn(PUBLISHED_CONTACT, coc)
        others = []
        for path, text in _text_files():
            for match in re.findall(r"[\w.+-]+@gmail\.com", text):
                if match != PUBLISHED_CONTACT:
                    others.append(f"{path.relative_to(ROOT)}: {match}")
        self.assertEqual(others, [], "unexpected Gmail addresses:\n" + "\n".join(others))


if __name__ == "__main__":
    unittest.main(verbosity=2)
