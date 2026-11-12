#!/usr/bin/env python3
"""Community-edition hygiene: no lab addresses, fingerprints, or repo-local secrets."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Patterns that must not appear in the published tree (except this file's own strings).
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
    "@gmail.com",
    "bravo1alpha95@gmail.com",
)

SKIP_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}


class Hygiene(unittest.TestCase):
    def test_no_internal_lab_or_secret_markers(self):
        hits = []
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
            for needle in FORBIDDEN:
                if needle in text:
                    hits.append(f"{path.relative_to(ROOT)}: {needle}")
        self.assertEqual(hits, [], "internal markers present:\n" + "\n".join(hits))


if __name__ == "__main__":
    unittest.main(verbosity=2)
