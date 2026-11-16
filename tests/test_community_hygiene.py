#!/usr/bin/env python3
"""Community-edition hygiene: no lab addresses, fingerprints, or repo-local secrets."""
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# SHA-256 (hex) of lowercase denied markers: IP prefixes, hostnames, and
# fingerprint fragments. Candidates extracted from each file are hashed and
# compared, so the markers themselves are not stored in this tree.
FORBIDDEN_HASHES = frozenset(
    {
        "608c01858acbf9d98c17e1955670dc1bcbdba209c0f88c0d4679d099fca31f87",
        "98d64f38329ef7d46acea504cf1532341ecdc10946a7168f73a5c685f4d8017a",
        "9397c3e356b96af7fce5f60f3c8c55007b0c4c70a45d66668723dd7293142476",
        "ce04a25f968566f3dc8ca634a4c9e9531f935c29ee5c2e325b4d068c449bd205",
        "0ecfd728378b3bcd2a3963ab72b42c09d3dc15b81d6cfe855c26500d4957bc57",
        "03989f51bd6ac948f8678725d233f27282c5c57454b0cc2d27f3df88936828ae",
        "0000835ed8a1534b54cf3068badf6734bbdd814e704121914aa228120f9519d9",
        "bad31798afb6aa47a20db0774e6aa029ab52605e86aa37372ee17241a565240b",
        "3cf08f1fded51e5a16e2b3e97d628c93990a01a7a71e31ad6e0a04291ea5602a",
        "fc22adf66c536f76b534f6a9f81b36c9d8b7b098a06e61f0c18b819dcc2bd52c",
        "16b3758787b0d35ecf558eea4b8d560fbe742c3a8d0fb6922a0ff431f0841199",
    }
)
PUBLISHED_CONTACT = "bravo1alpha95@gmail.com"
SKIP_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}

_IP_PREFIX = re.compile(r"\d{1,3}\.\d{1,3}\.")
_DOMAIN = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b"
)
_HYPHENATED = re.compile(r"\b[a-z0-9]+(?:-[a-z0-9]+)+\b")
_FP_FRAG = re.compile(r"\b[0-9a-f]{4} [0-9a-f]{4}\b")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidates(text: str):
    lowered = text.lower()
    found = set()
    for pattern in (_IP_PREFIX, _DOMAIN, _HYPHENATED, _FP_FRAG):
        found.update(pattern.findall(lowered))
    return found


def _text_files():
    for path in ROOT.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield path, text


class Hygiene(unittest.TestCase):
    def test_forbidden_hashes_are_well_formed(self):
        self.assertEqual(len(FORBIDDEN_HASHES), 11)
        for digest in FORBIDDEN_HASHES:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_hasher_detects_injected_token(self):
        token = "example-forbidden-token"
        digest = _sha256(token)
        hashed = {_sha256(candidate) for candidate in _candidates(f"prefix {token} suffix")}
        self.assertIn(digest, hashed)
        self.assertNotIn(digest, FORBIDDEN_HASHES)

    def test_no_internal_lab_or_secret_markers(self):
        hits = []
        for path, text in _text_files():
            for candidate in sorted(_candidates(text)):
                if _sha256(candidate) in FORBIDDEN_HASHES:
                    hits.append(f"{path.relative_to(ROOT)}: hashed marker {_sha256(candidate)[:12]}")
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
