"""Attribution guards — keep NOTICE.md honest as we add/remove upstream content."""

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
NOTICE = REPO_ROOT / "NOTICE.md"
LICENSES_DIR = REPO_ROOT / "third_party" / "LICENSES"


class TestNoticeFilePresent(unittest.TestCase):
    def test_notice_exists(self):
        self.assertTrue(NOTICE.is_file(), f"missing repo-root NOTICE.md at {NOTICE}")

    def test_licenses_dir_exists(self):
        self.assertTrue(LICENSES_DIR.is_dir(), f"missing {LICENSES_DIR}")

    def test_notice_mentions_every_adapted_upstream(self):
        text = NOTICE.read_text()
        # Upstream projects we pull rule content or code from.
        for upstream in ("gitleaks", "phonenumbers", "aiohttp", "pyahocorasick", "pyyaml"):
            self.assertIn(upstream, text.lower(), f"NOTICE.md does not mention {upstream}")

    def test_notice_references_every_license_file(self):
        text = NOTICE.read_text()
        for path in LICENSES_DIR.glob("*.txt"):
            self.assertIn(
                path.name,
                text,
                f"NOTICE.md does not reference {path.name} — attribution drift",
            )

    def test_license_files_nonempty(self):
        for path in LICENSES_DIR.glob("*.txt"):
            self.assertGreater(path.stat().st_size, 100, f"{path} is suspiciously small")

    def test_gitleaks_tagged_rules_listed_in_notice(self):
        import json

        community = json.loads(
            (REPO_ROOT / "packages" / "proxy" / "lumen_argus" / "rules" / "community.json").read_text()
        )
        gitleaks_rules = sorted(r["name"] for r in community["rules"] if "gitleaks" in r.get("tags", []))
        self.assertTrue(gitleaks_rules, "no gitleaks-tagged rules found — sanity check failed")

        notice_text = NOTICE.read_text()
        # Every gitleaks-tagged rule must be named in NOTICE.md so provenance
        # can't silently drift if a rule is added/removed.
        for name in gitleaks_rules:
            self.assertIn(
                name,
                notice_text,
                f"rule {name!r} is tagged gitleaks but not listed in NOTICE.md",
            )


if __name__ == "__main__":
    unittest.main()
