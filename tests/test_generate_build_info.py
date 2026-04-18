"""Tests for ``scripts/generate_build_info.py`` — the build-time module
generator that PyInstaller specs invoke before ``Analysis()``.

These tests guard the single point of failure for build-time metadata
injection: a silently broken generator would only surface as garbage in
``/api/v1/build`` on a deployed binary. By running the real script as a
subprocess against a controlled temp workspace we catch regressions in
pyproject parsing, git rev-parse handling, template formatting, and
error paths before a PyInstaller build is attempted.
"""

from __future__ import annotations

import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "generate_build_info.py"


def _load_generated(path: str) -> types.SimpleNamespace:
    """Read the generated file and return its module-level names.

    Uses ``runpy.run_path`` (not ``importlib``) so back-to-back reads of
    a file rewritten within the same filesystem-mtime second still see
    the current source — ``importlib``'s bytecode cache would serve the
    stale version otherwise. The generator produces plain module-level
    assignments, so there is nothing to import.
    """
    ns = runpy.run_path(path)
    return types.SimpleNamespace(**ns)


class TestGenerator(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.package_dir = os.path.join(self.tmpdir, "fake_pkg")
        os.makedirs(self.package_dir)
        self.pyproject = os.path.join(self.tmpdir, "pyproject.toml")
        with open(self.pyproject, "w", encoding="utf-8") as f:
            f.write('[project]\nname = "fake"\nversion = "1.2.3"\n')

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *extra: str) -> subprocess.CompletedProcess[str]:
        cmd = [
            sys.executable,
            str(_SCRIPT),
            "--package-dir",
            self.package_dir,
            "--pyproject",
            self.pyproject,
            *extra,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _target(self) -> str:
        return os.path.join(self.package_dir, "_build_info.py")

    # -- happy path --------------------------------------------------

    def test_generates_valid_module_with_repo_git(self) -> None:
        result = self._run("--git-root", str(_REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)

        module = _load_generated(self._target())
        self.assertEqual(module.VERSION, "1.2.3")
        self.assertEqual(len(module.GIT_COMMIT), 40)
        self.assertTrue(all(c in "0123456789abcdef" for c in module.GIT_COMMIT))
        self.assertRegex(module.BUILT_AT, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_exit_zero_prints_summary(self) -> None:
        result = self._run("--git-root", str(_REPO_ROOT))
        self.assertEqual(result.returncode, 0)
        self.assertIn("wrote", result.stdout)
        self.assertIn("version=1.2.3", result.stdout)

    def test_overwrites_existing_file(self) -> None:
        # First run
        result = self._run("--git-root", str(_REPO_ROOT))
        self.assertEqual(result.returncode, 0)
        first = _load_generated(self._target()).BUILT_AT
        # Mutate pyproject and re-run
        with open(self.pyproject, "w", encoding="utf-8") as f:
            f.write('[project]\nname = "fake"\nversion = "9.9.9"\n')
        result = self._run("--git-root", str(_REPO_ROOT))
        self.assertEqual(result.returncode, 0)
        module = _load_generated(self._target())
        self.assertEqual(module.VERSION, "9.9.9")
        # BUILT_AT may repeat if within the same second — allow ==
        self.assertGreaterEqual(module.BUILT_AT, first)

    # -- version fallbacks ------------------------------------------

    def test_pep440_version_with_local_segment(self) -> None:
        """``repr()`` in the template must survive any PEP 440 version."""
        with open(self.pyproject, "w", encoding="utf-8") as f:
            f.write('[project]\nname = "fake"\nversion = "1.0.0+local.2"\n')
        result = self._run("--git-root", str(_REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(_load_generated(self._target()).VERSION, "1.0.0+local.2")

    # -- git fallback -----------------------------------------------

    def test_git_root_outside_repo_falls_back_to_unknown(self) -> None:
        """Outside a git checkout, ``git_commit`` degrades to "unknown"."""
        non_repo = tempfile.mkdtemp()
        try:
            result = self._run("--git-root", non_repo)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(_load_generated(self._target()).GIT_COMMIT, "unknown")
        finally:
            shutil.rmtree(non_repo, ignore_errors=True)

    # -- error paths -------------------------------------------------

    def test_missing_pyproject_fails_with_clear_message(self) -> None:
        cmd = [
            sys.executable,
            str(_SCRIPT),
            "--package-dir",
            self.package_dir,
            "--pyproject",
            os.path.join(self.tmpdir, "does-not-exist.toml"),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pyproject not found", result.stderr)

    def test_missing_package_dir_fails_with_clear_message(self) -> None:
        cmd = [
            sys.executable,
            str(_SCRIPT),
            "--package-dir",
            os.path.join(self.tmpdir, "no-such-dir"),
            "--pyproject",
            self.pyproject,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package dir does not exist", result.stderr)

    def test_pyproject_missing_version_fails(self) -> None:
        with open(self.pyproject, "w", encoding="utf-8") as f:
            f.write('[project]\nname = "fake"\n')  # no version key
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version", result.stderr)


if __name__ == "__main__":
    unittest.main()
