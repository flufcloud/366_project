"""Smoke test for python -m secanalyzer."""

import subprocess
import sys


def test_module_invocation_help():
    proc = subprocess.run(
        [sys.executable, "-m", "secanalyzer", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "--scan" in proc.stdout
