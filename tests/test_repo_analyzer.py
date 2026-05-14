"""RepositoryAnalyzer tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secanalyzer.exceptions import ScanError
from secanalyzer.repo_analyzer import (
    ALLOWED_EXTENSIONS,
    redact_text,
    scan_repository,
)


def test_redact_github_classic() -> None:
    text = "token ghp_123456789012345678901234567890123456"
    out, n = redact_text(text)
    assert n >= 1
    assert "ghp_123456789012345678901234567890123456" not in out
    assert "ghp_REDACTED" in out


def test_redact_private_key_block() -> None:
    text = "k\n-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----\n"
    out, n = redact_text(text)
    assert n >= 1
    assert "ABC" not in out
    assert "REDACTED" in out


def test_scan_skips_disallowed_extension(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"\x00\x01")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    r = scan_repository(str(tmp_path))
    assert len(r.files) == 1
    assert r.files[0].relative_path == "b.py"


def test_scan_not_dir(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ScanError):
        scan_repository(str(f))


def test_scan_missing() -> None:
    with pytest.raises(ScanError):
        scan_repository("/nonexistent/path/that/does/not/exist/ever")


def test_path_confinement(tmp_path: Path) -> None:
    """Regression: only files under root are included."""
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "m.py").write_text("# ok\n", encoding="utf-8")
    r = scan_repository(str(tmp_path))
    rels = {f.relative_path.replace("\\", "/") for f in r.files}
    assert "pkg/m.py" in rels


@pytest.mark.skipif(os.name == "nt", reason="symlink privilege often unavailable on Windows")
def test_symlink_escape_not_followed(tmp_path: Path) -> None:
    """followlinks=False: do not descend into symlinked dirs."""
    safe = tmp_path / "safe"
    safe.mkdir()
    outside = tmp_path.parent / f"outside_{os.getpid()}"
    outside.mkdir(exist_ok=True)
    try:
        (outside / "secret.py").write_text("pw = 'x'\n", encoding="utf-8")
        link = safe / "evil"
        link.symlink_to(outside, target_is_directory=True)
        (safe / "good.py").write_text("a = 1\n", encoding="utf-8")
        r = scan_repository(str(tmp_path))
        rels = [f.relative_path.replace("\\", "/") for f in r.files]
        assert any("good.py" in x for x in rels)
        assert not any("secret.py" in x for x in rels)
    finally:
        (outside / "secret.py").unlink(missing_ok=True)
        outside.rmdir()


def test_allowlist_contains_python() -> None:
    assert ".py" in ALLOWED_EXTENSIONS
