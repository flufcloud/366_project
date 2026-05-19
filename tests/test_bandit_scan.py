"""Bandit integration for --scan."""

from __future__ import annotations

import json
from pathlib import Path

from secanalyzer import bandit_scan


def test_parse_bandit_json_counts(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    payload = {
        "results": [
            {
                "filename": str(root / "app.py"),
                "line_number": 10,
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password.",
                "test_id": "B105",
            },
            {
                "filename": str(root / "util.py"),
                "line_number": 3,
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "issue_text": "Use of assert.",
                "test_id": "B101",
            },
        ],
        "metrics": {
            "_totals": {
                "loc": 120,
                "SEVERITY.HIGH": 1,
                "SEVERITY.MEDIUM": 0,
                "SEVERITY.LOW": 1,
                "CONFIDENCE.HIGH": 1,
                "CONFIDENCE.MEDIUM": 1,
                "CONFIDENCE.LOW": 0,
                "skipped_tests": 0,
                "nosec": 0,
            },
        },
    }
    result = bandit_scan._parse_bandit_json(payload, root)
    assert result.severity_high == 1
    assert result.severity_low == 1
    assert result.loc == 120
    assert len(result.issues) == 2
    assert result.issues[0].test_id == "B105"
    assert result.top_test_ids[0][0] == "B105"


def test_run_bandit_mocked_subprocess(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.py").write_text("password = 'secret'\n", encoding="utf-8")

    sample = {
        "results": [
            {
                "filename": str(root / "main.py"),
                "line_number": 1,
                "issue_severity": "HIGH",
                "issue_confidence": "LOW",
                "issue_text": "hardcoded",
                "test_id": "B105",
            },
        ],
        "metrics": {"_totals": {"loc": 1, "SEVERITY.HIGH": 1}},
    }

    class Proc:
        returncode = 0
        stdout = json.dumps(sample)
        stderr = ""

    def fake_run(cmd, **kwargs):
        assert "-m" in cmd and "bandit" in cmd
        return Proc()

    monkeypatch.setattr(bandit_scan.subprocess, "run", fake_run)
    result, skip = bandit_scan.run_bandit_on_tree(root)
    assert skip is None
    assert result is not None
    assert result.total_issues >= 1
    assert result.python_files_scanned == 1

    md = bandit_scan.bandit_metrics_markdown(result)
    assert "## Static analysis (Bandit)" in md
    assert "B105" in md


def test_bandit_metrics_markdown_empty_issues(tmp_path: Path) -> None:
    result = bandit_scan.BanditScanResult(
        root=tmp_path,
        python_files_scanned=3,
        loc=50,
        severity_high=0,
        severity_medium=0,
        severity_low=0,
        confidence_high=0,
        confidence_medium=0,
        confidence_low=0,
        skipped_tests=0,
        nosec=0,
        issues=[],
    )
    md = bandit_scan.bandit_metrics_markdown(result)
    assert "No Bandit issues" in md
    assert "Python files under tree | 3" in md
