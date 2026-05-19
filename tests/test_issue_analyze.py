"""Issue list + analyze commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from secanalyzer.github_client import IssueComment, WorkItem
from secanalyzer.issues_session import (
    format_comments_thread,
    infer_report_scope_from_pr_summary,
    run_analyze_issue,
    run_list_issues,
)
from secanalyzer.report_tree import load_rolling_context_for_issue


def test_format_comments_thread_truncates() -> None:
    comments = [
        IssueComment(author_login="a", body="x" * 5000, created_at="2026-01-01"),
        IssueComment(author_login="b", body="y", created_at="2026-01-02"),
    ]
    text = format_comments_thread(comments, max_chars=6000)
    assert "comment 1" in text
    assert "comment 2" in text


def test_infer_report_scope_from_pr() -> None:
    pr = "### File: apps/api/handler.py\n```diff\n+line\n```\n### File: apps/api/util.py\n"
    assert infer_report_scope_from_pr_summary(pr) == "apps/api"


def test_load_rolling_context_final(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "compaction").mkdir(parents=True)
    (tree / "compaction" / "final-rolling-summary.md").write_text(
        "- auth in src/\n",
        encoding="utf-8",
    )
    text, warns = load_rolling_context_for_issue(tree)
    assert "auth in src" in text
    assert any("final-rolling" in w for w in warns)


def test_load_rolling_context_by_directory(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    d = tree / "compaction" / "by-directory" / "apps" / "api"
    d.mkdir(parents=True)
    (d / "0001-rolling-summary.md").write_text("API layer notes\n", encoding="utf-8")
    text, _ = load_rolling_context_for_issue(tree, scope="apps/api")
    assert "API layer" in text


def test_run_list_issues_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "github_token").write_text("ghp_" + "z" * 36 + "\n", encoding="utf-8")

    items = [
        WorkItem(1, "T", "b", "https://x/1", False, "alice"),
        WorkItem(2, "P", "b2", "https://x/2", True, "bob"),
    ]
    monkeypatch.setattr(
        "secanalyzer.issues_session.list_open_work_items",
        lambda *_a, **_k: items,
    )
    code = run_list_issues("o/r")
    assert code == 0


def test_run_analyze_issue_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "github_token").write_text("ghp_" + "z" * 36 + "\n", encoding="utf-8")
    (tmp_path / "llm_credentials.json").write_text(
        '{"provider":"claude","api_key":"sk-ant-api03-' + "q" * 24 + '"}',
        encoding="utf-8",
    )

    item = WorkItem(7, "Sec bug", "details", "https://x/7", False, "u")

    monkeypatch.setattr(
        "secanalyzer.issues_session.fetch_work_item",
        lambda *_a, **_k: item,
    )
    monkeypatch.setattr(
        "secanalyzer.issues_session.fetch_issue_comments",
        lambda *_a, **_k: [
            IssueComment("c", "also check auth", "2026-01-01"),
        ],
    )

    def fake_brief(*_a, **_k):
        return (
            "## Risk level\n\nhigh — auth bypass mentioned.\n\n"
            "## Security overview\n\nOverview text.\n\n"
            "## Recommended actions\n\n- Fix auth.\n",
            [],
        )

    monkeypatch.setattr(
        "secanalyzer.issues_session.llm_mod.complete_issue_brief_analysis",
        fake_brief,
    )

    md, warns = run_analyze_issue("o/r", 7)
    assert "Security overview" in md
    assert "Issue #7" in md
    assert "## Risk level" in md or "high" in md.lower()
