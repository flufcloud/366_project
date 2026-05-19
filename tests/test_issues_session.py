"""Issues / PR interactive session tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from secanalyzer.exceptions import UserFacingError
from secanalyzer.github_client import WorkItem
from secanalyzer.issues_session import (
    _resolve_llm_provider,
    render_analysis_markdown,
    run_interactive_issues,
)


def test_resolve_provider_ok() -> None:
    p, k = _resolve_llm_provider(("claude", "sk-ant-api03-abc"), "anthropic")
    assert p == "claude"
    assert k == "sk-ant-api03-abc"


def test_resolve_provider_mismatch() -> None:
    with pytest.raises(UserFacingError):
        _resolve_llm_provider(("claude", "sk-ant-api03-abc"), "gemini")


def test_render_markdown() -> None:
    item = WorkItem(
        number=9,
        title="T",
        body="b",
        html_url="https://x",
        is_pull_request=True,
        author_login="u",
    )
    md = render_analysis_markdown(
        "o",
        "r",
        item,
        {
            "risk_level": "low",
            "justification": "J",
            "code_locations": [{"path": "p.py", "line_start": 2, "line_end": 4}],
            "suggested_mitigation": "Do",
        },
    )
    assert "Pull request" in md
    assert "`p.py`" in md


def test_run_interactive_issues_deprecated_lists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "github_token").write_text("ghp_" + "z" * 36 + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "secanalyzer.issues_session.list_open_work_items",
        lambda *_a, **_k: [],
    )
    code = run_interactive_issues("o/r")
    assert code == 0
