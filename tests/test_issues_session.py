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


def test_run_interactive_issues_mocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "github_token").write_text("ghp_" + "z" * 36 + "\n", encoding="utf-8")
    (tmp_path / "llm_credentials.json").write_text(
        '{"provider":"claude","api_key":"sk-ant-api03-' + "q" * 24 + '"}',
        encoding="utf-8",
    )

    items = [
        WorkItem(
            number=1,
            title="Hi",
            body="Body",
            html_url="https://example/1",
            is_pull_request=False,
            author_login="a",
        ),
    ]

    def fake_list(*a: object, **k: object) -> list[WorkItem]:
        return items

    analysis = {
        "risk_level": "low",
        "justification": "ok",
        "code_locations": [],
        "suggested_mitigation": "patch",
    }

    def fake_llm(*a: object, **k: object) -> tuple[dict, list]:
        return analysis, []

    monkeypatch.setattr(
        "secanalyzer.issues_session.list_open_work_items",
        fake_list,
    )
    monkeypatch.setattr(
        "secanalyzer.issues_session.llm_mod.complete_issue_analysis",
        fake_llm,
    )

    calls: list[WorkItem | None] = [items[0], None]

    def fake_select(_its: list[WorkItem]) -> WorkItem | None:
        return calls.pop(0)

    code = run_interactive_issues(
        "o/r",
        select_work_item=fake_select,
    )
    assert code == 0
