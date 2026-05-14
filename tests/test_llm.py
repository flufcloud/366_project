"""LLM orchestration tests."""

from __future__ import annotations

import json
from typing import Any

import pytest

from secanalyzer.exceptions import LLMError
from secanalyzer import llm as llm_mod


def test_estimate_tokens() -> None:
    assert llm_mod.estimate_tokens("") == 0
    assert llm_mod.estimate_tokens("abc") == 1


def test_presend_filter_blocks_secrets() -> None:
    bad = "token " + "ghp_" + "0" * 36
    with pytest.raises(LLMError):
        llm_mod.assert_prompt_passes_presend_filter(bad)


def test_validate_schema_ok() -> None:
    obj = {
        "risk_level": "high",
        "justification": "Because.",
        "code_locations": [{"path": "a.py", "line_start": 1, "line_end": 2}],
        "suggested_mitigation": "Fix it.",
    }
    out = llm_mod.validate_analysis_schema(obj)
    assert out["risk_level"] == "high"


def test_validate_schema_bad_risk() -> None:
    with pytest.raises(LLMError):
        llm_mod.validate_analysis_schema({"risk_level": "nope"})


def test_parse_json_strips_fence() -> None:
    raw = '```json\n{"risk_level":"low","justification":"x","code_locations":[],"suggested_mitigation":"y"}\n```'
    obj = llm_mod.parse_json_object_from_model(raw)
    assert obj["risk_level"] == "low"


def test_complete_issue_analysis_anthropic_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    analysis = {
        "risk_level": "medium",
        "justification": "J",
        "code_locations": [],
        "suggested_mitigation": "M",
    }
    body = json.dumps(
        {
            "content": [
                {"type": "text", "text": json.dumps(analysis)},
            ],
        },
    ).encode("utf-8")

    class Resp:
        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return body

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        return Resp()

    out, warns = llm_mod.complete_issue_analysis(
        "claude",
        "sk-ant-api03-" + "k" * 20,
        "system text here",
        "user " * 50,
        urlopen=fake_open,
    )
    assert out["risk_level"] == "medium"
    assert isinstance(warns, list)
