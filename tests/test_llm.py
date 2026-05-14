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


def test_compress_text_for_llm_collapses_blanks() -> None:
    raw = "a\n\n\n\nb\n" + "x" * 600
    out = llm_mod.compress_text_for_llm(raw, max_line_length=200, collapse_blank_lines=True)
    assert "\n\n\n" not in out
    assert "...[truncated]" in out


def test_split_into_estimated_token_chunks() -> None:
    text = "\n".join(["x" * 30 for _ in range(20)])
    chunks = llm_mod.split_into_estimated_token_chunks(text, max_tokens=100)
    assert len(chunks) >= 2
    for c in chunks:
        assert llm_mod.estimate_tokens(c) <= 110


def test_complete_issue_map_reduce_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_LLM_MAX_USER_TOKENS", "180")

    def fake_split(text: str, max_tokens: int) -> list[str]:
        if "BIGPATCH" in text:
            return ["alpha hunk\n", "beta hunk\n"]
        return llm_mod.split_into_estimated_token_chunks(text, max_tokens=max_tokens)

    monkeypatch.setattr(llm_mod, "split_into_estimated_token_chunks", fake_split)
    monkeypatch.setattr(llm_mod, "_between_batch_sleep", lambda: None)

    analysis = {
        "risk_level": "low",
        "justification": "ok",
        "code_locations": [],
        "suggested_mitigation": "monitor",
    }
    bodies = [
        json.dumps({"content": [{"type": "text", "text": "- digest a"}]}).encode(),
        json.dumps({"content": [{"type": "text", "text": "- digest b"}]}).encode(),
        json.dumps(
            {"content": [{"type": "text", "text": json.dumps(analysis)}]},
        ).encode(),
    ]

    class Resp:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return self._payload

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        if not bodies:
            raise AssertionError("unexpected extra LLM call")
        return Resp(bodies.pop(0))

    sys_p, user_p = llm_mod.build_issue_analysis_prompts(
        "o",
        "r",
        item_title="t",
        item_body="body",
        pr_patch_summary="BIGPATCH\n" + "z\n" * 400,
    )
    out, warns = llm_mod.complete_issue_analysis(
        "claude",
        "sk-ant-api03-" + "k" * 20,
        sys_p,
        user_p,
        issue_context=("o", "r", "t", "body", "BIGPATCH\n" + "z\n" * 400),
        urlopen=fake_open,
    )
    assert not bodies
    assert out["risk_level"] == "low"
    assert any("multiple small" in w for w in warns)


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


def test_ping_llm_claude_mocked() -> None:
    body = json.dumps(
        {"content": [{"type": "text", "text": "OK"}]},
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

    text = llm_mod.ping_llm(
        "claude",
        "sk-ant-api03-" + "k" * 20,
        urlopen=fake_open,
    )
    assert text == "OK"


def test_ping_llm_gemini_mocked() -> None:
    body = json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "OK"}],
                    },
                },
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

    text = llm_mod.ping_llm(
        "gemini",
        "AIza" + "0" * 35,
        urlopen=fake_open,
    )
    assert text == "OK"
