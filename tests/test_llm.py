"""LLM orchestration tests."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from secanalyzer.exceptions import LLMError
from secanalyzer import llm as llm_mod


def test_resolve_google_generative_model_default(monkeypatch: pytest.MonkeyPatch) -> None:
    llm_mod.set_google_model_override(None)
    monkeypatch.delenv("SECANALYZER_GEMMA_MODEL", raising=False)
    monkeypatch.delenv("SECANALYZER_GEMINI_MODEL", raising=False)
    monkeypatch.setattr("secanalyzer.config.load_google_model", lambda: None)
    assert llm_mod.resolve_google_generative_model() == "gemma-3-27b-it"
    monkeypatch.setenv("SECANALYZER_GEMMA_MODEL", "gemma-3-4b-it")
    assert llm_mod.resolve_google_generative_model() == "gemma-3-4b-it"


def test_resolve_google_model_cli_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECANALYZER_GEMMA_MODEL", raising=False)
    monkeypatch.delenv("SECANALYZER_GEMINI_MODEL", raising=False)
    llm_mod.set_google_model_override("gemini-2.5-flash")
    assert llm_mod.resolve_google_generative_model() == "gemini-2.5-flash"
    llm_mod.set_google_model_override(None)


def test_is_gemma_model() -> None:
    assert llm_mod.is_gemma_model("gemma-3-27b-it")
    assert not llm_mod.is_gemma_model("gemini-2.5-flash")


def test_list_google_generate_content_models_pagination() -> None:
    pages = [
        {
            "models": [
                {"name": "models/gemma-3-27b-it", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
            ],
            "nextPageToken": "t2",
        },
        {
            "models": [
                {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
            ],
        },
    ]

    class Resp:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._raw = json.dumps(payload).encode()

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return self._raw

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        if "pageToken=t2" in req.full_url:
            return Resp(pages[1])
        return Resp(pages[0])

    models = llm_mod.list_google_generate_content_models("key", urlopen=fake_open)
    assert models == ["gemini-2.5-flash", "gemma-3-27b-it"]


def test_assert_google_model_available_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        llm_mod,
        "list_google_generate_content_models",
        lambda *_a, **_k: ["gemini-2.5-flash"],
    )
    with pytest.raises(LLMError, match="not available"):
        llm_mod.assert_google_model_available("key", "gemma-3-12b-it")


def test_gemma_call_omits_json_mime_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_GEMMA_MODEL", "gemma-3-27b-it")
    captured: dict[str, Any] = {}

    class Resp:
        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]},
            ).encode()

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        captured["body"] = json.loads(req.data.decode())
        return Resp()

    llm_mod._call_gemini(
        "AIza" + "0" * 35,
        "sys",
        "user",
        urlopen=fake_open,
        json_response=True,
    )
    gen = captured["body"].get("generationConfig") or {}
    assert "responseMimeType" not in gen


def test_parse_google_api_response_payload_error() -> None:
    with pytest.raises(LLMError, match="API error"):
        llm_mod.parse_google_api_response_payload(
            {"error": {"message": "model not found", "code": 404}},
            vendor="Gemma",
        )


def test_apply_presend_redaction_redacts_instead_of_aborting() -> None:
    secret = "ghp_" + "a" * 36
    sys_s, user_s, hits = llm_mod.apply_presend_redaction(
        "system",
        f"token = '{secret}'",
    )
    assert hits > 0
    assert "ghp_" not in user_s or "REDACTED" in user_s
    assert "system" in sys_s


def test_parse_retry_after_seconds() -> None:
    detail = "Please retry in 37.364090206s."
    assert llm_mod._parse_retry_after_seconds(429, detail) == pytest.approx(38.364, rel=0.01)
    assert llm_mod._parse_retry_after_seconds(500, detail) is None


def test_gemini_retries_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    ok_body = json.dumps(
        {
            "candidates": [
                {"content": {"parts": [{"text": "{\"ok\": true}"}]}},
            ],
        },
    ).encode()

    class Resp:
        def __init__(self, code: int, body: bytes) -> None:
            self.code = code
            self._body = body

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            if self.code >= 400:
                raise urllib.error.HTTPError(
                    "https://example/",
                    self.code,
                    "rate",
                    None,
                    self._body,
                )
            return self._body

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        calls["n"] += 1
        if calls["n"] == 1:
            err = b'{"error":{"message":"Please retry in 0.1s."}}'
            return Resp(429, err)
        return Resp(200, ok_body)

    monkeypatch.setattr(llm_mod.time, "sleep", lambda _s: None)
    raw = llm_mod._call_gemini(
        "AIza" + "0" * 35,
        "sys",
        "user",
        urlopen=fake_open,
        json_response=True,
    )
    assert calls["n"] == 2
    assert "ok" in raw


def test_server_error_retry_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECANALYZER_LLM_SERVER_ERROR_RETRY_SEC", raising=False)
    assert llm_mod._server_error_retry_seconds() == 10.0
    monkeypatch.setenv("SECANALYZER_LLM_SERVER_ERROR_RETRY_SEC", "5")
    assert llm_mod._server_error_retry_seconds() == 5.0


def test_server_error_max_retries_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECANALYZER_LLM_SERVER_ERROR_MAX_RETRIES", raising=False)
    assert llm_mod._server_error_max_retries() == 30


def test_gemini_retries_on_500(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    err_body = b'{"error":{"message":"Internal error encountered.","code":500}}'
    ok_body = json.dumps(
        {
            "candidates": [
                {"content": {"parts": [{"text": "ok"}]}},
            ],
        },
    ).encode()

    class Resp:
        def __init__(self, code: int, body: bytes) -> None:
            self.code = code
            self._body = body

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            if self.code >= 400:
                raise urllib.error.HTTPError(
                    "https://example/",
                    self.code,
                    "internal",
                    None,
                    self._body,
                )
            return self._body

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        calls["n"] += 1
        if calls["n"] == 1:
            return Resp(500, err_body)
        return Resp(200, ok_body)

    monkeypatch.setattr(llm_mod.time, "sleep", lambda _s: None)
    raw = llm_mod._call_gemini(
        "AIza" + "0" * 35,
        "sys",
        "user",
        urlopen=fake_open,
        json_response=False,
    )
    assert calls["n"] == 2
    assert "ok" in raw


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
