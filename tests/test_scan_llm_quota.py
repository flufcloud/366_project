"""Quota / degraded-report helpers for scan LLM orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secanalyzer import scan_llm
from secanalyzer.repo_analyzer import FileRecord, ScanReport


def test_estimate_llm_report_api_calls() -> None:
    assert scan_llm.estimate_llm_report_api_calls(0) == 0
    assert scan_llm.estimate_llm_report_api_calls(8, compact_every=8) == 10


def test_llm_analyzable_files_skips_lockfiles(tmp_path: Path) -> None:
    report = ScanReport(
        root=tmp_path,
        generated_at_utc=datetime.now(timezone.utc),
        files=[
            FileRecord(
                relative_path="package-lock.json",
                extension=".json",
                size_bytes=10,
                line_count=1,
                redaction_hits=0,
                snippet="{}",
            ),
            FileRecord(
                relative_path="src/app.py",
                extension=".py",
                size_bytes=10,
                line_count=1,
                redaction_hits=0,
                snippet="x=1",
            ),
        ],
    )
    out = scan_llm.llm_analyzable_files(report)
    assert len(out) == 1
    assert out[0].relative_path == "src/app.py"


def test_parse_file_analysis_text_accepts_prose() -> None:
    raw = (
        "Attack surface: low\n"
        "Architectural role: documentation\n"
        "Findings:\n"
        "- Describes install steps only\n"
        "Recommended review: Confirm no secrets in examples.\n"
    )
    obj = scan_llm.parse_file_analysis_text(raw)
    assert obj["attack_surface"] == "low"
    assert "documentation" in obj["architectural_role"]
    assert obj["narrative"].strip() == raw.strip()


def test_parse_file_analysis_text_accepts_unstructured() -> None:
    raw = (
        "* Input: A README.md file from a repository.\n"
        "* Task: Act as a security reviewer.\n"
        "Overall this looks low risk for production auth."
    )
    obj = scan_llm.parse_file_analysis_text(raw)
    assert obj["attack_surface"] in ("low", "medium", "high")
    assert obj["narrative"] == raw
    assert obj["findings"]


def test_mini_analysis_record_truncates_findings() -> None:
    mini = scan_llm.mini_analysis_record(
        {
            "path": "a.py",
            "attack_surface": "high",
            "architectural_role": "auth",
            "findings": ["one " * 40, "two", "three"],
            "recommended_review": "ignored in mini",
        },
    )
    assert mini["path"] == "a.py"
    assert len(mini["findings"]) == 2


def test_cap_rolling_summary() -> None:
    huge = "word " * 50_000
    capped, trimmed = scan_llm._cap_text_tokens(
        huge,
        100,
        label="test",
    )
    assert trimmed
    assert scan_llm.llm_mod.estimate_tokens(capped) <= 110


def test_extract_report_markdown_strips_preamble() -> None:
    raw = (
        "Unified Security Report for a repository scan.\n"
        "Markdown only.\n\n"
        "## Executive summary\n\n"
        "This repo is low risk.\n\n"
        "## Architecture and trust boundaries\n\n"
        "Local only.\n\n"
        "## High attack-surface files\n\n"
        "None.\n\n"
        "## Broader codebase themes\n\n"
        "Hygiene.\n\n"
        "## Recommended review checklist\n\n"
        "- Fix paths.\n"
    )
    out = scan_llm._extract_report_markdown(raw)
    assert out.startswith("## Executive summary")
    assert "Unified Security Report" not in out


def test_looks_like_synthesis_plan() -> None:
    plan = "*Needs to state* the low risk.\n*Expanding the* executive summary."
    assert scan_llm._looks_like_synthesis_plan(plan)
    report = (
        "## Executive summary\n\nOk.\n\n"
        "## Architecture and trust boundaries\n\nOk.\n\n"
        "## High attack-surface files\n\nOk.\n\n"
        "## Broader codebase themes\n\nOk.\n\n"
        "## Recommended review checklist\n\nOk.\n"
    )
    assert not scan_llm._looks_like_synthesis_plan(report)


def test_compact_splits_oversized_batch(monkeypatch) -> None:
    calls: list[int] = []

    def fake_once(
        provider,
        api_key,
        prior,
        analyses,
        *,
        urlopen=None,
        report_tree=None,
        split_depth=0,
    ):
        calls.append(len(analyses))
        return f"summary-{len(analyses)}", []

    monkeypatch.setattr(scan_llm, "_compact_once", fake_once)
    monkeypatch.setattr(scan_llm, "_estimate_compact_user_tokens", lambda _p, a: 50_000)

    rolling, _ = scan_llm._compact_running_context(
        "gemini",
        "key",
        "",
        [{"path": f"f{i}.py", "narrative": "x"} for i in range(4)],
    )
    assert len(calls) == 4
    assert all(n == 1 for n in calls)
    assert rolling == "summary-1"


def test_invoke_llm_step_retries_then_succeeds(monkeypatch) -> None:
    attempts = {"n": 0}

    def fake_invoke(*_a, **_k) -> str:
        attempts["n"] += 1
        if attempts["n"] < 2:
            from secanalyzer.exceptions import LLMError

            raise LLMError("Gemma HTTP 500: internal")
        return "ok"

    monkeypatch.setattr(scan_llm.llm_mod, "_invoke_llm_raw", fake_invoke)
    monkeypatch.setattr(scan_llm, "_step_max_attempts", lambda: 3)
    monkeypatch.setattr(scan_llm.llm_mod, "_server_error_retry_seconds", lambda: 0.0)
    monkeypatch.setattr(scan_llm.llm_mod, "_between_batch_sleep", lambda: None)
    monkeypatch.setattr(scan_llm, "_sleep_before_step_retry", lambda: None)

    out = scan_llm._invoke_llm_step(
        "gemini",
        "key",
        "sys",
        "user",
        step_label="test",
    )
    assert out == "ok"
    assert attempts["n"] == 2


def test_build_degraded_report_body() -> None:
    body = scan_llm._build_degraded_report_body(
        rolling_summary="- auth in src/",
        highlight_files=[
            {
                "path": "auth.py",
                "attack_surface": "high",
                "architectural_role": "login",
                "findings": ["token in response"],
                "recommended_review": "Check cookies",
            },
        ],
        per_file=[
            {
                "path": "auth.py",
                "attack_surface": "high",
                "architectural_role": "login",
            },
        ],
        error="HTTP 429",
    )
    assert "Report incomplete" in body
    assert "auth.py" in body
    assert "HTTP 429" in body
