"""Per-file LLM scan orchestration tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from secanalyzer import scan_llm
from secanalyzer.repo_analyzer import FileRecord, ScanReport


def _tiny_report(tmp_path: Path) -> ScanReport:
    return ScanReport(
        root=tmp_path,
        generated_at_utc=datetime.now(timezone.utc),
        files=[
            FileRecord(
                relative_path="auth.py",
                extension=".py",
                size_bytes=40,
                line_count=2,
                redaction_hits=0,
                snippet='def login():\n    return "token"\n',
            ),
            FileRecord(
                relative_path="util.py",
                extension=".py",
                size_bytes=20,
                line_count=1,
                redaction_hits=0,
                snippet="x = 1\n",
            ),
        ],
    )


def test_validate_file_analysis_schema() -> None:
    obj = {
        "attack_surface": "high",
        "architectural_role": "auth entry",
        "findings": ["session handling"],
        "recommended_review": "Check cookies.",
    }
    out = scan_llm.validate_file_analysis(obj)
    assert out["attack_surface"] == "high"


def test_pick_high_attack_surface() -> None:
    items = [
        {"path": "a.py", "attack_surface": "low"},
        {"path": "b.py", "attack_surface": "high"},
        {"path": "c.py", "attack_surface": "medium"},
    ]
    picked = scan_llm._pick_high_attack_surface(items, top_n=2)
    assert picked[0]["path"] == "b.py"
    assert len(picked) == 2


def test_generate_llm_security_report_mocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECANALYZER_LLM_COMPACT_EVERY", "2")
    monkeypatch.setattr(scan_llm.llm_mod, "_between_batch_sleep", lambda: None)

    file_note = (
        "Attack surface: high\n"
        "Architectural role: auth\n"
        "Findings:\n"
        "- token in response\n"
        "Recommended review: Harden session.\n"
    )
    compact_text = "- Auth module handles login\n- Token returned in plaintext"
    final_md = (
        "## Executive summary\n\nMock unified report.\n\n"
        "## Architecture and trust boundaries\n\nLocal.\n\n"
        "## High attack-surface files\n\nSee notes.\n\n"
        "## Broader codebase themes\n\nN/A.\n\n"
        "## Recommended review checklist\n\n- Review.\n"
    )
    responses = [file_note, file_note, compact_text, final_md]

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
        if not responses:
            raise AssertionError("unexpected extra LLM call")
        nxt = responses.pop(0)
        body = json.dumps({"content": [{"type": "text", "text": nxt}]})
        return Resp(body.encode())

    report = _tiny_report(tmp_path)
    md, warns = scan_llm.generate_llm_security_report(
        "claude",
        "sk-ant-api03-" + "k" * 20,
        report,
        urlopen=fake_open,
    )
    assert not responses
    assert "# LLM security report" in md
    assert "Mock unified report" in md
    assert "Files analyzed by LLM" in md
    assert isinstance(warns, list)
