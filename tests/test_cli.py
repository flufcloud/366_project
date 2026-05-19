"""Tests for CLI behavior and command dispatch."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

from secanalyzer import cli


def test_build_parser_prog():
    p = cli.build_parser()
    assert p.prog == "secanalyzer"


def test_set_google_model_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "llm_credentials.json").write_text(
        '{"provider":"gemini","api_key":"AIza' + "0" * 35 + '"}',
        encoding="utf-8",
    )
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--set-google-model", "gemini-2.5-flash"])
    assert code == 0
    from secanalyzer import config

    assert config.load_google_model() == "gemini-2.5-flash"


def test_help_exits_zero():
    buf_out = StringIO()
    buf_err = StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        with pytest.raises(SystemExit) as exc:
            cli.main(["--help"])
    assert exc.value.code == 0
    assert "secanalyzer" in buf_out.getvalue().lower() or "usage" in buf_out.getvalue().lower()


def test_version_exits_zero():
    buf_out = StringIO()
    buf_err = StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        with pytest.raises(SystemExit) as exc:
            cli.main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in buf_out.getvalue()


def test_no_args_prints_help_and_zero():
    buf_out = StringIO()
    buf_err = StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        code = cli.main([])
    assert code == 0
    out = buf_out.getvalue()
    assert "--scan" in out and "--list-issues" in out and "--llm-report" in out


def test_llm_report_mocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(cfg))
    (cfg / "llm_credentials.json").write_text(
        '{"provider":"claude","api_key":"sk-ant-api03-' + "k" * 24 + '"}',
        encoding="utf-8",
    )

    def fake_gen(
        provider: str,
        api_key: str,
        report: object,
        *,
        urlopen=None,
        progress=None,
        report_tree=None,
    ) -> tuple[str, list[str]]:
        if progress:
            progress("mock step")
        return "# LLM security report\n\n## Executive summary\n\nDone.\n", []

    monkeypatch.setattr(
        "secanalyzer.scan_llm.generate_llm_security_report",
        fake_gen,
    )
    out_md = tmp_path / "llm.md"
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--llm-report", str(repo), "-o", str(out_md)])
    assert code == 0
    assert "Executive summary" in out_md.read_text(encoding="utf-8")
    assert "mock step" in buf_err.getvalue()


def test_scan_writes_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path / "empty_cfg"))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hello.py").write_text('print("hi")\n', encoding="utf-8")
    out_md = tmp_path / "out.md"
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--scan", str(repo), "-o", str(out_md)])
    assert code == 0
    text = out_md.read_text(encoding="utf-8")
    assert "Repository security scan" in text
    assert "hello.py" in text
    assert "--llm-report" in text
    assert "## Snippets" not in text
    assert 'print("hi")' not in text


def test_scan_redaction_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    secret = "ghp_" + "0" * 36
    (repo / "t.py").write_text(f"KEY = '{secret}'\n", encoding="utf-8")
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--scan", str(repo)])
    assert code == 0
    err = buf_err.getvalue()
    assert "[WARNING]" in err and "redact" in err.lower()


def test_output_without_scan_errors() -> None:
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["-o", "x.md"])
    assert code == 1
    assert "ERROR" in buf_err.getvalue()


def test_mutually_exclusive_actions() -> None:
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--api-key-status", "--scan", "."])
    assert code == 1
    assert "one primary action" in buf_err.getvalue()


def test_test_llm_missing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--test-llm"])
    assert code == 1
    assert "not configured" in buf_err.getvalue().lower()


def test_list_google_models_ok_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "llm_credentials.json").write_text(
        '{"provider":"gemini","api_key":"AIza' + "0" * 35 + '"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "secanalyzer.llm.list_google_generate_content_models",
        lambda *_a, **_k: ["gemma-3-27b-it", "gemini-2.5-flash"],
    )
    buf_out = StringIO()
    with redirect_stdout(buf_out):
        code = cli.main(["--list-google-models"])
    assert code == 0
    assert "gemma-3-27b-it" in buf_out.getvalue()


def test_test_llm_ok_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    (tmp_path / "llm_credentials.json").write_text(
        '{"provider":"claude","api_key":"sk-ant-api03-' + "k" * 24 + '"}',
        encoding="utf-8",
    )

    def fake_ping(
        provider: str,
        api_key: str,
        *,
        urlopen=None,
    ) -> str:
        assert provider == "claude"
        return "OK"

    monkeypatch.setattr("secanalyzer.llm.ping_llm", fake_ping)
    buf_out = StringIO()
    buf_err = StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        code = cli.main(["--test-llm"])
    assert code == 0
    assert "[OK]" in buf_out.getvalue() and "claude" in buf_out.getvalue()


def test_list_issues_requires_github_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--list-issues", "o/r"])
    assert code == 1
    assert "GitHub token missing" in buf_err.getvalue()


def test_list_issues_cli_dispatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: dict[str, str] = {}

    def fake_run(owner_repo: str, **kwargs: object) -> int:
        called["owner_repo"] = owner_repo
        return 0

    monkeypatch.setattr(
        "secanalyzer.issues_session.run_list_issues",
        fake_run,
    )
    code = cli.main(["--list-issues", "octo/Hello-World"])
    assert code == 0
    assert called.get("owner_repo") == "octo/Hello-World"


def test_analyze_issue_cli_dispatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: dict[str, object] = {}

    def fake_analyze(owner_repo: str, number: int, **kwargs: object) -> tuple[str, list]:
        called["owner_repo"] = owner_repo
        called["number"] = number
        called["kwargs"] = kwargs
        return "## Risk level\n\nlow\n", []

    monkeypatch.setattr(
        "secanalyzer.issues_session.run_analyze_issue",
        fake_analyze,
    )
    buf_out = StringIO()
    with redirect_stdout(buf_out):
        code = cli.main(
            [
                "--analyze-issue",
                "octo/Hello-World",
                "--issue-number",
                "3",
                "--provider",
                "claude",
            ],
        )
    assert code == 0
    assert called.get("number") == 3
    kw = called.get("kwargs") or {}
    assert kw.get("provider_override") == "claude"


def test_api_key_status_missing_both(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    buf_out = StringIO()
    buf_err = StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        code = cli.main(["--api-key-status"])
    assert code == 1
    out = buf_out.getvalue()
    assert "[MISSING]" in out and "GitHub" in out


def test_set_token_github(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("getpass.getpass", lambda _p: "ghp_" + "c" * 36)
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--set-token", "github"])
    assert code == 0
    assert "saved" in buf_err.getvalue().lower()


def test_set_token_llm_with_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("getpass.getpass", lambda _p: "sk-ant-api03-" + "d" * 24)
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--set-token", "llm", "--provider", "claude"])
    assert code == 0


def test_provider_requires_context() -> None:
    buf_err = StringIO()
    with redirect_stderr(buf_err):
        code = cli.main(["--provider", "claude"])
    assert code == 1
    assert "ERROR" in buf_err.getvalue()
    assert "--issues" in buf_err.getvalue() or "--set-token" in buf_err.getvalue()
