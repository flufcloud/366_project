"""ConfigManager unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from secanalyzer import config
from secanalyzer.exceptions import ConfigurationError


@pytest.fixture
def cfg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SECANALYZER_CONFIG_DIR", str(tmp_path))
    return tmp_path


def test_save_and_load_github_token(cfg_home: Path) -> None:
    tok = "ghp_" + "x" * 36
    config.save_github_token(tok)
    assert config.load_github_token() == tok


def test_save_github_token_rejects_bad_prefix(cfg_home: Path) -> None:
    with pytest.raises(ConfigurationError):
        config.save_github_token("not-a-token")


def test_save_llm_roundtrip(cfg_home: Path) -> None:
    config.save_llm_credentials("claude", "sk-ant-api03-" + "y" * 20)
    p, k = config.load_llm_config()  # type: ignore[misc]
    assert p == "claude"
    assert k.startswith("sk-ant-")


def test_anthropic_alias_normalizes(cfg_home: Path) -> None:
    config.save_llm_credentials("anthropic", "sk-ant-api03-" + "z" * 20)
    p, _ = config.load_llm_config()  # type: ignore[misc]
    assert p == "claude"


def test_validate_github_token_shape_error() -> None:
    ok, msg = config.validate_github_token("bad")
    assert ok is False
    assert "ghp_" in msg or "github_pat_" in msg


def test_validate_github_token_mocked_ok(cfg_home: Path) -> None:
    tok = "ghp_" + "a" * 36

    class Resp:
        status = 200

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def getcode(self) -> int:
            return 200

    def fake_open(*a: object, **k: object) -> Resp:
        return Resp()

    ok, msg = config.validate_github_token(tok, urlopen=fake_open)
    assert ok is True


def test_validate_github_token_mocked_401(cfg_home: Path) -> None:
    tok = "ghp_" + "b" * 36
    err = __import__("urllib.error", fromlist=["HTTPError"]).HTTPError(
        "https://api.github.com/user",
        401,
        "Unauthorized",
        {},
        None,
    )

    def boom(*a: object, **k: object) -> None:
        raise err

    ok, msg = config.validate_github_token(tok, urlopen=boom)
    assert ok is False
    assert "401" in msg or "invalid" in msg.lower()
