"""ConfigManager — store GitHub and LLM secrets outside the repo, validate shapes, and load keys only for outbound API calls."""

from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from platformdirs import user_config_dir

from secanalyzer.exceptions import ConfigurationError

APP_DIR_NAME = "secanalyzer"
GITHUB_API_USER = "https://api.github.com/user"

# If set (e.g. in tests), credentials are read/written under this directory only.
_CONFIG_DIR_ENV = "SECANALYZER_CONFIG_DIR"

_LLM_INPUT_ALIASES = frozenset({"claude", "gemini", "anthropic"})


def config_dir() -> Path:
    override = os.environ.get(_CONFIG_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return Path(user_config_dir(APP_DIR_NAME, appauthor=False))


def github_token_path() -> Path:
    return config_dir() / "github_token"


def llm_config_path() -> Path:
    return config_dir() / "llm_credentials.json"


def _chmod_secret_file(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def ensure_config_dir() -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(d, stat.S_IRWXU)
        except OSError:
            pass
    return d


def _validate_github_token_shape(token: str) -> None:
    t = token.strip()
    if not t:
        raise ConfigurationError("GitHub token is empty.")
    if t.startswith("ghp_") and len(t) >= 40:
        return
    if t.startswith("github_pat_") and len(t) >= 20:
        return
    raise ConfigurationError(
        "GitHub token does not look like a valid PAT "
        "(expected prefix ghp_ or github_pat_ with plausible length).",
    )


def save_github_token(token: str) -> None:
    _validate_github_token_shape(token)
    ensure_config_dir()
    path = github_token_path()
    path.write_text(token.strip() + "\n", encoding="utf-8")
    _chmod_secret_file(path)


def load_github_token() -> str | None:
    path = github_token_path()
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    return raw or None


def _normalize_provider(name: str) -> str:
    p = name.strip().lower()
    if p == "anthropic":
        return "claude"
    return p


def _validate_llm_key_shape(provider: str, api_key: str) -> None:
    if not api_key.strip():
        raise ConfigurationError("LLM API key is empty.")
    if provider == "claude":
        if not api_key.startswith("sk-ant-"):
            raise ConfigurationError(
                "Anthropic API keys usually start with sk-ant-. Check your key.",
            )
        return
    if provider == "gemini":
        if not api_key.startswith("AIza"):
            raise ConfigurationError(
                "Google AI Studio / Gemini keys usually start with AIza. Check your key.",
            )
        return


def save_llm_credentials(provider: str, api_key: str) -> None:
    raw = provider.strip().lower()
    if raw not in _LLM_INPUT_ALIASES:
        raise ConfigurationError(
            f"Unsupported LLM provider {provider!r}. "
            f"Use one of: {', '.join(sorted(_LLM_INPUT_ALIASES))}.",
        )
    p = _normalize_provider(raw)
    _validate_llm_key_shape(p, api_key)
    ensure_config_dir()
    path = llm_config_path()
    payload = {"provider": p, "api_key": api_key.strip()}
    path.write_text(json.dumps(payload), encoding="utf-8")
    _chmod_secret_file(path)


def load_llm_config() -> tuple[str, str] | None:
    path = llm_config_path()
    if not path.is_file():
        return None
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ConfigurationError(
            "LLM credentials file is corrupted (invalid JSON). Re-run --set-token llm.",
        ) from e
    if not isinstance(data, dict):
        raise ConfigurationError("LLM credentials file has unexpected shape.")
    prov = data.get("provider")
    key = data.get("api_key")
    if not isinstance(prov, str) or not isinstance(key, str):
        raise ConfigurationError("LLM credentials file is missing provider or api_key.")
    return _normalize_provider(prov), key


def validate_github_token(
    token: str,
    urlopen: Callable[..., Any] | None = None,
) -> tuple[bool, str]:
    """Return (ok, human_message). Does not raise for HTTP or malformed tokens."""
    try:
        _validate_github_token_shape(token)
    except ConfigurationError as e:
        return False, str(e)
    opener = urlopen or urllib.request.urlopen
    req = urllib.request.Request(
        GITHUB_API_USER,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "secanalyzer-cli",
        },
        method="GET",
    )
    try:
        with opener(req, timeout=15) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            if code == 200:
                return True, "valid"
            return False, f"GitHub returned HTTP {code}."
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, "invalid or unauthorized (check token scopes)."
        return False, f"GitHub HTTP error: {e.code}."
    except urllib.error.URLError as e:
        return False, f"cannot reach GitHub ({e.reason})."
    except OSError as e:
        return False, f"network error ({e})."


def validate_llm_credentials_shape() -> tuple[bool, str, str | None]:
    """Format-only check for stored LLM key. Returns (ok, message, provider_or_none)."""
    cfg = load_llm_config()
    if cfg is None:
        return False, "not configured", None
    provider, key = cfg
    try:
        _validate_llm_key_shape(provider, key)
    except ConfigurationError as e:
        return False, str(e), provider
    return True, "format looks valid", provider
