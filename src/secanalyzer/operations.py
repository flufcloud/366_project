"""Operational logging for secanalyzer.

The CLI is intentionally local-only, so "monitoring" means durable, private
events that a user can inspect after a run: command starts/failures, scan
metrics, redaction hits, GitHub/LLM API errors, and retry pressure.  This module
keeps those events out of stdout/stderr reports and aggressively avoids secrets.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from platformdirs import user_log_dir

APP_LOGGER_NAME = "secanalyzer.operations"
_RUN_ID = uuid.uuid4().hex[:12]
_CONFIGURED = False
_LOG_PATH: Path | None = None

_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)


class JsonLineFormatter(logging.Formatter):
    """Serialize log records as one compact JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "run_id": _RUN_ID,
            "event": getattr(record, "event_name", record.getMessage()),
        }
        fields = getattr(record, "event_fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _default_log_path() -> Path:
    return Path(user_log_dir("secanalyzer", appauthor=False)) / "operations.jsonl"


def _coerce_level(raw: str | None) -> int:
    if not raw:
        return logging.INFO
    return getattr(logging, raw.strip().upper(), logging.INFO)


def _sanitize_value(value: Any) -> Any:
    """Keep logs useful while preventing accidental prompt/token dumps."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        text = value.replace("\r", "\\r").replace("\n", "\\n")
        return text[:500] + ("...[truncated]" if len(text) > 500 else "")
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_value(item) for item in list(value)[:20]]
    if isinstance(value, dict):
        return _sanitize_fields(value)
    return repr(value)[:500]


def _sanitize_fields(fields: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in fields.items():
        key_text = str(key)
        lower = key_text.lower()
        if any(part in lower for part in _SENSITIVE_KEY_PARTS):
            safe[key_text] = "[REDACTED]"
        else:
            safe[key_text] = _sanitize_value(value)
    return safe


def configure_logging() -> Path | None:
    """Configure JSONL operational logging once per process.

    Environment controls:
    - ``SECANALYZER_LOG_DISABLE=1`` disables file logging.
    - ``SECANALYZER_LOG_FILE=/path/file.jsonl`` overrides the default location.
    - ``SECANALYZER_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR`` changes verbosity.
    """
    global _CONFIGURED, _LOG_PATH
    if _CONFIGURED:
        return _LOG_PATH

    _CONFIGURED = True
    logger = logging.getLogger(APP_LOGGER_NAME)
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(_coerce_level(os.environ.get("SECANALYZER_LOG_LEVEL")))

    if os.environ.get("SECANALYZER_LOG_DISABLE", "").strip().lower() in {"1", "true", "yes"}:
        logger.addHandler(logging.NullHandler())
        _LOG_PATH = None
        return None

    raw_path = os.environ.get("SECANALYZER_LOG_FILE")
    path = Path(raw_path).expanduser() if raw_path and raw_path.strip() else _default_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
    except OSError:
        logger.addHandler(logging.NullHandler())
        _LOG_PATH = None
        return None

    handler.setFormatter(JsonLineFormatter())
    logger.addHandler(handler)
    _LOG_PATH = path
    event("operations.logging_configured", log_file=path)
    return path


def event(name: str, *, level: int = logging.INFO, **fields: Any) -> None:
    """Record one sanitized operational event."""
    logger = logging.getLogger(APP_LOGGER_NAME)
    if not _CONFIGURED:
        configure_logging()
    logger.log(
        level,
        name,
        extra={
            "event_name": name,
            "event_fields": _sanitize_fields(fields),
        },
    )


def security_event(name: str, **fields: Any) -> None:
    """Record a warning-level event for security-relevant behavior."""
    event(name, level=logging.WARNING, security_event=True, **fields)
