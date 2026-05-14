"""RepositoryAnalyzer — confine reads to the scan root, allowlist extensions, and redact secret-like patterns before downstream use."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from secanalyzer.exceptions import ScanError

# Only common source/config extensions are scanned (limits noise and accidental reads of unrelated blobs).
ALLOWED_EXTENSIONS = frozenset({
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".cxx",
    ".hpp",
    ".java",
    ".kt",
    ".rs",
    ".rb",
    ".php",
    ".swift",
    ".cs",
    ".sql",
    ".sh",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".md",
    ".html",
    ".css",
    ".scss",
    ".vue",
    ".svelte",
})

SKIP_DIR_NAMES = frozenset({
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".eggs",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "dist",
    "build",
    ".ruff_cache",
    ".idea",
    ".vscode",
})

# Per-file cap for embedded snippets (bytes); larger files are still listed.
MAX_SNIPPET_BYTES = 96_000

_REDACTION_SPECS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "github_classic_pat",
        re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
        "ghp_REDACTED",
    ),
    (
        "github_fine_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "github_pat_REDACTED",
    ),
    (
        "anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{10,}\b"),
        "sk-ant-REDACTED",
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
        "AIzaREDACTED",
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AKIAREDACTED",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "xox-REDACTED",
    ),
    (
        "stripe_live",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
        "sk_live_REDACTED",
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "-----BEGIN REDACTED PRIVATE KEY-----",
    ),
]


def redact_text(text: str) -> tuple[str, int]:
    """Return redacted text and total number of pattern matches replaced."""
    total = 0
    out = text
    for _name, pattern, repl in _REDACTION_SPECS:
        out, n = pattern.subn(repl, out)
        total += n
    return out, total


def _is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    return ctrl / max(len(sample), 1) > 0.3


def _is_under_root(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


@dataclass
class FileRecord:
    relative_path: str
    extension: str
    size_bytes: int
    line_count: int | None
    redaction_hits: int
    snippet: str | None
    skipped_reason: str | None = None


@dataclass
class ScanReport:
    root: Path
    generated_at_utc: datetime
    files: list[FileRecord] = field(default_factory=list)
    total_redactions: int = 0
    warnings: list[str] = field(default_factory=list)


def scan_repository(root_arg: str) -> ScanReport:
    """Walk *root_arg* safely and build a structured report (no LLM)."""
    root = Path(root_arg).expanduser()
    if not root.exists():
        raise ScanError(f"Path does not exist: {root_arg!r}.")
    if not root.is_dir():
        raise ScanError(f"Not a directory: {root_arg!r}.")
    root_real = root.resolve()
    if not root_real.is_dir():
        raise ScanError(f"Could not resolve directory: {root_arg!r}.")

    report = ScanReport(root=root_real, generated_at_utc=datetime.now(timezone.utc))
    for dirpath, dirnames, filenames in os.walk(
        root_real,
        topdown=True,
        followlinks=False,
    ):
        dir_path = Path(dirpath)
        if not _is_under_root(dir_path, root_real):
            report.warnings.append(f"Skipped directory outside root (symlink?): {dir_path}")
            dirnames[:] = []
            continue

        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]

        for name in filenames:
            full = dir_path / name
            try:
                rel = full.relative_to(root_real)
            except ValueError:
                report.warnings.append(f"Skipped file outside root: {full}")
                continue
            ext = full.suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue
            try:
                st = full.stat()
            except OSError as e:
                report.warnings.append(f"Could not stat {rel}: {e}")
                continue
            size = int(st.st_size)
            rec = FileRecord(
                relative_path=str(rel).replace("\\", "/"),
                extension=ext,
                size_bytes=size,
                line_count=None,
                redaction_hits=0,
                snippet=None,
            )
            if size > MAX_SNIPPET_BYTES:
                rec.skipped_reason = f"file too large for inline snippet (>{MAX_SNIPPET_BYTES} bytes)"
                report.files.append(rec)
                continue
            try:
                raw = full.read_bytes()
            except OSError as e:
                rec.skipped_reason = f"unreadable: {e}"
                report.files.append(rec)
                continue
            sample = raw[: 8000]
            if _is_probably_binary(sample):
                rec.skipped_reason = "skipped as binary"
                report.files.append(rec)
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                rec.skipped_reason = "not valid UTF-8"
                report.files.append(rec)
                continue
            redacted, hits = redact_text(text)
            rec.redaction_hits = hits
            rec.line_count = redacted.count("\n") + (1 if redacted and not redacted.endswith("\n") else 0)
            rec.snippet = redacted
            report.total_redactions += hits
            report.files.append(rec)

    report.files.sort(key=lambda f: f.relative_path)
    return report


def report_to_markdown(report: ScanReport) -> str:
    """Emit deterministic Markdown: file index, stats, and redacted snippets (no LLM in this path)."""
    lines: list[str] = []
    lines.append("# Repository security scan")
    lines.append("")
    lines.append(f"- **Root:** `{report.root}`")
    lines.append(
        f"- **Generated (UTC):** {report.generated_at_utc.strftime('%Y-%m-%d %H:%M:%S')}Z",
    )
    lines.append(f"- **Files matched allowlist:** {len(report.files)}")
    lines.append(
        f"- **Redaction pattern matches (total):** {report.total_redactions}",
    )
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(
        "This report is generated locally from allowlisted source files. "
        "An optional LLM pass could later add architecture narrative and deeper "
        "security commentary on top of this deterministic output.",
    )
    lines.append("")
    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")
    lines.append("## File index")
    lines.append("")
    lines.append("| Path | Ext | Bytes | Lines | Redactions | Notes |")
    lines.append("|------|-----|------:|------:|-----------:|-------|")
    for f in report.files:
        note = f.skipped_reason or ""
        ln = "" if f.line_count is None else str(f.line_count)
        lines.append(
            f"| `{f.relative_path}` | {f.extension} | {f.size_bytes} | {ln} | "
            f"{f.redaction_hits} | {note} |",
        )
    lines.append("")
    lines.append("## Snippets (redacted)")
    lines.append("")
    for f in report.files:
        if not f.snippet:
            continue
        lines.append(f"### `{f.relative_path}`")
        lines.append("")
        lines.append("```text")
        lines.append(f.snippet.strip("\n"))
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
