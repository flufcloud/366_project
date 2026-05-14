"""OutputHandler — write UTF-8 Markdown or text to stdout or a file path."""

from __future__ import annotations

import sys
from pathlib import Path


def write_report(markdown: str, output_path: Path | None) -> None:
    """Write *markdown* to *output_path* or stdout. UTF-8 only."""
    if output_path is None:
        sys.stdout.write(markdown)
        if not markdown.endswith("\n"):
            sys.stdout.write("\n")
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
