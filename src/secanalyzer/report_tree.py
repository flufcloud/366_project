"""Hierarchical on-disk artifacts for ``--llm-report`` (per-file → compaction → synthesis)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def common_parent_dir(relative_paths: list[str]) -> str:
    """Longest shared directory prefix for repo-relative paths (POSIX-style)."""
    if not relative_paths:
        return "_root"
    normed = [p.replace("\\", "/") for p in relative_paths]
    if len(normed) == 1:
        parent = Path(normed[0]).parent
        text = parent.as_posix()
        return "_root" if text in ("", ".") else text
    part_lists = [Path(p).parts for p in normed]
    common: list[str] = []
    for tokens in zip(*part_lists, strict=False):
        if len(set(tokens)) == 1:
            common.append(tokens[0])
        else:
            break
    if not common:
        return "_root"
    return Path(*common).as_posix()


def resolve_report_tree_dir(
    explicit: Path | str | None,
    output_file: Path | None,
) -> Path | None:
    """Choose report tree directory from flag, env, or ``-o`` path."""
    if explicit is not None and str(explicit).strip():
        return Path(explicit).expanduser()
    env = os.environ.get("SECANALYZER_LLM_REPORT_DIR")
    if env and str(env).strip():
        return Path(env).expanduser()
    if output_file is not None:
        out = output_file.expanduser()
        return out.parent / f"{out.stem}.report-tree"
    return None


@dataclass
class ReportTreeWriter:
    """Write per-file reviews, compaction layers, and synthesis under *root*."""

    root: Path
    _sequential_pass: int = 0
    _directory_pass: dict[str, int] = field(default_factory=dict)
    _synthesis_partial: int = 0

    def __post_init__(self) -> None:
        self.root = self.root.expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("files", "compaction/sequential", "compaction/by-directory", "synthesis"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def write_readme(self, *, scan_root: Path, files_analyzed: int) -> None:
        text = (
            "# LLM report artifact tree\n\n"
            f"- **Scan root:** `{scan_root}`\n"
            f"- **Files analyzed:** {files_analyzed}\n\n"
            "## Layout\n\n"
            "| Path | Contents |\n"
            "|------|----------|\n"
            "| `files/` | Per-file security reviews (mirrors repo paths) |\n"
            "| `compaction/sequential/` | Rolling summaries after each compaction pass (time order) |\n"
            "| `compaction/by-directory/` | Rolling summaries grouped by directory in the batch |\n"
            "| `compaction/final-rolling-summary.md` | Last rolling context before synthesis |\n"
            "| `synthesis/` | Final (and optional partial) unified reports |\n"
            "| `REPORT.md` | Full deliverable (same as `-o` when used) |\n"
        )
        (self.root / "README.md").write_text(text, encoding="utf-8")

    def _file_review_path(self, relative_path: str) -> Path:
        rel = relative_path.replace("\\", "/")
        out = self.root / "files" / f"{rel}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        return out

    def write_file_review(self, analysis: dict[str, Any]) -> Path:
        rel = str(analysis.get("path", "unknown"))
        path = self._file_review_path(rel)
        findings = analysis.get("findings") or []
        lines = [
            f"# File review: `{rel}`",
            "",
            f"- **Attack surface:** {analysis.get('attack_surface', '?')}",
            f"- **Architectural role:** {analysis.get('architectural_role', '')}",
            "",
        ]
        if findings:
            lines.append("## Findings")
            lines.append("")
            for item in findings:
                if isinstance(item, str) and item.strip():
                    lines.append(f"- {item.strip()}")
            lines.append("")
        review = analysis.get("recommended_review")
        if isinstance(review, str) and review.strip():
            lines.extend(["## Recommended review", "", review.strip(), ""])
        narrative = analysis.get("narrative")
        if isinstance(narrative, str) and narrative.strip():
            lines.extend(["## Full model notes", "", narrative.strip(), ""])
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def write_compaction(
        self,
        *,
        relative_paths: list[str],
        prior_summary: str,
        batch_input: str,
        rolling_output: str,
        split_depth: int = 0,
    ) -> Path:
        self._sequential_pass += 1
        seq_dir = self.root / "compaction" / "sequential" / f"{self._sequential_pass:04d}"
        seq_dir.mkdir(parents=True, exist_ok=True)
        manifest = "\n".join(relative_paths) + "\n"
        (seq_dir / "manifest.txt").write_text(manifest, encoding="utf-8")
        (seq_dir / "prior-rolling-summary.md").write_text(
            prior_summary.strip() or "(empty)\n",
            encoding="utf-8",
        )
        (seq_dir / "batch-input.md").write_text(batch_input.strip() + "\n", encoding="utf-8")
        out_path = seq_dir / "rolling-summary.md"
        out_path.write_text(rolling_output.strip() + "\n", encoding="utf-8")
        if split_depth:
            (seq_dir / "meta.txt").write_text(
                f"split_depth={split_depth}\n",
                encoding="utf-8",
            )

        parent = common_parent_dir(relative_paths)
        self._directory_pass[parent] = self._directory_pass.get(parent, 0) + 1
        dir_dir = self.root / "compaction" / "by-directory" / parent
        dir_dir.mkdir(parents=True, exist_ok=True)
        dir_out = dir_dir / f"{self._directory_pass[parent]:04d}-rolling-summary.md"
        dir_body = [
            f"# Compaction — `{parent}`",
            "",
            f"**Pass:** {self._directory_pass[parent]} (global sequential #{self._sequential_pass})",
            "",
            "## Files in batch",
            "",
        ]
        for p in relative_paths:
            dir_body.append(f"- `{p}`")
        dir_body.extend(
            [
                "",
                "## Rolling summary",
                "",
                rolling_output.strip(),
                "",
            ],
        )
        dir_out.write_text("\n".join(dir_body), encoding="utf-8")
        return out_path

    def write_final_rolling(self, rolling_summary: str) -> Path:
        path = self.root / "compaction" / "final-rolling-summary.md"
        path.write_text(rolling_summary.strip() + "\n", encoding="utf-8")
        return path

    def write_synthesis_partial(self, body: str, *, label: str) -> Path:
        self._synthesis_partial += 1
        path = self.root / "synthesis" / f"partial-{self._synthesis_partial:03d}-{label}.md"
        path.write_text(body.strip() + "\n", encoding="utf-8")
        return path

    def write_synthesis_final(self, body: str) -> Path:
        path = self.root / "synthesis" / "final-report.md"
        path.write_text(body.strip() + "\n", encoding="utf-8")
        return path

    def write_deliverable(self, full_markdown: str) -> Path:
        path = self.root / "REPORT.md"
        path.write_text(full_markdown, encoding="utf-8")
        return path


def _normalize_scope(scope: str) -> str:
    text = scope.strip().replace("\\", "/").strip("/")
    if not text or text == ".":
        return "_root"
    return text


def _latest_rolling_summary_in_dir(directory: Path) -> str | None:
    if not directory.is_dir():
        return None
    files = sorted(directory.glob("*-rolling-summary.md"))
    if not files:
        return None
    return files[-1].read_text(encoding="utf-8")


def load_rolling_context_for_issue(
    tree_root: Path,
    *,
    scope: str | None = None,
    max_tokens: int | None = None,
) -> tuple[str, list[str]]:
    """Load codebase rolling summary from an ``--llm-report`` artifact tree.

    With *scope* (repo-relative directory prefix), uses the newest
    ``compaction/by-directory/<scope>/`` summary; otherwise uses
    ``compaction/final-rolling-summary.md``.
    """
    from secanalyzer import llm as llm_mod

    warnings: list[str] = []
    root = tree_root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Report tree not found: {root}")

    text: str | None = None
    if scope and str(scope).strip():
        norm = _normalize_scope(scope)
        walked = Path(*norm.split("/")) if norm != "_root" else Path()
        parts = walked.parts
        for i in range(len(parts), -1, -1):
            prefix = Path(*parts[:i]).as_posix() if i else "_root"
            if prefix == ".":
                prefix = "_root"
            candidate = root / "compaction" / "by-directory" / prefix
            text = _latest_rolling_summary_in_dir(candidate)
            if text:
                warnings.append(
                    f"Using directory rolling summary: compaction/by-directory/{prefix}/",
                )
                break
        if text is None:
            warnings.append(
                f"No by-directory rolling summary for scope {scope!r}; "
                "falling back to final-rolling-summary.md.",
            )

    if text is None:
        final_path = root / "compaction" / "final-rolling-summary.md"
        if final_path.is_file():
            text = final_path.read_text(encoding="utf-8")
            warnings.append("Using compaction/final-rolling-summary.md.")
        else:
            raise FileNotFoundError(
                f"No rolling summary in report tree {root} "
                "(expected compaction/final-rolling-summary.md).",
            )

    cap = max_tokens
    if cap is None:
        raw = os.environ.get("SECANALYZER_ISSUE_REPORT_CONTEXT_MAX_TOKENS", "6000")
        try:
            cap = max(500, int(raw))
        except ValueError:
            cap = 6000

    if llm_mod.estimate_tokens(text) > cap:
        text = llm_mod._head_within_token_budget(text, cap)
        warnings.append(
            f"Codebase rolling context truncated to ~{cap} estimated tokens.",
        )
    return text.strip(), warnings
