"""Run Bandit static analysis on a repository tree (non-LLM ``--scan``)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from secanalyzer.repo_analyzer import SKIP_DIR_NAMES

# Align with repository walk skips (Bandit ``-x`` comma-separated path fragments).
_BANDIT_EXCLUDE = ",".join(sorted(SKIP_DIR_NAMES))


@dataclass(frozen=True)
class BanditIssue:
    relative_path: str
    line_number: int
    severity: str
    confidence: str
    test_id: str
    issue_text: str


@dataclass
class BanditScanResult:
    """Aggregated Bandit output for one repository root."""

    root: Path
    python_files_scanned: int
    loc: int
    severity_high: int
    severity_medium: int
    severity_low: int
    confidence_high: int
    confidence_medium: int
    confidence_low: int
    skipped_tests: int
    nosec: int
    issues: list[BanditIssue] = field(default_factory=list)
    issues_truncated: bool = False
    top_test_ids: list[tuple[str, int]] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        return self.severity_high + self.severity_medium + self.severity_low


def _parse_bandit_json(payload: dict[str, object], root: Path) -> BanditScanResult:
    results_raw = payload.get("results")
    results: list[dict[str, object]] = []
    if isinstance(results_raw, list):
        for item in results_raw:
            if isinstance(item, dict):
                results.append(item)

    metrics_raw = payload.get("metrics")
    totals: dict[str, object] = {}
    if isinstance(metrics_raw, dict):
        t = metrics_raw.get("_totals")
        if isinstance(t, dict):
            totals = t

    def _int(key: str) -> int:
        val = totals.get(key)
        if isinstance(val, (int, float)):
            return int(val)
        return 0

    issues: list[BanditIssue] = []
    test_counts: Counter[str] = Counter()
    root_resolved = root.resolve()

    for row in results:
        fname = row.get("filename")
        if not isinstance(fname, str):
            continue
        try:
            rel = Path(fname).resolve().relative_to(root_resolved).as_posix()
        except ValueError:
            rel = fname.replace("\\", "/")

        sev = str(row.get("issue_severity") or "UNDEFINED").upper()
        conf = str(row.get("issue_confidence") or "UNDEFINED").upper()
        test_id = str(row.get("test_id") or "")
        text = str(row.get("issue_text") or "").strip()
        line = row.get("line_number")
        line_no = int(line) if isinstance(line, (int, float)) else 0
        issues.append(
            BanditIssue(
                relative_path=rel,
                line_number=line_no,
                severity=sev,
                confidence=conf,
                test_id=test_id,
                issue_text=text,
            ),
        )
        if test_id:
            test_counts[test_id] += 1

    issues.sort(key=lambda i: (-_severity_rank(i.severity), i.relative_path, i.line_number))

    loc = _int("loc")

    return BanditScanResult(
        root=root_resolved,
        python_files_scanned=0,
        loc=loc,
        severity_high=_int("SEVERITY.HIGH") or sum(1 for i in issues if i.severity == "HIGH"),
        severity_medium=_int("SEVERITY.MEDIUM") or sum(1 for i in issues if i.severity == "MEDIUM"),
        severity_low=_int("SEVERITY.LOW") or sum(1 for i in issues if i.severity == "LOW"),
        confidence_high=_int("CONFIDENCE.HIGH"),
        confidence_medium=_int("CONFIDENCE.MEDIUM"),
        confidence_low=_int("CONFIDENCE.LOW"),
        skipped_tests=_int("skipped_tests"),
        nosec=_int("nosec"),
        issues=issues,
        top_test_ids=test_counts.most_common(10),
    )


def _severity_rank(severity: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity.upper(), 0)


def run_bandit_on_tree(
    root: Path,
    *,
    max_issues_in_report: int | None = None,
) -> tuple[BanditScanResult | None, str | None]:
    """Run ``bandit -r`` on *root*. Returns (result, skip_warning).

    *skip_warning* is set when Bandit is missing, the tree has no Python, or JSON parse fails.
    """
    if os.environ.get("SECANALYZER_SCAN_SKIP_BANDIT", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return None, "Bandit skipped (SECANALYZER_SCAN_SKIP_BANDIT is set)."

    root = root.resolve()
    has_py = any(root.rglob("*.py"))
    if not has_py:
        return None, "No .py files under scan root; Bandit not run."

    cap = max_issues_in_report
    if cap is None:
        raw_cap = os.environ.get("SECANALYZER_BANDIT_MAX_ISSUES", "50")
        try:
            cap = max(5, int(raw_cap))
        except ValueError:
            cap = 50

    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-f",
        "json",
        "-q",
        "--exit-zero",
    ]
    if _BANDIT_EXCLUDE:
        cmd.extend(["-x", _BANDIT_EXCLUDE])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except FileNotFoundError:
        return None, "Bandit not installed. Run: uv sync --all-groups"
    except subprocess.TimeoutExpired:
        return None, "Bandit timed out after 600s."

    if proc.returncode not in (0, 1) and not proc.stdout.strip():
        err = (proc.stderr or proc.stdout or "unknown error").strip()[:400]
        return None, f"Bandit failed (exit {proc.returncode}): {err}"

    raw_out = proc.stdout.strip()
    if not raw_out:
        return None, "Bandit produced no JSON output."

    try:
        data = json.loads(raw_out)
    except json.JSONDecodeError:
        return None, "Bandit returned non-JSON output."

    if not isinstance(data, dict):
        return None, "Bandit JSON root was not an object."

    result = _parse_bandit_json(data, root)

    # Count .py files under root (respecting skip dirs roughly)
    py_count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            if name.endswith(".py"):
                py_count += 1
    if py_count:
        result.python_files_scanned = py_count

    if len(result.issues) > cap:
        result.issues_truncated = True
        result.issues = result.issues[:cap]

    return result, None


def bandit_metrics_markdown(result: BanditScanResult) -> str:
    """Markdown section for a scan report."""
    lines = [
        "## Static analysis (Bandit)",
        "",
        "Non-LLM Python security lint via [Bandit](https://bandit.readthedocs.io/).",
        "",
        "### Summary metrics",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| Python files under tree | {result.python_files_scanned} |",
        f"| Lines of code (Bandit LOC) | {result.loc} |",
        f"| **Total issues** | **{result.total_issues}** |",
        f"| Severity HIGH | {result.severity_high} |",
        f"| Severity MEDIUM | {result.severity_medium} |",
        f"| Severity LOW | {result.severity_low} |",
        f"| Confidence HIGH | {result.confidence_high} |",
        f"| Confidence MEDIUM | {result.confidence_medium} |",
        f"| Confidence LOW | {result.confidence_low} |",
        f"| `# nosec` suppressions (Bandit) | {result.nosec} |",
        f"| Skipped tests | {result.skipped_tests} |",
        "",
    ]
    if result.top_test_ids:
        lines.append("### Most common test ids")
        lines.append("")
        for test_id, count in result.top_test_ids:
            lines.append(f"- `{test_id}`: {count}")
        lines.append("")

    if result.issues:
        lines.append("### Findings (sorted by severity)")
        lines.append("")
        if result.issues_truncated:
            lines.append(
                f"*Showing first {len(result.issues)} issue(s); "
                "raise `SECANALYZER_BANDIT_MAX_ISSUES` for more.*",
            )
            lines.append("")
        lines.append("| Severity | Confidence | Test | Location | Summary |")
        lines.append("|----------|------------|------|----------|---------|")
        for issue in result.issues:
            loc = f"`{issue.relative_path}`:{issue.line_number}"
            summary = issue.issue_text.replace("|", "\\|")[:120]
            if len(issue.issue_text) > 120:
                summary += "…"
            lines.append(
                f"| {issue.severity} | {issue.confidence} | `{issue.test_id}` | "
                f"{loc} | {summary} |",
            )
        lines.append("")
    else:
        lines.append("No Bandit issues reported for this tree.")
        lines.append("")

    return "\n".join(lines)
