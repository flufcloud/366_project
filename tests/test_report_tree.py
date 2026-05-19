"""Report artifact tree layout tests."""

from __future__ import annotations

from pathlib import Path

from secanalyzer.report_tree import ReportTreeWriter, common_parent_dir, resolve_report_tree_dir


def test_common_parent_dir() -> None:
    assert common_parent_dir(["apps/a.py", "apps/b.py"]) == "apps"
    assert common_parent_dir(["part1.py"]) == "_root"
    assert common_parent_dir(["src/pkg/a.py", "lib/b.py"]) == "_root"


def test_resolve_report_tree_dir_from_output(tmp_path: Path) -> None:
    out = tmp_path / "reports" / "final.md"
    resolved = resolve_report_tree_dir(None, out)
    assert resolved == tmp_path / "reports" / "final.report-tree"


def test_report_tree_writes_hierarchy(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    writer = ReportTreeWriter(root)
    writer.write_readme(scan_root=tmp_path, files_analyzed=2)
    writer.write_file_review(
        {
            "path": "src/app.py",
            "attack_surface": "high",
            "architectural_role": "entry",
            "findings": ["issue"],
            "recommended_review": "check auth",
            "narrative": "details",
        },
    )
    writer.write_compaction(
        relative_paths=["src/app.py", "src/util.py"],
        prior_summary="old",
        batch_input="batch notes",
        rolling_output="new rolling",
    )
    writer.write_final_rolling("final roll")
    writer.write_synthesis_final("## Executive summary\n\nOk.")
    writer.write_deliverable("# Full\n")

    assert (root / "README.md").is_file()
    assert (root / "files" / "src" / "app.py.md").is_file()
    assert (root / "compaction" / "sequential" / "0001" / "rolling-summary.md").is_file()
    assert (root / "compaction" / "by-directory" / "src" / "0001-rolling-summary.md").is_file()
    assert (root / "compaction" / "final-rolling-summary.md").read_text(encoding="utf-8") == "final roll\n"
    assert (root / "synthesis" / "final-report.md").is_file()
    assert (root / "REPORT.md").read_text(encoding="utf-8") == "# Full\n"
