"""Repository scan inventory for LLM."""

from secanalyzer.repo_analyzer import build_scan_inventory_for_llm, scan_repository


def test_build_scan_inventory_bounded(tmp_path) -> None:
    for i in range(3):
        (tmp_path / f"f{i}.py").write_text(f"x = {i}\n" * 50, encoding="utf-8")
    r = scan_repository(str(tmp_path))
    inv = build_scan_inventory_for_llm(r)
    assert "paths:" in inv
    assert "redacted_excerpts" in inv
    assert "f0.py" in inv
