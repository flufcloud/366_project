"""LLM scan narrative helpers."""

from secanalyzer import llm as llm_mod


def test_generate_repo_scan_markdown_strips_fence() -> None:
    raw = "```markdown\n## Hi\n\nBody.\n```"

    assert llm_mod._strip_optional_markdown_fence(raw).startswith("## Hi")
