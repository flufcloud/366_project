"""Interactive GitHub issue/PR menu, bounded context assembly, and LLM-backed risk triage."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

import questionary

from secanalyzer import config
from secanalyzer import llm as llm_mod
from secanalyzer.exceptions import LLMError, UserFacingError
from secanalyzer.github_client import (
    WorkItem,
    fetch_pr_files_summary,
    list_open_work_items,
    parse_owner_repo,
)


def _resolve_llm_provider(
    stored: tuple[str, str],
    override: str | None,
) -> tuple[str, str]:
    stored_prov, key = stored
    if override is None or not str(override).strip():
        return stored_prov, key
    want = config._normalize_provider(str(override).strip())
    if want != stored_prov:
        raise UserFacingError(
            f"--provider {override!r} does not match stored LLM credentials ({stored_prov!r}). "
            "Run --set-token llm for the provider you want, or omit --provider.",
        )
    return stored_prov, key


def _format_choice_label(it: WorkItem) -> str:
    kind = "PR" if it.is_pull_request else "Issue"
    title = (it.title or "(no title)").replace("\n", " ")
    if len(title) > 72:
        title = title[:69] + "..."
    return f"#{it.number} [{kind}] {title}"


def prompt_select_work_item(items: list[WorkItem]) -> WorkItem | None:
    """Keyboard-driven menu (↑↓ Enter, Esc cancels)."""
    choices = [
        questionary.Choice(title=_format_choice_label(it), value=it) for it in items
    ]
    return questionary.select(
        "Select an open issue or PR (↑↓, Enter, Esc to quit):",
        choices=choices,
    ).ask()


def render_analysis_markdown(
    owner: str,
    repo: str,
    item: WorkItem,
    analysis: dict[str, Any],
) -> str:
    kind = "Pull request" if item.is_pull_request else "Issue"
    lines = [
        f"## {kind} #{item.number} — {item.title or '(no title)'}",
        "",
        f"- **Repository:** `{owner}/{repo}`",
        f"- **URL:** {item.html_url}",
        f"- **Author:** `@{item.author_login}`",
        "",
        f"### Risk level: **{analysis['risk_level']}**",
        "",
        "### Justification",
        "",
        str(analysis["justification"]).strip(),
        "",
        "### Suggested mitigation",
        "",
        str(analysis["suggested_mitigation"]).strip(),
        "",
    ]
    locs = analysis.get("code_locations") or []
    if isinstance(locs, list) and locs:
        lines.extend(["### Referenced locations", ""])
        for loc in locs:
            if not isinstance(loc, dict):
                continue
            path = loc.get("path") or "(unspecified path)"
            ls = loc.get("line_start")
            le = loc.get("line_end")
            if ls is not None or le is not None:
                lines.append(f"- `{path}` lines {ls}–{le}")
            else:
                lines.append(f"- `{path}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def run_interactive_issues(
    owner_repo: str,
    *,
    provider_override: str | None = None,
    github_urlopen: Callable[..., Any] | None = None,
    llm_urlopen: Callable[..., Any] | None = None,
    select_work_item: Callable[[list[WorkItem]], WorkItem | None] | None = None,
) -> int:
    owner, repo = parse_owner_repo(owner_repo)
    token = config.load_github_token()
    if not token:
        raise UserFacingError(
            "GitHub token missing. Run: secanalyzer --set-token github",
        )
    llm_stored = config.load_llm_config()
    if llm_stored is None:
        raise UserFacingError(
            "LLM API key missing. Run: secanalyzer --set-token llm --provider claude",
        )
    provider, api_key = _resolve_llm_provider(llm_stored, provider_override)

    items = list_open_work_items(
        owner,
        repo,
        token,
        urlopen=github_urlopen,
    )
    if not items:
        print(f"No open issues or PRs found for `{owner}/{repo}`.")
        return 0

    selector = select_work_item or prompt_select_work_item

    while True:
        try:
            selected = selector(items)
        except KeyboardInterrupt:
            sys.stderr.write("\nInterrupted.\n")
            return 130
        if selected is None:
            return 0

        pr_extra = ""
        if selected.is_pull_request:
            pr_extra = fetch_pr_files_summary(
                owner,
                repo,
                selected.number,
                token,
                urlopen=github_urlopen,
            )

        sys_prompt, user_prompt = llm_mod.build_issue_analysis_prompts(
            owner,
            repo,
            item_title=selected.title,
            item_body=selected.body or "",
            pr_patch_summary=pr_extra or "(not a PR or no patch text available)",
        )
        try:
            analysis, warns = llm_mod.complete_issue_analysis(
                provider,
                api_key,
                sys_prompt,
                user_prompt,
                urlopen=llm_urlopen,
            )
        except LLMError as e:
            sys.stderr.write(f"[ERROR] {e}\n")
            continue
        for w in warns:
            sys.stderr.write(f"[WARNING] {w}\n")
        print(render_analysis_markdown(owner, repo, selected, analysis))
        print()
