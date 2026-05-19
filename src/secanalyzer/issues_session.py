"""GitHub issue/PR listing and per-item LLM security analysis."""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from secanalyzer import config
from secanalyzer import llm as llm_mod
from secanalyzer.exceptions import LLMError, UserFacingError
from secanalyzer.github_client import (
    IssueComment,
    WorkItem,
    fetch_issue_comments,
    fetch_pr_files_summary,
    fetch_work_item,
    list_open_work_items,
    parse_owner_repo,
)
from secanalyzer.report_tree import common_parent_dir, load_rolling_context_for_issue


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


def format_issues_list_markdown(owner: str, repo: str, items: list[WorkItem]) -> str:
    lines = [
        f"# Open issues and pull requests — `{owner}/{repo}`",
        "",
        f"**Total:** {len(items)}",
        "",
        "| # | Type | Title | Author | URL |",
        "|--:|------|-------|--------|-----|",
    ]
    for it in items:
        kind = "PR" if it.is_pull_request else "Issue"
        title = (it.title or "").replace("|", "\\|").replace("\n", " ")
        if len(title) > 80:
            title = title[:77] + "…"
        lines.append(
            f"| {it.number} | {kind} | {title} | `@{it.author_login}` | {it.html_url} |",
        )
    lines.append("")
    lines.append(
        "Analyze one item: "
        f"`secanalyzer --analyze-issue {owner}/{repo} --issue-number <N>`",
    )
    lines.append("")
    return "\n".join(lines)


def format_comments_thread(comments: list[IssueComment], *, max_chars: int = 48_000) -> str:
    if not comments:
        return "(no comments on this issue/PR)"
    parts: list[str] = []
    total = 0
    for idx, c in enumerate(comments, start=1):
        body = (c.body or "").strip()
        block = (
            f"--- comment {idx} by @{c.author_login} ({c.created_at}) ---\n"
            f"{body}\n"
        )
        if total + len(block) > max_chars:
            parts.append(
                f"\n*(Additional comments omitted; {len(comments) - idx + 1} not shown.)*\n",
            )
            break
        parts.append(block)
        total += len(block)
    return "\n".join(parts)


def infer_report_scope_from_pr_summary(pr_summary: str) -> str:
    """Guess a repo directory prefix from PR file paths."""
    paths = re.findall(r"^### File:\s*(.+)$", pr_summary, re.MULTILINE)
    paths = [p.strip().replace("\\", "/") for p in paths if p.strip()]
    if not paths:
        return ""
    return common_parent_dir(paths)


def render_brief_analysis_markdown(
    owner: str,
    repo: str,
    item: WorkItem,
    body: str,
    *,
    comment_count: int,
) -> str:
    kind = "Pull request" if item.is_pull_request else "Issue"
    lines = [
        f"# Security overview — {kind} #{item.number}",
        "",
        f"- **Repository:** `{owner}/{repo}`",
        f"- **Title:** {item.title or '(no title)'}",
        f"- **URL:** {item.html_url}",
        f"- **Author:** `@{item.author_login}`",
        f"- **Comments included:** {comment_count}",
        "",
        body.strip(),
        "",
    ]
    return "\n".join(lines)


def run_list_issues(
    owner_repo: str,
    *,
    github_urlopen: Callable[..., Any] | None = None,
) -> int:
    """Print a table of open issues/PRs (non-interactive)."""
    owner, repo = parse_owner_repo(owner_repo)
    token = config.load_github_token()
    if not token:
        raise UserFacingError(
            "GitHub token missing. Run: secanalyzer --set-token github",
        )
    items = list_open_work_items(owner, repo, token, urlopen=github_urlopen)
    if not items:
        print(f"No open issues or PRs found for `{owner}/{repo}`.")
        return 0
    print(format_issues_list_markdown(owner, repo, items))
    return 0


def run_analyze_issue(
    owner_repo: str,
    issue_number: int,
    *,
    provider_override: str | None = None,
    report_tree_dir: str | Path | None = None,
    report_scope: str | None = None,
    github_urlopen: Callable[..., Any] | None = None,
    llm_urlopen: Callable[..., Any] | None = None,
) -> tuple[str, list[str]]:
    """Fetch issue + comments, optional codebase context, return markdown + warnings."""
    owner, repo = parse_owner_repo(owner_repo)
    if issue_number < 1:
        raise UserFacingError("--issue-number must be a positive integer.")

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

    item = fetch_work_item(owner, repo, issue_number, token, urlopen=github_urlopen)
    comments = fetch_issue_comments(
        owner,
        repo,
        issue_number,
        token,
        urlopen=github_urlopen,
    )
    comments_text = format_comments_thread(comments)

    pr_extra = ""
    if item.is_pull_request:
        pr_extra = fetch_pr_files_summary(
            owner,
            repo,
            item.number,
            token,
            urlopen=github_urlopen,
        )

    warnings: list[str] = []
    codebase_context = ""
    if report_tree_dir is not None:
        tree = Path(report_tree_dir).expanduser()
        scope = report_scope
        if scope is None or not str(scope).strip():
            scope = infer_report_scope_from_pr_summary(pr_extra)
            if scope:
                warnings.append(
                    f"Inferred report scope `{scope}` from PR changed files.",
                )
        try:
            codebase_context, ctx_warns = load_rolling_context_for_issue(
                tree,
                scope=scope,
            )
            warnings.extend(ctx_warns)
        except OSError as e:
            raise UserFacingError(f"Could not load report tree context: {e}") from e

    sys_prompt, user_prompt = llm_mod.build_issue_brief_prompts(
        owner,
        repo,
        item_title=item.title,
        item_body=item.body or "",
        comments_text=comments_text,
        pr_patch_summary=pr_extra or "(not a PR or no patch text available)",
        codebase_context=codebase_context,
    )
    try:
        overview, llm_warns = llm_mod.complete_issue_brief_analysis(
            provider,
            api_key,
            sys_prompt,
            user_prompt,
            issue_context=(
                owner,
                repo,
                item.title,
                item.body or "",
                comments_text,
                pr_extra or "(not a PR or no patch text available)",
            ),
            urlopen=llm_urlopen,
        )
    except LLMError as e:
        raise UserFacingError(str(e)) from e
    warnings.extend(llm_warns)

    md = render_brief_analysis_markdown(
        owner,
        repo,
        item,
        overview,
        comment_count=len(comments),
    )
    return md, warnings


def run_interactive_issues(
    owner_repo: str,
    *,
    provider_override: str | None = None,
    github_urlopen: Callable[..., Any] | None = None,
    llm_urlopen: Callable[..., Any] | None = None,
    select_work_item: Callable[[list[WorkItem]], WorkItem | None] | None = None,
) -> int:
    """Deprecated: use ``run_list_issues`` and ``run_analyze_issue`` instead."""
    _ = select_work_item
    sys.stderr.write(
        "[NOTE] Interactive --issues is deprecated. "
        f"Use: secanalyzer --list-issues {owner_repo!r} "
        "and secanalyzer --analyze-issue … --issue-number N\n",
    )
    return run_list_issues(owner_repo, github_urlopen=github_urlopen)


def render_analysis_markdown(
    owner: str,
    repo: str,
    item: WorkItem,
    analysis: dict[str, Any],
) -> str:
    """Legacy JSON analysis renderer (kept for tests)."""
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
