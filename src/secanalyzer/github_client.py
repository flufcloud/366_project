"""GitHub REST client — list open issues/PRs and fetch bounded PR patch text for security triage."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from secanalyzer import operations
from secanalyzer.exceptions import GitHubApiError, UserFacingError

USER_AGENT = "secanalyzer-cli/0.1"


def parse_owner_repo(spec: str) -> tuple[str, str]:
    raw = spec.strip()
    parts = raw.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise UserFacingError(
            "Expected owner/repo with a single slash, e.g. octocat/Hello-World.",
        )
    return parts[0].strip(), parts[1].strip()


def github_json_request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    urlopen: Callable[..., Any] | None = None,
) -> Any:
    """Send one GitHub JSON request.

    Authorization never enters logs; operational events include only method,
    status, and the path without query parameters for troubleshooting.
    """
    opener = urlopen or urllib.request.urlopen
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener(req, timeout=60) as resp:
            code = resp.getcode()
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:800]
        operations.event(
            "github.request_failed",
            level=30,
            method=method,
            status=e.code,
            url=url.split("?")[0],
        )
        raise GitHubApiError(
            f"GitHub HTTP {e.code} for {url.split('?')[0]}: {detail or e.reason}",
        ) from e
    except urllib.error.URLError as e:
        operations.event(
            "github.request_unreachable",
            level=30,
            method=method,
            url=url.split("?")[0],
            reason=str(e.reason),
        )
        raise GitHubApiError(f"Cannot reach GitHub: {e.reason}.") from e
    except OSError as e:
        operations.event(
            "github.request_network_error",
            level=30,
            method=method,
            url=url.split("?")[0],
            error=str(e),
        )
        raise GitHubApiError(f"Network error talking to GitHub: {e}") from e

    if code == 204:
        operations.event("github.request_completed", method=method, status=code, url=url.split("?")[0])
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        operations.event(
            "github.invalid_json",
            level=30,
            method=method,
            status=code,
            url=url.split("?")[0],
        )
        raise GitHubApiError("GitHub returned invalid JSON.") from e
    operations.event("github.request_completed", method=method, status=code, url=url.split("?")[0])
    return data
    return data


@dataclass(frozen=True)
class WorkItem:
    number: int
    title: str
    body: str
    html_url: str
    is_pull_request: bool
    author_login: str


@dataclass(frozen=True)
class IssueComment:
    author_login: str
    body: str
    created_at: str


def _work_item_from_api_row(row: dict[str, Any]) -> WorkItem | None:
    num = row.get("number")
    if not isinstance(num, int):
        return None
    pr = row.get("pull_request")
    is_pr = isinstance(pr, dict)
    title = row.get("title") or ""
    body = row.get("body") or ""
    if not isinstance(title, str):
        title = str(title)
    if not isinstance(body, str):
        body = str(body) if body is not None else ""
    html_url = row.get("html_url") or ""
    if not isinstance(html_url, str):
        html_url = str(html_url)
    user = row.get("user")
    author = "unknown"
    if isinstance(user, dict):
        login = user.get("login")
        if isinstance(login, str):
            author = login
    return WorkItem(
        number=num,
        title=title,
        body=body,
        html_url=html_url,
        is_pull_request=is_pr,
        author_login=author,
    )


def fetch_work_item(
    owner: str,
    repo: str,
    number: int,
    token: str,
    *,
    urlopen: Callable[..., Any] | None = None,
) -> WorkItem:
    """Fetch one issue or PR by number."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}"
    data = github_json_request(url, token, urlopen=urlopen)
    if not isinstance(data, dict):
        raise GitHubApiError("Unexpected GitHub issue payload (expected an object).")
    item = _work_item_from_api_row(data)
    if item is None:
        raise GitHubApiError(f"Could not parse GitHub issue #{number}.")
    return item


def fetch_issue_comments(
    owner: str,
    repo: str,
    number: int,
    token: str,
    *,
    urlopen: Callable[..., Any] | None = None,
    max_pages: int = 5,
) -> list[IssueComment]:
    """Issue/PR discussion comments (chronological)."""
    out: list[IssueComment] = []
    for page in range(1, max_pages + 1):
        qs = urllib.parse.urlencode({"per_page": "100", "page": str(page)})
        url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues/"
            f"{number}/comments?{qs}"
        )
        data = github_json_request(url, token, urlopen=urlopen)
        if not isinstance(data, list):
            raise GitHubApiError("Unexpected GitHub comments payload (expected a list).")
        if not data:
            break
        for row in data:
            if not isinstance(row, dict):
                continue
            user = row.get("user")
            author = "unknown"
            if isinstance(user, dict):
                login = user.get("login")
                if isinstance(login, str):
                    author = login
            body = row.get("body") or ""
            if not isinstance(body, str):
                body = str(body) if body is not None else ""
            created = row.get("created_at") or ""
            if not isinstance(created, str):
                created = str(created) if created is not None else ""
            out.append(
                IssueComment(
                    author_login=author,
                    body=body,
                    created_at=created,
                ),
            )
        if len(data) < 100:
            break
    return out


def list_open_work_items(
    owner: str,
    repo: str,
    token: str,
    *,
    urlopen: Callable[..., Any] | None = None,
    max_pages: int = 5,
) -> list[WorkItem]:
    """Open issues and PRs (GitHub lists PRs in the issues endpoint with ``pull_request`` set)."""
    items: list[WorkItem] = []
    for page in range(1, max_pages + 1):
        qs = urllib.parse.urlencode(
            {
                "state": "open",
                "per_page": "100",
                "page": str(page),
                "sort": "updated",
                "direction": "desc",
            },
        )
        url = f"https://api.github.com/repos/{owner}/{repo}/issues?{qs}"
        data = github_json_request(url, token, urlopen=urlopen)
        if not isinstance(data, list):
            raise GitHubApiError("Unexpected GitHub issues payload (expected a list).")
        if len(data) == 0:
            break
        for row in data:
            if not isinstance(row, dict):
                continue
            item = _work_item_from_api_row(row)
            if item is not None:
                items.append(item)
        if len(data) < 100:
            break
    return items


def fetch_pr_files_summary(
    owner: str,
    repo: str,
    pr_number: int,
    token: str,
    *,
    urlopen: Callable[..., Any] | None = None,
    max_files: int = 15,
    max_patch_per_file: int = 4500,
    max_total_chars: int = 48_000,
) -> str:
    """Concatenate truncated per-file patches for context (bounded size)."""
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/pulls/"
        f"{pr_number}/files?per_page={max_files}"
    )
    data = github_json_request(url, token, urlopen=urlopen)
    if not isinstance(data, list):
        return ""
    parts: list[str] = []
    total = 0
    for row in data:
        if not isinstance(row, dict):
            continue
        fn = row.get("filename", "")
        patch = row.get("patch") or ""
        if not isinstance(fn, str):
            fn = str(fn)
        if not isinstance(patch, str):
            patch = str(patch) if patch is not None else ""
        chunk = f"### File: {fn}\n```diff\n{patch[:max_patch_per_file]}\n```\n"
        if total + len(chunk) > max_total_chars:
            parts.append("\n*(Additional PR files omitted for size budget.)*\n")
            break
        parts.append(chunk)
        total += len(chunk)
    return "\n".join(parts)
