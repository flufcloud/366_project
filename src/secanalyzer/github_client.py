"""GitHub REST client — list open issues/PRs and fetch bounded PR patch text for security triage."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

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
        raise GitHubApiError(
            f"GitHub HTTP {e.code} for {url.split('?')[0]}: {detail or e.reason}",
        ) from e
    except urllib.error.URLError as e:
        raise GitHubApiError(f"Cannot reach GitHub: {e.reason}.") from e
    except OSError as e:
        raise GitHubApiError(f"Network error talking to GitHub: {e}") from e

    if code == 204:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise GitHubApiError("GitHub returned invalid JSON.") from e


@dataclass(frozen=True)
class WorkItem:
    number: int
    title: str
    body: str
    html_url: str
    is_pull_request: bool
    author_login: str


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
            num = row.get("number")
            if not isinstance(num, int):
                continue
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
            items.append(
                WorkItem(
                    number=num,
                    title=title,
                    body=body,
                    html_url=html_url,
                    is_pull_request=is_pr,
                    author_login=author,
                ),
            )
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
