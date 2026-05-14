"""GitHub client tests."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from secanalyzer.exceptions import GitHubApiError, UserFacingError
from secanalyzer.github_client import (
    github_json_request,
    list_open_work_items,
    parse_owner_repo,
)


def test_parse_owner_repo_ok() -> None:
    assert parse_owner_repo(" Foo / bar ") == ("Foo", "bar")


def test_parse_owner_repo_bad() -> None:
    with pytest.raises(UserFacingError):
        parse_owner_repo("onlyone")


def test_list_open_work_items_mocked() -> None:
    payload = [
        {
            "number": 1,
            "title": "Hello",
            "body": "World",
            "html_url": "https://example/1",
            "user": {"login": "alice"},
        },
        {
            "number": 2,
            "title": "PR title",
            "body": "",
            "html_url": "https://example/2",
            "pull_request": {"url": "https://api.github.com/repos/o/r/pulls/2"},
            "user": {"login": "bob"},
        },
    ]

    class Resp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return self._body

        def getcode(self) -> int:
            return 200

    def fake_open(req: Any, timeout: int = 0, **kwargs: Any) -> Resp:
        return Resp(json.dumps(payload).encode("utf-8"))

    items = list_open_work_items(
        "o",
        "r",
        "ghp_" + "x" * 36,
        urlopen=fake_open,
        max_pages=1,
    )
    assert len(items) == 2
    assert items[0].number == 1
    assert items[0].is_pull_request is False
    assert items[1].is_pull_request is True


def test_github_json_http_error() -> None:
    import urllib.error

    def boom(req: Any, timeout: int = 0, **kwargs: Any) -> Any:
        raise urllib.error.HTTPError(
            "url",
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"message":"missing"}'),
        )

    with pytest.raises(GitHubApiError):
        github_json_request("https://api.github.com/x", "tok", urlopen=boom)
