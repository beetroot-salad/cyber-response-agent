from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import httpx

from .auth import ForgejoIdentity


class ForgeError(Exception):
    pass


#: The port each network scheme means when an origin spells none (O-G: made explicit at parse).
_DEFAULT_PORTS = {"http": 80, "https": 443}
#: A Forgejo owner or repository name as it may appear in an origin or an API path. Anything else
#: (a percent escape, a dot segment, an empty segment) is refused rather than normalised.
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _forge_name(raw: str) -> str | None:
    """`raw` as an owner or repository name, case folded (Forgejo resolves both without case),
    or `None` when it is not one."""
    if not _NAME.fullmatch(raw) or raw in {".", ".."}:
        return None
    return raw.lower()


@dataclass(frozen=True)
class ForgeAddress:
    """One forge repository, parsed once from its origin (#1108 amendment 2, O-G): scheme and
    host case folded, the default port made explicit, owner and repository case folded, so
    equal addresses are equal values and every comparison is `==`. No base path: a forge
    served under a sub-path is not one this parses."""

    scheme: str
    host: str
    port: int
    owner: str
    repo: str

    @classmethod
    def parse(cls, url: str) -> ForgeAddress:
        """`http(s)://host[:port]/owner/repo[.git]`, or a `ForgeError` naming the origin: no
        network scheme, no host, credentials in the URL, a bad port, a query or fragment, or a
        path that is not exactly an owner and a repository."""
        if any(
            character.isspace() or ord(character) < 32 or character in '"\\'
            for character in url
        ):
            raise ForgeError("origin contains invalid URL characters")
        try:
            parts = urlsplit(url)
            host, port = parts.hostname, parts.port
        except ValueError as e:
            raise ForgeError(
                f"origin {url!r} is not a forge repository URL: {e}"
            ) from e
        # `/owner/repo[.git]` splits into exactly an empty root, the owner and the repository.
        segments = parts.path.split("/")
        owner = repo = None
        if len(segments) == 3 and segments[0] == "":
            owner = _forge_name(segments[1])
            repo = _forge_name(segments[2].removesuffix(".git"))
        if (
            parts.scheme not in _DEFAULT_PORTS
            or not host
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or owner is None
            or repo is None
        ):
            raise ForgeError(
                f"origin {url!r} is not a network forge repository URL "
                "(http(s)://host[:port]/owner/repo[.git], no credentials)"
            )
        return cls(
            scheme=parts.scheme,
            host=host,
            port=port or _DEFAULT_PORTS[parts.scheme],
            owner=owner,
            repo=repo,
        )

    @property
    def netloc(self) -> str:
        """`host[:port]` as a URL spells it: the port only when it is not the scheme's default,
        an IPv6 host in brackets."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return (
            host if self.port == _DEFAULT_PORTS[self.scheme] else f"{host}:{self.port}"
        )

    @property
    def origin(self) -> str:
        """The scheme and authority alone, e.g. `https://forge.example`."""
        return f"{self.scheme}://{self.netloc}"

    @property
    def api(self) -> str:
        """The repository's Forgejo API root."""
        return f"{self.origin}/api/v1/repos/{self.owner}/{self.repo}"


#: The page size a listing asks for. Forgejo clamps it to its `max_response_items`, so a page
#: shorter than this is not the end of the listing.
_PAGE_LIMIT = 50


def _head_repository_id(row: dict) -> int | None:
    """The id of the repository a PR row's head branch lives in, or `None` when the row names
    none: Forgejo drops the head repository of a deleted fork's PR (D-fork), and such a row,
    like any fork's, is never ours. The id, not the full name: a rename or a transfer keeps
    it, and another repository can take the name (#1108 amendment 3, C1)."""
    head = row["head"]
    repo_id = head.get("repo_id")
    if type(repo_id) is not int:
        repo = head.get("repo")
        repo_id = repo.get("id") if isinstance(repo, dict) else None
    return repo_id if type(repo_id) is int else None


def _total_count(response: httpx.Response) -> int | None:
    """`X-Total-Count`, a nonnegative count, or `None` when the forge sent no header.
    A malformed count refuses the listing instead of guessing where it ends."""
    raw = response.headers.get("X-Total-Count")
    if raw is None:
        return None
    raw = raw.strip()
    if not raw.isascii() or not raw.isdecimal():
        raise ForgeError("Forgejo X-Total-Count must be a nonnegative whole number")
    try:
        return int(raw)
    except ValueError as e:
        raise ForgeError("Forgejo X-Total-Count is too large") from e


@dataclass(frozen=True)
class PullRequest:
    """One PR of our repository as Forgejo lists it: its number and URL, its head commit
    (`None` when the row carries none; the head branch plays no part in which PR is whose),
    and its `status`: `open`, `merged` or `closed` (closed unmerged)."""

    number: int
    url: str
    head_sha: str | None
    status: str


def _pull_request(row: dict) -> PullRequest:
    state, merged = row.get("state"), row.get("merged")
    if state == "open":
        status = "open"
    elif state == "closed":
        status = "merged" if merged is True or row.get("merged_at") else "closed"
    else:
        raise ForgeError(
            f"Forgejo pull #{row['number']} has an unknown state {state!r}"
        )
    sha = row["head"].get("sha")
    return PullRequest(
        number=row["number"],
        url=row["html_url"],
        head_sha=sha if isinstance(sha, str) and sha else None,
        status=status,
    )


class ForgejoForge:
    """Host-only Forgejo client; importing the legacy forge needs no HTTP stack.

    The origin is parsed once, here, into `address` (O-G): every request goes to its API. A
    listing asks for each page by number on that address (`?state=S&page=N&limit=L`) and never
    follows or compares Forgejo's `Link`, which Forgejo builds from its own `ROOT_URL` (#1108
    amendment 3, C4): it stops at an empty page, or once the rows seen (every row, counted
    before any is skipped) reach `X-Total-Count`. Only PRs whose head repository id is this
    repository's (read once from `GET /repos/{o}/{r}`) count, by exact head and by prefix
    alike: a fork's PR, a namesake's, or one with no head repository at all (D-fork) is never
    ours, and never holds the writer lease. This service owns client dependencies, not a
    serialized boundary record; its default representation exposes no credentials."""

    def __init__(
        self, *, origin: str, identity: ForgejoIdentity, client: httpx.Client
    ) -> None:
        self.address = ForgeAddress.parse(origin)
        self._identity = identity
        self._client = client
        self._repository_id: int | None = None

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        import httpx

        try:
            response = self._client.request(
                method,
                url,
                headers={
                    "Authorization": f"Bearer {self._identity.token(min_validity=60)}"
                },
                follow_redirects=False,
                timeout=30.0,
                **kwargs,
            )
            response.raise_for_status()
            return response
        except httpx.HTTPError as e:
            raise ForgeError(f"Forgejo {method} failed: {e}") from e

    @staticmethod
    def _json(response: httpx.Response) -> object:
        try:
            return response.json()
        except ValueError as e:
            raise ForgeError("Forgejo returned invalid JSON") from e

    def repository_id(self) -> int:
        """This repository's id, read once (`GET /repos/{o}/{r}`) and kept: what a PR's head
        repository is compared with."""
        if self._repository_id is None:
            value = self._json(self._request("GET", self.address.api))
            if not isinstance(value, dict) or type(value.get("id")) is not int:
                raise ForgeError("Forgejo's repository read names no repository id")
            self._repository_id = value["id"]
        return self._repository_id

    def verify_main_protection(self) -> None:
        response = self._request("GET", f"{self.address.api}/branches/main")
        value = self._json(response)
        if (
            not isinstance(value, dict)
            or value.get("protected") is not True
            or value.get("user_can_push") is not False
        ):
            raise ForgeError(
                "main protection must be known and the bot must not be able to push"
            )

    def _rows(self, state: str) -> list[dict]:
        """Every PR row of `state` whose head is this repository, page by page on our own
        address. A row of another shape is a `ForgeError`; a fork's row, or one with no head
        repository, is skipped after it is counted."""
        import httpx

        ours = self.repository_id()
        rows: list[dict] = []
        seen, page = 0, 1
        while True:
            url = httpx.URL(
                f"{self.address.api}/pulls",
                params={"state": state, "page": str(page), "limit": str(_PAGE_LIMIT)},
            )
            response = self._request("GET", str(url))
            value = self._json(response)
            if not isinstance(value, list):
                raise ForgeError("Forgejo pulls JSON must be an array")
            if not value:
                return rows
            for row in value:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("head"), dict)
                    or not isinstance(row["head"].get("ref"), str)
                    or type(row.get("number")) is not int
                    or not isinstance(row.get("html_url"), str)
                ):
                    raise ForgeError("Forgejo pull has invalid number, head or URL")
                if _head_repository_id(row) == ours:
                    rows.append(row)
            seen += len(value)
            total = _total_count(response)
            if total is not None and seen >= total:
                return rows
            page += 1

    def _open(self) -> list[dict]:
        return [
            {
                "number": row["number"],
                "headRefName": row["head"]["ref"],
                "url": row["html_url"],
            }
            for row in self._rows("open")
        ]

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        return [
            row for row in self._open() if row["headRefName"].startswith(head_prefix)
        ]

    def list_prs_for_head(self, head: str) -> list[dict]:
        return [row for row in self._open() if row["headRefName"] == head]

    def pull_requests(self) -> list[PullRequest]:
        """Every PR of this repository's own, open, merged or closed (a `state=all` listing),
        with its head commit: where a batch's PR is found by its head commit (amendment 3, C1)."""
        return [_pull_request(row) for row in self._rows("all")]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        response = self._request(
            "POST",
            f"{self.address.api}/pulls",
            json={
                "base": base,
                "head": head,
                "title": title,
                "body": body,
            },
        )
        value = self._json(response)
        if not isinstance(value, dict) or not isinstance(value.get("html_url"), str):
            raise ForgeError("Forgejo pull creation returned no PR URL")
        return value["html_url"]
