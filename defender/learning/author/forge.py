from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    import httpx
from defender._model import model
from pathlib import Path
from typing import Protocol, runtime_checkable

from defender._git import REPO_ROOT


class ForgeError(Exception):
    pass


# `@runtime_checkable` because `AuthorBranch.forge` is a strict pydantic field validated with
# `isinstance`, which a plain `Protocol` rejects. The check is by method name only.
@runtime_checkable
class Forge(Protocol):

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        ...

    def list_prs_for_head(self, head: str) -> list[dict]:
        ...

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        ...


@model(frozen=True)
class GhForge:

    cwd: Path = REPO_ROOT

    def _list_prs(self, *match_args: str) -> list[dict]:
        proc = subprocess.run(
            ["gh", "pr", "list", *match_args, "--state", "open",
             "--json", "number,headRefName,url"],
            cwd=self.cwd, capture_output=True, text=True, encoding="utf-8"
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr list failed: {proc.stderr.strip()}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise ForgeError(f"gh pr list returned non-JSON: {e}") from e
        return [r for r in rows if isinstance(r, dict)]

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        return self._list_prs("--search", f"head:{head_prefix}")

    def list_prs_for_head(self, head: str) -> list[dict]:
        return self._list_prs("--head", head)

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        proc = subprocess.run(
            ["gh", "pr", "create", "--base", base, "--head", head,
             "--title", title, "--body", body],
            cwd=self.cwd, capture_output=True, text=True, encoding="utf-8"
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr create failed: {proc.stderr.strip()}")
        return proc.stdout.strip()


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
        try:
            parts = urlsplit(url)
            host, port = parts.hostname, parts.port
        except ValueError as e:
            raise ForgeError(f"origin {url!r} is not a forge repository URL: {e}") from e
        # `/owner/repo[.git]` splits into exactly an empty root, the owner and the repository.
        segments = parts.path.split("/")
        owner = repo = None
        if len(segments) == 3 and segments[0] == "":
            owner = _forge_name(segments[1])
            repo = _forge_name(segments[2].removesuffix(".git"))
        if (parts.scheme not in _DEFAULT_PORTS or not host or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment
                or owner is None or repo is None):
            raise ForgeError(
                f"origin {url!r} is not a network forge repository URL "
                "(http(s)://host[:port]/owner/repo[.git], no credentials)")
        return cls(scheme=parts.scheme, host=host, port=port or _DEFAULT_PORTS[parts.scheme],
                   owner=owner, repo=repo)

    def serves(self, url: str) -> bool:
        """Does `url` (a credential entry, `scheme://[user[:token]@]host[:port]`) name this
        address's server? Scheme, host and port compared as `parse` reads them, the default port
        explicit; a URL that does not parse names none."""
        try:
            parts = urlsplit(url)
            host, port = parts.hostname, parts.port
        except ValueError:
            return False
        return (parts.scheme in _DEFAULT_PORTS
                and (parts.scheme, host, port or _DEFAULT_PORTS[parts.scheme])
                == (self.scheme, self.host, self.port))

    @property
    def netloc(self) -> str:
        """`host[:port]` as a URL spells it: the port only when it is not the scheme's default,
        an IPv6 host in brackets."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == _DEFAULT_PORTS[self.scheme] else f"{host}:{self.port}"

    @property
    def origin(self) -> str:
        """The scheme and authority alone, e.g. `https://forge.example`: what a URL-scoped git
        setting (`credential.<url>.*`) is keyed by."""
        return f"{self.scheme}://{self.netloc}"

    @property
    def api(self) -> str:
        """The repository's Forgejo API root."""
        return f"{self.origin}/api/v1/repos/{self.owner}/{self.repo}"

    @property
    def full_name(self) -> str:
        """`owner/repo`, as a PR row's head repository names it (case folded)."""
        return f"{self.owner}/{self.repo}"


def _head_repository(row: dict) -> str:
    """The `owner/repo` a PR row's head branch lives in, case folded. A row without its head
    repository (Forgejo drops it for a deleted fork) cannot be shown to be ours, and excluding
    it would release the writer lease on unknown evidence: it is a `ForgeError` (#1108 P3
    contract choice 9, pending a user decision; this function is the one place that decides)."""
    repo = row["head"].get("repo")
    if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str):
        raise ForgeError(f"Forgejo pull #{row.get('number')} names no head repository")
    return repo["full_name"].lower()


class ForgejoForge:
    """Host-only Forgejo client; importing the legacy forge needs no HTTP stack.

    The origin is parsed once, here, into `address` (O-G): every request goes to its API, every
    next-page Link is compared against it before it is followed, and only PRs whose head
    repository is this repository count, by exact head and by prefix alike (a fork's PR is never
    ours, and never holds the writer lease). This service owns client dependencies, not a
    serialized boundary record; its default representation exposes no credentials."""

    def __init__(self, *, origin: str, token: str, client: httpx.Client) -> None:
        self.address = ForgeAddress.parse(origin)
        self._token = token
        self._client = client

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        import httpx

        try:
            response = self._client.request(
                method, url, headers={"Authorization": f"token {self._token}"},
                follow_redirects=False, **kwargs,
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

    def verify_main_protection(self) -> None:
        response = self._request("GET", f"{self.address.api}/branches/main")
        value = self._json(response)
        if (not isinstance(value, dict) or value.get("protected") is not True
                or value.get("user_can_push") is not False):
            raise ForgeError("main protection must be known and the bot must not be able to push")

    def _next_page(self, link: str) -> str:
        """The next page's URL, rebuilt on this forge's own address, once the Link has been
        shown to name this repository's open pulls (scheme, host, port, owner and repository
        compared as parsed). A Link that does not parse, or names anything else, is refused
        before it is requested, so it cannot redirect the token."""
        try:
            parts = urlsplit(link)
            host, port = parts.hostname, parts.port
        except ValueError as e:
            raise ForgeError(f"Forgejo pagination Link has an invalid URL: {e}") from e
        segments = parts.path.split("/")
        named = None
        if (parts.scheme in _DEFAULT_PORTS and host and len(segments) == 7
                and segments[:4] == ["", "api", "v1", "repos"] and segments[6] == "pulls"):
            owner, repo = _forge_name(segments[4]), _forge_name(segments[5])
            if owner is not None and repo is not None:
                named = ForgeAddress(scheme=parts.scheme, host=host,
                                     port=port or _DEFAULT_PORTS[parts.scheme],
                                     owner=owner, repo=repo)
        if (named != self.address or parts.username is not None or parts.password is not None
                or parts.fragment or parse_qs(parts.query).get("state") != ["open"]):
            raise ForgeError("Forgejo pagination Link left this repository's open pulls")
        return f"{self.address.api}/pulls?{parts.query}"

    def _list(self) -> list[dict]:
        import httpx

        url = str(httpx.URL(f"{self.address.api}/pulls",
                            params={"state": "open", "page": "1", "limit": "50"}))
        visited: set[str] = set()
        rows: list[dict] = []
        while url:
            if url in visited:
                raise ForgeError("Forgejo pull pagination repeated a page")
            visited.add(url)
            response = self._request("GET", url)
            value = self._json(response)
            if not isinstance(value, list):
                raise ForgeError("Forgejo pulls JSON must be an array")
            for row in value:
                if (not isinstance(row, dict) or not isinstance(row.get("head"), dict)
                        or not isinstance(row["head"].get("ref"), str)
                        or type(row.get("number")) is not int
                        or not isinstance(row.get("html_url"), str)):
                    raise ForgeError("Forgejo pull has invalid number, head or URL")
                if _head_repository(row) != self.address.full_name:
                    continue
                rows.append({"number": row["number"], "headRefName": row["head"]["ref"],
                             "url": row["html_url"]})
            link = response.links.get("next", {}).get("url", "")
            url = self._next_page(link) if link else ""
        return rows

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        return [row for row in self._list() if row["headRefName"].startswith(head_prefix)]

    def list_prs_for_head(self, head: str) -> list[dict]:
        return [row for row in self._list() if row["headRefName"] == head]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        response = self._request("POST", f"{self.address.api}/pulls", json={
            "base": base, "head": head, "title": title, "body": body,
        })
        value = self._json(response)
        if not isinstance(value, dict) or not isinstance(value.get("html_url"), str):
            raise ForgeError("Forgejo pull creation returned no PR URL")
        return value["html_url"]
