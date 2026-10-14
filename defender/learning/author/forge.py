from __future__ import annotations

import json
import subprocess
from dataclasses import field as dataclass_field
from typing import Any
from urllib.parse import unquote, urlsplit

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


@model(frozen=True)
class ForgejoForge:
    """Host-only Forgejo client for the repository named by its network origin."""

    origin: str
    token: str = dataclass_field(repr=False)
    client: httpx.Client = dataclass_field(repr=False)

    @property
    def _repository_url(self) -> str:
        parsed = urlsplit(self.origin)
        path = parsed.path.removesuffix(".git").strip("/")
        parts = path.split("/")
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or len(parts) != 2
                or any(not p or unquote(p) in {".", ".."} or "/" in unquote(p) for p in parts)):
            raise ForgeError("origin must be a network Forgejo repository URL")
        return f"{parsed.scheme}://{parsed.netloc}/api/v1/repos/{path}"

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.client.request(
                method, url, headers={"Authorization": f"token {self.token}"},
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
        response = self._request("GET", f"{self._repository_url}/branches/main")
        value = self._json(response)
        if (not isinstance(value, dict) or value.get("protected") is not True
                or value.get("user_can_push") is not False):
            raise ForgeError("main protection must be known and the bot must not be able to push")

    def _list(self) -> list[dict]:
        endpoint = f"{self._repository_url}/pulls"
        url = str(httpx.URL(endpoint, params={"state": "open", "page": "1", "limit": "50"}))
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
                rows.append({"number": row["number"], "headRefName": row["head"]["ref"],
                             "url": row["html_url"]})
            url = response.links.get("next", {}).get("url", "")
            if url:
                next_url = httpx.URL(url)
                if str(next_url.copy_with(query=None)) != endpoint or next_url.params.get("state") != "open":
                    raise ForgeError("Forgejo pagination left the repository's open pulls")
        return rows

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        return [row for row in self._list() if row["headRefName"].startswith(head_prefix)]

    def list_prs_for_head(self, head: str) -> list[dict]:
        return [row for row in self._list() if row["headRefName"] == head]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        response = self._request("POST", f"{self._repository_url}/pulls", json={
            "base": base, "head": head, "title": title, "body": body,
        })
        value = self._json(response)
        if not isinstance(value, dict) or not isinstance(value.get("html_url"), str):
            raise ForgeError("Forgejo pull creation returned no PR URL")
        return value["html_url"]
