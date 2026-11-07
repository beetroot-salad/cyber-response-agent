"""Every Forgejo API call the product makes, by what it does (#1440): the lifecycle's admin and bot
calls and the learning author's PR calls. Each answers an `ApiCall` its caller sends with its
own client and credential. A repository is its full name, `<owner>/<name>`.

No other module writes a Forgejo API path (`tooling/lint/lint_inline_api_paths.py`)."""
from __future__ import annotations

from typing import Any

from defender._api_call import ApiCall

_API = "/api/v1"


def _repo(repo: str) -> str:
    return f"{_API}/repos/{repo}"


# --- repositories ---------------------------------------------------------------------------------


def repository(repo: str) -> ApiCall:
    """Read a repository (404 when absent or not visible)."""
    return ApiCall("GET", _repo(repo))


def create_empty_private_repository(org: str, name: str) -> ApiCall:
    """Make `org/name` private and empty, its default branch `main`."""
    return ApiCall("POST", f"{_API}/orgs/{org}/repos", json={
        "name": name, "private": True, "auto_init": False, "default_branch": "main"})


def archive_repository(repo: str) -> ApiCall:
    return ApiCall("PATCH", _repo(repo), json={"archived": True})


def delete_repository(repo: str) -> ApiCall:
    return ApiCall("DELETE", _repo(repo))


def branch(repo: str, name: str) -> ApiCall:
    """Read a branch, with whether the caller may push to or merge it."""
    return ApiCall("GET", f"{_repo(repo)}/branches/{name}")


# --- users and collaborators ----------------------------------------------------------------------


def user(login: str) -> ApiCall:
    """Read a user (404 when absent)."""
    return ApiCall("GET", f"{_API}/users/{login}")


def create_bot_user(login: str, *, password: str) -> ApiCall:
    """Make a private bot account at `<login>@bots.invalid` whose password needs no change."""
    return ApiCall("POST", f"{_API}/admin/users", json={
        "username": login, "email": f"{login}@bots.invalid", "visibility": "private",
        "password": password, "must_change_password": False})


def delete_user(login: str) -> ApiCall:
    """Delete an account, never with purge (#1433: purge erases what it wrote)."""
    return ApiCall("DELETE", f"{_API}/admin/users/{login}")


def collaborators(repo: str, *, page: int, limit: int) -> ApiCall:
    """One page of a repository's collaborators."""
    return ApiCall("GET", f"{_repo(repo)}/collaborators", params={"page": page, "limit": limit})


def add_collaborator(repo: str, login: str, *, permission: str) -> ApiCall:
    return ApiCall("PUT", f"{_repo(repo)}/collaborators/{login}", json={"permission": permission})


def remove_collaborator(repo: str, login: str) -> ApiCall:
    return ApiCall("DELETE", f"{_repo(repo)}/collaborators/{login}")


# --- branch protection ----------------------------------------------------------------------------


def branch_protection(repo: str, rule: str) -> ApiCall:
    """Read the protection rule `rule` as stored (404 when absent)."""
    return ApiCall("GET", f"{_repo(repo)}/branch_protections/{rule}")


def create_branch_protection(repo: str, fields: dict[str, Any]) -> ApiCall:
    return ApiCall("POST", f"{_repo(repo)}/branch_protections", json=fields)


def edit_branch_protection(repo: str, rule: str, fields: dict[str, Any]) -> ApiCall:
    """Change the rule `rule`; a list `fields` omits is kept as it was."""
    return ApiCall("PATCH", f"{_repo(repo)}/branch_protections/{rule}", json=fields)


# --- pull requests --------------------------------------------------------------------------------


def pulls(repo: str, *, state: str, page: int, limit: int) -> ApiCall:
    """One page of a repository's PRs in `state` (`open`, `closed` or `all`)."""
    return ApiCall("GET", f"{_repo(repo)}/pulls", params={"state": state, "page": page, "limit": limit})


def open_pull(repo: str, *, base: str, head: str, title: str, body: str) -> ApiCall:
    return ApiCall("POST", f"{_repo(repo)}/pulls", json={"base": base, "head": head, "title": title, "body": body})
