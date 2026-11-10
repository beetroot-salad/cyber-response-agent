"""Who may merge into a tenant's `main` (#1414 D13), read from the forge with the service's admin token: the merge
whitelist's users and the members of its teams. Any read that does not answer whole is a `StepFailed`, never a
shorter list: the caller then leaves the tenant's earlier record as it was."""
from __future__ import annotations

from typing import Any

import httpx

from defender.lifecycle._job import StepFailed, answered

#: The forge's largest page (it may answer fewer, and then pages by what it gave).
PAGE = 50


async def listed_logins(forge: httpx.AsyncClient, path: str, what: str) -> list[str]:
    """The `login` of every entry the forge lists at `path`. The forge may page by fewer than asked (its own
    maximum), so only an empty page, or one that adds nobody (a forge ignoring `page`), ends the listing."""
    found: list[str] = []
    page = 1
    while True:
        listed = answered(await forge.get(path, params={"page": page, "limit": PAGE})).json()
        if not isinstance(listed, list):
            raise StepFailed(f"{what} are not a list")
        logins = [str(c.get("login")) for c in listed if isinstance(c, dict)]
        if not set(logins) - set(found):
            return found
        found += logins
        page += 1


def _names(rule: dict[str, Any], key: str) -> list[str]:
    listed = rule.get(key)
    return [str(n) for n in listed] if isinstance(listed, list) else []


async def _whitelist(forge: httpx.AsyncClient, repo: str) -> tuple[list[str], list[str]]:
    """`main`'s merge whitelist as stored: its users and its teams. A missing rule or a disabled whitelist is a failure."""
    rule = answered(await forge.get(f"/api/v1/repos/{repo}/branch_protections/main")).json()
    if not isinstance(rule, dict) or rule.get("enable_merge_whitelist") is not True:
        raise StepFailed(f"main on {repo} has no merge whitelist")
    return _names(rule, "merge_whitelist_usernames"), _names(rule, "merge_whitelist_teams")


async def _team_id(forge: httpx.AsyncClient, org: str, team: str) -> int:
    found = answered(await forge.get(f"/api/v1/orgs/{org}/teams/search", params={"q": team, "limit": PAGE})).json()
    teams = found.get("data") if isinstance(found, dict) else None
    named = [t for t in teams if isinstance(t, dict) and t.get("name") == team] if isinstance(teams, list) else []
    if len(named) != 1 or not isinstance(named[0].get("id"), int):
        raise StepFailed(f"the team {team} of {org} is not found")
    return int(named[0]["id"])


async def eligible_to_merge(forge: httpx.AsyncClient, repo: str, *, bots: set[str]) -> frozenset[str]:
    """The logins on `repo`'s `main` merge whitelist, directly and through its teams, but no bot in `bots`."""
    users, teams = await _whitelist(forge, repo)
    org = repo.split("/", 1)[0]
    logins = set(users)
    for team in teams:
        team_id = await _team_id(forge, org, team)
        logins.update(await listed_logins(forge, f"/api/v1/teams/{team_id}/members", f"the members of {team}"))
    return frozenset(logins - bots)
