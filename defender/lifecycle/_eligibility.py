"""The forge's listings the lifecycle reads with the service's admin token: a paged list of logins, and an
organisation's team by its exact name. Any read that does not answer whole is a `StepFailed`, never a shorter list."""
from __future__ import annotations

from typing import Any

import httpx

from defender.lifecycle._job import StepFailed, answered

#: The forge's largest page (it may answer fewer, and then pages by what it gave).
PAGE = 50


async def listed_entries(forge: httpx.AsyncClient, path: str, what: str, *, key: str,
                         params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every entry the forge lists at `path` (with `params`), one per `key`. The forge may page by fewer than asked (its
    own maximum), so only an empty page, or one that adds nothing (a forge ignoring `page`), ends the listing."""
    found: dict[str, dict[str, Any]] = {}
    page = 1
    while True:
        answer = answered(await forge.get(path, params={**(params or {}), "page": page, "limit": PAGE})).json()
        if not isinstance(answer, list):
            raise StepFailed(f"{what} are not a list")
        new = {str(e.get(key)): e for e in answer if isinstance(e, dict) and str(e.get(key)) not in found}
        if not new:
            return list(found.values())
        found.update(new)
        page += 1


async def listed(forge: httpx.AsyncClient, path: str, what: str, *, key: str) -> list[str]:
    """The `key` of every entry the forge lists at `path` (`listed_entries`)."""
    return [str(e.get(key)) for e in await listed_entries(forge, path, what, key=key)]


async def listed_logins(forge: httpx.AsyncClient, path: str, what: str) -> list[str]:
    """The `login` of every entry the forge lists at `path` (`listed`)."""
    return await listed(forge, path, what, key="login")


async def teams_named(forge: httpx.AsyncClient, org: str, team: str, *, absent_org_ok: bool = False) -> list[dict[str, Any]]:
    """The teams of `org` named exactly `team` (the forge's search matches substrings). An organisation that answers 404
    has none when `absent_org_ok`; any other answer that is not a list of teams is a `StepFailed`."""
    found = await forge.get(f"/api/v1/orgs/{org}/teams/search", params={"q": team, "limit": PAGE})
    if absent_org_ok and found.status_code == 404:
        return []
    body = answered(found).json()
    teams = body.get("data") if isinstance(body, dict) else None
    if not isinstance(teams, list):
        raise StepFailed(f"the team search of {org} answered no list")
    return [t for t in teams if isinstance(t, dict) and t.get("name") == team]


def single_team_id(named: list[dict[str, Any]], org: str, team: str) -> int:
    """The one team of `teams_named`'s answer: its id, or a `StepFailed` when there is none, several, or no numeric id."""
    if len(named) != 1 or not isinstance(named[0].get("id"), int) or isinstance(named[0].get("id"), bool):
        raise StepFailed(f"the team {team} of {org} is not found as one team with an id")
    return int(named[0]["id"])


async def _team_id(forge: httpx.AsyncClient, org: str, team: str) -> int:
    return single_team_id(await teams_named(forge, org, team), org, team)
