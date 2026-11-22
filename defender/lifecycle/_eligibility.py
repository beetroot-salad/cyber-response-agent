"""The forge's listings the lifecycle reads with the service's admin token: a paged list of logins, and an
organisation's team by its exact name. Any read that does not answer whole is a `StepFailed`, never a shorter list."""
from __future__ import annotations

import httpx

from defender.lifecycle._job import StepFailed, answered

#: The forge's largest page (it may answer fewer, and then pages by what it gave).
PAGE = 50


async def listed(forge: httpx.AsyncClient, path: str, what: str, *, key: str) -> list[str]:
    """The `key` of every entry the forge lists at `path`. The forge may page by fewer than asked (its own maximum), so
    only an empty page, or one that adds nothing (a forge ignoring `page`), ends the listing."""
    found: list[str] = []
    page = 1
    while True:
        answer = answered(await forge.get(path, params={"page": page, "limit": PAGE})).json()
        if not isinstance(answer, list):
            raise StepFailed(f"{what} are not a list")
        values = [str(c.get(key)) for c in answer if isinstance(c, dict)]
        if not set(values) - set(found):
            return found
        found += values
        page += 1


async def listed_logins(forge: httpx.AsyncClient, path: str, what: str) -> list[str]:
    """The `login` of every entry the forge lists at `path` (`listed`)."""
    return await listed(forge, path, what, key="login")


async def _team_id(forge: httpx.AsyncClient, org: str, team: str) -> int:
    found = answered(await forge.get(f"/api/v1/orgs/{org}/teams/search", params={"q": team, "limit": PAGE})).json()
    teams = found.get("data") if isinstance(found, dict) else None
    named = [t for t in teams if isinstance(t, dict) and t.get("name") == team] if isinstance(teams, list) else []
    if len(named) != 1 or not isinstance(named[0].get("id"), int):
        raise StepFailed(f"the team {team} of {org} is not found")
    return int(named[0]["id"])
