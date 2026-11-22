"""`resync-people` (#1592 F6(c)): after a restore, and at the upgrade, record a people request for every tenant with a
forge wiring, (none, T), and for every `p-<id>` account on the Keycloak login source, (U, none), known to the product or
not; the request worker does the rest. Accounts it cannot vouch for are listed and left unchanged: a login on the
source that is not `p-` followed by a canonical user id (no request), and a `p-` account whose `login_name` is not its
user's sub (still recorded). It writes nothing to Forgejo."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from defender.lifecycle._eligibility import PAGE
from defender.lifecycle._job import StepFailed, answered
from defender.lifecycle._people_run import user_of
from defender.records.formats import TenantId, UserId


async def source_accounts(forge: httpx.AsyncClient, source_id: int) -> list[dict[str, Any]]:
    """Every account on login source `source_id`, page by page until a page adds none (the forge may page by less)."""
    found: dict[str, dict[str, Any]] = {}
    page = 1
    while True:
        answer = answered(await forge.get("/api/v1/admin/users",
                                          params={"source_id": source_id, "page": page, "limit": PAGE})).json()
        if not isinstance(answer, list):
            raise StepFailed("the forge's account listing is not a list")
        new = {str(a["login"]): a for a in answer if isinstance(a, dict) and "login" in a and str(a["login"]) not in found}
        if not new:
            return list(found.values())
        found.update(new)
        page += 1


async def resync_people(tenants: Any, identity: Any, forge: httpx.AsyncClient, *, source_id: int,
                        say: Callable[[str], None]) -> int:
    """Record the requests, in one transaction; `say` each account listed. The number of requests recorded."""
    add: list[tuple[UserId | None, TenantId | None]] = [
        (None, t.id) for t in await tenants.tenants() if await tenants.forge_wiring(t.id) is not None]
    odd: list[str] = []
    for account in sorted(await source_accounts(forge, source_id), key=lambda a: str(a["login"])):
        if account.get("source_id", source_id) != source_id:
            continue
        login = str(account["login"])
        user = user_of(login)
        if user is None:
            odd.append(f"{login}: not a p-<user id> login (no request recorded)")
            continue
        add.append((user, None))
        known = await identity.user(user)
        if known is not None and known.signin_account_id != account.get("login_name"):
            odd.append(f"{login}: its login_name is not its user's sub")
    if add:
        await tenants.edit_people_requests(add=add)
    for line in odd:
        say(line)
    say(f"recorded {len(add)} people request(s)")
    return len(add)
