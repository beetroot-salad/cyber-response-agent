"""#1592 r12 step 5, "Sessions": which of a person's Forgejo session rows a run deletes (F11, OD-4a, P35).

Rows by the person's Forgejo uid, among those the prefilter selects (data holding the gob key `uid`):
- suspended (wanted nowhere): every one;
- otherwise: those with no `signed_in_at` (revived), and, with a `signed_out_at`, those stamped before it.
Other people's rows and anonymous rows are never touched. Marked `postgres` (the sessions database is real).
"""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from defender.tests.tenancy.people_1592._spec1592 import ANONYMOUS_DATA, login_of, signed_in_data
from defender.tests.tenancy.people_1592._world1592 import NOW, T, U2, People

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

MINUTE = dt.timedelta(minutes=1)


async def _rows(people: People, user: Any, other: Any) -> None:
    """Erin's rows around her sign-out (if any), plus Frank's and an anonymous one; key -> what it is."""
    uid, other_uid = (people.forge.uid(login_of(str(u.id))) for u in (user, other))
    signed_out = (await people.identity.user(user.id)).signed_out_at
    pivot = signed_out or dt.datetime.now(dt.UTC)
    rows = {
        "before0000000000": (signed_in_data(uid), pivot - 10 * MINUTE),
        "after00000000000": (signed_in_data(uid), pivot + MINUTE),
        "unstamped0000000": (signed_in_data(uid), None),
        "frank00000000000": (signed_in_data(other_uid), None),
        "anonymous0000000": (ANONYMOUS_DATA, None),
    }
    for key, (data, stamped) in rows.items():
        people.sessions.plant(key, data, signed_in_at=stamped)


async def _erin_and_frank(people: People) -> tuple[Any, Any]:
    await people.tenant(T)
    await people.tenant(U2)
    erin = await people.person("erin@x.org", T, U2)
    frank = await people.person("frank@x.org", T)
    # `person` planted one stamped row each; these cases plant their own
    from defender.tests.support.shared._postgres1339 import execute

    execute(people.sessions.dsn, "DELETE FROM session")
    return erin, frank


async def test_after_a_product_sign_out_rows_stamped_before_it_and_unstamped_rows_go(people: People):
    """Erin signs out of the product and stays wanted: her rows stamped before `signed_out_at` and her unstamped
    (revived) row are deleted; the one begun after it stays; Frank's and the anonymous row stay."""
    erin, frank = await _erin_and_frank(people)
    await people.identity.add_session("erin-product", erin.id, now=NOW, expires_at=NOW + dt.timedelta(days=7))
    await people.identity.sign_out(erin.id, "erin-product")
    await _rows(people, erin, frank)

    await people.step()

    assert people.sessions.keys() == {"after00000000000", "frank00000000000", "anonymous0000000"}
    assert (await people.open_requests()) == []


async def test_with_no_sign_out_no_stamped_row_is_deleted_but_an_unstamped_one_is(people: People):
    """OD-4a: Erin leaves T and stays in U2, never having signed out: every stamped row of hers stays; the unstamped
    one (P35, revived) is deleted."""
    erin, frank = await _erin_and_frank(people)
    await _rows(people, erin, frank)
    await people.end(erin, T)

    await people.step()

    assert people.sessions.keys() == {"before0000000000", "after00000000000", "frank00000000000", "anonymous0000000"}


async def test_a_suspended_person_loses_every_row_stamped_or_not(people: People):
    """Frank's only membership ends: he is suspended, and every row of his goes, whatever its stamp; Erin's stay."""
    erin, frank = await _erin_and_frank(people)
    uid = people.forge.uid(login_of(str(frank.id)))
    people.sessions.plant("frank-old0000000", signed_in_data(uid), signed_in_at=dt.datetime.now(dt.UTC) - MINUTE)
    people.sessions.plant("frank-new0000000", signed_in_data(uid), signed_in_at=dt.datetime.now(dt.UTC) + MINUTE)
    people.sessions.plant("erin000000000000", signed_in_data(people.forge.uid(login_of(str(erin.id)))),
                          signed_in_at=dt.datetime.now(dt.UTC) - MINUTE)
    await people.end(frank, T)

    await people.step()

    assert people.sessions.keys() == {"erin000000000000"}
