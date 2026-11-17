"""#1471 r8 W7 at the API: the case record is `{version, system_id}`; a client still sending the template gets 422.
Postgres-gated; the app is the real server over a migrated database (`scripted`, as `tests/api/conftest.py` imports it)."""
from __future__ import annotations

import pytest

from defender.tests.support.api._config1470 import A, TICKET, scripted  # noqa: F401 — the fixture
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def _stored(served) -> int:
    return execute(served.dsn, "SELECT count(*) FROM tenancy.case_versions WHERE tenant_id = %s", (A,))[0][0]


async def test_1471_w7_the_case_record_is_a_system_alone_on_the_wire_and_an_old_clients_template_is_422(scripted):  # noqa: F811 — the imported fixture
    """PUT `{replaces, system_id}` is 201 and reads back as exactly `{version, system_id}`; the same body carrying
    `comment_body` is 422 naming it and stores nothing; the GET never serves it. (W7)"""
    path = f"/tenants/{A}/case-record"
    assert (await scripted.put_system(TICKET, 0)).status_code == 201

    old = await scripted.put_raw(path, {"replaces": 0, "system_id": TICKET, "comment_body": "{disposition}"})
    assert old.status_code == 422, old.text
    assert "comment_body" in old.text, old.text
    assert _stored(scripted) == 0, "the refused write stored a version"

    created = await scripted.put_raw(path, {"replaces": 0, "system_id": TICKET})
    assert created.status_code == 201, created.text
    assert created.json() == {"version": 1, "system_id": TICKET}, created.json()
    assert (await scripted.get("/case-record")).json() == {"version": 1, "system_id": TICKET}

    again = await scripted.put_raw(path, {"replaces": 1, "system_id": TICKET, "comment_body": "x"})
    assert again.status_code == 422, again.text
    assert (await scripted.get("/case-record")).json() == {"version": 1, "system_id": TICKET}
