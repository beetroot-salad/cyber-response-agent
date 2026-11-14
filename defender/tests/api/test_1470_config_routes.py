"""#1470: a tenant admin configures the tenant's systems, case record and credentials through the API, on the real server.

The app is composed by `defender.api_server.serving` (its `_api_deps`) over a fresh migrated database and this test's
slice of the OpenBao test server, holding the write-only writer policy; Keycloak is played as in `test_1083_real_server`.
Tenants are registered with no records (O8: a tenant's systems are its records from creation). Postgres- and
OpenBao-gated."""
from __future__ import annotations

import collections
import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.support.api._server1083 import (
    A,
    ANN,
    B,
    ORIGIN,
    FakeKeycloak,
    Seeded,
    environment,
    person,
    seed_identity,
)
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._openbao1163 import Bao, openbao  # noqa: F401 — the fixture
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

pytestmark = [pytest.mark.anyio, pytest.mark.postgres, pytest.mark.openbao]

#: FORCED CHOICE (sketch): the design names "the OpenBao address and the role's login" as settings but no names, no
#: KV mount setting, and no login form; these are the sketch's guesses, kept in this one place.
OPENBAO_SETTINGS = ("DEFENDER_OPENBAO_ADDR", "DEFENDER_OPENBAO_KV_MOUNT", "DEFENDER_API_OPENBAO_TOKEN_FILE")

TICKET, ELASTIC = "ticket", "elastic"
TICKET_SETTINGS = dict(R.FIXTURE_FOLDERS[TICKET][0])
TICKET_ACCESS = R.FIXTURE_FOLDERS[TICKET][1]
ELASTIC_SETTINGS = dict(R.FIXTURE_FOLDERS[ELASTIC][0])
ELASTIC_ACCESS = R.FIXTURE_FOLDERS[ELASTIC][1]
TICKET_NAME = "Ticket store (lab)"  # ticket_adapter.DISPLAY_NAME
TOKEN = "a-ticket-token-of-sixteen-or-more"
BODY = "{disposition} — {cause}\n\n{narrative}"


class Configured:
    def __init__(self, client: httpx.AsyncClient, dsn: str, bao: Bao, seeded: Seeded) -> None:
        self.client, self.dsn, self.bao, self.seeded = client, dsn, bao, seeded

    def ann(self, *, write: bool = True) -> dict[str, str]:
        return person(self.seeded.ann_session, write=write)

    def user_id(self, email: str) -> str:
        [(found,)] = execute(self.dsn, "SELECT id FROM identity.users WHERE email = %s", (email,))
        return str(found)

    async def put_system(self, system: str, replaces: int, *, settings: dict[str, str] | None = None,
                         access: str | None = None, enabled: bool = True, tenant: str = A) -> httpx.Response:
        body = {"replaces": replaces, "enabled": enabled,
                "settings": TICKET_SETTINGS if settings is None else settings,
                "access": TICKET_ACCESS if access is None else access}
        return await self.client.put(f"/tenants/{tenant}/systems/{system}", headers=self.ann(), json=body)

    async def get_system(self, system: str) -> httpx.Response:
        return await self.client.get(f"/tenants/{A}/systems/{system}", headers=self.ann(write=False))

    async def delete_system(self, system: str, replaces: int) -> httpx.Response:
        return await self.client.delete(f"/tenants/{A}/systems/{system}", params={"replaces": replaces},
                                        headers=self.ann())

    async def put_case(self, replaces: int, system_id: str = TICKET, comment_body: str = BODY) -> httpx.Response:
        return await self.client.put(f"/tenants/{A}/case-record", headers=self.ann(),
                                     json={"replaces": replaces, "system_id": system_id, "comment_body": comment_body})

    async def put_credentials(self, system: str, for_version: int, credentials: dict[str, str]) -> httpx.Response:
        return await self.client.put(f"/tenants/{A}/systems/{system}/credentials", headers=self.ann(),
                                     json={"for_version": for_version, "credentials": credentials})

    def stored_set(self, system: str, generation: int, tenant: str = A) -> Any:
        """What OpenBao holds at `<tenant>/<system>/g<N>`, read as root (the API cannot read it back)."""
        got = self.bao.call("GET", f"{self.bao.kv_mount}/data/{tenant}/{system}/g{generation}")
        return got.json()["data"]["data"] if got.status_code == 200 else None


@pytest.fixture
async def configured(migrated_database: str, openbao: Bao, tmp_path: Path) -> AsyncIterator[Configured]:  # noqa: F811
    """The real server over A and B (each with the fixture's alert mapping, no records), the API holding the writer
    policy on this test's KV mount."""
    from defender.api_server import Settings, serving
    from defender.credential_proxy._openbao import store_policies

    register_tenant(migrated_database, A, records=None)
    register_tenant(migrated_database, B, records=None)
    seeded = await seed_identity(migrated_database)
    writer = openbao.token_for(openbao.apply_policy("api-writer", store_policies(kv_mount=openbao.kv_mount)["writer"]))
    token_file = tmp_path / "openbao-token"
    token_file.write_text(f"{writer}\n")
    environ = environment(tmp_path, dsn=migrated_database) | dict(zip(
        OPENBAO_SETTINGS, (openbao.addr, openbao.kv_mount, str(token_file)), strict=True))
    keycloak = FakeKeycloak()
    async with serving(Settings.from_environ(environ), transport=keycloak) as running, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=running.app), base_url=ORIGIN) as client:
        yield Configured(client, migrated_database, openbao, seeded)
    assert keycloak.unmodelled == []


def _text(problem: httpx.Response) -> str:
    """Everything a problem body says, `detail` and each listed error: the design does not say where faults sit."""
    body = problem.json()
    return " ".join([str(body.get("detail") or ""), *(str(e) for e in body.get("errors") or [])])


def _names_version(problem: httpx.Response, version: int) -> bool:
    return re.search(rf"(?<![\w-]){version}(?![\w-]|\.\d)", _text(problem)) is not None


def _served(version: int, *, has_credentials: bool = False, settings: dict[str, str] | None = None,
            access: str | None = None, enabled: bool = True) -> dict[str, Any]:
    return {"system_id": TICKET, "version": version, "display_name": TICKET_NAME, "enabled": enabled,
            "settings": TICKET_SETTINGS if settings is None else settings,
            "access": TICKET_ACCESS if access is None else access, "has_credentials": has_credentials}


# --- O3 / O4: save and read a system --------------------------------------------------------------------------------

async def test_o3_o4_a_system_is_created_201_replaced_200_and_read_back_as_stored(configured):
    """A save with `replaces: 0` is 201 at version 1, one naming 1 is 200 at version 2; reads answer the record. (O3, O4)"""
    assert (await configured.get_system(TICKET)).status_code == 404  # never written: absent
    created = await configured.put_system(TICKET, 0)
    assert created.status_code == 201, created.text
    assert created.json() == _served(1)
    assert (await configured.get_system(TICKET)).json() == _served(1)

    edited = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    replaced = await configured.put_system(TICKET, 1, settings=edited, enabled=False)
    assert replaced.status_code == 200, replaced.text
    assert replaced.json() == _served(2, settings=edited, enabled=False)
    listed = await configured.client.get(f"/tenants/{A}/systems", headers=configured.ann(write=False))
    assert listed.status_code == 200
    assert listed.json()["items"] == [_served(2, settings=edited, enabled=False)]
    assert [v.version for v in R.system_versions(configured.dsn, A, TICKET)] == [1, 2]
    assert {v.author for v in R.system_versions(configured.dsn, A, TICKET)} == {configured.user_id(ANN)}


async def test_o4_p2_a_save_naming_a_version_a_read_no_longer_shows_is_409_naming_the_current_one(configured):
    """Two admins edit from version 1: the first gets 2, the second 409 naming 2, and nothing is written. (O4, P2)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_system(TICKET, 1)).status_code == 200
    stale = await configured.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "30"})
    assert stale.status_code == 409, stale.text
    assert _names_version(stale, 2), stale.text
    assert [v.version for v in R.system_versions(configured.dsn, A, TICKET)] == [1, 2]


async def test_o4_p6_a_record_the_judgement_refuses_is_422_listing_every_fault_naming_system_and_key(configured):
    """Settings missing both required keys: 422 naming the system and each key; nothing is stored. (O4, P6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201  # control: the same route takes a good record
    refused = await configured.put_system(TICKET, 1, settings={})
    assert refused.status_code == 422, refused.text
    said = _text(refused)
    assert all(name in said for name in (TICKET, "TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN")), said
    assert [v.version for v in R.system_versions(configured.dsn, A, TICKET)] == [1]


async def test_o4_p6_an_id_that_is_not_a_catalog_adapter_is_the_judgements_422(configured):
    """`tix` names no catalog adapter: 422 naming it (the judgement's fault), nothing stored. (O4, P4, P6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201  # control
    refused = await configured.put_system("tix", 0)
    assert refused.status_code == 422, refused.text
    assert "tix" in _text(refused)
    assert R.system_versions(configured.dsn, A, "tix") == []


# --- P2 / O5: delete and re-create ----------------------------------------------------------------------------------

async def test_p2_o5_a_deleted_system_reads_absent_and_is_re_created_with_replaces_0_as_201(configured):
    """Delete v1 (tombstone v2) → 204, absent; re-create with `replaces: 0` → 201 v3; again → 409 naming 3. (P2, O4, O5)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    deleted = await configured.delete_system(TICKET, 1)
    assert deleted.status_code == 204, deleted.text
    assert (await configured.get_system(TICKET)).status_code == 404
    recreated = await configured.put_system(TICKET, 0)
    assert recreated.status_code == 201, recreated.text
    assert recreated.json() == _served(3)
    again = await configured.put_system(TICKET, 0)
    assert again.status_code == 409, again.text
    assert _names_version(again, 3), again.text


async def test_o5_deleting_with_no_current_record_is_404_and_a_stale_delete_409(configured):
    """No current record: 404 whatever `replaces` says; a delete naming 0 over v1: 409 naming 1. (O5, P2)"""
    assert (await configured.delete_system(TICKET, 7)).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    stale = await configured.delete_system(TICKET, 0)
    assert stale.status_code == 409, stale.text
    assert _names_version(stale, 1), stale.text
    assert [v.deleted for v in R.system_versions(configured.dsn, A, TICKET)] == [False]


async def test_o5_deleting_the_case_records_system_is_refused_by_the_cover_rule(configured):
    """The case record names ticket: deleting ticket is 422 naming it; after the case goes, the delete is 204. (O5, O6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 201
    covered = await configured.delete_system(TICKET, 1)
    assert covered.status_code == 422, covered.text
    assert TICKET in _text(covered)
    assert (await configured.client.delete(f"/tenants/{A}/case-record", params={"replaces": 1},
                                           headers=configured.ann())).status_code == 204
    assert (await configured.delete_system(TICKET, 1)).status_code == 204


# --- O6: the case record --------------------------------------------------------------------------------------------

async def test_o6_the_case_record_is_created_read_stale_refused_deleted_and_then_absent(configured):
    """PUT 201 v1 and GET it; a stale PUT 409 naming 1; DELETE 204; GET 404. (O6, P2)"""
    path = f"/tenants/{A}/case-record"
    assert (await configured.client.get(path, headers=configured.ann(write=False))).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    created = await configured.put_case(0)
    assert created.status_code == 201, created.text
    record = {"version": 1, "system_id": TICKET, "comment_body": BODY}
    assert created.json() == record
    assert (await configured.client.get(path, headers=configured.ann(write=False))).json() == record
    stale = await configured.put_case(0, comment_body="{disposition}")
    assert stale.status_code == 409, stale.text
    assert _names_version(stale, 1), stale.text
    assert (await configured.client.delete(path, params={"replaces": 1}, headers=configured.ann())).status_code == 204
    assert (await configured.client.get(path, headers=configured.ann(write=False))).status_code == 404


# --- O7: credentials ------------------------------------------------------------------------------------------------

async def test_o7_p3_credentials_follow_the_generation_not_the_version(configured):
    """Set for v1 → 204 at g1; v2 changes a setting (same generation): for v1 still 204; v3 moves the base: for v2 is
    409 naming 3 and `has_credentials` is false until a set for v3. (O7, P3, D-D)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    first = await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert first.status_code == 204, first.text
    assert configured.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True

    timeout = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    same_generation = await configured.put_system(TICKET, 1, settings=timeout)
    assert same_generation.json()["has_credentials"] is True  # as of before the write, same generation
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN + "-2"})).status_code == 204

    moved = TICKET_ACCESS.replace("http://soc-playground:8004", "http://soc-elsewhere:8004")
    assert moved != TICKET_ACCESS, "premise: the base is in the fixture's access text"
    new_generation = await configured.put_system(TICKET, 2, settings=timeout, access=moved)
    assert new_generation.status_code == 200, new_generation.text
    assert new_generation.json()["has_credentials"] is False
    refused = await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})
    assert refused.status_code == 409, refused.text
    assert _names_version(refused, 3), refused.text
    assert configured.stored_set(TICKET, 2) is None
    assert (await configured.put_credentials(TICKET, 3, {"api_key": TOKEN})).status_code == 204
    assert configured.stored_set(TICKET, 2) == {"kind": "static", "fields": {"api_key": TOKEN}}
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True


async def test_o7_a_set_that_breaks_the_schemes_credential_schema_is_422_naming_the_field(configured):
    """elastic is basic: `{username, password}` is 204; a username holding `:` is 422 naming `username`, nothing
    stored at its generation beyond the good set. (O7, credential schema)"""
    assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    good = {"username": "defender-reader", "password": "a-password-of-sixteen-or-more"}
    assert (await configured.put_credentials(ELASTIC, 1, good)).status_code == 204
    refused = await configured.put_credentials(ELASTIC, 1, {**good, "username": "defender:reader"})
    assert refused.status_code == 422, refused.text
    assert "username" in _text(refused)
    assert configured.stored_set(ELASTIC, 1) == {"kind": "static", "fields": good}


async def test_o7_credentials_for_a_system_with_no_current_record_are_404(configured):
    """No record: 404, nothing written to the secret store. (O7)"""
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 404
    assert configured.stored_set(TICKET, 1) is None


# --- O9: one audit event per stored write ---------------------------------------------------------------------------

MAPPING_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
AUDITED = ("system.update", "system.delete", "case_record.update", "case_record.delete", "system.credentials",
           "alert_mapping.update")


async def test_o9_each_stored_write_announces_one_event_naming_the_member_and_refused_writes_none(configured, caplog):
    """System put x2, case put/delete, credentials, system delete, mapping: one event each, by Ann in A; a stale
    put, a judged put and a refused credential set announce nothing; the credential event names fields, not values. (O9)"""
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_system(TICKET, 1)).status_code == 200
    assert (await configured.put_system(TICKET, 1)).status_code == 409
    assert (await configured.put_system(TICKET, 2, settings={})).status_code == 422
    assert (await configured.put_case(0)).status_code == 201
    assert (await configured.client.delete(f"/tenants/{A}/case-record", params={"replaces": 1},
                                           headers=configured.ann())).status_code == 204
    assert (await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
    assert (await configured.put_credentials(TICKET, 9, {"api_key": TOKEN})).status_code == 409
    assert (await configured.delete_system(TICKET, 2)).status_code == 204
    assert (await configured.client.put(f"/tenants/{A}/alert-mapping", headers=configured.ann(),
                                        json={e: FIXTURE_ALERT_MAPPING.get(e) for e in MAPPING_ENTRIES})).status_code == 200

    events = [r for r in caplog.records if getattr(r, "action", None) in AUDITED]
    assert collections.Counter(r.action for r in events) == {
        "system.update": 2, "case_record.update": 1, "case_record.delete": 1, "system.credentials": 1,
        "system.delete": 1, "alert_mapping.update": 1}, [(r.name, r.getMessage()) for r in events]
    ann = configured.user_id(ANN)
    assert {(r.actor, r.tenant_id) for r in events} == {(ann, A)}
    assert {r.target for r in events if r.action.startswith("system.")} == {TICKET}
    [credentials] = [r for r in events if r.action == "system.credentials"]
    told = f"{credentials.getMessage()} {getattr(credentials, 'detail', '')}"
    assert "api_key" in told, told
    assert TOKEN not in told, told


# --- O15: the remaining refusal names its owner ---------------------------------------------------------------------

async def test_o15_the_connection_check_still_refuses_501_naming_its_owner_not_this_piece(configured):
    """A saved system's check is 501 naming #1460, never #1470. (O15, D-C)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    refused = await configured.client.post(f"/tenants/{A}/systems/{TICKET}/check", headers=configured.ann())
    assert refused.status_code == 501, refused.text
    assert "#1460" in refused.json()["detail"]
    assert "#1470" not in refused.json()["detail"]
