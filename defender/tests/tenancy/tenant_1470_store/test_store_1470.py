"""#1470 P2, P3, O4-O8, store side: a write names the version a read showed, a tombstone reads as none, the store says
whether a write created the record or raised its generation, refusals are typed, `credential_slot` answers P3, and a
tenant that is not active takes nothing. Entry: `RecordStore` over a migrated Postgres, the judgement injected."""
from __future__ import annotations

import uuid

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _records1470 as K
from defender.tests.support.tenancy import _systems1366 as R

BASE_A, BASE_B = R.declaration("http://ticket.test"), R.declaration("http://other.test")
SETTINGS = dict(R.FIXTURE_FOLDERS["ticket"][0])
INDEXED = {**SETTINGS, "TICKET_TIMEOUT_SEC": "30"}
BASIC = R.declaration("http://basic.test", scheme="basic")

pytestmark = pytest.mark.postgres


def _tenant(dsn: str, *, state: str = "active") -> str:
    tenant = str(uuid.uuid4())
    register_tenant(dsn, tenant, state=state, records=None)
    return tenant


def put(tenant: str, *, replaces: int, access: str = BASE_A, settings: dict | None = None, system: str = "ticket",
        enabled: bool | None = True):
    async def work(store):
        return await store.put_system(tenant, system, replaces=replaces, adapter=system, enabled=enabled,
                                      settings=dict(settings or SETTINGS), access=access, author=K.SEED)
    return work


def delete(tenant: str, *, replaces: int, system: str = "ticket"):
    async def work(store):
        return await store.delete_system(tenant, system, replaces=replaces, author=K.SEED)
    return work


def put_case(tenant: str, *, replaces: int):
    async def work(store):
        return await store.put_case(tenant, replaces=replaces, system_id="ticket", comment_body="Hello", author=K.SEED)
    return work


def delete_case(tenant: str, *, replaces: int):
    async def work(store):
        return await store.delete_case(tenant, replaces=replaces, author=K.SEED)
    return work


def slot(tenant: str, for_version: int, system: str = "ticket"):
    async def work(store):
        return await store.credential_slot(tenant, system, for_version)
    return work


def stored(dsn: str, tenant: str, system: str = "ticket") -> list[tuple[int, bool]]:
    return [(v.version, v.deleted) for v in R.system_versions(dsn, tenant, system)]


def stored_case(dsn: str, tenant: str) -> list[tuple[int, bool]]:
    return [(v.version, v.deleted) for v in R.case_versions(dsn, tenant)]


def test_1470_p2_a_system_write_names_the_shown_version_and_a_tombstone_shows_as_none(migrated_database):  # noqa: F811
    """v1, v2, delete (v3): `replaces=3` (the tombstone's number) is stale naming 0, `replaces=0` re-creates as v4 and says
    it created; a second `replaces=0` is stale naming 4; the number never goes back. (P2, O4 scenarios)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    first = K.run(dsn, put(tenant, replaces=0))
    assert first.created is True
    assert K.run(dsn, put(tenant, replaces=1, settings=INDEXED)).created is False
    K.run(dsn, delete(tenant, replaces=2))
    assert stored(dsn, tenant) == [(1, False), (2, False), (3, True)]

    stale = K.refused(dsn, put(tenant, replaces=3))
    assert (K.kind_of(stale), stale.current_version) == ("Stale", 0)
    assert stored(dsn, tenant) == [(1, False), (2, False), (3, True)], "a refused write stores nothing"

    assert K.run(dsn, put(tenant, replaces=0)).created is True
    assert stored(dsn, tenant)[-1] == (4, False)
    again = K.refused(dsn, put(tenant, replaces=0))
    assert (K.kind_of(again), again.current_version) == ("Stale", 4)
    assert len(stored(dsn, tenant)) == 4


def test_1470_p2_a_replace_of_a_live_record_names_the_current_version_and_any_other_is_stale(migrated_database):  # noqa: F811
    """With v2 current: `replaces` 0, 1 and 5 are each stale naming 2 and store nothing; `replaces=2` replaces. (P2)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put(tenant, replaces=1, settings=INDEXED))
    for wrong in (0, 1, 5):
        stale = K.refused(dsn, put(tenant, replaces=wrong))
        assert (K.kind_of(stale), stale.current_version) == ("Stale", 2), wrong
    assert stored(dsn, tenant) == [(1, False), (2, False)]
    assert K.run(dsn, put(tenant, replaces=2)).created is False
    assert stored(dsn, tenant)[-1] == (3, False)


def _moved(dsn: str, tenant: str, move: str) -> None:
    """Another writer's move of v1 to v2: a new base (the credential generation rises), a settings edit or a disable (it
    does not)."""
    moves = {"base": put(tenant, replaces=1, access=BASE_B), "settings": put(tenant, replaces=1, settings=INDEXED),
             "disable": put(tenant, replaces=1, enabled=False)}
    K.run(dsn, moves[move])


@pytest.mark.parametrize("move", ["base", "settings", "disable"])
@pytest.mark.parametrize("act", ["put", "delete"])
def test_1470_p2_a_write_prepared_for_a_version_another_writers_move_replaced_is_stale_naming_the_current_one(
        migrated_database, act, move):  # noqa: F811
    """Whichever way another writer moved v1 to v2 (a new base, a settings edit, a disable), a put or a delete still
    naming v1 is `Stale` naming 2, and nothing is stored. (#1366 O5 over the store, P2)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    _moved(dsn, tenant, move)
    before = stored(dsn, tenant)
    assert before == [(1, False), (2, False)], "premise: the other writer's move is version 2"

    stale = K.refused(dsn, put(tenant, replaces=1, settings=INDEXED) if act == "put" else delete(tenant, replaces=1))

    assert (K.kind_of(stale), stale.current_version) == ("Stale", 2)
    assert stored(dsn, tenant) == before, "a refused write stores nothing"


def test_1470_p2_the_case_record_shows_a_tombstone_as_none_and_re_creates_with_the_next_number(migrated_database):  # noqa: F811
    """The case record, as the system: v1, delete (v2); `replaces=2` is stale naming 0; `replaces=0` creates v3; again is
    stale naming 3; a live record's wrong `replaces` is stale naming it. (P2, O6)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    assert K.run(dsn, put_case(tenant, replaces=0)).created is True
    wrong = K.refused(dsn, put_case(tenant, replaces=0))
    assert (K.kind_of(wrong), wrong.current_version) == ("Stale", 1)
    K.run(dsn, delete_case(tenant, replaces=1))
    assert stored_case(dsn, tenant) == [(1, False), (2, True)]

    stale = K.refused(dsn, put_case(tenant, replaces=2))
    assert (K.kind_of(stale), stale.current_version) == ("Stale", 0)
    assert K.run(dsn, put_case(tenant, replaces=0)).created is True
    assert stored_case(dsn, tenant) == [(1, False), (2, True), (3, False)]
    again = K.refused(dsn, put_case(tenant, replaces=0))
    assert (K.kind_of(again), again.current_version) == ("Stale", 3)


@pytest.mark.parametrize("replaces", [0, 1, 2, 99])
def test_1470_p2_deleting_what_has_no_current_record_is_refused_as_that_before_any_version_comparison(
        migrated_database, replaces):  # noqa: F811
    """A delete of a system never written, or one whose newest version is a tombstone, is `NoCurrentRecord` whatever
    `replaces` says (the stale answer would name a version of nothing); a live system's wrong `replaces` is stale (control).
    The case record likewise. (P2 exception, O5, O6)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    never = K.refused(dsn, delete(tenant, replaces=replaces))
    assert K.kind_of(never) == "NoCurrentRecord", never
    assert K.kind_of(K.refused(dsn, delete_case(tenant, replaces=replaces))) == "NoCurrentRecord"

    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put_case(tenant, replaces=0))
    K.run(dsn, delete_case(tenant, replaces=1))
    K.run(dsn, delete(tenant, replaces=1))
    assert stored(dsn, tenant) == [(1, False), (2, True)], "premise: the system is deleted"
    assert K.kind_of(K.refused(dsn, delete(tenant, replaces=replaces))) == "NoCurrentRecord"
    assert K.kind_of(K.refused(dsn, delete_case(tenant, replaces=replaces))) == "NoCurrentRecord"

    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put_case(tenant, replaces=0))
    live = K.refused(dsn, delete(tenant, replaces=7))
    assert (K.kind_of(live), live.current_version) == ("Stale", 3), "control: a live record's wrong replaces is stale"
    live_case = K.refused(dsn, delete_case(tenant, replaces=7))
    assert (K.kind_of(live_case), live_case.current_version) == ("Stale", 3), "control"


def test_1470_o4_a_write_says_whether_it_raised_the_credential_generation_and_it_agrees_with_what_is_stored(
        migrated_database):  # noqa: F811
    """An index-key change and a disable keep the generation; a changed base raises it; the flag is what the stored
    generations show, and a replace is not a create. (O4, P3)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    kept = K.run(dsn, put(tenant, replaces=1, settings=INDEXED))
    disabled = K.run(dsn, put(tenant, replaces=2, settings=INDEXED, enabled=False))
    moved = K.run(dsn, put(tenant, replaces=3, access=BASE_B, settings=INDEXED, enabled=False))

    assert [(r.created, r.generation_raised) for r in (kept, disabled, moved)] == [(False, False), (False, False), (False, True)]
    assert [v.credential_generation for v in R.system_versions(dsn, tenant, "ticket")] == [1, 1, 1, 2]


def test_1470_p3_a_re_create_after_a_delete_takes_a_generation_no_earlier_version_had(migrated_database):  # noqa: F811
    """v1 at generation 1, v2 at 2; delete (v3); re-create (v4): generation 3, never a reused one. (P3, #1366 P5)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put(tenant, replaces=1, access=BASE_B))
    K.run(dsn, delete(tenant, replaces=2))
    K.run(dsn, put(tenant, replaces=0))
    assert [v.credential_generation for v in R.system_versions(dsn, tenant, "ticket")] == [1, 2, 2, 3]


def test_1470_p6_a_judged_write_is_refused_with_every_fault_the_judge_found_and_stores_nothing(migrated_database):  # noqa: F811
    """The judge's faults come back, all of them and unaltered, as the typed judgement refusal; none of the four writes
    stores a row. (P6, O4, O5, O6)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put_case(tenant, replaces=0))
    faults = ["system ticket: first fault", "system ticket: second fault"]
    judge = K.refuse_with(*faults)
    for work in (put(tenant, replaces=1), delete(tenant, replaces=1), put_case(tenant, replaces=1),
                 delete_case(tenant, replaces=1)):
        refusal = K.refused(dsn, work, judge=judge)
        assert K.kind_of(refusal) == "Judged", refusal
        assert list(refusal.faults) == faults, refusal
    assert (stored(dsn, tenant), stored_case(dsn, tenant)) == ([(1, False)], [(1, False)])


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_1470_o8_a_tenant_that_is_not_active_takes_no_write_and_none_names_an_import(migrated_database, state):  # noqa: F811
    """On every door (system put and delete, case put and delete, the credential slot) a tenant in any state but `active`
    is refused as `TenantNotActive`, naming no import, with nothing stored; the active tenant beside it is written
    (control, on the same doors). (O8: one rule, known iff active)"""
    dsn = migrated_database
    closed, open_ = _tenant(dsn, state=state), _tenant(dsn)
    K.run(dsn, put(open_, replaces=0))
    K.run(dsn, put_case(open_, replaces=0))
    assert K.run(dsn, slot(open_, 1)) is not None, "control: the active tenant's slot answers"

    for work in (put(closed, replaces=0), delete(closed, replaces=0), put_case(closed, replaces=0),
                 delete_case(closed, replaces=0), slot(closed, 1)):
        refusal = K.refused(dsn, work)
        assert K.kind_of(refusal) == "TenantNotActive", (state, refusal)
        assert "import" not in str(refusal).lower(), str(refusal)
    assert (stored(dsn, closed), stored_case(dsn, closed)) == ([], [])


def test_1470_o8_a_tenant_with_no_row_is_no_such_tenant_on_every_door_and_not_the_not_active_refusal(migrated_database):  # noqa: F811
    """A tenant id with no row: `NoSuchTenant` (404), a type apart from `TenantNotActive` (409). (O8, O7)"""
    dsn, ghost = migrated_database, str(uuid.uuid4())
    for work in (put(ghost, replaces=0), delete(ghost, replaces=0), put_case(ghost, replaces=0),
                 delete_case(ghost, replaces=0), slot(ghost, 1)):
        assert K.kind_of(K.refused(dsn, work)) == "NoSuchTenant"


def test_1470_o8_a_tenant_with_no_records_takes_its_first_write_with_no_import_step(migrated_database):  # noqa: F811
    """An active tenant nothing was written for (no mark, no import) takes `put_system(replaces=0)` as version 1 and
    says it created it. (O8: a tenant with no records is not a refusal)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    assert K.run(dsn, put(tenant, replaces=0)).created is True
    assert stored(dsn, tenant) == [(1, False)]


def test_1470_p3_the_slot_is_the_current_versions_generation_and_parsed_scheme_for_any_version_of_that_generation(
        migrated_database):  # noqa: F811
    """v1, v2 (index key) at generation 1, v3 (base) at 2, v4 disabled at 2: `for_version` 4 and 3 (a disabled current
    version counts; an older version of the same generation) answer generation 2 and the declaration's scheme; 1 and 2
    (an older generation), 0, 5 and 100 (unknown, future) are refused as `Stale` naming current version 4.
    (P3, O7)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, put(tenant, replaces=1, settings=INDEXED))
    K.run(dsn, put(tenant, replaces=2, access=BASE_B, settings=INDEXED))
    K.run(dsn, put(tenant, replaces=3, access=BASE_B, settings=INDEXED, enabled=False))

    for accepted in (4, 3):
        generation, auth = K.slot_parts(K.run(dsn, slot(tenant, accepted)))
        assert (generation, auth.scheme) == (2, "bearer"), accepted
    for moved in (1, 2, 0, 5, 100):
        refusal = K.refused(dsn, slot(tenant, moved))
        assert K.kind_of(refusal) == "Stale", (moved, refusal)
        assert refusal.current_version == 4, (moved, refusal)

    other = K.run(dsn, lambda store: store.put_system(tenant, "ticket", replaces=4, adapter="ticket", enabled=True,
                                                      settings=INDEXED, access=BASIC, author=K.SEED))
    assert other.generation_raised is True, "premise: a new auth scheme is a new generation"
    assert K.slot_parts(K.run(dsn, slot(tenant, 5)))[1].scheme == "basic"


def test_1470_p3_the_slot_refuses_a_deleted_or_never_written_system_and_a_re_created_one_is_a_new_generation(
        migrated_database):  # noqa: F811
    """No record (never written, or deleted) is `NoCurrentRecord` for any `for_version`; after a re-create the old versions'
    generation is not the current one (refused naming the new version), and the re-created version answers a generation
    never used before. (P3, O7)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    assert K.kind_of(K.refused(dsn, slot(tenant, 1))) == "NoCurrentRecord"
    K.run(dsn, put(tenant, replaces=0))
    K.run(dsn, delete(tenant, replaces=1))
    for version in (1, 2, 3):
        assert K.kind_of(K.refused(dsn, slot(tenant, version))) == "NoCurrentRecord", version
    K.run(dsn, put(tenant, replaces=0))
    for old in (1, 2):
        refusal = K.refused(dsn, slot(tenant, old))
        assert K.kind_of(refusal) == "Stale", old
        assert refusal.current_version == 3, old
    assert K.slot_parts(K.run(dsn, slot(tenant, 3)))[0] == 2


def test_1470_p3_a_stored_access_that_no_longer_parses_is_a_refusal_naming_the_system_not_a_scheme(migrated_database):  # noqa: F811
    """A current version whose access text cannot be parsed (planted by SQL: the store would not have written it) makes the
    slot refuse with the parse fault naming the system; it is the store's `Judged`. (O7, G1)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    execute(dsn, "INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings, access, "
                 "credential_generation, deleted, author, written_at) VALUES (%s, 'ticket', 1, 'ticket', true, '{}'::jsonb, "
                 "'not: [a declaration', 1, false, 'seed', now())", (tenant,))
    refusal = K.refused(dsn, slot(tenant, 1))
    assert K.kind_of(refusal) == "Judged", refusal
    assert list(refusal.faults), refusal
    assert any("ticket" in fault for fault in refusal.faults), refusal.faults


def test_1470_o8_tenant_records_carry_no_imported_flag_and_their_wire_form_has_none():
    """`TenantRecords` has no `imported` field; its wire form has no such key and reads back equal, so a job image built
    from this revision and a helper from it agree. (O8, O12: the old image refuses the new wire, with no shim)"""
    import dataclasses

    from defender.tenancy.models import TenantRecords

    records = R.to_value(R.fixture_records())
    assert "imported" not in {f.name for f in dataclasses.fields(TenantRecords)}
    wire = records.as_wire()
    assert "imported" not in wire
    assert set(wire) == {"systems", "case"}, sorted(wire)
    assert TenantRecords.from_wire(wire) == records
    assert TenantRecords.from_wire(TenantRecords().as_wire()) == TenantRecords()


# --- G1: refusal precedence over every door and every set of faults it can meet ---------------------------------------

#: The faults a write or the slot can meet, in the order the design states its refusals (O5, O7: 404, stale, judgement).
ORDER = ("no current record", "stale", "judged")
FIRST = {"no current record": "NoCurrentRecord", "stale": "Stale", "judged": "Judged"}
#: Each door's faults: a put creates, so it meets no "no current record".
DOOR_FAULTS = {"put_system": ORDER[1:], "delete_system": ORDER, "put_case": ORDER[1:], "delete_case": ORDER,
               "credential_slot": ORDER}
BROKEN_ACCESS = "not: [a declaration"


def _plant_system(dsn: str, tenant: str, version: int, *, generation: int = 1, deleted: bool = False,
                  access: str = BASE_A) -> None:
    import json

    execute(dsn, "INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings, access, "
                 "credential_generation, deleted, author, written_at) VALUES (%s, 'ticket', %s, 'ticket', true, %s::jsonb, %s, "
                 "%s, %s, 'planted', now())", (tenant, version, json.dumps(SETTINGS), access, generation, deleted))


def _plant_case(dsn: str, tenant: str, version: int, *, deleted: bool = False) -> None:
    execute(dsn, "INSERT INTO tenancy.case_versions (tenant_id, version, system_id, comment_body, deleted, author, "
                 "written_at) VALUES (%s, %s, 'ticket', 'Hello', %s, 'planted', now())", (tenant, version, deleted))


def _meeting(dsn: str, tenant: str, door: str, faults: frozenset[str]):
    """Plant `tenant`'s history so that `door` meets exactly `faults`; the work that calls it."""
    none, stale = "no current record" in faults, "stale" in faults
    if door == "credential_slot":  # v1 at g1; v2 at g2 (its access broken when judged); v3 a tombstone over it when none
        access = BROKEN_ACCESS if "judged" in faults else BASE_A
        _plant_system(dsn, tenant, 1)
        _plant_system(dsn, tenant, 2, generation=2, access=access)
        if none:
            _plant_system(dsn, tenant, 3, generation=2, deleted=True, access=access)
        return slot(tenant, 1 if stale else 2)
    _plant_system(dsn, tenant, 1)
    if door in ("put_case", "delete_case"):
        _plant_case(dsn, tenant, 1)
        if none:
            _plant_case(dsn, tenant, 2, deleted=True)
        if door == "put_case":
            return put_case(tenant, replaces=5 if stale else 1)
        return delete_case(tenant, replaces=7 if stale else (0 if none else 1))
    if none:
        _plant_system(dsn, tenant, 2, deleted=True)
    if door == "put_system":
        return put(tenant, replaces=5 if stale else 1, settings=INDEXED)
    return delete(tenant, replaces=7 if stale else (0 if none else 1))


def _every_subset() -> list[tuple[str, frozenset[str]]]:
    import itertools

    return [(door, frozenset(chosen)) for door, faults in DOOR_FAULTS.items()
            for n in range(1, len(faults) + 1) for chosen in itertools.combinations(faults, n)]


def test_1470_g1_every_door_of_the_store_is_in_the_precedence_table():
    """The table's doors are exactly `RecordStore`'s public coroutines (but `close`): a door added later is held too. (G1)"""
    import inspect

    from defender.system_records import RecordStore

    doors = {n for n, f in inspect.getmembers(RecordStore, inspect.iscoroutinefunction) if not n.startswith("_")}
    assert doors - {"close"} == set(DOOR_FAULTS)


@pytest.mark.parametrize(("door", "faults"), _every_subset(),
                         ids=[f"{d}-{'+'.join(sorted(f))}" for d, f in _every_subset()])
def test_1470_g1_a_refusal_is_the_first_fault_in_the_stated_order_and_nothing_is_written(migrated_database, door, faults):  # noqa: F811
    """Over each store door and every non-empty set of the faults it can meet (no current record, stale or another
    generation, judged or unparseable access), the refusal is the first in the stated order (404, stale, judgement) and no
    row is written. (G1, P2, O5, O7)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    work = _meeting(dsn, tenant, door, faults)
    before = (stored(dsn, tenant), stored_case(dsn, tenant))
    judge = K.refuse_with("system ticket: the judge refuses") if "judged" in faults and door != "credential_slot" else K.accept_all

    refusal = K.refused(dsn, work, judge=judge)

    assert K.kind_of(refusal) == FIRST[next(f for f in ORDER if f in faults)], (door, sorted(faults), refusal)
    assert (stored(dsn, tenant), stored_case(dsn, tenant)) == before, "a refused write stores nothing"


def _versions_to_ask() -> list[int]:
    """Version numbers of every magnitude, either sign: each power of two to 2**80 and its neighbours, and a seeded
    sample between (the 32- and 64-bit column bounds fall among them)."""
    import random

    rng = random.Random(1470)
    edges = {s * (2 ** k + d) for k in range(81) for d in (-1, 0, 1) for s in (1, -1)}
    return sorted(edges | {rng.randint(-2 ** 80, 2 ** 80) for _ in range(200)} | {0})


def test_1470_b6_a_slot_asked_for_any_version_number_outside_the_current_generation_is_stale_naming_the_current_one(
        migrated_database):  # noqa: F811
    """v1 at g1, v2 and v3 at g2: any `for_version` but 2 and 3 (zero, negatives, past the newest, past a 32- or 64-bit
    integer) is `Stale` naming 3, never another error; 2 and 3 answer (control). (O7: unknown or future is 409)"""
    dsn, tenant = migrated_database, _tenant(migrated_database)
    _plant_system(dsn, tenant, 1)
    _plant_system(dsn, tenant, 2, generation=2)
    _plant_system(dsn, tenant, 3, generation=2)
    asked = _versions_to_ask()
    assert min(asked) <= 0 and max(asked) >= 2 ** 63, "premise: the sweep passes both column bounds"

    async def ask_each(store):
        from defender.system_records import RecordRefused

        seen = {}
        for version in [*asked, 2, 3]:
            try:
                seen[version] = await store.credential_slot(tenant, "ticket", version)
            except RecordRefused as refusal:
                seen[version] = refusal
            except Exception as failed:  # noqa: BLE001 — the defect this test is for: reported, not raised
                seen[version] = failed
        return seen

    seen = K.run(dsn, ask_each)
    assert [K.slot_parts(seen[v])[0] for v in (2, 3)] == [2, 2], "control: the current generation's versions answer"
    wrong = [(v, type(seen[v]).__name__, getattr(seen[v], "current_version", None)) for v in asked if v not in (2, 3)
             and not (K.kind_of(seen[v]) == "Stale" and seen[v].current_version == 3)]
    assert wrong == [], wrong[:10]
