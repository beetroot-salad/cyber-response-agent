"""#1592 r15.1 "The request worker": a poll carries out each user's requests from the current wanted state and deletes
exactly the ids it took (S2-1..11, 22..25, 30..35). Marked postgres: the sessions database is real."""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import random
import uuid

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy._twin1496 import offboard_twin
from defender.tests.tenancy.people_1592._sessions1592 import sessions  # noqa: F401 — overrides the package fixture
from defender.tests.tenancy.people_1592._spec1592 import KEYCLOAK_SOURCE_ID, login_of, org_of, requests_sql, signed_in_data
from defender.tests.tenancy.people_1592._worker1592 import accept, errors, invite, member, settled, until, use
from defender.tests.tenancy.people_1592._world1592 import NOW, T, U2, People

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
SEARCH = "/api/v1/orgs/{org}/teams/search"


def _patches(people: People, login: str) -> list[dict]:
    return [c.body for c in people.forge.calls if c.method == "PATCH" and c.path.endswith(f"/admin/users/{login}")]


# --- the step table: removal, joining ------------------------------------------------------------------

async def test_a_membership_ended_in_the_only_tenant_removes_suspends_and_ends_sessions(people: People):
    """S2-1: Bob leaves his only tenant: out of the team, suspended, stamped rows gone, request deleted; Alice untouched."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    alice = await people.person("alice@x.org", T)
    await settled(people)
    log = people.log()
    await log.mark()
    await people.end(bob, T)
    assert dict(await log.since()) == {(str(bob.id), T): 1}

    await people.step()

    assert people.forge.members(T) == {login_of(str(alice.id))}
    assert login_of(str(bob.id)) in people.forge.prohibit_login
    assert login_of(str(alice.id)) not in people.forge.prohibit_login
    assert people.sessions.keys() == {people.key("alice@x.org")}
    assert await people.open_requests() == []


async def test_a_person_kept_in_another_tenant_leaves_the_team_and_keeps_their_sessions(people: People):
    """S2-2 / OD-4a: Carol leaves T, stays in U2, never signed out: out of T, still in U2, not suspended, sessions kept."""
    await people.tenant(T)
    await people.tenant(U2)
    carol = await people.person("carol@x.org", T, U2)
    await settled(people)
    await people.end(carol, T)

    await people.step()

    login = login_of(str(carol.id))
    assert login not in people.forge.members(T)
    assert login in people.forge.members(U2)
    assert login not in people.forge.prohibit_login
    assert people.sessions.keys() == {people.key("carol@x.org")}


async def test_ended_then_reinvited_and_accepted_before_a_poll_stays_in_the_team(people: People):
    """S2-3: end, re-invite and accept before the worker runs: she stays, from the current state."""
    await people.tenant(T)
    erin = await people.person("erin@x.org", T)
    await settled(people)
    log = people.log()
    await log.mark()
    await people.end(erin, T)
    invitation = await people.identity.ensure_invitation(erin.id, T, invited_by=None, now=NOW)
    assert await people.identity.accept_invitation(invitation.id, now=NOW)
    assert dict(await log.since()) == {(str(erin.id), T): 3}

    await people.step()

    assert login_of(str(erin.id)) in people.forge.members(T)
    assert login_of(str(erin.id)) not in people.forge.prohibit_login
    assert await people.open_requests() == []


async def test_ended_and_reinvited_but_not_accepted_is_removed(people: People):
    """S2-3: the second variant: an invitation is not a wanted place, so she is removed (and suspended)."""
    await people.tenant(T)
    erin = await people.person("erin@x.org", T)
    await settled(people)
    await people.end(erin, T)
    await people.identity.ensure_invitation(erin.id, T, invited_by=None, now=NOW)

    await people.step()

    assert login_of(str(erin.id)) not in people.forge.members(T)
    assert login_of(str(erin.id)) in people.forge.prohibit_login


async def test_a_wanted_person_without_an_account_gets_one_restricted_then_limited_then_added(people: People):
    """S2-4: the account's creation body, the PATCH that creation ignores, then the team place, in that order."""
    await people.tenant(T)
    await settled(people)
    alice = await member(people, "alice@x.org", T, account=False, display_name="Alice A")
    login = login_of(str(alice.id))

    await people.step()

    posts = [(i, c) for i, c in enumerate(people.forge.calls) if c.method == "POST" and c.path.endswith("/admin/users")]
    assert len(posts) == 1
    at, post = posts[0]
    assert post.body["username"] == login
    assert post.body["login_name"] == "sub-alice@x.org"
    assert post.body["source_id"] == KEYCLOAK_SOURCE_ID
    assert post.body["restricted"] is True
    assert post.body["must_change_password"] is False  # r15.2: an external account forced to change a password the edge refuses
    assert post.body["email"] == f"{login}@people.invalid"
    assert post.body["full_name"] == "Alice A"
    assert not post.body.get("password")
    later = people.forge.calls[at + 1:]
    patch = next(i for i, c in enumerate(later) if c.method == "PATCH" and c.path.endswith(f"/admin/users/{login}"))
    merged = {k: v for c in later[:patch + 1] if c.method == "PATCH" for k, v in c.body.items()}
    assert merged["max_repo_creation"] == 0
    assert merged["allow_create_organization"] is False
    put = next(i for i, c in enumerate(later) if c.method == "PUT")
    assert patch < put
    assert login in people.forge.members(T)
    assert await people.open_requests() == []


async def test_a_wanted_person_with_no_sub_is_kept_and_logged_never_created_blank(people: People, caplog):
    """S2-5: no `signin_account_id`: nothing is created, the request stays, an error is logged."""
    await people.tenant(T)
    await settled(people)
    ghost = await member(people, "ghost@x.org", T, account=False, sub=False)

    await people.step()

    assert not [c for c in people.forge.calls if c.method == "POST" and c.path.endswith("/admin/users")]
    assert (str(ghost.id), T) in await people.open_requests()
    assert any(str(ghost.id) in m for m in errors(caplog))


async def test_a_login_held_by_a_stray_account_stays_logged_and_does_not_block_the_queue(people: People, caplog):
    """S2-6: Gil's creation conflicts (422) and is logged on each attempt; Bob's later removal runs ahead of him (OD-9:
    never-attempted users go first, so with one slot Gil is not attempted at poll 2)."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    gil = await member(people, "gil@x.org", T, account=False)
    people.forge.users.add(login_of(str(gil.id)))  # a stray account the lookup does not return: POST answers 422
    use(people, people_concurrency=1)
    seen = []
    await people.step()
    seen.append(len([m for m in errors(caplog) if str(gil.id) in m]))
    await people.end(bob, T)
    await people.step()
    assert login_of(str(bob.id)) not in people.forge.members(T), "Bob waited behind Gil"
    seen.append(len([m for m in errors(caplog) if str(gil.id) in m]))
    await people.step()
    seen.append(len([m for m in errors(caplog) if str(gil.id) in m]))

    assert seen[0] >= 1
    assert seen[1] == seen[0], "Gil was attempted at poll 2, ahead of never-attempted Bob (OD-9)"
    assert seen[2] > seen[1]
    assert (str(gil.id), T) in await people.open_requests()


async def test_a_suspended_wanted_person_is_unsuspended(people: People):
    """S2-7: step 5."""
    await people.tenant(T)
    alice = await people.person("alice@x.org", T)
    await settled(people)
    login = login_of(str(alice.id))
    people.forge.prohibit_login.add(login)
    await people.sign_out(alice)

    await people.step()

    assert {"prohibit_login": False} in _patches(people, login)
    assert login not in people.forge.prohibit_login


async def test_someone_already_suspended_is_not_suspended_again(people: People):
    """S2-8: idempotent: wanted nowhere and already suspended writes no `prohibit_login`."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    login = login_of(str(bob.id))
    people.forge.prohibit_login.add(login)
    await people.end(bob, T)

    await people.step()

    assert not [b for b in _patches(people, login) if "prohibit_login" in b]
    assert login not in people.forge.members(T)


async def test_a_login_already_out_or_unknown_to_forgejo_is_a_success(people: People):
    """S2-9: a 404 on the removal is success: the requests are deleted."""
    await people.tenant(T)
    out = await people.person("out@x.org", T)
    unknown = await member(people, "unknown@x.org", T, account=False)
    await settled(people)
    people.forge.team_members[(org_of(T), "members")].discard(login_of(str(out.id)))
    await people.end(out, T)
    await people.end(unknown, T)

    await people.step()

    assert await people.open_requests() == []


async def test_a_wanted_person_whose_team_is_absent_is_kept_and_logged_for_the_tenant(people: People, caplog):
    """S2-10: step 6 with no team: an error naming T, the request stays."""
    await people.tenant(T)
    await people.tenant(U2, team=False)
    await settled(people)
    alice = await member(people, "alice@x.org", U2)

    await people.step()

    assert (str(alice.id), U2) in await people.open_requests()
    assert any(U2 in m for m in errors(caplog))


@pytest.mark.parametrize("outcome", ["org-404", "decoy-only", "found", "failed"])
async def test_the_team_lookup_has_three_outcomes(people: People, outcome: str):
    """S2-11: absent (org 404, or only `members-old`) has nothing to remove; found removes; a failed lookup keeps."""
    await people.tenant(T, team=False)
    await settled(people)
    bob = await member(people, "bob@x.org", T, account=True, in_team=False)
    login = login_of(str(bob.id))
    if outcome != "org-404":
        people.forge.add_team(T, login, name="members" if outcome in ("found", "failed") else "members-old")
    if outcome == "failed":
        people.forge.fail(f"GET {SEARCH.format(org=org_of(T))}", status=500)
    await settled_removal(people, bob)

    searches = [c for c in people.forge.calls if c.path == SEARCH.format(org=org_of(T))]
    assert len(searches) >= 1
    if outcome == "found":
        assert login not in people.forge.members(T)
        assert await people.open_requests() == []
    elif outcome == "failed":
        assert (str(bob.id), T) in await people.open_requests()
        assert login in people.forge.members(T)
    else:
        assert await people.open_requests() == []
        assert login in people.forge.team_members.get((org_of(T), "members-old"), {login})
        assert not [c for c in people.forge.calls if c.method == "DELETE"]


async def settled_removal(people: People, user) -> None:
    await people.end(user, T)
    await people.step()
    await people.step()


# --- order, in flight ------------------------------------------------------------------------------------

async def _removals(people: People, count: int) -> list:
    await people.tenant(T)
    users = [await people.person(f"u{i}@x.org", T, session=False) for i in range(count)]
    await settled(people)
    for user in users:
        await people.end(user, T)
    return users


def _a_arrivals(people: People) -> list[str]:
    return [a.rsplit("/", 1)[1] for a in people.forge.arrived if a.startswith("GET /api/v1/users/p-")]


async def test_users_are_taken_oldest_request_first_and_never_more_than_the_concurrency(people: People):
    """S2-22 / OD-9: of six gated runs the four oldest start first, never more than four are in flight."""
    users = await _removals(people, 6)
    by_age = sorted(await people.requests(), key=lambda r: r.requested_at)
    assert len({r.requested_at for r in by_age}) == 6, "control: the requests have distinct ages"
    order = [login_of(r.user) for r in by_age]
    gates = {login: people.forge.gate("GET", f"/api/v1/users/{login}") for login in order}
    worker = use(people, people_concurrency=4)
    try:
        await worker.poll()
        assert await until(lambda: len(_a_arrivals(people)) >= 4)
        await worker.poll()
        await asyncio.sleep(0.05)
        assert set(_a_arrivals(people)) == set(order[:4])
        for login in order[:4]:
            gates[login].set()
        await asyncio.wait_for(worker.settle(), 5)
        await worker.poll()
        assert await until(lambda: len(_a_arrivals(people)) >= 6)
    finally:
        for gate in gates.values():
            gate.set()
    await asyncio.wait_for(worker.settle(), 5)
    assert set(_a_arrivals(people)[4:]) == set(order[4:])
    assert len(users) == 6


async def test_a_failing_user_goes_to_the_back_and_does_not_hold_the_others(people: People):
    """S2-23: U1 fails on every attempt; with one slot, three steps still reach U1, U2, U3 in turn."""
    await _removals(people, 4)
    first = sorted(await people.requests(), key=lambda r: r.requested_at)
    order = [login_of(r.user) for r in first]
    people.forge.fail(f"GET /api/v1/users/{order[0]}", status=500)
    use(people, people_concurrency=1)

    await people.steps(3)

    assert _a_arrivals(people) == order[:3]
    assert first[0].user in {u for u, _t in await people.open_requests()}


# --- the turn order over generated worlds (OD-9, "Expansion keeps the request's age") -------------------------------

def _due(rows: list, attempted: dict[str, int], concurrency: int) -> tuple[set[str], set[str], int]:
    """The reference schedule of one poll, from the design's rule alone (written apart from the worker): users never
    attempted first, by their oldest `requested_at`; then attempted users by their last attempt, oldest first; at most
    `concurrency`. Returns (must start, may start, how many start): the rule does not order equal keys (users expanded
    from one tenant share its age), so a tie at the cut may go either way."""
    oldest: dict[str, dt.datetime] = {}
    for r in rows:
        if r.user is not None:
            oldest[r.user] = min(oldest.get(r.user, r.requested_at), r.requested_at)

    def key(user: str) -> tuple:
        return (1, attempted[user], NOW) if user in attempted else (0, 0, oldest[user])

    ranked = sorted(oldest, key=key)
    count = min(concurrency, len(ranked))
    if not count:
        return set(), set(), 0
    cut = key(ranked[count - 1])
    return {u for u in ranked if key(u) < cut}, {u for u in ranked if key(u) <= cut}, count


def _insert_request(dsn: str, user: str | None, tenant: str | None, at: dt.datetime) -> None:
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "INSERT INTO tenancy.forge_people_requests (id, user_id, tenant_id, requested_at) "
                 "VALUES (gen_random_uuid(), %s, %s, %s)", (user, tenant, at))


@pytest.mark.parametrize("seed", range(10))
async def test_generated_worlds_take_users_in_the_design_turn_order_and_expansion_keeps_the_oldest_age(  # noqa: C901 — one model run
        pg_people: People, seed: int):
    """S2-22b (OD-9; "Expansion keeps the request's age"): seeded worlds with several requests per user, several
    (none, T) rows per tenant, more persistently failing users than slots and concurrency 1..4: each poll starts the runs
    the reference schedule allows, and each expanded (U, T) carries the oldest (none, T) `requested_at` of T."""
    rng = random.Random(seed)  # noqa: S311 — generated cases, not secrets
    people, dsn = pg_people, pg_people.dsn
    assert dsn is not None
    concurrency = rng.randint(1, 4)
    plain = [fixture_uuid(f"tenant:1592-turn-{seed}-p{i}") for i in range(2)]
    expanding = [fixture_uuid(f"tenant:1592-turn-{seed}-e{i}") for i in range(rng.randint(1, 2))]
    for tenant in plain + expanding:
        await people.tenant(tenant)
    users = [await people.person(f"u{i}@x.org", *rng.sample(plain, rng.randint(1, 2)), session=False)
             for i in range(concurrency + rng.randint(2, 5))]
    members = {t: [await people.person(f"e{j}-{i}@x.org", t, session=False) for i in range(rng.randint(1, 3))]
               for j, t in enumerate(expanding)}
    await settled(people)

    everyone = users + [u for group in members.values() for u in group]
    failing = {str(u.id) for u in rng.sample(everyone, concurrency + 1 + rng.randint(0, 2))}
    stamps = iter([NOW - dt.timedelta(minutes=m) for m in rng.sample(range(1, 50_000), 3 * len(users) + 3 * len(expanding))])
    for user in users:  # several requests per user, each with its own age; members of E get theirs only by expansion
        tenants = [r.tenant_id for r in await people.identity.memberships_of_user(user.id)]
        for _ in range(rng.randint(1, 3)):
            _insert_request(dsn, str(user.id), rng.choice([*map(str, tenants), None]), next(stamps))
    tenant_ages: dict[str, list[dt.datetime]] = {}
    for tenant in expanding:  # several (none, T) rows of one tenant
        for _ in range(rng.randint(2, 3)):
            at = next(stamps)
            tenant_ages.setdefault(tenant, []).append(at)
            _insert_request(dsn, None, tenant, at)
    for user in failing:
        people.forge.fail(f"GET /api/v1/users/{login_of(user)}", status=500)
    use(people, people_concurrency=concurrency)

    attempted: dict[str, int] = {}
    expansions_checked = False
    for poll in range(len(everyone) // concurrency + len(failing) + 4):
        rows = requests_sql(dsn)
        if poll == 1:
            for tenant, ages_of in tenant_ages.items():
                assert not [r for r in rows if r.user is None and r.tenant == tenant], f"seed {seed}: not expanded"
                for member_ in members[tenant]:
                    got = [r.requested_at for r in rows if r.user == str(member_.id) and r.tenant == tenant]
                    assert got == [min(ages_of)], f"seed {seed}: expanded at {got}, the tenant's (none, T) ages {ages_of}"
            expansions_checked = True
        must, may, size = _due(rows, attempted, concurrency)
        before = len(people.forge.arrived)
        people.clock.advance(dt.timedelta(minutes=1))
        await people.step()
        arrivals = [a.rsplit("/", 1)[1] for a in people.forge.arrived[before:] if a.startswith("GET /api/v1/users/p-")]
        started = {a.removeprefix("p-") for a in arrivals}
        where = (f"seed {seed}, concurrency {concurrency}, poll {poll}: started {sorted(started)}, must {sorted(must)},"
                 f" may {sorted(may)}, attempted {attempted}")
        assert len(arrivals) == len(started) == size, where
        assert must <= started <= may, where
        left = {r.user for r in requests_sql(dsn) if r.user is not None}
        for user in started:
            attempted[user] = poll
            assert (user in left) == (user in failing), f"{where}: {user} failing={user in failing}, kept={user in left}"
    assert expansions_checked
    assert {r.user for r in requests_sql(dsn) if r.user is not None} == failing, f"seed {seed}: only the failing stay"


async def test_a_poll_never_starts_a_second_run_for_a_user_with_one_in_flight(people: People):
    """S2-24 / OD-7: a poll meanwhile starts no run; the run deletes only the ids it took; the next poll removes him."""
    await people.tenant(T)
    dave = await people.person("dave@x.org", T)
    await settled(people)
    login = login_of(str(dave.id))
    row = await people.identity.active_membership(dave.id, T)
    await people.sign_out(dave)
    path = f"/api/v1/users/{login}"
    gate = people.forge.gate("GET", path)
    worker = use(people)
    await worker.poll()
    assert await until(lambda: f"GET {path}" in people.forge.arrived), "control: the first run reached Forgejo"
    assert await people.identity.end_membership(row.id, ended_by=None, now=NOW)

    await worker.poll()
    await asyncio.sleep(0.05)
    assert people.forge.arrived.count(f"GET {path}") == 1, "a second run started for Dave"
    gate.set()
    await asyncio.wait_for(worker.settle(), 5)
    assert await people.open_requests() == [(str(dave.id), T)]

    await people.step()
    assert login not in people.forge.members(T)
    assert await people.open_requests() == []


async def test_removals_come_before_grants(people: People):
    """S2-25: moving T to U2 deletes from T's team before adding to U2's; a suspended one is unsuspended between."""
    await people.tenant(T)
    await people.tenant(U2)
    mover = await people.person("mover@x.org", T)
    invitation = await invite(people, mover, U2)
    await settled(people)
    login = login_of(str(mover.id))
    people.forge.prohibit_login.add(login)  # step 5 reads the account whatever the requests name
    await accept(people, invitation)  # the request that names U2: the run is per named tenant (OD-2)
    await people.end(mover, T)

    await people.step()

    writes = people.forge.writes()
    delete = next(i for i, w in enumerate(writes) if w.startswith("DELETE") and w.endswith(login))
    unsuspend = next(i for i, w in enumerate(writes) if w.startswith("PATCH") and w.endswith(login))
    put = next(i for i, w in enumerate(writes) if w.startswith("PUT") and w.endswith(login))
    assert delete < unsuspend < put


# --- tenant requests ---------------------------------------------------------------------------------------

async def test_expansion_records_every_membership_and_every_well_formed_team_login_with_the_original_age(
        people: People, caplog):
    """S2-30: (none, T) becomes (U, T) for every membership row and `p-<id>` login, at its `requested_at`; a bad login stays."""
    from defender.tests.support.identity._seed1496 import seed_membership

    caplog.set_level(logging.INFO)
    await people.tenant(T)
    first = await people.person("a@x.org", T)
    others = {}
    for name, status in (("inv", "invited"), ("rev", "revoked"), ("end", "ended")):
        user = await member(people, f"{name}@x.org", account=False)
        await seed_membership(people.identity, user.id, T, status=status, invited_by=None, created_at=NOW,
                              accepted_at=NOW if status == "ended" else None, ended_at=NOW if status == "ended" else None)
        others[name] = user
    xavier = login_of(str(uuid.UUID(fixture_uuid("user:1592-xavier"))))
    people.forge.add_account(xavier, login_name="sub-of-nobody")
    people.forge.add_account("p-not-a-uuid")
    people.forge.team_members[(org_of(T), "members")] |= {xavier, "p-not-a-uuid"}
    tenant_age = next(r.requested_at for r in await people.requests() if r.user is None and r.tenant == T)
    use(people, people_concurrency=1)

    await people.step()

    expected = {str(first.id), *(str(u.id) for u in others.values()), xavier.removeprefix("p-")}
    aged = {r.user for r in await people.requests() if r.requested_at == tenant_age and r.tenant == T}
    assert expected <= aged
    assert not [r for r in await people.requests() if r.user is None and r.tenant == T]
    assert "p-not-a-uuid" in people.forge.members(T)
    assert any("p-not-a-uuid" in r.getMessage() for r in caplog.records)


async def test_a_failed_team_lookup_keeps_the_tenant_request_and_records_nothing(people: People):
    """S2-31: no partial recording when the lookup fails."""
    await people.tenant(T)
    await people.person("a@x.org", T)
    xavier = login_of(str(uuid.UUID(fixture_uuid("user:1592-xavier"))))
    people.forge.add_account(xavier)
    people.forge.team_members[(org_of(T), "members")].add(xavier)
    people.forge.fail(f"GET {SEARCH.format(org=org_of(T))}", status=500)
    log = people.log()
    await log.mark()

    await people.steps(2)

    assert await log.new() == []
    assert (None, T) in await people.open_requests()


async def test_one_expansion_per_tenant_at_a_time(people: People):
    """S2-32: the lookup is gated; two polls make one search."""
    await people.tenant(T)
    gate = people.forge.gate("GET", SEARCH.format(org=org_of(T)))
    worker = use(people)
    try:
        await worker.poll()
        assert await until(lambda: any(a.endswith("/teams/search") for a in people.forge.arrived))
        await worker.poll()
        await asyncio.sleep(0.05)
    finally:
        gate.set()
    await asyncio.wait_for(worker.settle(), 5)
    assert len([a for a in people.forge.arrived if a.endswith("/teams/search")]) == 1


async def test_offboarding_a_creating_tenant_whose_team_is_absent_expands_to_nothing(people: People):
    """S2-33: a creating tenant has no team: the (none, T) is expanded to nothing, Forgejo is not written."""
    await people.tenant(T, state="creating", team=False)
    await offboard_twin(people.tenants, T)
    people.forge.calls.clear()

    await people.steps(2)

    assert await people.open_requests() == []
    assert people.forge.writes() == []


async def test_an_unknown_p_login_in_the_team_is_wanted_nowhere_and_is_removed(people: People):
    """S2-33: activation's request expands to every `p-<id>` in the team; an unknown one is removed and suspended."""
    await people.tenant(T)
    xavier = login_of(str(uuid.UUID(fixture_uuid("user:1592-xavier"))))
    people.forge.add_account(xavier, login_name="sub-of-nobody")
    people.forge.team_members[(org_of(T), "members")].add(xavier)
    people.sessions.plant("xavier", signed_in_data(people.forge.uid(xavier)), signed_in_at=dt.datetime.now(dt.UTC))

    await people.steps(3)

    assert xavier not in people.forge.members(T)
    assert xavier in people.forge.prohibit_login
    assert people.sessions.keys() == set()
    assert await people.open_requests() == []


# --- scheduling --------------------------------------------------------------------------------------------

async def test_poll_returns_at_once_and_settle_waits_for_the_runs(people: People):
    """S2-34: with a run gated, `poll()` returns; `settle()` returns only after the gate opens."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    await people.end(bob, T)
    gate = people.forge.gate("GET", f"/api/v1/users/{login_of(str(bob.id))}")
    worker = use(people)
    try:
        await asyncio.wait_for(worker.poll(), 1)
        waiting = asyncio.ensure_future(worker.settle())
        await asyncio.sleep(0.1)
        assert not waiting.done()
    finally:
        gate.set()
    await asyncio.wait_for(waiting, 5)
    assert await people.open_requests() == []


async def test_start_carries_requests_out_with_no_manual_poll(people: People):
    """S2-35: `start()` polls every `people_poll` on its own."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    await people.end(bob, T)
    worker = use(people)
    task = asyncio.ensure_future(worker.start())
    try:
        assert await until(lambda: _empty(people), 5), "the request was not carried out"
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert login_of(str(bob.id)) not in people.forge.members(T)


async def _empty(people: People) -> bool:
    return await people.open_requests() == []
