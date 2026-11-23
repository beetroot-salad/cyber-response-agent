"""#1592 r15.1 step table, "Needs" column: a failed external call or input skips exactly the steps that need it and
no others, keeps the request ids, and is logged (S2-12, 13, 14, 41). The expectations come from the design's table
written here, not from the product. Postgres-marked (the sessions database)."""
from __future__ import annotations

import datetime as dt

import httpx
import pytest

from defender.tests.tenancy.people_1592._sessions1592 import MINUTE, sessions  # noqa: F401 — overrides the fixture
from defender.tests.tenancy.people_1592._spec1592 import UNREACHABLE_DSN, login_of, org_of, sessions_port, signed_in_data
from defender.tests.tenancy.people_1592._worker1592 import FaultingIdentity, accept, errors, invite, member, settled, use
from defender.tests.tenancy.people_1592._world1592 import T, U2, People

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
API = "/api/v1"
ALL = {"removed", "unsuspended", "added", "session"}


async def _move(people: People):
    """U leaves T, joins U2 (invited before, accepted after the seeding drained) but is suspended, and signs out: every
    step has work. The run is per named tenant (OD-2, "Carrying out the requests"), so U2 is named by U's accepted
    invitation, a recorded request; nothing edits Forgejo's U2 team by hand, because the worker watches no hand edit."""
    await people.tenant(T)
    await people.tenant(U2)
    user = await people.person("u@x.org", T, session=False)
    invitation = await invite(people, user, U2)
    await settled(people)
    login = login_of(str(user.id))
    people.forge.prohibit_login.add(login)  # step 5 reads the account whatever the requests name
    people.sessions.plant("old", signed_in_data(people.forge.uid(login)), signed_in_at=dt.datetime.now(dt.UTC) - 10 * MINUTE)
    await accept(people, invitation)
    await people.end(user, T)
    await people.sign_out(user)
    return user, login


def _done_move(people: People, login: str) -> set[str]:
    done = set()
    if login not in people.forge.members(T):
        done.add("removed")
    if login not in people.forge.prohibit_login:
        done.add("unsuspended")
    if login in people.forge.members(U2):
        done.add("added")
    if not people.sessions.keys():
        done.add("session")
    return done


def _signatures_move(people: People, login: str) -> dict[str, str]:
    t1, t2 = (people.forge._team_id(org_of(t), "members") for t in (T, U2))  # noqa: SLF001 — the fake's ids
    return {
        "A": f"GET {API}/users/{login}", "L1": f"GET {API}/orgs/{org_of(T)}/teams/search",
        "L2": f"GET {API}/orgs/{org_of(U2)}/teams/search", "DELETE": f"DELETE {API}/teams/{t1}/members/{login}",
        "STANDING": f"PATCH {API}/admin/users/{login}", "PUT": f"PUT {API}/teams/{t2}/members/{login}",
    }


#: which of the four observable effects a failure of each call prevents (design: step table, Needs). Step 6 needs step
#: 5: nobody is added to a team until their account's standing (unsuspended, limited) is set in the same run.
MOVE_PREVENTS = {"A": {"unsuspended", "added", "session"}, "L1": {"removed"}, "L2": {"added"},
                 "DELETE": {"removed"}, "STANDING": {"unsuspended", "added"}, "PUT": {"added"}}
MOVE_TENANT = {"L1": T, "DELETE": T, "L2": U2, "PUT": U2}


async def test_a_clean_run_makes_exactly_the_expected_calls_and_finishes(people: People):
    """S2-12 control: no fault, every step works, nothing else is called, the requests are gone."""
    _user, login = await _move(people)

    await people.step()

    assert _done_move(people, login) == ALL
    assert await people.open_requests() == []
    assert set(people.forge.signatures()) == set(_signatures_move(people, login).values())


@pytest.mark.parametrize("failure", ["status", "connect"])
@pytest.mark.parametrize("call", sorted(MOVE_PREVENTS))
async def test_a_failed_call_skips_only_the_steps_that_need_it(people: People, caplog, call: str, failure: str):
    """S2-12, S2-41: a persistent 500 or a connection error on one call: the other steps still do their work, the
    ids stay, and the failure is logged with the user (and the tenant where one is involved)."""
    user, login = await _move(people)
    signature = _signatures_move(people, login)[call]
    if failure == "status":
        people.forge.fail(signature, status=500)
    else:
        people.forge.fail(signature, error=httpx.ConnectError)

    await people.step()

    assert _done_move(people, login) == ALL - MOVE_PREVENTS[call]
    assert str(user.id) in {u for u, _t in await people.open_requests()}
    messages = [m for m in errors(caplog) if str(user.id) in m]
    assert messages, "the failure was not logged with the user"
    if call in MOVE_TENANT:
        assert any(MOVE_TENANT[call] in m for m in messages)


async def _create(people: People):
    await people.tenant(T)
    await settled(people)
    user = await member(people, "new@x.org", T, account=False)
    return user, login_of(str(user.id))


def _created(people: People, login: str) -> set[str]:
    return ({"created"} if login in people.forge.accounts else set()) | (
        {"added"} if login in people.forge.members(T) else set())


def _signatures_create(people: People, login: str) -> dict[str, str]:
    t = people.forge._team_id(org_of(T), "members")  # noqa: SLF001
    return {"A": f"GET {API}/users/{login}", "POST": f"POST {API}/admin/users",
            "STANDING": f"PATCH {API}/admin/users/{login}", "L": f"GET {API}/orgs/{org_of(T)}/teams/search",
            "PUT": f"PUT {API}/teams/{t}/members/{login}"}


#: the limits ride on step 5's PATCH, which every run with an account sends, so a failed one leaves a made account
#: that the next run limits; step 6 waits for it
CREATE_PREVENTS = {"A": {"created", "added"}, "POST": {"created", "added"}, "STANDING": {"added"}, "L": {"added"},
                   "PUT": {"added"}}


async def test_a_clean_creation_makes_exactly_the_expected_calls(people: People):
    """S2-12 control: creation, step 5's PATCH, the team lookup and the add; nothing else."""
    _user, login = await _create(people)

    await people.step()

    assert _created(people, login) == {"created", "added"}
    assert await people.open_requests() == []
    assert set(people.forge.signatures()) == set(_signatures_create(people, login).values())


@pytest.mark.parametrize("failure", ["status", "connect"])
@pytest.mark.parametrize("call", sorted(CREATE_PREVENTS))
async def test_a_failed_creation_call_keeps_the_request_and_adds_nobody(people: People, caplog, call: str, failure: str):
    """S2-12, S2-41: the creating path: step 4 and its Needs, with the failure logged."""
    user, login = await _create(people)
    signature = _signatures_create(people, login)[call]
    if failure == "status":
        people.forge.fail(signature, status=500)
    else:
        people.forge.fail(signature, error=httpx.ConnectError)

    await people.step()

    assert _created(people, login) == {"created", "added"} - CREATE_PREVENTS[call]
    assert (str(user.id), T) in await people.open_requests()
    assert any(str(user.id) in m for m in errors(caplog))


async def test_an_unreadable_wanted_state_writes_nothing_and_keeps_the_requests(people: People, caplog):
    """S2-13: the identity read of `wanted_tenants` fails: no Forgejo write, no session delete, nothing deleted."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    await people.end(bob, T)
    use(people, identity=FaultingIdentity(people.identity, "wanted_tenants"))

    await people.step()

    assert people.forge.writes() == []
    assert people.sessions.keys() == {people.key("bob@x.org")}
    assert (str(bob.id), T) in await people.open_requests()
    assert any(str(bob.id) in m for m in errors(caplog))


async def test_an_unreachable_sessions_database_still_lets_removals_and_other_runs_finish(people: People):
    """S2-14: Bob (wanted nowhere) is removed and suspended but his request stays; Carol's run has no session step."""
    await people.tenant(T)
    await people.tenant(U2)
    bob = await people.person("bob@x.org", T)
    carol = await people.person("carol@x.org", T, U2)
    await settled(people)
    people.sessions_port = sessions_port(UNREACHABLE_DSN)
    await people.end(bob, T)
    await people.end(carol, T)

    await people.step()

    assert login_of(str(bob.id)) not in people.forge.members(T)
    assert login_of(str(bob.id)) in people.forge.prohibit_login
    assert login_of(str(carol.id)) not in people.forge.members(T)
    pending = await people.open_requests()
    assert (str(bob.id), T) in pending
    assert str(carol.id) not in {u for u, _t in pending}


async def test_an_account_whose_limits_were_never_set_is_limited_by_the_next_run(people: People):
    """S2-4 (finalize, #1623 review): an account made but never limited (the PATCH after creation failed, or made before
    this rule) is not suspended, so nothing about it reads as unfinished. Every run that finds a wanted person's account
    sends its standing, so the next run limits it, before the team place."""
    user, login = await _create(people)
    people.forge.fail(_signatures_create(people, login)["STANDING"], status=500, times=1)
    await people.step()
    assert login in people.forge.accounts and login not in people.forge.members(T)
    assert "max_repo_creation" not in people.forge.accounts[login], "the fake recorded a failed PATCH"

    await people.step()

    assert (people.forge.accounts[login].get("max_repo_creation"),
            people.forge.accounts[login].get("allow_create_organization")) == (0, False)
    assert login in people.forge.members(T)
    assert (str(user.id), T) not in await people.open_requests()


async def test_a_person_whose_run_keeps_failing_is_retried_ever_less_often_and_still_finishes(people: People):
    """OD-9 (finalize, #1623 review): a run that fails every time is retried at the next poll, then after ever longer
    runs of polls (doubling, capped), not at every poll; once the fault is gone a later poll still carries it out."""
    _user, login = await _create(people)
    lookup = _signatures_create(people, login)["L"]
    people.forge.fail(lookup, status=500)

    await people.steps(32)

    attempts = people.forge.arrived.count(_signatures_create(people, login)["A"])
    assert 2 <= attempts <= 7, f"{attempts} runs in 32 polls"
    people.forge.clear_faults()
    await people.steps(40)
    assert _created(people, login) == {"created", "added"}
    assert await people.open_requests() == []
