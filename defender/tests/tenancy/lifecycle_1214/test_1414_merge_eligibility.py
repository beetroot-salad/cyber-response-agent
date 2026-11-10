# ruff: noqa: PT018
"""#1414 D13: on every management-service pass, each active tenant's merge whitelist (users and the members of its
teams, as the forge stores `main`'s rule) minus every generation's bot is recorded with the time read; the record
round-trips through both repositories; the integration carries `write:issue` as well as `write:repository`."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import database, empty_database, execute  # noqa: E402,F401
from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot, jwts  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402

TICK = dt.timedelta(seconds=30)
NOW = dt.datetime(2026, 11, 9, 12, 0, tzinfo=dt.UTC)
PRE_1414_HEAD = "0010_cost_lower_limit"  # the head #1414's eligibility revision sits on (main took 0008-0010 meanwhile)


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _whitelist(world, tenant: str, *, users=(), teams: dict[str, set[str]] | None = None) -> None:
    """Store `main`'s merge whitelist as the forge would hold it: `users` (collaborators) and `teams` (name -> members)."""
    full = f"{ORG}/{tenant}"
    teams = {"Owners": set()} if teams is None else teams
    for team, members in teams.items():
        world.forge.orgs[ORG].add(team)
        world.forge.team_members[(ORG, team)] = set(members)
        world.forge.users.update(members)
    for user in users:
        world.forge.users.add(user)
        world.forge.repos[full]["collaborators"][user] = "write"
    world.forge.put_rule(full, **{**world.forge.rule(full), "merge_whitelist_usernames": list(users),
                                  "merge_whitelist_teams": list(teams)})


def _pass(world, *, after: dt.timedelta = TICK) -> dt.datetime:
    """The clock moves on, the service makes one pass; the time of that pass."""
    world.clock.advance(after)
    world.service_pass()
    return world.clock()


def _recorded(world, tenant: str) -> Any:
    return world.call(world.tenants.merge_eligibility, tenant)


def _logins(world, tenant: str) -> frozenset[str]:
    return _recorded(world, tenant).logins


# --- the record, written by the service ------------------------------------------------------------------------

def test_a_pass_records_named_users_and_team_members_with_the_time_read_and_never_a_bot(world):
    """D13: users and every whitelisted team's members are recorded at the pass's time; the live bot, as user and as
    team member, is not, and the directory reads it back."""
    tenant = world.active_tenant()
    bot = world.live(tenant).bot_login
    _whitelist(world, tenant, users=["dave", bot], teams={"Owners": {"olga"}, "Reviewers": {"carol", "rita", bot}})
    at = _pass(world)
    got = world.directory().merge_eligibility(tenant)
    assert got.logins == frozenset({"dave", "olga", "carol", "rita"})
    assert got.read_at == at


def test_no_generations_bot_is_recorded_after_a_rotation(world):
    """D13: the destroyed generation's login, still on the stored rule and a team, and the live one are both left out."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    [old] = [g for g in world.generations(tenant) if g.status == "destroyed"]
    live = world.live(tenant)
    _whitelist(world, tenant, users=["dave", live.bot_login], teams={"Owners": {"olga", old.bot_login}})
    world.forge.rule(f"{ORG}/{tenant}")["merge_whitelist_usernames"].append(old.bot_login)  # a purged bot's stale name
    _pass(world)
    assert _logins(world, tenant) == frozenset({"dave", "olga"})


def test_a_team_larger_than_a_page_is_recorded_whole(world):
    """D13: the members of a team beyond the forge's page size (50) are all recorded."""
    tenant = world.active_tenant()
    crowd = {f"member-{i:03d}" for i in range(75)}
    _whitelist(world, tenant, users=["dave"], teams={"Owners": {"olga"}, "Reviewers": crowd})
    _pass(world)
    assert _logins(world, tenant) == frozenset({"dave", "olga", *crowd})


@pytest.mark.parametrize("change", ["leaves-team", "leaves-users", "team-dropped"])
def test_a_person_removed_from_the_whitelist_is_gone_after_the_next_pass(world, change):
    """D13: a person removed from the whitelist (user, team member or a whole team) stops being recorded one pass later."""
    tenant = world.active_tenant()
    _whitelist(world, tenant, users=["dave"], teams={"Owners": {"olga"}, "Reviewers": {"carol"}})
    _pass(world)
    assert _logins(world, tenant) == frozenset({"dave", "olga", "carol"}), "control: all three are eligible first"
    after = {"leaves-team": (["dave"], {"Owners": {"olga"}, "Reviewers": set()}, {"dave", "olga"}),
             "leaves-users": ([], {"Owners": {"olga"}, "Reviewers": {"carol"}}, {"olga", "carol"}),
             "team-dropped": (["dave"], {"Owners": {"olga"}}, {"dave", "olga"})}[change]
    _whitelist(world, tenant, users=after[0], teams=after[1])
    at = _pass(world)
    assert _logins(world, tenant) == frozenset(after[2])
    assert _recorded(world, tenant).read_at == at


def test_an_idle_pass_still_renews_the_time_read_and_still_counts_no_step(world):
    """D13: a pass with no job step to run records a fresh read_at, and `work()` still returns the steps run (0)."""
    tenant = world.active_tenant()
    _whitelist(world, tenant, users=["dave"])
    assert world.service_pass() == 0
    first = _recorded(world, tenant).read_at
    world.clock.advance(TICK)
    assert world.service_pass() == 0
    assert _recorded(world, tenant).read_at == first + TICK


def test_the_served_loop_records_eligibility(world):
    """D13: `lifecycle._process.serve` (the production loop) makes the recording, not only a direct `work()`."""
    from defender.lifecycle._process import serve

    tenant = world.active_tenant()
    _whitelist(world, tenant, users=["dave"], teams={"Owners": {"olga"}})
    world.clock.advance(TICK)
    world.call(lambda: serve(world.service_actor, world.host_actor, config=world.config, stop=lambda: True))
    got = _recorded(world, tenant)
    assert (got.logins, got.read_at) == (frozenset({"dave", "olga"}), world.clock())


def test_the_read_is_made_with_the_admin_credential_and_the_bot_is_never_asked(world):
    """D13: whitelist and team reads carry the service's admin token; no bot (Bearer) call reads them."""
    tenant = world.active_tenant()
    mark = len(world.forge.calls)
    _pass(world)
    reads = [c for c in world.forge.calls[mark:] if c.method == "GET" and f"/{tenant}/branch_protections" in c.path]
    assert reads, "control: the pass read the rule"
    assert all(world.forge.credential_of(c) == "token" for c in reads)
    assert world.forge.bearer_calls() == [] or all(f"/{tenant}/branch_protections" not in c.path for c in world.forge.bearer_calls())



def test_a_fresh_record_is_not_read_again_until_it_ages_and_never_goes_stale_between_passes(world):
    """D13/D15: a pass reads a tenant's whitelist only when its record is older than the refresh age, a third of the
    tick's 60 s bound, so the forge is not read every 5 s pass and a record is never past the bound while passes run."""
    from defender.lifecycle._service import ELIGIBILITY_REFRESH

    tenant = world.active_tenant()
    _whitelist(world, tenant, users=["dave"])
    first = _pass(world)

    def rule_reads(since):
        return [c for c in world.forge.calls[since:] if f"/{tenant}/branch_protections" in c.path]

    mark = len(world.forge.calls)
    _pass(world, after=dt.timedelta(seconds=5))
    assert rule_reads(mark) == [], "a fresh record was read again"
    assert _recorded(world, tenant).read_at == first
    later = _pass(world, after=ELIGIBILITY_REFRESH)
    assert rule_reads(mark), "an aged record was not read again"
    assert _recorded(world, tenant).read_at == later
    assert dt.timedelta(seconds=60) >= ELIGIBILITY_REFRESH * 3, "the refresh age lets a record go stale between passes"


# --- a forge failure -------------------------------------------------------------------------------------------

def _two_tenants(world) -> tuple[str, str]:
    first = world.active_tenant()
    world.clock.advance(dt.timedelta(seconds=1))  # created later: listed after the first
    second = world.active_tenant()
    _whitelist(world, first, users=["dave"], teams={"Owners": {"olga"}, "Auditors": {"ann"}})
    _whitelist(world, second, users=["erin"], teams={"Owners": {"olga"}})
    return first, second


def _fail(world, tenant: str, how: str) -> None:
    if how == "rule":
        world.forge.protection_read_status[f"{ORG}/{tenant}"] = 502
    else:
        world.forge.team_members_status["Auditors"] = 500


@pytest.mark.parametrize("failing", ["first", "second"])
@pytest.mark.parametrize("how", ["rule", "team-members"])
def test_a_forge_failure_on_one_tenant_keeps_its_record_whole_and_the_others_are_refreshed(world, how, failing):
    """D13: a rule or team-members read that fails records nothing for that tenant (no partial list, read_at not advanced)
    and the other tenant is still refreshed; once the forge answers the tenant is refreshed too."""
    a, b = _two_tenants(world)
    if failing == "second":  # the failing one is the one listed last: the first must be refreshed before it
        a, b = b, a
        _whitelist(world, a, users=["dave"], teams={"Owners": {"olga"}, "Auditors": {"ann"}})
    _pass(world)
    kept = _recorded(world, a)
    assert kept.logins == frozenset({"dave", "olga", "ann"}), "control: the first read of the tenant succeeded"
    _whitelist(world, a, users=["dave", "zed"], teams={"Owners": {"olga"}, "Auditors": {"ann"}})
    _whitelist(world, b, users=["erin", "fay"], teams={"Owners": {"olga"}})
    _fail(world, a, how)
    at = _pass(world)
    assert _recorded(world, a) == kept
    other = _recorded(world, b)
    assert (other.logins, other.read_at) == (frozenset({"erin", "fay", "olga"}), at)
    world.forge.protection_read_status.clear()
    world.forge.team_members_status.clear()
    later = _pass(world)
    healed = _recorded(world, a)
    assert (healed.logins, healed.read_at) == (frozenset({"dave", "zed", "olga", "ann"}), later)


def test_a_tenant_whose_first_read_fails_has_no_record_not_an_empty_one(world):
    """D13: before any read succeeded the record is absent (None), never an empty fresh list; the first good read records."""
    world.forge.team_members_status["Owners"] = 500  # fails every read of the Owners team from the tenant's first pass
    tenant = world.active_tenant()
    _pass(world)
    assert _recorded(world, tenant) is None
    world.forge.team_members_status.clear()
    _whitelist(world, tenant, users=["dave"], teams={"Owners": {"olga"}})
    _pass(world)
    assert _logins(world, tenant) == frozenset({"dave", "olga"})


@pytest.mark.parametrize("how", ["no-rule", "whitelist-disabled"])
def test_a_missing_rule_or_a_disabled_whitelist_is_a_failure_never_an_empty_set(world, how):
    """A8: `main` without a rule (404), or with its merge whitelist disabled, leaves the record as it was, read_at included,
    never an empty set; once the rule is whole again the tenant is refreshed."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    whole = {"rule_name": "main", "branch_name": "main", "enable_merge_whitelist": True,
             "merge_whitelist_usernames": ["dave"], "merge_whitelist_teams": ["Owners"]}
    _whitelist(world, tenant, users=["dave"], teams={"Owners": {"olga"}})
    _pass(world)
    kept = _recorded(world, tenant)
    assert kept.logins == frozenset({"dave", "olga"}), "control: the whole rule was read first"
    if how == "no-rule":
        world.forge.repos[full]["protections"].pop("main")
    else:
        world.forge.put_rule(full, **{**world.forge.rule(full), "enable_merge_whitelist": False})
    _pass(world)
    assert _recorded(world, tenant) == kept
    world.forge.put_rule(full, **whole)
    later = _pass(world)
    healed = _recorded(world, tenant)
    assert (healed.logins, healed.read_at) == (frozenset({"dave", "olga"}), later)


# --- tenants that are not active -------------------------------------------------------------------------------

def _creating_failed(world) -> str:
    world.forge.orgs[ORG].discard("Owners")  # the rule is refused: create stops at `template`, state `creating`
    tenant = world.create()
    world.drive()
    world.forge.orgs[ORG].add("Owners")
    assert world.item(tenant)["state"] == "creating" and world.item(tenant)["failure"]
    return tenant


def _offboarding(world) -> str:
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    assert world.item(tenant)["state"] == "offboarding"
    return tenant


def _offboarded(world) -> str:
    tenant = _offboarding(world)
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    return tenant


@pytest.mark.parametrize("make", [_creating_failed, _offboarding, _offboarded])
def test_a_tenant_that_is_not_active_is_not_read_and_its_record_is_left_alone(world, make):
    """D13: creating, offboarding and offboarded tenants are neither read on the forge nor recorded; an active
    tenant in the same pass is (control)."""
    active = world.active_tenant()
    _whitelist(world, active, users=["dave"])
    tenant = make(world)
    before = _recorded(world, tenant)
    mark = len(world.forge.calls)
    at = _pass(world)
    assert _recorded(world, tenant) == before
    touched = [c.path for c in world.forge.calls[mark:] if f"/{tenant}/branch_protections" in c.path]
    assert touched == []
    assert (_recorded(world, active).logins, _recorded(world, active).read_at) == (frozenset({"dave"}), at)


# --- the integration's grant -----------------------------------------------------------------------------------

def _scopes(world, bot: str) -> set[str]:
    [made] = [c for c in world.integration.created if c["user"] == bot]
    return set(made["scopes"])


def test_a_new_tenants_integration_carries_write_issue_as_well_as_write_repository(world):
    """D13: create grants both scopes, and the bot's JWT then reaches the repository and the issue API (a forge that
    enforces the scope)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    assert _scopes(world, gen.bot_login) == {"write:repository", "write:issue"}
    jwt = jwts(world, gen)[-1]
    assert as_bot(world, jwt, f"repos/{ORG}/{tenant}/branches/main").status_code == 200
    assert as_bot(world, jwt, f"repos/{ORG}/{tenant}/issues").status_code == 200


def test_rotation_gives_an_existing_tenants_new_integration_write_issue(world):
    """D13: a tenant whose live integration predates the grant (write:repository only: the issue API refuses its bot)
    has write:issue on the integration its next rotation creates."""
    tenant = world.active_tenant()
    old = world.live(tenant)
    [rule] = [r for r in world.forge.integration_rules.values() if r["user"] == old.bot_login]
    rule["scopes"] = ["write:repository"]
    assert as_bot(world, jwts(world, old)[-1], f"repos/{ORG}/{tenant}/issues").status_code == 403, "control: no write:issue"
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    new = world.live(tenant)
    assert new.salt != old.salt
    assert _scopes(world, new.bot_login) == {"write:repository", "write:issue"}
    assert as_bot(world, jwts(world, new)[-1], f"repos/{ORG}/{tenant}/issues").status_code == 200


# --- the record in both repositories ---------------------------------------------------------------------------

@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def repo(request) -> AsyncIterator[Any]:
    with contextlib.ExitStack() as stack:
        if request.param == "memory":
            from defender.tenancy import InMemoryTenantRepository

            repository: Any = InMemoryTenantRepository()
        else:
            from defender.tenancy.postgres import PostgresTenantRepository

            repository = PostgresTenantRepository(stack.enter_context(database(migrated=True)))
        try:
            yield repository
        finally:
            await repository.close()


@pytest.mark.anyio
async def test_a_tenant_with_nothing_recorded_reads_none(repo):
    """D13: absent record is None, not an empty list."""
    tenant = (await repo.request_create(now=NOW)).id
    assert await repo.merge_eligibility(tenant) is None


@pytest.mark.anyio
async def test_the_record_reads_back_as_written_and_a_later_record_replaces_it_whole(repo):
    """D13: logins (case and punctuation kept) and read_at round-trip as a frozenset and an aware time; the empty set is
    a record; recording again replaces both; another tenant's record is its own."""
    one, two = (await repo.request_create(now=NOW)).id, (await repo.request_create(now=NOW)).id
    first = frozenset({"Carol", "dave.x-1", "o_lga"})
    await repo.record_merge_eligibility(one, logins=first, read_at=NOW)
    got = await repo.merge_eligibility(one)
    assert (got.logins, got.read_at) == (first, NOW) and isinstance(got.logins, frozenset)
    assert got.read_at.utcoffset() == dt.timedelta(0)
    assert await repo.merge_eligibility(two) is None
    await repo.record_merge_eligibility(two, logins=frozenset(), read_at=NOW)
    empty = await repo.merge_eligibility(two)
    assert (empty.logins, empty.read_at) == (frozenset(), NOW)
    await repo.record_merge_eligibility(one, logins=frozenset({"rita"}), read_at=NOW + TICK)
    second = await repo.merge_eligibility(one)
    assert (second.logins, second.read_at) == (frozenset({"rita"}), NOW + TICK)
    assert (await repo.merge_eligibility(two)).logins == frozenset()


@pytest.mark.anyio
async def test_a_read_at_in_another_zone_is_the_same_instant(repo):
    """D13: the time is an instant: a +05:00 read_at reads back equal to itself."""
    tenant = (await repo.request_create(now=NOW)).id
    zoned = NOW.astimezone(dt.timezone(dt.timedelta(hours=5)))
    await repo.record_merge_eligibility(tenant, logins=frozenset({"dave"}), read_at=zoned)
    assert (await repo.merge_eligibility(tenant)).read_at == NOW


@pytest.mark.parametrize("backend", ["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def test_the_directory_reads_what_the_repository_recorded(backend):
    """D13: `TenantDirectory.merge_eligibility` (sync, one repository per call) returns the record, and None when absent."""
    from defender.tenancy import MergeEligibility, TenantDirectory

    with contextlib.ExitStack() as stack:
        if backend == "memory":
            from defender.tenancy import InMemoryTenantRepository

            shared: Any = InMemoryTenantRepository()
            directory = TenantDirectory(lambda: shared)

            def run(call: Any) -> Any:
                return asyncio.run(call(shared))
        else:
            from defender.tenancy.postgres import PostgresTenantRepository

            dsn = stack.enter_context(database(migrated=True))
            directory = TenantDirectory(lambda: PostgresTenantRepository(dsn))

            def run(call: Any) -> Any:
                async def once() -> Any:
                    opened = PostgresTenantRepository(dsn)
                    try:
                        return await call(opened)
                    finally:
                        await opened.close()
                return asyncio.run(once())

        tenant = run(lambda r: r.request_create(now=NOW)).id
        assert directory.merge_eligibility(tenant) is None
        run(lambda r: r.record_merge_eligibility(tenant, logins=frozenset({"dave", "olga"}), read_at=NOW))
        got = directory.merge_eligibility(tenant)
        assert isinstance(got, MergeEligibility)
        assert (got.logins, got.read_at) == (frozenset({"dave", "olga"}), NOW)


@pytest.mark.postgres
def test_the_upgrade_keeps_existing_tenants_without_a_record_and_the_record_can_then_be_written(empty_database):  # noqa: F811
    """D13 migration: from the revision before it, a tenant row survives with no record; at head it can be recorded."""
    from defender.migrations import upgrade
    from defender.tenancy.postgres import PostgresTenantRepository
    from defender.tests.migrations.test_1214_migrations import _upgrade_to

    tenant = "a4140000-0000-4000-8000-000000000001"
    _upgrade_to(empty_database, PRE_1414_HEAD)
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (tenant, NOW))
    upgrade(empty_database)

    async def go() -> Any:
        opened = PostgresTenantRepository(empty_database)
        try:
            before = await opened.merge_eligibility(tenant)
            await opened.record_merge_eligibility(tenant, logins=frozenset({"dave"}), read_at=NOW)
            return before, await opened.merge_eligibility(tenant)
        finally:
            await opened.close()

    before, after = asyncio.run(go())
    assert before is None
    assert (after.logins, after.read_at) == (frozenset({"dave"}), NOW)
