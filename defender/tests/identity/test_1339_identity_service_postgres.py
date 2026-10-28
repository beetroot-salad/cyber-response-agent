"""#1339 O6: the identity service over PostgreSQL, with the races owed since #1306 held at known points.

`IdentityService` runs over `PostgresIdentityRepository` and recording doubles for sign-in and mail, all on
one event loop. A raw connection holds a row lock, or a test event pauses a service step, so each
interleaving is the same on every run. The repository wrapper only records and forwards.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib
import logging
from collections.abc import AsyncIterator, Callable, Iterator

import pytest

from defender.identity import Bootstrap, IdentityService, VerifiedSignIn
from defender.records._tenant_id import TenantId
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import (
    TIMEOUT,
    connections,
    fetch,
    holding_row,
    until,
    until_blocked,
)
from defender.tests.support.shared._postgres1339 import database, execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
WEEK = dt.timedelta(days=7)
T1 = TenantId(fixture_uuid("tenant:t1"))
T2 = TenantId(fixture_uuid("tenant:t2"))
AUDIT_LOGGER = "defender.identity.audit"


class Spy:
    """Forwards every repository call and records `(name, result)`; `after[name]` runs once after that call returns."""

    def __init__(self, repo) -> None:
        self.repo = repo
        self.calls: list[tuple[str, object]] = []
        self.after: dict[str, Callable[[], object]] = {}

    def __getattr__(self, name: str):
        target = getattr(self.repo, name)

        async def call(*args, **kwargs):
            result = await target(*args, **kwargs)
            self.calls.append((name, result))
            hook = self.after.pop(name, None)
            if hook is not None:
                await hook()
            return result

        return call

    def results(self, name: str) -> list[object]:
        return [result for called, result in self.calls if called == name]


class SignIn:
    """The sign-in port as a recorder: `answers` maps a code to what its verification returns."""

    def __init__(self) -> None:
        self.answers: dict[str, VerifiedSignIn] = {}
        self.set_password_sent: list[str] = []
        self.closed = False

    async def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        return f"acct-{username}"

    async def send_set_password_email(self, account_id: str, *, lifespan: dt.timedelta) -> None:
        self.set_password_sent.append(account_id)

    async def has_otp(self, account_id: str) -> bool:
        return False

    async def require_otp_setup(self, account_id: str) -> None:
        return None

    async def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        return f"https://signin.test/?state={state}"

    async def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        return self.answers[code]

    async def close(self) -> None:
        self.closed = True


@dataclasses.dataclass(frozen=True)
class Notice:
    to: str
    tenant_id: str
    invitation_id: str


class Mail:
    def __init__(self) -> None:
        self.sent: list[Notice] = []

    async def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None:
        self.sent.append(Notice(to, str(tenant_id), str(invitation_id)))


@dataclasses.dataclass
class Stack:
    dsn: str
    repo: Spy
    service: IdentityService
    signin: SignIn
    mail: Mail


@pytest.fixture
def pg_dsn() -> Iterator[str]:
    with database(migrated=True) as dsn:
        yield dsn


async def _build(dsn: str) -> Stack:
    """The service over the database at `dsn`, with T1 and T2 registered."""
    from defender.identity.postgres import PostgresIdentityRepository

    repo = Spy(PostgresIdentityRepository(dsn))
    signin, mail = SignIn(), Mail()
    service = IdentityService(
        repo, signin=signin, mail=mail, clock=lambda: NOW, bootstrap=Bootstrap(administrators=(), tenants={}))
    for tenant in (T1, T2):
        await repo.register_tenant(tenant, now=NOW)
    return Stack(dsn, repo, service, signin, mail)


@pytest.fixture
async def stack(pg_dsn) -> AsyncIterator[Stack]:
    """The service over a fresh database; closed through the service, which closes the repository."""
    built = await _build(pg_dsn)
    try:
        yield built
    finally:
        await built.service.close()


async def _signed_in(stack: Stack, email: str, value: str):
    """An active user with a live session, as the service sees them."""
    user = await stack.repo.add_user(email, created_at=NOW, status="active")
    await stack.repo.add_session(value, user.id, now=NOW, expires_at=NOW + WEEK)
    return user, await stack.service.authenticate(value)


async def _invitee(stack: Stack, email: str, account: str):
    """An `invited` user who already has a sign-in account, ready to sign in with the code `account`."""
    user = await stack.repo.add_user(email, created_at=NOW)
    assert await stack.repo.record_signin_account(user.id, account) is True
    return user


async def _sign_in(stack: Stack, account: str, name: str) -> str:
    stack.signin.answers[name] = VerifiedSignIn(account_id=account, name=name, amr=("pwd",))
    login = await stack.service.begin_signin()
    return await stack.service.complete_signin(code=name, state=login.prelogin.split(".")[0], prelogin=login.prelogin)


class Audit(logging.Handler):
    """Records `(action, what a second connection reads at that moment)` for every audit event."""

    def __init__(self, observe: Callable[[logging.LogRecord], object]) -> None:
        super().__init__(logging.INFO)
        self.observe = observe
        self.seen: list[tuple[str, object]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.seen.append((record.action, self.observe(record)))  # type: ignore[attr-defined]


@pytest.fixture
def audit_logger() -> Iterator[logging.Logger]:
    logger = logging.getLogger(AUDIT_LOGGER)
    previous = logger.level
    logger.setLevel(logging.INFO)
    yield logger
    logger.setLevel(previous)


# --- O6a concurrent invitations --------------------------------------------------------------


async def test_concurrent_invitations_of_one_person_wait_on_the_user_row_and_return_one_invitation(stack):
    """O6a: two invites of one (user, tenant) both wait on the user row, then return the same invitation."""
    _, owner = await _signed_in(stack, "owner@x.org", "owner-session")
    pat = await stack.repo.ensure_user("pat@x.org", now=NOW)
    async with holding_row(stack.dsn, "users", pat.id):
        tasks = [asyncio.ensure_future(stack.service.invite(owner, str(T1), "pat@x.org")) for _ in range(2)]
        await until_blocked(stack.dsn, 2)
        assert not any(t.done() for t in tasks)
    first, second = await asyncio.wait_for(asyncio.gather(*tasks), TIMEOUT)  # neither raised DataRuleViolation
    assert first.id == second.id
    rows = await stack.repo.memberships_of_user(pat.id)
    assert [(m.id, m.status, m.tenant_id) for m in rows] == [(first.id, "invited", str(T1))]


# --- O6b concurrent first sign-ins -----------------------------------------------------------


async def test_concurrent_first_sign_ins_of_one_user_activate_exactly_once(stack):
    """O6b: two sign-ins reach the activation together; one `activate_user` applies, the other falls back to the name."""
    ann = await _invitee(stack, "ann@x.org", "acct-ann")
    rows = [await stack.repo.ensure_invitation(ann.id, t, invited_by="system", now=NOW) for t in (T1, T2)]
    stack.repo.calls.clear()
    async with holding_row(stack.dsn, "users", ann.id):
        tasks = [asyncio.ensure_future(_sign_in(stack, "acct-ann", name)) for name in ("Ann One", "Ann Two")]
        await until_blocked(stack.dsn, 2)
        assert not any(t.done() for t in tasks)
    values = await asyncio.wait_for(asyncio.gather(*tasks), TIMEOUT)
    assert sorted(stack.repo.results("activate_user")) == [False, True]
    assert len(stack.repo.results("set_display_name")) == 1  # the one that did not activate
    assert len(set(values)) == 2
    for value in values:
        assert (await stack.service.authenticate(value)).user.id == ann.id  # both sessions are good
    got = await stack.repo.user(ann.id)
    assert (got.status, got.activated_at) == ("active", NOW)
    assert got.display_name in {"Ann One", "Ann Two"}
    assert [(m.status, m.accepted_at) for m in [await stack.repo.membership(r.id) for r in rows]] == [("active", NOW)] * 2


# --- O6c an invitation racing the invitee's first sign-in ------------------------------------


@pytest.mark.parametrize(("pause_after", "outcome"), [
    pytest.param("ensure_user", "notified", id="sign-in-before-the-row-exists"),
    pytest.param("ensure_invitation", "joined", id="sign-in-after-the-row-exists"),
    pytest.param("request_set_password", "joined", id="sign-in-after-the-first-request"),
])
async def test_an_invitation_racing_the_invitees_first_sign_in_ends_joined_or_notified(stack, pause_after, outcome):
    """O6c: wherever the invitee's first sign-in lands inside the invite, they end up a member or get a notification."""
    _, owner = await _signed_in(stack, "owner@x.org", "owner-session")
    pat = await _invitee(stack, "pat@x.org", "acct-pat")
    reached, proceed = asyncio.Event(), asyncio.Event()

    async def pause() -> None:
        reached.set()
        await proceed.wait()

    stack.repo.after[pause_after] = pause
    invite = asyncio.ensure_future(stack.service.invite(owner, str(T1), "pat@x.org"))
    await asyncio.wait_for(reached.wait(), TIMEOUT)
    await _sign_in(stack, "acct-pat", "Pat")  # the whole first sign-in happens while the invite is paused
    proceed.set()
    view = await asyncio.wait_for(invite, TIMEOUT)
    await stack.service.send_pending()

    row = await stack.repo.membership(view.id)
    assert (await stack.repo.user(pat.id)).status == "active"
    if outcome == "joined":
        assert (row.status, row.accepted_at) == ("active", NOW)
        assert stack.mail.sent == []
    else:
        assert row.status == "invited"
        assert stack.mail.sent == [Notice("pat@x.org", str(T1), view.id)]
    assert stack.signin.set_password_sent == []  # control: a set-password link never goes to an active user


# --- O6d is in the repository contract suite -------------------------------------------------
# --- O6f the sessions table holds only the hash ----------------------------------------------


async def test_the_sessions_table_holds_the_hash_of_a_session_and_never_its_value(stack):
    """O6f: after a sign-in, the stored row has the SHA-256 of the cookie value and nothing that contains the value."""
    ann = await _invitee(stack, "ann@x.org", "acct-ann")
    value = await _sign_in(stack, "acct-ann", "Ann")
    seeded = "seeded-session-value"
    await stack.repo.add_session(seeded, ann.id, now=NOW, expires_at=NOW + WEEK)
    rows = [text for (text,) in await fetch(stack.dsn, "SELECT t::text FROM identity.sessions t")]
    assert len(rows) == 2
    for raw in (value, seeded):
        assert not any(raw in row for row in rows)
        assert sum(hashlib.sha256(raw.encode()).hexdigest() in row for row in rows) == 1  # control: the hash is there
    assert all(ann.id in row for row in rows)


# --- O6g audit follows the commit ------------------------------------------------------------


async def test_an_audit_event_is_emitted_only_after_its_write_is_committed(stack, audit_logger):
    """O6g: when the handler reads through a second connection, the write the event reports is already visible."""
    _, owner = await _signed_in(stack, "owner@x.org", "owner-session")
    bob, bob_auth = await _signed_in(stack, "bob@x.org", "bob-session")

    def status_of_the_reported_write(record: logging.LogRecord) -> object:
        if record.action == "member.remove":  # type: ignore[attr-defined]
            query, key = "SELECT status FROM identity.memberships WHERE user_id = %s", record.target  # type: ignore[attr-defined]
        else:
            query, key = "SELECT status FROM identity.memberships WHERE id = %s", record.target  # type: ignore[attr-defined]
        rows = execute(stack.dsn, query, (key,))
        return rows[0][0] if rows else None

    handler = Audit(status_of_the_reported_write)
    audit_logger.addHandler(handler)
    try:
        revoked = await stack.service.invite(owner, str(T1), "pat@x.org")
        await stack.service.revoke(owner, str(T1), revoked.id)
        joining = await stack.service.invite(owner, str(T1), "bob@x.org")
        await stack.service.accept(bob_auth, joining.id)
        await stack.service.remove(owner, str(T1), bob.id)
    finally:
        audit_logger.removeHandler(handler)
    assert handler.seen == [
        ("member.invite", "invited"),
        ("invitation.revoke", "revoked"),
        ("member.invite", "invited"),
        ("invitation.accept", "active"),
        ("member.remove", "ended"),
    ]


# --- lifecycle (amendment E) -----------------------------------------------------------------


async def test_closing_the_service_closes_its_repository_and_its_sign_in_port(pg_dsn):
    """Lifecycle (E): `IdentityService.close()` releases the database connections and closes the sign-in port."""
    stack = await _build(pg_dsn)
    await stack.repo.ensure_user("a@x.org", now=NOW)

    async def idle() -> bool:
        return await connections(stack.dsn) == 0

    assert await connections(stack.dsn) > 0  # control: the repository holds connections while open
    assert stack.signin.closed is False
    await stack.service.close()
    assert stack.signin.closed is True
    await until(idle)
