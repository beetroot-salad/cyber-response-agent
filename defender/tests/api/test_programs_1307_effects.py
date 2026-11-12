"""#1307 contract repair (W5, A8, O8, D6): an audit event and its effect are one fact. `program_credential.create` exists exactly when
the credential ended up usable (a key at insert, an OAuth credential at `pending -> live`), `program_client.delete` exactly when the
client is gone from the realm, and a failed delete of one client stops no other.

The input is the whole class of partial failures: for each operation that writes a credential or deletes a client (create, revoke,
program removal, reconciliation, and the removal that races a creation), the operation is run once to count its repository and realm
calls, then once more for each call number with a fault raised at that call, and the facts are checked after every run."""
from __future__ import annotations

import asyncio
import dataclasses
import collections
import itertools
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import ANN, T1, AuditLog  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    CLIENT_DELETE,
    CREDENTIAL_CREATE,
    Client,
    FaultPlan,
    InjectedProgramsFault,
    Soar,
    create_program,
    issue,
    issue_oauth,
    revoke,
    soar,
)

import datetime as _dt  # noqa: E402

PENDING_DEADLINE = _dt.timedelta(minutes=10)
ORPHAN_PREFIX = "6d3c1f0e-0000-4000-8000-"
ORPHANS = ("6d3c1f0e-0000-4000-8000-0000000000a1", "6d3c1f0e-0000-4000-8000-0000000000a2")


@dataclasses.dataclass
class Run:
    """One run of an operation: the world, the acts to perform, and what the realm held before."""

    s: Soar
    audit: AuditLog
    plan: FaultPlan
    act: Callable[[], Any]
    programs: list[str]
    clients_before: set[str] = dataclasses.field(default_factory=set)
    outcome: Any = None


def _world(caplog: pytest.LogCaptureFixture) -> tuple[Soar, AuditLog, FaultPlan]:
    audit = AuditLog(caplog)
    plan = FaultPlan()
    s = soar(faults=plan)
    s.ann = s.world.sign_in(ANN, browser=s.world.client(raise_errors=False))  # a fault is a 500, not an exception in the test
    return s, audit, plan


def _orphan(s: Soar, client_id: str) -> None:
    s.world.realm.clients[client_id] = Client(client_id, f"00000000-5a00-4000-8000-{client_id[-12:]}", "kc-secret")


def _reconcilable(s: Soar, more: int = 0) -> list[str]:
    """A realm with a kept client, one whose credential was revoked, two no row names, and one whose creation crashed midway and whose
    `pending` row is past its deadline, plus `more` of each of those three: the clients reconciliation deletes are returned (sorted)."""
    kept = issue_oauth(s.ann, T1, str(create_program(s.ann, T1, "Kept")["id"]))
    revoked = issue_oauth(s.ann, T1, s.program_id)
    assert revoke(s.ann, T1, s.program_id, revoked).status_code == 204
    for orphan in ORPHANS:
        _orphan(s, orphan)
    other = str(create_program(s.ann, T1, "Other")["id"])
    stale = s.world.crashed_oauth_create(s.ann, other)
    s.world.clock.advance(PENDING_DEADLINE + _dt.timedelta(seconds=1))
    assert kept in s.world.realm.clients
    extra = []
    for n in range(more):
        extra.append(issue_oauth(s.ann, T1, s.program_id))
        assert revoke(s.ann, T1, s.program_id, extra[-1]).status_code == 204
        extra.append(f"{ORPHAN_PREFIX}{0x100 + n:012x}")
        _orphan(s, extra[-1])
        extra.append(s.world.crashed_oauth_create(s.ann, str(create_program(s.ann, T1, f"Other {n}")["id"])))
    s.world.clock.advance(PENDING_DEADLINE + _dt.timedelta(seconds=1))  # the extra crashed rows were made after the last advance: age them past their own deadline
    return sorted([revoked, stale, *ORPHANS, *extra])


def _issue(kind: str) -> Callable[[Soar], Callable[[], Any]]:
    return lambda s: lambda: issue(s.ann, T1, s.program_id, kind=kind, name="subject")


def _revoke_an_oauth_credential(s: Soar) -> Callable[[], Any]:
    credential = issue_oauth(s.ann, T1, s.program_id)
    return lambda: revoke(s.ann, T1, s.program_id, credential)


def _remove_the_program(s: Soar) -> Callable[[], Any]:
    issue_oauth(s.ann, T1, s.program_id)
    return lambda: s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}")


def _reconcile(s: Soar) -> Callable[[], Any]:
    _reconcilable(s)

    def act() -> Any:
        try:
            s.world.call(s.world.service.reconcile_program_clients)
        except Exception as e:  # the pass raises its first failure at the end
            return e
        return None
    return act


def _removal_racing_a_creation(s: Soar) -> Callable[[], Any]:
    remover = s.world.sign_in(ANN, browser=s.world.client(raise_errors=False))
    realm, create = s.world.realm, s.world.realm.create_client

    async def racing(credential_id: str) -> tuple[str, str]:
        await asyncio.wait_for(asyncio.to_thread(remover.delete, f"/tenants/{T1}/programs/{s.program_id}"), 10)
        return await create(credential_id)

    realm.create_client = racing  # type: ignore[method-assign]
    return lambda: issue(s.ann, T1, s.program_id, kind="oauth_client", name="racing")


OPERATIONS: dict[str, Callable[[Soar], Callable[[], Any]]] = {
    "create-a-key": _issue("key"),
    "create-an-oauth-credential": _issue("oauth_client"),
    "revoke-a-credential": _revoke_an_oauth_credential,
    "remove-the-program": _remove_the_program,
    "reconcile": _reconcile,
    "removal-racing-a-creation": _removal_racing_a_creation,
}


def _rows(s: Soar) -> list[Any]:
    # the seeded program (which an operation may remove, so it is named) and the tenant's other active programs (#1454: programs
    # are their own rows, not memberships)
    active = {str(p.id) for p in s.world.call(s.world.raw_repo.programs_of_tenant, T1)}
    return [row for program in sorted({s.program_id, *active}) for row in s.world.credentials(program)]


def _facts(s: Soar, audit: AuditLog, clients_before: set[str]) -> list[str]:
    """What is wrong, if anything, between the audit trail and the state it describes."""
    wrong = []
    events = audit.events()
    created = [e.target for e in events if e.action == CREDENTIAL_CREATE]
    rows = _rows(s)
    # a credential became usable exactly when it was `live`, or was live once (a key at insert; an OAuth row that went live
    # records its service account, which a revocation keeps)
    ever_usable = sorted(r.id for r in rows if r.state == "live" or r.kind == "key" or r.service_account_id is not None)
    if sorted(created) != ever_usable:
        wrong.append(f"program_credential.create for {sorted(created)}, credentials that became usable {ever_usable}")
    ever_in_the_realm = clients_before | set(s.world.realm.created)
    gone = sorted(ever_in_the_realm - set(s.world.realm.clients))
    deleted = sorted(e.target for e in events if e.action == CLIENT_DELETE)
    if deleted != gone:
        wrong.append(f"program_client.delete for {deleted}, clients gone from the realm {gone}")
    return wrong


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_an_audit_event_exists_exactly_when_its_effect_does_under_a_fault_at_any_call(
        operation: str, caplog: pytest.LogCaptureFixture) -> None:
    """For every call number of the operation, a fault raised there leaves the audit trail and the state agreeing: the create
    event for exactly the credentials that became usable (so none for an OAuth creation that ended in 503 or 409, one for a
    credential that went live whose answer was lost, A5), the delete event for exactly the clients gone from the realm (W5, A8)."""
    def run(at: int | None) -> tuple[Run, list[str]]:
        caplog.clear()
        s, audit, plan = _world(caplog)
        act = OPERATIONS[operation](s)
        before = set(s.world.realm.clients)
        plan.arm(at)
        outcome = act()
        plan.disarm()
        run_ = Run(s, audit, plan, act, [s.program_id], before, outcome)
        return run_, _facts(s, audit, before)

    clean, wrong = run(None)
    assert wrong == [], "unfaulted"
    calls = len(clean.plan.calls)
    assert calls > 3, clean.plan.calls  # control: the operation was observed making calls
    if operation == "reconcile":
        assert clean.outcome is None
        assert len(clean.s.world.realm.deleted) == 4  # the revoked, the stale pending and the two with no row
    problems = []
    for at in range(calls):
        faulted, wrong = run(at)
        assert faulted.plan.fired is not None
        if wrong:
            who, name, _ = faulted.plan.calls[at]
            problems.append(f"fault at call {at} ({who}.{name}): {wrong}")
    assert problems == []


def test_a_failed_delete_stops_no_other_and_the_first_failure_is_raised_at_the_end(caplog: pytest.LogCaptureFixture) -> None:
    """Reconciliation over every subset of the clients it deletes whose delete fails (A8): each client whose delete was not
    refused is gone and has its event, each refused one stays and has none, and the pass then raises the first refusal."""
    def run(refused: set[int]) -> tuple[Soar, AuditLog, Any, list[str], list[str]]:
        caplog.clear()
        s, audit, _ = _world(caplog)
        doomed = _reconcilable(s)
        names = [doomed[i] for i in sorted(refused)]
        s.world.realm.fail_deletes = set(names)
        return s, audit, _reconcile_once(s), doomed, names

    s, audit, outcome, doomed, _ = run(set())
    assert outcome is None
    assert sorted(s.world.realm.deleted) == doomed  # control: nothing refused, all four deleted
    for size in range(1, len(doomed) + 1):
        for refused in itertools.combinations(range(len(doomed)), size):
            s, audit, outcome, doomed, names = run(set(refused))
            realm = s.world.realm
            assert [c for c in doomed if c in realm.clients] == sorted(names), refused  # exactly the refused remain
            assert sorted(e.target for e in audit.events() if e.action == CLIENT_DELETE) == sorted(set(doomed) - set(names)), refused
            assert isinstance(outcome, InjectedProgramsFault), (refused, outcome)
            assert outcome is realm.failed_deletes[0], refused  # the first failure raised, not a later one or a summary
            assert sorted(f.args for f in realm.failed_deletes) == sorted((f"the delete of {c} was refused",) for c in names), refused


def _reconcile_once(s: Soar) -> Any:
    try:
        s.world.call(s.world.service.reconcile_program_clients)
    except Exception as e:  # noqa: BLE001 — the pass raises its first failure; the test inspects it
        return e
    return None


def _repo_calls_before_the_first_delete(plan: FaultPlan) -> list[tuple[int, str]]:
    """(call number, method) of every repository call the pass made before its first client deletion."""
    first_delete = next(i for i, (who, name, _) in enumerate(plan.calls) if (who, name) == ("realm", "delete_client"))
    return [(i, name) for i, (who, name, _) in enumerate(plan.calls[:first_delete]) if who == "repo"]


def test_1454_a_cleanup_pass_reads_the_tenants_it_needs_once_before_it_deletes_and_audits_them(caplog: pytest.LogCaptureFixture) -> None:
    """The keep-set and the tenants are read once before the first deletion, and the repository calls the pass makes do not grow
    with the clients to delete; each deletion is audited with its tenant, none for a client with no row (O-F)."""
    calls = {}
    for more in (0, 3):  # 4 clients to delete, then 13
        caplog.clear()
        s, audit, plan = _world(caplog)
        doomed = _reconcilable(s, more)
        plan.arm(None)
        assert _reconcile_once(s) is None
        assert sorted(s.world.realm.deleted) == doomed
        assert len(doomed) == 4 + 3 * more
        assert sorted((e.target, e.tenant_id) for e in audit.events() if e.action == CLIENT_DELETE) == sorted(
            (c, None if c.startswith(ORPHAN_PREFIX) else T1) for c in doomed)
        before = [name for _, name in _repo_calls_before_the_first_delete(plan)]
        assert before.count("oauth_credentials_to_keep") == before.count("tenants_of_credentials") == 1, before
        calls[more] = collections.Counter(name for who, name, _ in plan.calls if who == "repo")
    assert calls[0] == calls[3], calls  # no per-client or per-row lookup of any kind


def test_1454_a_failed_read_in_a_cleanup_pass_deletes_nothing_and_fails_the_pass(caplog: pytest.LogCaptureFixture) -> None:
    """A fault at the keep-set read or at the tenant read, both of which come before the first deletion, leaves every client in
    the realm, audits no deletion and fails the pass with the fault; the unfaulted pass deletes them all (O-F)."""
    s, audit, plan = _world(caplog)
    doomed = _reconcilable(s)
    plan.arm(None)
    assert _reconcile_once(s) is None
    assert sorted(s.world.realm.deleted) == doomed  # control: unfaulted, all deleted
    reads = [(i, name) for i, name in _repo_calls_before_the_first_delete(plan)
             if name in ("oauth_credentials_to_keep", "tenants_of_credentials")]
    assert sorted(name for _, name in reads) == ["oauth_credentials_to_keep", "tenants_of_credentials"], reads
    for at, name in reads:
        caplog.clear()
        s, audit, plan = _world(caplog)
        doomed_here = _reconcilable(s)  # ids are minted per world
        plan.arm(at)
        outcome = _reconcile_once(s)
        assert isinstance(outcome, InjectedProgramsFault), (name, outcome)
        assert s.world.realm.deleted == [], name
        assert [c for c in doomed_here if c not in s.world.realm.clients] == [], name
        assert CLIENT_DELETE not in [e.action for e in audit.events()], name
