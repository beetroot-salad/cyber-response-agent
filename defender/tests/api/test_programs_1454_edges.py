"""#1454 edges of the program lifecycle at the service and the API, one test per family (the second repair of the contract).

F1 offboarding at the service: `end_tenant` is loud when a call it depends on fails (a swallowed program removal would
let the tenant's program outlive its offboarding), audits nothing for a program someone else removed between its read and its
remove, and removes a program with no credentials like any other. F2 re-inviting a person who already has a live row in a tenant
that left `active` during the request is 404 with nothing audited or mailed. F4 a removed program is gone to the credential
routes, the program list is ordered by (display_name, id), a removal audits its revokes oldest first, and the cleanup pass stamps
each audit line with its own credential's tenant."""
from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity import Bootstrap, IdentityService  # noqa: E402
from defender.tests.support.api._identity1306 import NEW, T1, T2, AuditLog, InjectedFailure, items, user_id  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    CLIENT_DELETE,
    CREDENTIAL_REVOKE,
    PROGRAM_REMOVE,
    RaisingProgramsRealm,
    create_program,
    issue,
    issue_key,
    issue_oauth,
    revoke,
    soar,
)

SYSTEM = "system"
HOUR = _dt.timedelta(hours=1)
MEMBER_INVITE = "member.invite"
CY = "cy@a.example"


def _lifecycle(world: Any) -> Any:
    """The service as offboarding runs it, over the world's failure-scripted repository, with the loud-null programs port."""
    return IdentityService(world.repo, signin=world.signin, mail=world.mail, clock=world.clock,
                           bootstrap=Bootstrap(administrators=()), programs=RaisingProgramsRealm())


def _leaves_active(world: Any, tenant: str) -> Any:
    async def hook() -> None:
        await world.amove_tenant(tenant, "offboarding")
    return hook


# --- F1 offboarding -----------------------------------------------------------------------------------

@pytest.mark.parametrize("call", ["programs_of_tenant", "remove_program", "memberships_of_tenant", "end_membership",
                                  "revoke_invitation"])
def test_end_tenant_raises_when_a_call_it_depends_on_fails_and_a_retry_finishes_the_job(call: str) -> None:
    """Each repository call `end_tenant` makes (the programs read, a program's removal, the memberships read, a membership's end,
    an invitation's revoke) that fails fails the offboarding step with that error; with the fault gone the retry removes the
    program, ends the member and revokes the invitation (O-E)."""
    s = soar(failing_writes=True)
    world = s.world
    assert world.invite(s.ann, T1, NEW).status_code == 202
    world.repo.failing = {call}
    with pytest.raises(InjectedFailure):
        world.call(_lifecycle(world).end_tenant, T1, now=world.clock())
    assert world.repo.refusals == {call: 1}
    world.repo.failing = set()
    world.call(_lifecycle(world).end_tenant, T1, now=world.clock())
    assert world.call(world.raw_repo.program, s.program_id).status == "removed"
    assert {m.status for m in world.call(world.raw_repo.memberships_of_tenant, T1)} == {"ended", "revoked"}
    assert {r.state for r in world.credentials(s.program_id)} == {"revoked"}


def test_end_tenant_audits_nothing_for_a_program_removed_between_its_read_and_its_removal(caplog) -> None:
    """An administrator removes the program after `end_tenant` read its tenant's programs and before it removes it: the removal
    finds nothing to remove, so `end_tenant` emits no `program.remove` and no revoke for it (the admin's own lines are the
    record); the same offboarding without the interleaved removal audits the program's removal by the system (O-E, O-A)."""
    audit = AuditLog(caplog)
    s, control = soar(failing_writes=True), soar(failing_writes=True)

    async def admin_removes_it() -> None:
        await s.world.raw_repo.remove_program(s.program_id, removed_by=None, now=s.world.clock())

    s.world.repo.after["programs_of_tenant"] = admin_removes_it
    mark = audit.mark()
    s.world.call(_lifecycle(s.world).end_tenant, T1, now=s.world.clock())
    assert "programs_of_tenant" not in s.world.repo.after  # the removal did happen between the read and ours
    assert [e for e in audit.since(mark) if e.action in (PROGRAM_REMOVE, CREDENTIAL_REVOKE)] == []
    mark = audit.mark()
    control.world.call(_lifecycle(control.world).end_tenant, T1, now=control.world.clock())
    assert [(e.action, e.actor, e.target) for e in audit.since(mark) if e.action == PROGRAM_REMOVE] == [
        (PROGRAM_REMOVE, SYSTEM, control.program_id)]


def test_a_program_with_no_credentials_is_removed_and_audited_by_an_admin_and_by_offboarding(caplog) -> None:
    """A program that never had a credential: its admin's DELETE is 204 and audits `program.remove` (no revoke lines); the
    tenant's offboarding removes such a program too and audits `program.remove` by the system (O-E, O-A)."""
    audit = AuditLog(caplog)
    s = soar()
    by_admin = str(create_program(s.ann, T1, "Bare, removed by its admin")["id"])
    by_system = str(create_program(s.ann, T1, "Bare, removed by offboarding")["id"])
    mark = audit.mark()
    assert s.ann.delete(f"/tenants/{T1}/programs/{by_admin}").status_code == 204
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)] == [
        (PROGRAM_REMOVE, user_id(s.ann), T1, by_admin)]
    assert s.world.call(s.world.raw_repo.program, by_admin).status == "removed"
    mark = audit.mark()
    s.world.call(s.world.lifecycle_service().end_tenant, T1, now=s.world.clock())
    removals = [(e.actor, e.tenant_id, e.target) for e in audit.since(mark) if e.action == PROGRAM_REMOVE]
    assert sorted(removals) == sorted([(SYSTEM, T1, s.program_id), (SYSTEM, T1, by_system)])
    assert s.world.call(s.world.raw_repo.program, by_system).status == "removed"


# --- F2 re-inviting an existing live row ----------------------------------------------------------------

def test_re_inviting_a_person_already_invited_in_a_tenant_that_left_active_is_404_with_nothing_audited_or_sent(caplog) -> None:
    """The person has an open invitation to T1 when T1 is offboarded between the member's check and the invitation write: 404,
    no `member.invite`, no second set-password mail; the same re-invitation into a tenant that stays active is 202, audited and
    sent (P-L)."""
    audit = AuditLog(caplog)
    s = soar(failing_writes=True)
    world = s.world
    assert world.invite(s.ann, T1, NEW).status_code == 202
    assert world.invite(s.bob, T2, NEW).status_code == 202
    world.send_pending()
    sent = world.signin.sends_to(NEW)
    world.repo.before["ensure_invitation"] = _leaves_active(world, T1)
    mark = audit.mark()
    response = world.invite(s.ann, T1, NEW)
    assert response.status_code == 404, response.text
    assert audit.since(mark) == []
    world.send_pending()
    assert world.signin.sends_to(NEW) == sent
    assert [m.status for m in world.call(world.raw_repo.memberships_of_tenant, T1) if str(m.user_id) != user_id(s.ann)] == [
        "invited"]  # the invitation made while T1 was active is still open for the offboarding to revoke
    again = world.invite(s.bob, T2, NEW)  # control: the same re-invitation where the tenant stays active
    assert again.status_code == 202, again.text
    world.send_pending()
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(MEMBER_INVITE, T2)]
    assert world.signin.sends_to(NEW) == sent + 1


def test_inviting_a_member_already_active_in_a_tenant_that_left_active_is_404_not_a_conflict(caplog) -> None:
    """The invitee is already an active member of T1, which is offboarded between the member's check and the write: 404 as for
    any tenant not active (not the 409 an active tenant answers), nothing audited or sent (P-L)."""
    audit = AuditLog(caplog)
    s = soar(failing_writes=True)
    world = s.world
    world.member(s.ann, T1, CY)
    sent = world.signin.calls()
    conflict = world.invite(s.ann, T1, CY)  # control: while T1 is active the answer is the conflict
    assert conflict.status_code == 409, conflict.text
    world.repo.before["ensure_invitation"] = _leaves_active(world, T1)
    mark = audit.mark()
    response = world.invite(s.ann, T1, CY)
    assert response.status_code == 404, response.text
    assert audit.since(mark) == []
    world.send_pending()
    assert world.signin.calls() == sent


# --- F4 O-A edges ---------------------------------------------------------------------------------------

def test_a_removed_programs_credentials_are_gone_to_the_credential_routes() -> None:
    """After its removal the program's credential list, a revoke of its credential and a new credential are 404 (the program
    is not found, as another tenant's is); the tenant's other program answers all three (O-A, control)."""
    s = soar()
    other = str(create_program(s.ann, T1, "Other")["id"])
    other_key, _ = issue_key(s.ann, T1, other)
    assert s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204
    assert s.ann.get(f"/tenants/{T1}/programs/{s.program_id}/credentials").status_code == 404
    assert revoke(s.ann, T1, s.program_id, s.key_id).status_code == 404
    assert issue(s.ann, T1, s.program_id, kind="key", name="late").status_code == 404
    assert [r.state for r in s.world.credentials(s.program_id)] == ["revoked"]  # the removal's, and nothing was added
    assert [c["id"] for c in items(s.ann.get(f"/tenants/{T1}/programs/{other}/credentials"))] == [other_key]
    assert issue(s.ann, T1, other, kind="key", name="second").status_code == 201
    assert revoke(s.ann, T1, other, other_key).status_code == 204


def test_the_program_list_is_ordered_by_display_name_then_id() -> None:
    """Programs made at different times in no name order, and several sharing a name: the list reads by (display_name, id), not by
    creation (O-A)."""
    s = soar()
    created = []
    for name in ["Zeta", "Alpha", "Mid", *["Twin"] * 6]:
        s.world.clock.advance(HOUR)
        created.append(create_program(s.ann, T1, name))
    listed = items(s.ann.get(f"/tenants/{T1}/programs"))
    expected = sorted([{"display_name": "SOAR prod", "id": s.program_id}, *created], key=lambda p: (p["display_name"], p["id"]))
    assert [(p["display_name"], p["id"]) for p in listed] == [(p["display_name"], p["id"]) for p in expected]
    assert [p["display_name"] for p in listed] == ["Alpha", "Mid", "SOAR prod", "Twin", "Twin", "Twin", "Twin", "Twin", "Twin", "Zeta"]


@pytest.mark.parametrize("by", ["its admin", "its tenant's offboarding"])
def test_a_removal_audits_the_revokes_oldest_credential_first_then_the_program(caplog, by: str) -> None:
    """A program's credentials made an hour apart are revoked in the audit oldest first and then the program is removed, whether
    an admin removes it or its tenant's offboarding does (O-A)."""
    audit = AuditLog(caplog)
    s = soar()
    s.world.clock.advance(HOUR)
    newer = issue_oauth(s.ann, T1, s.program_id)
    mark = audit.mark()
    if by == "its admin":
        assert s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204
    else:
        s.world.call(s.world.lifecycle_service().end_tenant, T1, now=s.world.clock())
    lines = [(e.action, e.target) for e in audit.since(mark) if e.action in (CREDENTIAL_REVOKE, PROGRAM_REMOVE)]
    assert lines == [(CREDENTIAL_REVOKE, s.key_id), (CREDENTIAL_REVOKE, newer), (PROGRAM_REMOVE, s.program_id)]


def test_the_cleanup_pass_stamps_each_audit_line_with_its_own_credentials_tenant(caplog) -> None:
    """Two tenants each with a stuck `pending` OAuth credential: the pass revokes each as the system in its own tenant and then
    deletes its client, each line in its own tenant, not in one tenant's for both (O-A, O8)."""
    audit = AuditLog(caplog)
    s = soar()
    theirs = str(create_program(s.bob, T2)["id"])
    ours_pending = s.world.crashed_oauth_create(s.ann, s.program_id)
    theirs_pending = s.world.crashed_oauth_create(s.bob, theirs)
    s.world.clock.advance(HOUR)  # past the ten-minute pending deadline
    mark = audit.mark()
    s.world.call(s.world.service.reconcile_program_clients)
    lines = sorted((e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark))
    assert lines == sorted([
        (CREDENTIAL_REVOKE, SYSTEM, T1, ours_pending), (CREDENTIAL_REVOKE, SYSTEM, T2, theirs_pending),
        (CLIENT_DELETE, SYSTEM, T1, ours_pending), (CLIENT_DELETE, SYSTEM, T2, theirs_pending)])


def test_the_cleanup_of_revoked_credentials_clients_stamps_each_deletion_with_its_own_tenant(caplog) -> None:
    """Revoked OAuth credentials in two tenants: the pass deletes both clients, each audited in its own credential's tenant (O-A, O8)."""
    audit = AuditLog(caplog)
    s = soar()
    theirs = str(create_program(s.bob, T2)["id"])
    ours_oauth, theirs_oauth = issue_oauth(s.ann, T1, s.program_id), issue_oauth(s.bob, T2, theirs)
    assert revoke(s.ann, T1, s.program_id, ours_oauth).status_code == 204
    assert revoke(s.bob, T2, theirs, theirs_oauth).status_code == 204
    mark = audit.mark()
    s.world.call(s.world.service.reconcile_program_clients)
    assert sorted((e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)) == sorted([
        (CLIENT_DELETE, SYSTEM, T1, ours_oauth), (CLIENT_DELETE, SYSTEM, T2, theirs_oauth)])
