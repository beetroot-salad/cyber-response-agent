"""#1454 P-L at the service, through the app: a write that makes something live in a tenant holds the tenant `active` while it
writes. Each case flips the tenant to `offboarding` right before the repository write, after the request's membership check
passed (the race P-L closes), and answers as an unknown tenant would: create program, invite and admin invite are 404 with
nothing audited and nothing sent; accepting an invitation, explicitly or at first sign-in, finds nothing / is skipped; an expiry
warning claimed before the flip is settled and not mailed. Each negative has its positive control on the same route."""
from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    EMPTY,
    LAB,
    ME,
    NEW,
    OPS,
    T1,
    T2,
    AuditLog,
    World,
    me,
    tenants_of,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    DAY,
    DEFAULT_LIFETIME,
    PROGRAM_CREATE,
    ProgramsWorld,
    soar,
)

HOUR = _dt.timedelta(hours=1)
MEMBER_INVITE, ADMIN_INVITE, INVITATION_ACCEPT = "member.invite", "admin.invite", "invitation.accept"


def _leaves_active(world: World, tenant: str):  # type: ignore[no-untyped-def]
    """A hook for `world.repo.before[...]`: the tenant is offboarded at that moment, by the twin's own request."""
    async def hook() -> None:
        await world.amove_tenant(tenant, "offboarding")
    return hook


def test_creating_a_program_in_a_tenant_that_left_active_during_the_request_is_404_and_nothing_is_audited(caplog) -> None:
    """The tenant is offboarded after the admin's membership check and before the repository write: 404, no program, no
    `program.create`; the same request in a tenant that stays active is 201 and audited (P-L)."""
    audit = AuditLog(caplog)
    s = soar(failing_writes=True)
    s.world.repo.before["add_program"] = _leaves_active(s.world, T1)
    mark = audit.mark()
    response = s.ann.post(f"/tenants/{T1}/programs", json={"display_name": "Late"})
    assert response.status_code == 404, response.text
    assert [str(p.id) for p in s.world.call(s.world.raw_repo.programs_of_tenant, T1)] == [s.program_id]
    assert PROGRAM_CREATE not in audit.actions(mark)
    created = s.bob.post(f"/tenants/{T2}/programs", json={"display_name": "On time"})  # control: an active tenant
    assert created.status_code == 201, created.text
    assert [(e.action, e.tenant_id, e.target) for e in audit.since(mark)] == [(PROGRAM_CREATE, T2, created.json()["id"])]


def test_inviting_into_a_tenant_that_left_active_during_the_request_is_404_with_nothing_audited_or_sent(caplog) -> None:
    """The tenant is offboarded between the member's check and the invitation write: 404, no invitation row, no
    `member.invite`, no set-password mail or notice; the same invite into a tenant that stays active is 202, audited and sent (P-L)."""
    audit = AuditLog(caplog)
    s = soar(failing_writes=True)
    world = s.world
    sent_before, notices_before = world.signin.calls(), len(world.mail.sent)
    world.repo.before["ensure_invitation"] = _leaves_active(world, T1)
    mark = audit.mark()
    response = world.invite(s.ann, T1, NEW)
    assert response.status_code == 404, response.text
    assert audit.since(mark) == []
    assert [(str(m.user_id), m.status) for m in world.call(world.raw_repo.memberships_of_tenant, T1)] == [
        (user_id(s.ann), "active")]  # ann's own row only: no invitation was written
    world.send_pending()
    assert (world.signin.calls(), len(world.mail.sent), world.signin.sends_to(NEW)) == (sent_before, notices_before, 0)
    accepted = world.invite(s.bob, T2, NEW)  # control: an active tenant takes the same invitee
    assert accepted.status_code == 202, accepted.text
    world.send_pending()
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(MEMBER_INVITE, T2)]
    assert world.signin.sends_to(NEW) == 1


def test_an_administrator_inviting_into_a_tenant_that_left_active_during_the_request_is_404_with_nothing_audited_or_sent(
        caplog) -> None:
    """The tenant (no active members) is offboarded between the administrator's checks and the invitation write: 404, no
    `admin.invite`, no `member.invite`, nothing sent; the same invite into another empty active tenant is 202 and audited (P-L)."""
    audit = AuditLog(caplog)
    world = ProgramsWorld(administrators=[OPS], failing_writes=True)
    ops = world.sign_in_admin()
    world.register(EMPTY)
    world.register(T2)
    sent_before = world.signin.calls()
    world.repo.before["ensure_invitation"] = _leaves_active(world, EMPTY)
    mark = audit.mark()
    response = ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW})
    assert response.status_code == 404, response.text
    assert audit.since(mark) == []
    assert world.call(world.raw_repo.memberships_of_tenant, EMPTY) == []
    world.send_pending()
    assert (world.signin.calls(), world.signin.sends_to(NEW)) == (sent_before, 0)
    accepted = ops.post(f"/admin/tenants/{T2}/invitations", json={"email": NEW})  # control
    assert accepted.status_code == 202, accepted.text
    world.send_pending()
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(ADMIN_INVITE, None), (MEMBER_INVITE, T2)]
    assert world.signin.sends_to(NEW) == 1


def test_accepting_an_invitation_whose_tenant_left_active_during_the_request_is_404_and_joins_nothing(caplog) -> None:
    """The tenant is offboarded between the invitation's lookup and the accept write: 404 as for any tenant not active, no
    membership, no `invitation.accept`; another tenant's invitation to the same person is accepted (P-L)."""
    audit = AuditLog(caplog)
    world = World(tenants={T1: [ANN], T2: [BOB], LAB: [ME]}, failing_writes=True)
    ann, bob, lab_member = world.sign_in(ANN), world.sign_in(BOB), world.sign_in(ME)
    assert world.invite(bob, T2, ANN).status_code == 202
    assert world.invite(lab_member, LAB, ANN).status_code == 202
    world.send_pending()
    offered = {row["tenant_id"]: row["id"] for row in me(ann)["invitations"]}
    assert set(offered) == {T2, LAB}
    world.repo.before["accept_invitation"] = _leaves_active(world, T2)
    mark = audit.mark()
    assert ann.post(f"/invitations/{offered[T2]}/accept").status_code == 404
    assert tenants_of(ann) == {T1}
    assert audit.since(mark) == []
    assert ann.post(f"/invitations/{offered[LAB]}/accept").status_code == 200  # control: the active tenant's invitation
    assert tenants_of(ann) == {T1, LAB}
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(INVITATION_ACCEPT, LAB)]


def test_the_first_sign_in_skips_an_invitation_whose_tenant_left_active_before_its_accept_and_takes_the_other(caplog) -> None:
    """The tenant is offboarded before the sign-in's accept write: that invitation stays open and unaccepted, with no
    `invitation.accept`; the invitation to a tenant that stays active is accepted in the same sign-in (P-L)."""
    audit = AuditLog(caplog)
    world = World(tenants={T1: [ANN], LAB: [ME]}, failing_writes=True)
    ann, lab_member = world.sign_in(ANN), world.sign_in(ME)
    assert world.invite(ann, T1, NEW).status_code == 202
    assert world.invite(lab_member, LAB, NEW).status_code == 202
    world.send_pending()
    world.repo.before["accept_invitation"] = _leaves_active(world, T1)
    mark = audit.mark()
    newcomer = world.sign_in(NEW)
    assert tenants_of(newcomer) == {LAB}
    assert [(e.action, e.tenant_id) for e in audit.since(mark)] == [(INVITATION_ACCEPT, LAB)]


def test_an_expiry_warning_claimed_before_its_tenant_left_active_is_settled_and_not_mailed(caplog) -> None:
    """The tenant is offboarded after the warning is claimed and before the send-time recheck: nobody is mailed and the
    warning is settled (the next one left is the 3-day one); the same steps with the tenant active mail the admin (P-L, O-D)."""
    s, control = soar(failing_writes=True), soar()
    s.world.repo.after["claim_expiry_warning"] = _leaves_active(s.world, T1)
    for world in (s.world, control.world):
        world.clock.advance(DEFAULT_LIFETIME - 14 * DAY + HOUR)  # 14 days minus an hour before the key expires
        world.send_pending()
    assert s.world.mail.warnings == []
    assert "claim_expiry_warning" not in s.world.repo.after  # the flip happened, between the claim and the recheck
    assert s.world.call(s.world.repo.credential_by_id, s.key_id).warn_threshold_days == 3
    assert [(w.to, w.credential_id) for w in control.world.mail.warnings] == [(ANN, control.key_id)]  # control
