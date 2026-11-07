"""#1307: fixed roles and program creation (O3, O4, P-H) — sketch."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity import DataRuleViolation  # noqa: E402
from defender.tests.support.api._identity1306 import ALERT, T1, T2, AuditLog, items  # noqa: E402
from defender.tests.support.api._programs1307 import create_program, soar, start_investigation  # noqa: E402

INV = "/investigations"


def _routes(investigation_id: str) -> list[tuple[str, str, object]]:
    return [
        ("post", "/learning-jobs", {"investigation_id": investigation_id, "client_request_id": "j1"}),  # D8
        ("delete", f"{INV}/{investigation_id}", None),
        ("get", "/systems", None),
        ("put", "/systems/s1", {"kind": "tickets", "display_name": "x", "enabled": True, "settings": {}}),
        ("put", "/alert-mapping", None),
        ("get", "/members", None),
        ("get", "/invitations", None),
        ("get", "/programs", None),
        ("post", "/programs", {"display_name": "child"}),
    ]


def test_automation_reads_work_and_runs_investigations() -> None:
    """automation: `work.read` and `investigations.run` (O3)."""
    s = soar()
    program = s.program()
    assert [a["alert_id"] for a in items(program.get(f"/tenants/{T1}/alerts"))] == [ALERT.alert_id]
    started = start_investigation(program, T1)
    assert started.status_code == 201, started.text
    investigation_id = started.json()["investigation_id"]
    assert program.get(f"/tenants/{T1}{INV}/{investigation_id}").status_code == 200
    assert program.post(f"/tenants/{T1}{INV}/{investigation_id}/cancel").status_code == 200
    assert program.get(f"/tenants/{T1}/learning-jobs").status_code == 200


def test_automation_is_refused_learning_jobs_deletion_config_and_people() -> None:
    """Every permission outside automation's row -> 403; an admin is not refused the same request (O3, D8)."""
    s = soar()
    investigation_id = start_investigation(s.ann, T1).json()["investigation_id"]
    mapping = s.ann.get(f"/tenants/{T1}/alert-mapping").json()
    for method, path, body in _routes(investigation_id):
        body = mapping if path == "/alert-mapping" else body
        kwargs = {} if body is None else {"json": body}
        refused = getattr(s.program(), method)(f"/tenants/{T1}{path}", **kwargs)
        assert refused.status_code == 403, (method, path, refused.text)
        assert getattr(s.ann, method)(f"/tenants/{T1}{path}", **kwargs).status_code != 403, (method, path)


def test_an_admin_creates_a_program_that_is_an_active_automation_member_with_no_email(caplog) -> None:
    """Program creation: active at once, one automation membership in the tenant, creator recorded, audited (O4, O8)."""
    audit = AuditLog(caplog)
    s = soar()
    mark = audit.mark()
    created = create_program(s.ann, T1, "Ticket sync")
    program_id = str(created["id"])
    assert created["display_name"] == "Ticket sync"
    listed = {p["id"]: p for p in items(s.ann.get(f"/tenants/{T1}/programs"))}
    assert set(listed) == {s.program_id, program_id}
    assert listed[program_id]["created_by"] == s.ann.get("/me").json()["user"]["id"]
    user = s.world.call(s.world.raw_repo.user, program_id)
    assert (user.kind, user.email, user.status, user.signin_account_id) == ("program", None, "active", None)
    [membership] = s.world.call(s.world.raw_repo.memberships_of_user, program_id)
    assert (str(membership.tenant_id), membership.status, membership.role) == (T1, "active", "automation")
    assert [(e.action, e.target) for e in audit.since(mark)] == [("program.create", program_id)]


def test_a_program_cannot_be_given_a_second_membership() -> None:
    """A program belongs to exactly one tenant; no invitation can address it (O4, D5)."""
    s = soar()
    before = s.world.call(s.world.raw_repo.memberships_of_user, s.program_id)
    with pytest.raises(DataRuleViolation):
        s.world.call(s.world.raw_repo.ensure_invitation, s.program_id, T2, invited_by=None,
                     now=s.world.clock())
    assert s.world.call(s.world.raw_repo.memberships_of_user, s.program_id) == before
