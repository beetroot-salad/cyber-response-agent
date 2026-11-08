"""#1307: the audit names the program and the credential, and the new identity events (O8, D6). "The Authorization
header is never logged" has no request logger to observe at this base (W3): not a test obligation."""
from __future__ import annotations

import datetime as _dt

import pytest

from defender.api.fakes import AuditEvent

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import T1, AuditLog, user_id  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    CLIENT_DELETE,
    CREDENTIAL_CREATE,
    CREDENTIAL_REVOKE,
    DAY,
    DEFAULT_LIFETIME,
    PROGRAM_CREATE,
    PROGRAM_REMOVE,
    Client,
    Soar,
    create_program,
    issue,
    issue_key,
    issue_oauth,
    revoke,
    soar,
    start_investigation,
)

SYSTEM = "system"
ORPHAN = "6d3c1f0e-0000-4000-8000-0000000000aa"


def _store_events(s: Soar, user: str) -> list[AuditEvent]:
    return [e for e in s.world.store.audit_events if e.user_id == user]


# --- tenant writes ------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["key", "oauth_client"])
def test_a_programs_tenant_write_names_the_program_and_the_credential_used(kind: str) -> None:
    """Actor = program, credential id its own field (the OAuth credential, not the token); a person's write has none (O8, D6)."""
    s = soar()
    if kind == "key":
        client, credential = s.program(), s.key_id
    else:
        credential = issue_oauth(s.ann, T1, s.program_id)
        client = s.world.bearer(s.world.realm.issue(credential))
    started = start_investigation(client, T1)
    assert started.status_code == 201, started.text
    by_ann = start_investigation(s.ann, T1, "r-ann")  # the in-memory store always creates: a second, separate event
    assert by_ann.status_code in (200, 201)
    [by_program] = [e for e in _store_events(s, s.program_id) if e.action == "investigation.start"]
    assert (by_program.credential_id, by_program.target) == (credential, started.json()["investigation_id"])
    [by_person] = [e for e in _store_events(s, user_id(s.ann)) if e.action == "investigation.start"]
    assert by_person.credential_id is None


def test_each_write_names_the_credential_it_came_in_on_not_the_programs_other_one() -> None:
    """Two live credentials of one program: events carry the one used; cancel is audited the same way (O8, D6)."""
    s = soar()
    second_id, second = issue_key(s.ann, T1, s.program_id, name="second")
    first_run = start_investigation(s.program(), T1, "r1")
    second_run = start_investigation(s.world.bearer(second), T1, "r2")
    cancelled = s.world.bearer(second).post(f"/tenants/{T1}/investigations/{first_run.json()['investigation_id']}/cancel")
    assert cancelled.status_code in (200, 202, 204), cancelled.text
    seen = [(e.action, e.target, e.credential_id) for e in _store_events(s, s.program_id)]
    assert seen == [
        ("investigation.start", first_run.json()["investigation_id"], s.key_id),
        ("investigation.start", second_run.json()["investigation_id"], second_id),
        ("investigation.cancel", first_run.json()["investigation_id"], second_id),
    ]


# --- identity events -----------------------------------------------------------------------------------

def test_creating_and_removing_programs_and_credentials_is_audited_with_actor_target_and_tenant(caplog) -> None:
    """program.create / program_credential.create / .revoke name the admin; removal emits a revoke for each credential
    it revoked, then program.remove, as offboarding does (O8, D6; #1450 review: one record for both ways out)."""
    audit = AuditLog(caplog)
    s = soar()
    ann = user_id(s.ann)
    mark = audit.mark()
    program = str(create_program(s.ann, T1, "Ticket sync")["id"])
    key, _ = issue_key(s.ann, T1, program, name="rotation")
    oauth = issue_oauth(s.ann, T1, program)
    assert revoke(s.ann, T1, program, key).status_code == 204
    assert s.ann.delete(f"/tenants/{T1}/programs/{program}").status_code == 204
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)] == [
        (PROGRAM_CREATE, ann, T1, program),
        (CREDENTIAL_CREATE, ann, T1, key),
        (CREDENTIAL_CREATE, ann, T1, oauth),
        (CREDENTIAL_REVOKE, ann, T1, key),
        (CREDENTIAL_REVOKE, ann, T1, oauth),  # revoked by the removal; `key` was already revoked, so not again
        (PROGRAM_REMOVE, ann, T1, program),
    ]


@pytest.mark.parametrize("failure", ["fail_creates", "lose_create_responses"])
def test_an_oauth_creation_that_ends_in_503_emits_no_create_event_until_it_is_usable(failure: str, caplog) -> None:
    """program_credential.create is emitted when the credential becomes usable: a 503 leaves none; a later success emits one (W5)."""
    audit = AuditLog(caplog)
    s = soar()
    setattr(s.world.realm, failure, 1)
    mark = audit.mark()
    assert issue(s.ann, T1, s.program_id, kind="oauth_client").status_code == 503
    assert CREDENTIAL_CREATE not in audit.actions(mark)
    s.world.clock.advance(_dt.timedelta(minutes=11))  # the stuck row's deadline: its slot is free again
    oauth = issue_oauth(s.ann, T1, s.program_id)
    created = [e for e in audit.since(mark) if e.action == CREDENTIAL_CREATE]
    assert [(e.target, e.tenant_id) for e in created] == [(oauth, T1)]


def test_a_refused_credential_creates_no_event_and_a_program_is_never_an_identity_actor(caplog) -> None:
    """Refusals (cap) audit nothing; a program's requests never appear as an identity actor (O8)."""
    audit = AuditLog(caplog)
    s = soar()
    issue_oauth(s.ann, T1, s.program_id)
    mark = audit.mark()
    assert issue(s.ann, T1, s.program_id, name="third").status_code == 409
    assert start_investigation(s.program(), T1).status_code == 201  # control: the program is active
    assert audit.since(mark) == []
    assert s.program_id not in {e.actor for e in audit.events()}


# --- system actors and client deletion ------------------------------------------------------------------

def test_a_stale_pending_credential_is_revoked_by_the_system_after_its_deadline(caplog) -> None:
    """The reconciliation's revoke of a stuck `pending` row is actor `system`; its client deletion follows (O8, D6)."""
    audit = AuditLog(caplog)
    s = soar()
    s.world.realm.lose_create_responses = 1
    assert issue(s.ann, T1, s.program_id, kind="oauth_client").status_code == 503
    [lost] = s.world.realm.created
    mark = audit.mark()
    s.world.call(s.world.service.reconcile_program_clients)
    assert audit.since(mark) == []  # inside the deadline
    s.world.clock.advance(_dt.timedelta(minutes=11))
    s.world.call(s.world.service.reconcile_program_clients)
    assert sorted((e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)) == sorted([
        (CREDENTIAL_REVOKE, SYSTEM, T1, lost), (CLIENT_DELETE, SYSTEM, T1, lost)])


def test_offboarding_revokes_each_programs_credentials_as_the_system(caplog) -> None:
    """`end_tenant` revokes program credentials with actor `system`; nothing is audited as a client deletion yet (O6, O8, D6)."""
    audit = AuditLog(caplog)
    s = soar()
    oauth = issue_oauth(s.ann, T1, s.program_id)
    mark = audit.mark()
    s.world.call(s.world.lifecycle_service().end_tenant, T1, now=s.world.clock())
    revokes = [(e.actor, e.tenant_id, e.target) for e in audit.since(mark) if e.action == CREDENTIAL_REVOKE]
    assert sorted(revokes) == sorted([(SYSTEM, T1, s.key_id), (SYSTEM, T1, oauth)])
    assert CLIENT_DELETE not in audit.actions(mark)


def test_a_client_deletion_is_audited_as_the_system_with_the_tenant_when_a_row_exists(caplog) -> None:
    """program_client.delete: actor system, tenant from the credential row, none for a client without a row (O8, D6)."""
    audit = AuditLog(caplog)
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    assert revoke(s.ann, T1, s.program_id, credential).status_code == 204
    s.world.realm.clients[ORPHAN] = Client(ORPHAN, "00000000-5a00-4000-8000-0000000000bb", "s")
    mark = audit.mark()
    s.world.call(s.world.service.reconcile_program_clients)
    assert sorted(((e.action, e.actor, e.tenant_id, e.target) for e in audit.since(mark)), key=repr) == sorted(
        [(CLIENT_DELETE, SYSTEM, T1, credential), (CLIENT_DELETE, SYSTEM, None, ORPHAN)], key=repr)
    mark = audit.mark()
    s.world.call(s.world.service.reconcile_program_clients)
    assert audit.since(mark) == []  # nothing left to delete: nothing to audit


def test_a_keys_expiry_writes_nothing_but_an_oauth_clients_cleanup_is_audited(caplog) -> None:
    """Expiry is computed, never an event; the later client deletion is the audited act (O8, W4)."""
    audit = AuditLog(caplog)
    s = soar()
    oauth = issue_oauth(s.ann, T1, s.program_id, expires_at=s.world.clock() + DEFAULT_LIFETIME)
    mark = audit.mark()
    s.world.clock.advance(DEFAULT_LIFETIME + DAY)
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 401  # the key has expired
    s.world.send_pending()
    assert audit.since(mark) == []
    s.world.call(s.world.service.reconcile_program_clients)
    assert [(e.action, e.actor, e.target) for e in audit.since(mark)] == [(CLIENT_DELETE, SYSTEM, oauth)]
