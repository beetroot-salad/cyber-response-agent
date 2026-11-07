"""#1307: the audit names the program and the credential (O8) — sketch. "Request logs never contain the
Authorization header" has no request log to observe at this base (design gap, see the sketch report)."""
from __future__ import annotations

import logging

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import AUDIT_LOGGER, T1, user_id  # noqa: E402
from defender.tests.support.api._programs1307 import issue_key, revoke, soar, start_investigation  # noqa: E402


def test_a_programs_tenant_write_is_audited_as_the_program_with_the_credential() -> None:
    """Tenant audit: actor = program, credential id its own field; a person's write has none (O8, FC-8)."""
    s = soar()
    started = start_investigation(s.program(), T1)
    assert started.status_code == 201, started.text
    by_ann = start_investigation(s.ann, T1, "r-ann")  # live already: answered, nothing new audited
    assert by_ann.status_code in (200, 201)
    [event] = [e for e in s.world.store.audit_events if e.action == "investigation.start"]
    assert (event.user_id, event.credential_id, event.target) == (
        s.program_id, s.key_id, started.json()["investigation_id"])


def test_credential_issue_and_revoke_are_audited_with_actor_and_target(caplog) -> None:
    """Identity audit: issuing and revoking a credential name the admin and the credential (O8)."""
    caplog.set_level(logging.DEBUG, logger=AUDIT_LOGGER)
    s = soar()
    ann = user_id(s.ann)
    second, _ = issue_key(s.ann, T1, s.program_id, name="rotation")
    assert revoke(s.ann, T1, s.program_id, second).status_code == 204
    events = [(r.action, r.actor, str(r.tenant_id), str(r.target)) for r in caplog.records if r.name == AUDIT_LOGGER]
    assert ("program_credential.create", ann, T1, second) in events
    assert ("program_credential.revoke", ann, T1, second) in events

