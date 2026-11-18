"""#767 — the investigation tail of the operator run (real `run.main`): it reaches neither the ticket seam's clear nor its
record (#1471 W7: the operator's `--update-ticket` is gone; the comment is the job lane's)."""
from __future__ import annotations

import dataclasses


import pytest

from defender import run as run_py
from defender.tests.support.sandbox._curation_store1278 import reach_store
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    drive_tail,
    plant_alert,
    satisfy_entrypoint_keys,
)

RECORD_STEP = "record_case_ticket"
#: The writer seam's second method (#1359 r4): run start clears an earlier attempt's receipt
#: through it, not through a module function.
CLEAR_STEP = "clear_receipt"


class Tail(SpecTail):
    """`_spec791`'s investigation-tail fake: the writer seam's two methods (`clear_receipt` is
    inherited, no open leg), the record leg keeping the tenant it was handed."""

    def record_case_ticket(self, run, *, tenant, defender_dir, env, **kw) -> None:
        self.ticket_tenants.append(tenant)
        self._note(RECORD_STEP, run.run_dir)


@pytest.fixture
def state(tmp_path, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """The tenant's learning paths over a scratch repo, a learning store holding the tenant active (the run end's curation
    request lands there, #1278), and a key per provider so the entrypoint's startup preflight cannot fail ahead of the
    tail under test."""
    from defender.learning.core.config import LoopPaths
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant

    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    tenant = set_up_tenant(current_data_root())
    reach_store(migrated_database, monkeypatch, tenant)
    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True)
    return dataclasses.replace(LoopPaths.for_tenant(tenant), repo_root=repo)


@pytest.mark.postgres
def test_767_an_operator_run_never_reaches_the_ticket_seam(tmp_path, state):
    """An operator run completes its tail (lifecycle, render) and reaches neither of the writer seam's methods: no
    clear, no record. #1471 W7 removed `--update-ticket`: the seam is accepted and ignored, and the ticket comment is the
    job lane's. A run that dies in its lifecycle records nothing either. The resume path's refusal of the removed switch
    is `test_947_resume_refuses_update_ticket`; the operator command's, `test_1471_w7_the_operator_command_refuses_...`."""
    tail = Tail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "operator"), tail) == 0
    for step in ("lifecycle", "visualize"):
        assert step in tail.names, (
            f"the operator run did not complete its tail at all (ran {tail.names})"
        )
    for step in (CLEAR_STEP, RECORD_STEP):
        assert step not in tail.names, (
            f"an operator run reached the ticket seam anyway (ran {tail.names})"
        )

    class Dying(Tail):
        def lifecycle(self, **kw):
            raise RuntimeError("the lifecycle died before the post-step")

    dying = Dying(state)
    with pytest.raises(RuntimeError):
        drive_tail(run_py.main, plant_alert(tmp_path / "dying"), dying)
    assert RECORD_STEP not in dying.names, "a run that never completed its lifecycle recorded anyway"
