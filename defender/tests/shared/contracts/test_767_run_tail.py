"""#767 — the investigation tail: when the run records its ticket comment, and when it does not (real `run.main`)."""
from __future__ import annotations

import dataclasses

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.records._episode_handle import Episode

import pytest

from defender import run as run_py
from defender.tests.support.runtime.engine._spec767 import (
    COMMENTS_SUFFIX,
    TENANT_ID,
    TICKETS_PATH,
    FakeStore,
    make_run,
    open_ticket,
    record,
    use_mapping,
)
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    author_markers,
    drive_tail,
    plant_alert,
    satisfy_entrypoint_keys,
)

RECORD_STEP = "record_case_ticket"
OPEN_STEP = "open_case_ticket"


class Tail(SpecTail):
    """`_spec791`'s investigation-tail fake, with the `record_case_ticket` writer method."""

    def record_case_ticket(self, run, *, tenant, defender_dir, env, **kw) -> None:
        self.ticket_tenants.append(tenant)
        self._note(RECORD_STEP, run.run_dir)


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A learning state root and a runs base under tmp, and a key per provider so the
    entrypoint's startup preflight cannot fail ahead of the tail under test."""
    from defender.learning.core.config import LoopPaths
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant

    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    tenant = set_up_tenant(current_data_root())
    location_path(tenant.learning).mkdir(exist_ok=True)
    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True)
    return dataclasses.replace(LoopPaths.for_tenant(tenant), repo_root=repo)


def test_767_run_under_flag_leaves_an_agent_comment(tmp_path, state, monkeypatch):
    """Under `--update-ticket`, a run whose lifecycle COMPLETES records into its ticket after the
    lifecycle, one that dies does not, and a failed open does not suppress the record."""
    tail = Tail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "flagged"), tail, "--update-ticket") == 0
    assert RECORD_STEP in tail.names, (
        f"a completing run under the flag never recorded into its case (ran {tail.names})")
    assert tail.names.index(OPEN_STEP) < tail.names.index("lifecycle") < tail.names.index(
        RECORD_STEP
    ), (
        f"the tail did not reach the record step after a completed lifecycle (ran {tail.names})"
    )
    assert tail.run_dirs, "main never drove the injected lifecycle"
    assert tail.step(RECORD_STEP).tree_certified, (
        "the record step read the run dir BEFORE the lifecycle certified it"
    )

    class Dying(Tail):
        def lifecycle(self, **kw):
            raise RuntimeError("the lifecycle died before the post-step")

    dying = Dying(state)
    with pytest.raises(RuntimeError):
        drive_tail(run_py.main, plant_alert(tmp_path / "dying"), dying, "--update-ticket")
    assert RECORD_STEP not in dying.names, "a run that never completed its lifecycle recorded anyway"

    # A failed open does not suppress the record attempt.
    use_mapping(monkeypatch, tmp_path / "dfn")
    for arm, (why, store) in enumerate((
        ("a 409 on the create (the key already exists)",
         FakeStore(status_by_suffix={TICKETS_PATH: "409"})),
        ("a raising transport (the bastion is unreachable)",
         FakeStore(transport_fault_on=TICKETS_PATH)),
    )):
        run_dir = make_run(tmp_path / f"open-failed-{arm}")
        try:
            open_ticket(run_dir, store)
        except Exception as exc:  # noqa: BLE001 — the open's own fate belongs to O7, not here
            pytest.fail(f"the open raised out of the writer on {why}: {exc!r}")
        record(run_dir, store)

        opened = [c.body for c in store.calls if c.path == TICKETS_PATH]
        assert [b.get("key") if isinstance(b, dict) else b for b in opened] == [
            run_dir.name
        ], f"the open was never attempted at all on {why}, so nothing here is a failed open"
        assert store.paths(COMMENTS_SUFFIX) == [
            f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}"
        ], f"a failed open suppressed the record step on {why} (the writer's calls: {store.paths()})"


def test_767_no_store_write_without_the_flag(tmp_path, state, monkeypatch):
    """`--update-ticket` is the whole switch: without it nothing reaches the ticket store, and
    the resume path refuses the flag."""
    assert run_py.parse_args(["/tmp/alert.json", "--tenant", TENANT_ID]).update_ticket is False, (
        "the ticket flag is no longer opt-in"
    )

    tail = Tail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "unflagged"), tail) == 0
    for step in ("lifecycle", "visualize"):
        assert step in tail.names, (
            f"the unflagged run did not complete its tail at all (ran {tail.names})"
        )
    for step in (OPEN_STEP, RECORD_STEP):
        assert step not in tail.names, (
            f"a run without --update-ticket reached the estate anyway (ran {tail.names})"
        )

    # A sibling resume names its episode by id; its container exists before any sibling runs.
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    episode_id = fixture_uuid("767-run-tail-resume")
    ep = T.episode(tmp_path, episode_id=episode_id,
                   doc={**T.family_doc(), "episode_id": episode_id})
    with Episode.open(ep) as held:
        T.episode_view(held).close()
    with pytest.raises(SystemExit) as refusal:
        run_py.main(["--episode", episode_id, "--world", "b",
                     "--tenant", ep.parent.parent.name, "--update-ticket"])
    assert "--update-ticket" in str(refusal.value), "the resume path accepted the ticket flag"


def test_767_record_runs_before_the_curation_marker(tmp_path, state):
    """The record step runs before the curation marker is queued, and before the render."""
    tail = Tail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "ordered"), tail, "--update-ticket") == 0

    assert tail.step(RECORD_STEP).curation_requests == (), (
        "the curation request was already on the queue when the ticket was recorded — a "
        "drainer can start the moment the marker lands"
    )
    assert author_markers(state), (
        "no curation request was written at all, so the ordering assertion above proves "
        "nothing about where the record step sits"
    )
    assert tail.names.index(RECORD_STEP) < tail.names.index("visualize"), (
        f"the record step no longer precedes the render step (ran {tail.names})"
    )
