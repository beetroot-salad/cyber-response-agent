"""#767 — the investigation tail: when the run records its ticket comment, and when it does not (real `run.main`)."""
from __future__ import annotations

import pytest

from defender import run as run_py
from defender.tests.support.runtime.engine._spec767 import (
    COMMENTS_SUFFIX,
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
    loop_paths,
    plant_alert,
    satisfy_entrypoint_keys,
)

RECORD_STEP = "record_case_ticket"
OPEN_STEP = "open_case_ticket"


class Tail(SpecTail):
    """`_spec791`'s investigation-tail fake, carrying D2's renamed writer method."""

    def record_case_ticket(self, run, *, tenant, defender_dir, env, **kw) -> None:
        self.ticket_tenants.append(tenant)
        self._note(RECORD_STEP, run.run_dir)


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A learning state root and a runs base under tmp, and a key per provider so the
    entrypoint's startup preflight cannot fail ahead of the tail these demands are about."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    return loop_paths(tmp_path)


def test_767_run_under_flag_leaves_an_agent_comment(tmp_path, state, monkeypatch):
    """o4_run_under_flag_always_comments — a run under `--update-ticket` whose store is
    reachable and whose lifecycle COMPLETES ends with an agent comment on its ticket."""
    tail = Tail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "flagged"), tail, "--update-ticket") == 0
    assert RECORD_STEP in tail.names, (
        f"a completing run under the flag never recorded into its case (ran {tail.names}) — "
        "D2 renames the post-step, and a run still calling `close_case_ticket` leaves the "
        "case with no agent comment on it, which is O4's own failure witness"
    )
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
    assert RECORD_STEP not in dying.names, (
        "a run that never completed its lifecycle recorded anyway: §7 R11 declined to build "
        "record-on-crash, so reaching the store here would be mechanism no D-row names"
    )

    # §7 R6 — a failed open does not suppress the record attempt (FK32/FK33).
    use_mapping(monkeypatch, tmp_path / "dfn")
    for arm, (why, store) in enumerate((
        ("a 409 on the create (FK33: the key already exists, c8)",
         FakeStore(status_by_suffix={TICKETS_PATH: "409"})),
        ("a raising transport (FK32: the bastion is unreachable, c14)",
         FakeStore(transport_fault_on=TICKETS_PATH)),
    )):
        run_dir = make_run(tmp_path / f"open-failed-{arm}")
        try:
            open_ticket(run_dir, store)
        except Exception as exc:  # noqa: BLE001 — the open's own fate belongs to O7, not here
            pytest.fail(
                f"the open raised out of the writer on {why}: O7 catches every write fault, "
                f"warns once and leaves the run's exit code untouched ({exc!r})"
            )
        record(run_dir, store)

        opened = [c.body for c in store.calls if c.path == TICKETS_PATH]
        assert [b.get("key") if isinstance(b, dict) else b for b in opened] == [
            run_dir.name
        ], f"the open was never attempted at all on {why}, so nothing here is a failed open"
        assert store.paths(COMMENTS_SUFFIX) == [
            f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}"
        ], (
            f"a failed open suppressed the record step on {why} (the writer's whole path was "
            f"{store.paths()}). §7 R6 pins the two post-steps as independent statements under "
            f"one flag, not `if the open worked: record`; the record proceeds against the "
            f"existing key, which on the platform is the only case there is"
        )


def test_767_no_store_write_without_the_flag(tmp_path, state, monkeypatch):
    """n7_writes_only_under_the_flag — `--update-ticket` remains the whole switch."""
    assert run_py.parse_args(["/tmp/alert.json", "--tenant", "playground"]).update_ticket is False, (
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

    # #1105 PR 2 (declared change 6): a sibling names its episode by id under the configured
    # episodes base, whose container the launcher made for its tenant before any sibling.
    from defender import _tenant

    episodes = tmp_path / "episodes-root"
    (episodes / "ep-767" / "runs").mkdir(parents=True)
    _tenant.ensure_runs_base_record(episodes / "ep-767" / "runs", "playground")
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(episodes))
    with pytest.raises(SystemExit) as refusal:
        run_py.main(["--episode", "ep-767", "--world", "b",
                     "--tenant", "playground", "--update-ticket"])
    assert "--update-ticket" in str(refusal.value), (
        "the resume path accepted the ticket flag: the two ticket calls are ordered around "
        "the curation marker, so accepting-and-ignoring breaks the pairing instead of the "
        "obligation"
    )


def test_767_record_runs_before_the_curation_marker(tmp_path, state):
    """n1_record_precedes_curation_marker — the #791/#947 ordering keeps its position across
    D2's rename."""
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
