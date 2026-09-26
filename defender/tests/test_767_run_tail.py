"""#767 — the investigation tail: when the run records, and when it does not.

Every test is one demand of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`,
named by that demand's `discharged_by`. The entry point driven is the REAL one — `run.py`'s
`main` — through the `ticket_writer=` injection seam `tests/_spec791.py` already established
(#791 R22, g10). Everything between the seams is production: the flag parse, the resume
refusal, the ordering against the curation marker, the queue itself.

§7 R11/FK09 SCOPES O4's WITNESS and both tests below read from it: the obligation is "a run
under the flag, store reachable, COMPLETING ITS LIFECYCLE, ending with no agent comment on its
ticket". No record-on-crash mechanism is built — that would need a `finally`/atexit hook
around the whole lifecycle that no D-row contemplates, plus new ordering risk against N1 — and
a run that dies before the post-step is an examined no (FK34: a killed run leaves an open,
uncommented ticket and nothing reconciles it).
"""
from __future__ import annotations

import pytest

from defender import run as run_py
from defender.tests._spec767 import (
    COMMENTS_SUFFIX,
    TICKETS_PATH,
    FakeStore,
    make_run,
    open_ticket,
    record,
    use_mapping,
)
from defender.tests._spec791 import (
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
    """`_spec791`'s investigation-tail fake, carrying D2's renamed writer method.

    Subclassed rather than edited in place: `_spec791.SpecTail` is #791's, and whether IT has
    been migrated off `close_case_ticket` is `test_767_record_case_ticket_is_the_writer_seam`'s
    own assertion (RF2 — a rename is silent at every duck-typed implementor of this seam, and
    the test that does not carry it keeps passing while the run's ticket step does nothing).
    `**kw` is #1047's exit-class pair, which the tail threads through and this suite does not
    interpret."""

    def record_case_ticket(self, run_dir, **kw) -> None:
        self._note(RECORD_STEP, run_dir)


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A learning state root and a runs base under tmp, and a key per provider so the
    entrypoint's startup preflight cannot fail ahead of the tail these demands are about."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    return loop_paths(tmp_path)


def test_767_run_under_flag_leaves_an_agent_comment(tmp_path, state, monkeypatch):
    """o4_run_under_flag_always_comments — a run under `--update-ticket` whose store is
    reachable and whose lifecycle COMPLETES ends with an agent comment on its ticket: the
    entrypoint reaches `record_case_ticket` over the run dir it materialized itself.

    §7 R6/FK32 pinned the INDEPENDENCE of the two post-steps as a specification rather than
    leaving it the accident of two independently-guarded calls: the record step is attempted
    whatever the open did. On the PLATFORM the ticket pre-exists (N4) so there is no open at
    all, and a short-circuit design would make the platform path unreachable — which is why
    the order here is observed as "open, then record, both reached" rather than as "record
    reached when open succeeded".

    THE THIRD PART MAKES THE OPEN FAIL, which is what turns that paragraph from a claim into
    an assertion. `run.py`'s tail seam is a fake writer, so no fault it can inject reaches a
    store; the independence is therefore driven one level down, at the writer's own
    `TicketWriterDeps` seam, over a store that answers 409 on the create (FK33's duplicate
    key, c8) and over one whose transport raises (FK32's unreachable bastion, c14). After
    each, the comment POST must still fire against the SAME key. Without this part an
    implementation spelled as "record only if the open succeeded" is green across the whole
    suite, and the platform path — the doc's own stated motive for keeping the write — is
    unreachable.

    §7 R11/FK09 scopes the witness: a run that does NOT complete its lifecycle reaches no
    post-step, and that is an examined no rather than a failure. The second half drives it."""
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
    """n7_writes_only_under_the_flag — `--update-ticket` remains the whole switch. It is
    declared `store_true` and default OFF, so a run without it reaches NEITHER post-step; and
    it is refused OUTRIGHT under `--resume`, before anything is spent (g5/r3: run.py carries
    THREE `if ns.update_ticket:` sites, and this demand's second observable lives at the first
    of them).

    REJECTED, and deliberately not asserted: making the flag the platform default is a later
    change (N7).

    The positive control is `test_767_run_under_flag_leaves_an_agent_comment` on the same
    seam — with the flag, both steps ARE reached — so "no write" here is not "the tail never
    ran". The inline control is the run's own completion: the lifecycle and the render step
    are reached either way."""
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

    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "resume-runs"))
    with pytest.raises(SystemExit) as refusal:
        run_py.main(["--resume", str(tmp_path / "family.yaml"), "--world", "b",
                     "--update-ticket"])
    assert "--update-ticket" in str(refusal.value), (
        "the resume path accepted the ticket flag: the two ticket calls are ordered around "
        "the curation marker, so accepting-and-ignoring breaks the pairing instead of the "
        "obligation"
    )


def test_767_record_runs_before_the_curation_marker(tmp_path, state):
    """n1_record_precedes_curation_marker — the #791/#947 ordering keeps its position across
    D2's rename: the case ticket is settled BEFORE the curation request is published, so the
    record step runs with no marker on the queue and the marker lands after it.

    REJECTED, and recorded rather than carried: the ordering's original rationale — "a drainer
    must never read this case with its ticket still open" — has NO READER at HEAD (c5: nothing
    reads a ticket's status, and the resolution lane D5 deletes was the only decoder). The
    ORDERING is kept; its reason is not. This demand exists so the rename cannot quietly move
    the call past the marker on the grounds that the reason evaporated.

    Driven through `_spec791`'s own tail recorder, whose every step carries the curation
    requests visible when it ran — so the ordering is an observation of a real run rather than
    a reading of `main`'s statement sequence."""
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
