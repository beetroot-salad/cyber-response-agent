"""#791 part 3 — catalog curation gets its own trigger at the investigation boundary.

Every test here is one demand of `defender/tests/spec_graph_791-retire-offline-oracle.yaml`,
named by that demand's `discharged_by`. RED against HEAD is the expected state: the shared
refusal predicate and the curation enqueue are COINED — neither symbol exists, because R3
makes the extraction a prerequisite for the trigger. If the implementation spells them
otherwise, these names follow the code.

WHY THE TRIGGER MOVES AT ALL: the queue the design called shared has ONE reader (S4, refuted).
Curation was reachable only downstream of the learning enqueue, so cutting that link silences
the lane completely — and totally, not eventually: its only other trigger is written from
inside its own run, so it drains its backlog once and goes quiet (C9).

WHY "CARRY THE FOUR REFUSALS" IS THE WRONG INSTRUCTION (PR1/PR2): all three run-dir refusals
are welded INSIDE the learn-enqueue helper as early returns, and that helper signals "not
refused" BY PERFORMING THE ENQUEUE — asking it whether a run would be refused enqueues the
run. And the held-out net at the boundary is PATH CONTAINMENT on the operator's argv path,
while the one that actually guards curation today is a CONTENT DIGEST over the run's own alert
copy. Only the second catches a copy, which is how the refusal is worded; carrying the
boundary's four forward literally drops it out of the curation path with nothing going red.

WHY main's TAIL IS DRIVEN AND NO LONGER READ (R22): the entrypoint now takes its three
undrivable dependencies — the credentialed investigation lifecycle, the HTML render, the case
ticket endpoint — through an injection seam, so "the tail asks for curation", "the trigger is
handed the operator's flag", "curation is sited above the render step" and both ordering cells
are observations of a real run. The refusal predicate, the curation write and the queue itself
are NOT injected: they are what these demands are about, so they run for real.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

from defender import run as run_py  # noqa: E402
from defender import run_common  # noqa: E402
from defender.learning.core import drains  # noqa: E402
from defender.runtime import scrub as scrub_mod  # noqa: E402
from defender.tests._spec791 import (  # noqa: E402
    RUN_COMMON_PY,
    SCRUB_PROPERTY_TEST,
    TAIL_SEAM,
    SpecBranch,
    SpecTail,
    author_markers,
    call_order,
    drive_tail,
    fn_node,
    loop_paths,
    make_run_dir,
    marker_body,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
    plant_alert,
    require_tail_seam,
    satisfy_entrypoint_keys,
)

SCRUB_PROPERTY_DEMAND = "test_scrub_runs_before_the_first_run_dir_consumer"
HELD_OUT_ALERT = json.dumps({"rule": {"id": "9999"}, "held": "out"}).encode("utf-8")


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A learning state root and a runs base under tmp, and a key per provider so the
    entrypoint's startup preflight cannot fail ahead of the tail these demands are about."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    return loop_paths(tmp_path)


def _certified_run(tmp_path, *, name="case-791", alert_bytes=None) -> Path:
    run_dir = make_run_dir(tmp_path, name=name, disposition="benign", alert_bytes=alert_bytes)
    scrub_mod.scrub(run_dir)
    return run_dir


def _held_out_set(tmp_path, alert_bytes: bytes) -> Path:
    """A held-out fixture set with one real member, planted because the shipped corpus holds a
    single README: its digest set is EMPTY, so the content-keyed net refuses nothing and a test
    that leans on the shipped set asserts nothing at all (PR2b)."""
    fixtures = tmp_path / "held-out"
    member = fixtures / "m01-planted"
    member.mkdir(parents=True)
    (member / "alert.json").write_bytes(alert_bytes)
    return fixtures


def test_791_the_investigation_tail_takes_its_dependencies_through_a_seam(tmp_path, state):
    """investigation_tail_has_an_injection_seam — the investigation entrypoint takes the three
    tail dependencies a hermetic test cannot drive through an injection seam, each defaulting
    to production, so what the tail DOES is observable rather than readable.

    This is R22, and it is a demand rather than test scaffolding for the same reason #741's
    lifecycle seam was: without it, five demands about the tail — that it writes no learn
    marker, that the trigger is handed the operator's flag, that curation sits above the
    render step, and both consumer-ordering cells — can only be read off `main`'s statement
    sequence. A test that reads source cannot fail when the behaviour changes, which is the
    failure this whole flow exists to prevent, and the exit-status half of R4's isolation has
    no source form at all.

    The seam covers exactly what cannot be driven: the credentialed investigation lifecycle,
    the HTML render, the case-ticket endpoint. The curation trigger is deliberately NOT
    injectable — it is what the demands are about, so it runs for real against a real queue.

    Observable: every dependency carries a production default, and a run driven with fakes
    reaches all three, over the run dir the entrypoint itself materialized."""
    require_tail_seam(run_py.main)
    params = inspect.signature(run_py.main).parameters
    for name in TAIL_SEAM:
        assert params[name].default is not inspect.Parameter.empty, (
            f"main's {name} seam has no production default — every existing caller, the "
            "entrypoint's own `__main__` included, now has to supply one"
        )
    assert "enqueue_curation" not in params, (
        "the curation trigger is injectable, so every demand about the trigger can be "
        "satisfied by a double instead of by the queue"
    )

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "seam"), tail, "--update-ticket") == 0
    assert tail.run_dirs, "main never drove the injected lifecycle"
    run_dir = tail.run_dirs[0]
    assert run_dir.is_dir(), "the lifecycle was handed a run dir that does not exist"
    assert (run_dir / "alert.json").is_file(), \
        "the lifecycle was handed a run dir the entrypoint had not materialized the alert into"
    for step in ("open_case_ticket", "lifecycle", "close_case_ticket", "visualize"):
        assert step in tail.names, f"the tail never reached {step} (ran {tail.names})"


def test_791_finished_investigation_drives_catalog_curation(tmp_path, state):
    """curation_trigger_at_the_investigation_boundary — a finished investigation asks for
    catalog curation at its own boundary, and the lane that serves the request RUNS.

    The second half is what the brief's F3 forces. The lead-author lane's only other trigger is
    a pending-pitfalls threshold written from inside its own run, so "a threshold could still
    fire" is not evidence the lane is alive — the lane has to be observed consuming the
    request. The placement is cheap because the marker is byte-identical to today's and the
    lane already consumes the INVESTIGATION run dir, not the learning one (E9/PR5)."""
    run_dir = _certified_run(tmp_path)
    assert run_common.enqueue_curation(run_dir, run_dir / "alert.json") is True

    assert author_markers(state), "the investigation boundary asked for no curation"

    served: list[Path] = []
    branch = SpecBranch(tmp_path / "worktrees")
    rc = drains.lead_author_drain(
        state,
        run_lead_author=lambda _paths, rd, *, box=None: served.append(rd),
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=branch, start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert rc == 0
    assert served == [run_dir.resolve()], \
        f"the curation lane never ran over the investigation's run dir (saw {served})"
    assert author_markers(state) == [], "the served request was left on the queue"


def test_791_the_curation_marker_names_the_case_and_the_run_dir(tmp_path, state):
    """curation_marker_shape — the curation request names the CASE it speaks for and carries a
    resolvable investigation run directory.

    Both parts are load-bearing and R4's accepted cost is exactly that they come apart: keying
    on the case means the request's identity no longer determines the run dir it points at. The
    run dir must still be carried and must still resolve, because it is the only thing the
    drain hands the curator."""
    run_dir = _certified_run(tmp_path)
    run_common.enqueue_curation(run_dir, run_dir / "alert.json")

    markers = sorted(state.author_queue_dir.glob("*.json"))
    assert len(markers) == 1
    body = marker_body(markers[0])

    assert body.get("case_id"), f"the curation request names no case: {body}"
    assert body.get("run_dir"), f"the curation request carries no run dir: {body}"
    assert Path(body["run_dir"]).is_dir(), "the run dir the drain would hand the curator is gone"
    assert Path(body["run_dir"]).resolve() == run_dir.resolve()


def test_791_a_retried_investigation_coalesces_onto_one_curation_request(tmp_path, state):
    """curation_request_is_keyed_on_the_case — two investigations of ONE case leave exactly one
    curation request, and it points at the later run.

    Bound at the composition frame, because a single-investigation test cannot see the
    collision: a retry mints a new run id, and today identity is the marker's FILE NAME derived
    from the run dir's name while the run id field inside is never read for it (P3), so two run
    ids for one case drive two curations. Accepted cost, recorded: a legitimate later
    re-investigation of the same case needs its own way to ask."""
    alert = json.dumps({"rule": {"id": "5710"}, "case": "one-and-the-same"}).encode("utf-8")
    first = _certified_run(tmp_path, name="run-A", alert_bytes=alert)
    second = _certified_run(tmp_path, name="run-B", alert_bytes=alert)

    run_common.enqueue_curation(first, first / "alert.json")
    run_common.enqueue_curation(second, second / "alert.json")

    markers = sorted(state.author_queue_dir.glob("*.json"))
    assert len(markers) == 1, \
        f"a retry added a second curation request instead of coalescing: {[m.name for m in markers]}"
    body = marker_body(markers[0])
    assert Path(body["run_dir"]).resolve() == second.resolve(), \
        "the coalesced request still points at the run the retry replaced"


def test_791_a_curation_re_ask_issued_mid_drain_is_not_destroyed(tmp_path, state):
    """curation_claim_and_serve_is_atomic — a curation request that arrives while the lane is
    already curating that case survives: the drain does not delete a marker whose contents it
    never read, so the second investigation's findings still reach the catalog.

    This is the composition of two facts each recorded on its own and never together. The lane
    reads a marker at the top of its pass and unlinks it BY PATH at the bottom (P2), and R4
    makes both requests of one case land on that one path. Today identity is the run dir's
    name, so a re-investigation writes a different marker and survives as a duplicate; keyed on
    the case it lands on the path the serving drain is about to remove.

    The loss is invisible by construction: the request count is right, the lane reports
    success, and nothing anywhere records that a re-ask existed. Either the claim is atomic —
    the marker is taken out of the queue before it is served — or the unlink must be of the
    contents that were read.

    Driven the way the probe that refuted the queue's idempotence was driven: the re-ask is
    issued from inside the serve, which is the only window in which it can be destroyed."""
    alert = json.dumps({"rule": {"id": "5710"}, "case": "one-and-the-same"}).encode("utf-8")
    first = _certified_run(tmp_path, name="run-A", alert_bytes=alert)
    second = _certified_run(tmp_path, name="run-B", alert_bytes=alert)
    run_common.enqueue_curation(first, first / "alert.json")

    served: list[Path] = []

    def serve_and_re_ask(_paths, run_dir, *, box=None):
        served.append(run_dir)
        if len(served) == 1:
            # The operator re-investigates the case while the lane is curating it.
            run_common.enqueue_curation(second, second / "alert.json")

    def drain() -> None:
        drains.lead_author_drain(
            state, run_lead_author=serve_and_re_ask, run_pitfalls=lambda *_a, **_kw: 0,
            branch=SpecBranch(tmp_path / "worktrees"),
            start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
        )

    drain()
    assert served[:1] == [first.resolve()], f"the first pass served {served}, not the queued run"
    drain()
    assert served == [first.resolve(), second.resolve()], (
        "the re-ask issued while the lane was curating this case was destroyed: the drain "
        f"unlinked a marker it never read, and the served set is {served}"
    )
    assert author_markers(state) == [], "the served re-ask was left on the queue"


def test_791_a_failed_curation_write_costs_the_investigation_nothing(tmp_path, state):
    """curation_write_is_isolated — a curation request that cannot be written costs the
    investigation nothing: the helper reports the failure rather than raising it, the run's
    EXIT STATUS is unchanged, and the tail steps sited after it still run.

    The old trigger sat inside the learning run cycle. The new one sits in the investigation's
    own tail, behind the step that certifies the tree and AHEAD of the steps that render the
    run for a human — so it is newly able to cost the investigation its human-facing output.
    Curation is an optimisation over a corpus; an investigation that produced a verdict has
    already delivered its value.

    The exit-status half is what R4's words actually say and what a helper-level assertion
    cannot reach: an entrypoint written as `if not enqueue_curation(...): return 1` returns a
    failure for a corpus optimisation, and passes every assertion about the helper. It is
    observable only by driving the entrypoint, which is what R22's seam is for.

    The write is broken by putting a FILE where the queue directory must be — a real fault
    through the real primitive, and one that this container's uid cannot ignore the way it
    ignores a permission bit."""
    run_dir = _certified_run(tmp_path)
    state.author_queue_dir.parent.mkdir(parents=True, exist_ok=True)
    state.author_queue_dir.write_text("not a directory\n", encoding="utf-8")

    assert run_common.enqueue_curation(run_dir, run_dir / "alert.json") is False, \
        "a failed curation write did not report itself"

    broken = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "broken"), broken) == 0, \
        "a curation request that could not be written changed the investigation's exit status"
    assert "visualize" in broken.names, \
        "the failed curation write took the render step with it — the investigation lost its " \
        "human-facing output to an optimisation over a corpus"

    state.author_queue_dir.unlink()
    working = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "working"), working) == 0
    assert working.step("visualize").curation_requests, \
        "the render step ran BEFORE the curation request existed: the trigger is sited below " \
        "the render, so its failure can no longer be the last word"


def test_791_both_enqueues_consult_the_same_refusal_predicate(tmp_path, state):
    """refusals_have_one_owner_across_both_enqueues — the learning enqueue and the curation
    enqueue consult ONE refusal predicate, so the corpus protection cannot diverge from the
    thing that documents it.

    A copied guard drifts; a shared predicate cannot. This is the load-bearing demand of the
    spec (PR5: every protection the committed catalog has is upstream at the enqueue — today at
    two, after the change at one).

    OWNERSHIP IS PINNED STRUCTURALLY, not by behaviour, because R3's words are "extract a shared
    predicate, NOT A COPY". Two hand-copied guards behave identically on the day they are
    written and drift from each other afterwards — the precise failure the resolution names —
    so a matrix of matching outcomes is satisfied by exactly the implementation it rejects.
    Both enqueue bodies must CALL the one predicate, and that is the first assertion below.

    The per-condition matrix stays as the second half: three refusals across two enqueues, plus
    the control that both enqueue a clean run — proof the shared owner is consulted for its
    answer rather than merely called."""
    for enqueue in ("enqueue_learning", "enqueue_curation"):
        called = call_order(RUN_COMMON_PY, enqueue)
        assert "learning_refusal_gate" in called, (
            f"{enqueue} does not call the shared refusal predicate (it calls {called}) — its "
            "guards are a copy, and a copy is what R3 rejected"
        )

    fixtures = _held_out_set(tmp_path, HELD_OUT_ALERT)
    clean = _certified_run(tmp_path, name="clean")
    held_out = _certified_run(tmp_path, name="held-out-copy", alert_bytes=HELD_OUT_ALERT)
    unverified = make_run_dir(tmp_path, name="unverified", disposition="benign")

    conditions = {
        "truncated": (clean, {"truncated_by": "budget"}),
        "held-out-alert-copy": (held_out, {}),
        "unverified-tree": (unverified, {}),
    }
    for label, (run_dir, kw) in conditions.items():
        reason = run_common.learning_refusal_gate(
            run_dir, run_dir / "alert.json", fixtures_dir=fixtures, **kw
        )
        assert reason, f"{label}: the shared predicate refuses nothing"
        for enqueue in (run_common.enqueue_learning, run_common.enqueue_curation):
            assert enqueue(run_dir, run_dir / "alert.json", fixtures_dir=fixtures, **kw) is False, \
                f"{label}: {enqueue.__name__} does not honour the shared predicate"

    assert run_common.learning_refusal_gate(
        clean, clean / "alert.json", fixtures_dir=fixtures
    ) is None, "the predicate refuses a clean run — the refusals above carry no information"
    for enqueue in (run_common.enqueue_learning, run_common.enqueue_curation):
        assert enqueue(clean, clean / "alert.json", fixtures_dir=fixtures) is True, \
            f"{enqueue.__name__} refuses a run nothing should refuse"


def test_791_curation_refuses_a_held_out_alert_copy_by_content(tmp_path, state):
    """curation_refuses_the_copy_keyed_held_out_alert — curation refuses a run whose own alert
    is a COPY of a held-out fixture, keyed on content rather than on where the operator's
    argument pointed.

    This is R3's sharpening and the whole reason "carry the four refusals" is the wrong
    instruction. The boundary's held-out net is path containment on the operator's argv path;
    on a copy taken outside the fixtures directory it MISSES, and only the digest catches —
    which is exactly how the refusal is worded. Both halves are asserted here, because the
    demand is that the RIGHT net is the one carried, not merely that something refused.

    The fixture set is planted rather than read: the shipped corpus holds one README, so its
    digest set is empty and the net that is semantically right is the one currently doing
    nothing (PR2b). A test leaning on the shipped set asserts nothing."""
    fixtures = _held_out_set(tmp_path, HELD_OUT_ALERT)
    copied = _certified_run(tmp_path, name="scored-alert", alert_bytes=HELD_OUT_ALERT)
    alert = copied / "alert.json"

    assert run_common.is_held_out_fixture(alert, fixtures) is False, \
        "the run's own alert copy is inside the fixtures dir — the path net would catch it " \
        "here and this test would not be about the digest at all"
    assert run_common.is_held_out_alert_copy(alert, fixtures) is True

    assert run_common.enqueue_curation(copied, alert, fixtures_dir=fixtures) is False
    assert author_markers(state) == [], "a held-out alert copy reached the committed catalog"

    ordinary = _certified_run(tmp_path, name="ordinary")
    assert run_common.enqueue_curation(
        ordinary, ordinary / "alert.json", fixtures_dir=fixtures
    ) is True, "the net starves curation of ordinary runs"


def test_791_no_learn_suppresses_curation_too(tmp_path, state):
    """curation_honours_no_learn — the operator's `--no-learn` suppresses catalog curation as
    well as learning.

    Fail-closed is the decided reading, not a placeholder (R14). With the branch open, the
    held-out eval procedure's own DOCUMENTED invocation — a scored alert run with `--no-learn`
    — starts feeding the committed catalog every later investigation reads at planning time,
    leaving the content digest as the sole net: one protection load-bearing alone. Accepted
    cost: an operator wanting to skip learning while keeping curation loses that, and the flag
    now governs a lane its name does not name, which is what the help-text clause repairs.

    Three arms, all driven through the REAL entrypoint over the operator's own argv, because
    "the flag reaches the trigger" is the whole demand: the flag set, the flag absent (the
    control — without it "no marker" is also true of a boundary that never fires), and the
    documented held-out scoring run, which is the alternative that crosses validation."""
    suppressed = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "suppressed"), suppressed, "--no-learn") == 0
    assert author_markers(state) == [], "--no-learn left a curation request behind"

    allowed = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "allowed"), allowed) == 0
    assert author_markers(state), \
        "the boundary never fires at all — the suppressed arm above proves nothing"

    for marker in state.author_queue_dir.glob("*.json"):
        marker.unlink()
    scoring = SpecTail(state)
    assert drive_tail(
        run_py.main, plant_alert(tmp_path / "scored", alert_bytes=HELD_OUT_ALERT), scoring, "--no-learn"
    ) == 0
    assert author_markers(state) == [], \
        "the held-out eval's own documented invocation started feeding the committed catalog"


def test_791_the_no_learn_flag_says_it_governs_curation(tmp_path, capsys):
    """no_learn_help_names_curation — the operator reading `--no-learn`'s own documentation can
    tell that it also suppresses catalog curation.

    R14 made the flag govern a lane its name does not name, and this help text is the only
    place an operator could find that out — the flag has exactly one reader in the whole
    production tree and is never persisted anywhere else (PR4).

    Promoted from a clause: the rationale for leaving it in prose was that pinning help text
    hardens a paragraph nobody wants frozen, and this asserts one WORD in one flag's block,
    which freezes nothing. The failure it guards against is the ordinary one — the behaviour
    ships and the documentation does not, and nothing goes red."""
    with pytest.raises(SystemExit):
        run_py.parse_args(["--help"])
    block = _flag_help(capsys.readouterr().out, "--no-learn")

    assert block, "the entrypoint's help does not describe --no-learn at all"
    assert "curation" in block.lower(), (
        f"--no-learn's help says only {block.strip()!r} — an operator cannot tell that the "
        "flag now governs the catalog curation lane as well as learning"
    )


def _flag_help(help_text: str, flag: str) -> str:
    """One option's own help block out of argparse's rendering — its line plus the wrapped
    continuation lines, stopping at the next option."""
    lines = help_text.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(flag):
            block = [line]
            for nxt in lines[i + 1:]:
                if not nxt.strip() or nxt.strip().startswith("-"):
                    break
                block.append(nxt)
            return "\n".join(block)
    return ""


def test_791_enqueue_curation_cannot_be_called_unguarded(tmp_path, state):
    """enqueue_curation_cannot_be_called_unguarded — the refusal predicate is WELDED inside the
    curation enqueue rather than left to caller discipline, and no argument turns it off.

    This is the one new caller in the change that touches attacker-influenced content: the
    curator that edits the committed query catalog and the system skills receives the
    investigation's goal text, bound parameters and rendered queries VERBATIM (PR5). Extracting
    the predicate is what makes misuse constructible at all — today's helper signals
    "not refused" by performing the enqueue, so misuse is structurally impossible there, and
    the extraction is exactly what could leave a newly-unsafe default behind.

    Driven with no caller-side check whatsoever, which is the misuse being ruled out."""
    fixtures = _held_out_set(tmp_path, HELD_OUT_ALERT)
    for label, run_dir, kw in (
        ("truncated", _certified_run(tmp_path, name="t"), {"truncated_by": "budget"}),
        ("held-out-copy",
         _certified_run(tmp_path, name="h", alert_bytes=HELD_OUT_ALERT), {}),
        ("unverified", make_run_dir(tmp_path, name="u", disposition="benign"), {}),
    ):
        assert run_common.enqueue_curation(
            run_dir, run_dir / "alert.json", fixtures_dir=fixtures, **kw
        ) is False, f"{label}: the unguarded call went through"
    assert author_markers(state) == [], "an unguarded call reached the committed catalog"

    import inspect

    params = set(inspect.signature(run_common.enqueue_curation).parameters)
    assert not (params & {"force", "skip_refusals", "unguarded", "check", "gate"}), \
        f"the curation enqueue offers a way to bypass its own guard: {sorted(params)}"


def test_791_the_curation_trigger_joins_the_scrub_ordering_property(tmp_path, state):
    """curation_reads_the_tree_only_after_certification — the shipped property that nothing
    reads the investigation's tree before the step certifying it now covers BOTH new
    consumers: the curation trigger, and the ticket close.

    The property is a hand-written list of the tree's consumers, and this change both removes a
    member and adds one — exactly the moment the list is meant to be re-examined (R6). Ordering
    is fine on the facts: the verdict is written in the lifecycle's `finally`, before the
    boundary is reached (PR3). The demand is about the property COVERING the new consumers, not
    about discovering a violation.

    The ticket close is a pre-existing gap, fixed here under this issue's name (R17): it reads
    the run dir and was not a member, so its ordering held by POSITION and by no check. Its
    cell is the third one, and the other two cells' credit never extended to it.

    MEMBERSHIP is read off the shipped property's own inline tuple — the one claim here that is
    genuinely about source shape. The ORDERING is driven (R22): the tail's consumers are
    observed running against a tree the lifecycle had already certified, and the fail-closed
    control drives an uncertified one, where the request must be refused rather than written."""
    members = _property_members()
    for consumer in ("enqueue_curation", "close_case_ticket"):
        assert consumer in members, \
            f"the pre-certification consumer property does not cover {consumer}"

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "ordered"), tail, "--update-ticket") == 0
    for consumer in ("close_case_ticket", "visualize"):
        assert tail.step(consumer).tree_certified, \
            f"{consumer} read the run dir BEFORE the lifecycle certified it"
    assert author_markers(state), \
        "no curation request was written at all, so the refusal below proves nothing"

    for marker in state.author_queue_dir.glob("*.json"):
        marker.unlink()
    uncertified = SpecTail(state, certify=False)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "uncertified"), uncertified) == 0
    assert author_markers(state) == [], \
        "a run whose tree carries no scan verdict was handed to the curation lane anyway"


def test_791_removing_a_consumer_from_the_scrub_property_states_a_reason(tmp_path):
    """shrinking_the_consumer_property_states_a_reason — a consumer leaving the property leaves
    a stated reason behind, so the membership cannot be shrunk into green.

    When this property goes red the CHEAPEST repair is to delete the departed name, and that
    repair leaves a security guarantee quietly covering less than it did with nothing failing —
    the definition of an unfalsifiable demand. The learning enqueue is the member this change
    removes, so it is the first case: every name the property carried before must be either a
    live member or a recorded departure whose reason names the issue that took it."""
    members = _property_members()
    source = SCRUB_PROPERTY_TEST.read_text(encoding="utf-8")

    assert "enqueue_learning" not in members, \
        "the departing consumer is still listed as live; this demand has nothing to check yet"
    reasons = [
        s for s in _string_constants(SCRUB_PROPERTY_TEST)
        if "enqueue_learning" in s and "791" in s
    ]
    assert reasons, (
        "the learning enqueue left the property with no stated reason — the cheapest repair "
        "was taken, and the guarantee now covers less with nothing failing"
    )
    assert "enqueue_learning" in source

    shipped_before = {"iterdir", "cross_check_tables", "enqueue_learning", "visualize"}
    recorded = {name for name in shipped_before if any(name in r for r in reasons)}
    assert shipped_before <= (set(members) | recorded), \
        f"the property lost {shipped_before - set(members) - recorded} with no record"


def _property_members() -> list[str]:
    """The consumer names the shipped ordering property walks — read out of its own `for`
    loop, because the property IS that inline tuple: there is no identifier to import and no
    module-level constant to follow (H3)."""
    fn = fn_node(SCRUB_PROPERTY_TEST, SCRUB_PROPERTY_DEMAND)
    for node in ast.walk(fn):
        if isinstance(node, ast.For) and isinstance(node.iter, (ast.Tuple, ast.List)):
            names = [e.value for e in node.iter.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if names:
                return names
    raise AssertionError(
        f"{SCRUB_PROPERTY_DEMAND} no longer walks a consumer list; re-site this demand"
    )


def _string_constants(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]
