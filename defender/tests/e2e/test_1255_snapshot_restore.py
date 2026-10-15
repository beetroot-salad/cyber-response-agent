"""#1255 slice A — an arm is a continuation, not a restart (P2, D2, P3, N4).

Design rev 4, "Fork snapshot (P2, P3)": when a MAIN response arrives, before any of its tool calls
run, the host records what the run holds — every counter the model can feel (budget, breaker,
the challenge gate's rounds and raised asks, main's request count including this response), the
length of each append-only model-readable file (queries table, lessons log, denials log, review
records), the content of each rewritable one (`investigation.md`), the hash of each write-once
one (gather summaries, raw payloads) — keyed by that response, OUTSIDE the run folder. An arm
restores it: files cut to the recorded length or content, counters restored, main's request
count entering the framework as its starting usage. A restore that does not match refuses the
arm at launch; a source with no snapshot (recorded before this change, N4) is refused.

THE OBSERVABLE IS ALWAYS THE NATURAL CONTINUATION. Each arm below is scripted to make exactly
the calls its source made after the branch point, so "restored" has an oracle that is not this
file's opinion: the arm must hit its limits, write its records and end up holding its files
exactly where the source did (D2: "an arm hits its limits where the source would have"). Today
an arm restarts every counter at zero and inherits only the queries table and the selected
leads' files (G7, G16) — the reversal each test names.

Nothing here reads, plants or names the snapshot. Its location and shape are not fixed by the
design; the P3 test below observes "outside the run folder" by what still restores when
everything else in the run folder is gone.

RED TODAY (expected): every arm is taken at a D1 branch point, which `branch.validate` refuses
("unanswered"), so the restore assertions are masked until D1 lands; the N4 test is the
exception (see its docstring). Unlike the D1 regression tests (`test_1255_snapshot_branch_point`,
`test_1255_snapshot_legality`), every test here except P3's stays red under D1 alone: each
needs the snapshot's restore (P2, D2, rev 5 C3).
"""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import challenge_gate, session_store  # noqa: E402
from defender.runtime.close_tool import (  # noqa: E402
    CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_TURN_BUDGET_SPENT,
)
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbRegistry  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests import _1255_snapshot as S  # noqa: E402
from defender.tests import _review_bundle  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION,
    LEGACY_BRANCH_CALL,
    legal_source,
    spec_at,
)
from defender.tests._invlang_warn_836 import REPAIRED_ROW_ATTRS, WARN_ROW, attr_block  # noqa: E402
from defender.tests._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    VerbRecorder,
    answer_hits,
    elastic_backend,
    envelope,
)
from defender.tests.e2e._replay_harness import DEFENDER, FakeVerbs, Turn  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)


def _arm_launched(arm: S.Driven) -> None:
    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the arm was refused at launch ({refused}) — the source was driven (so it has its fork "
        "snapshot) and the branch point is a tool-calling MAIN response outside any retry streak")


# --------------------------------------------------------------------------------------
# D2: every counter the model can feel is restored.
# --------------------------------------------------------------------------------------

#: A request ceiling small enough to reach in a handful of turns (base 6 + one forced turn).
SMALL_CEILING = challenge_gate.Bounds(extra_turns=1, base_request_limit=6)


@pytest.mark.parametrize("k", [2, 4])
def test_d2_mains_request_count_enters_the_arm_as_its_starting_usage(tmp_path, k):
    """D2 (G18): a source that never stops calling tools runs into its request ceiling after
    `L` model requests. Branched at its `k`-th response — whose request is the `k`-th, counted
    in the snapshot ("including this response") — the arm makes exactly `L - k` more requests
    and stops at the same ceiling for the same reason. Today the arm starts its count at zero
    and makes `L` requests of its own.

    Two branch points of ONE kind of source, so the restored count is keyed by the response
    the arm is branched at, not a single number the arm happens to carry."""
    source = S.drive_source(tmp_path, (), main=S.Forever(opening=[S.append(CHUNKS[0])]),
                            bounds=SMALL_CEILING)
    assert source.summary.get("truncated_by") == session_store.TRUNCATED_BY_REQUEST_LIMIT, (
        f"the source was not stopped by its request ceiling ({source.summary}) — the count "
        "below would not be measured against a limit")
    natural = source.main.calls
    assert natural > k, f"the source made {natural} requests; it cannot be branched at {k}"
    point = S.tool_calling_responses(source.store)[k - 1]

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Forever(), bounds=SMALL_CEILING)

    _arm_launched(arm)
    assert arm.summary.get("truncated_by") == session_store.TRUNCATED_BY_REQUEST_LIMIT, arm.summary
    assert arm.main.calls == natural - k, (
        f"the arm made {arm.main.calls} requests before its ceiling; the source, branched at its "
        f"request {k}, had {natural - k} left — the arm's request count restarted")


#: The call cap (`max_tool_calls`) that leaves the source two `echo`s and refuses the rest.
CAP = {**DEFAULT_LIMITS, "max_tool_calls": 5, "wall_clock_timeout": 3600, "grace_seconds": 600}
ECHOES = [f"ran-{i}" for i in range(1, 7)]


def _ran(model: S.Recorder) -> list[str]:
    """Which echoes RAN: an `echo` that ran prints its word into its tool result; a refused one
    appears only as the call's arguments, which `seen` does not flatten."""
    return [word for word in ECHOES if word in model.seen[-1]]


def test_d2_the_tool_call_budget_is_restored(tmp_path, monkeypatch):
    """D2: under the enforced budget, the source's call cap refuses its later `echo`s. Branched
    at the response that called `echo ran-1`, the arm — making the same calls — is refused at
    the SAME call: the same echoes run, the same are refused, and the run's tool-call count
    ends where the source's did. Today the arm's count restarts at zero and every echo runs.

    Positive control: the source's own script both runs and refuses echoes, so the cap is in
    reach of the branch."""
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    script = [S.append(CHUNKS[0]), *(S.echo(w) for w in ECHOES), S.done()]
    source = S.drive_source(tmp_path, script, limits=CAP)
    ran = _ran(source.main)
    assert ran and set(ran) != set(ECHOES), f"the cap did not split the source's echoes: {ran}"
    point = S.tool_calling_responses(source.store)[1]  # `echo ran-1`

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([*(S.echo(w) for w in ECHOES[1:]), S.done()]), limits=CAP)

    _arm_launched(arm)
    assert _ran(arm.main) == ran, (
        f"the arm ran {_ran(arm.main)}; the source, making the same calls, ran {ran}")
    assert _counters(arm.state) == _counters(source.state)


def _counters(state) -> dict:
    """The budget's COUNTERS — every key but the run's identity and its clock stamps (the
    clock's restore is slice D's: `test_1255_clock_*`)."""
    return {k: v for k, v in state.budget_snapshot().items()
            if k not in {"run_id", "created_at", "started_at"}}


#: A spawn cap the source reaches after the branch: the correlation lead, `l-001` and `l-002`
#: are spawned; `l-003` is refused ("the subagent-spawn cap is reached").
SPAWN_CAP = {**DEFAULT_LIMITS, "max_subagent_spawns": 3, "wall_clock_timeout": 3600,
             "grace_seconds": 600}
QUIET_LEADS = {lead: (Turn(text=f"{lead}: nothing to add"),)
               for lead in ("l-001", "l-002", "l-003")}
SPAWN_SCRIPT = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("x"), S.dispatch("l-002"),
                S.dispatch("l-003"), S.done())
#: The arm's script: the source's calls after its branch point (`echo x`, which it re-runs).
SPAWN_ARM = (S.dispatch("l-002"), S.dispatch("l-003"), S.done())


def test_d2_the_subagent_spawn_count_is_restored(tmp_path, monkeypatch):
    """D2 (R1-3): under the enforced budget the source's spawn cap admits the correlation lead,
    `l-001` and — after the branch point — `l-002`, and refuses `l-003`. The arm, branched at
    `echo x` (between the two dispatches) and dispatching `l-002` then `l-003` as the source
    did, is refused at the SAME dispatch: only `l-002` reaches a gather model, and its budget
    counters end where the source's did. Today the arm's spawn count restarts at zero and both
    leads run.

    Positive control: the source's own run both admits and refuses a dispatch after the branch,
    so the cap is in reach of the arm."""
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    source = S.drive_source(tmp_path, SPAWN_SCRIPT, leads=QUIET_LEADS, limits=SPAWN_CAP)
    assert source.gather.asked == [S.CORRELATION_LEAD, "l-001", "l-002"], (
        f"the spawn cap did not split the source's dispatches after the branch: {source.gather.asked}")
    point = S.tool_calling_responses(source.store)[2]  # `echo x`

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder(SPAWN_ARM),
                      leads=QUIET_LEADS, limits=SPAWN_CAP)

    _arm_launched(arm)
    assert arm.gather.asked == ["l-002"], (
        f"the arm's dispatches reached {arm.gather.asked}; the source, making the same calls, "
        "reached only l-002 after the branch — the arm's spawn count restarted")
    assert _counters(arm.state) == _counters(source.state)


#: Each cap with the arm configured LOOSER than the source (C3): the arm must still stop where
#: the source would, because it runs under the caps its snapshot recorded.
LOOSE = {**DEFAULT_LIMITS, "max_tool_calls": 500, "max_subagent_spawns": 40,
         "wall_clock_timeout": 3600, "grace_seconds": 600}


@pytest.mark.parametrize("cap", ["tool-call cap", "subagent-spawn cap", "request ceiling"])
def test_c3_an_arm_runs_under_the_sources_caps_not_its_own(tmp_path, monkeypatch, cap):
    """D2 / rev 5 C3: "arms inherit budget and limits" means the arm runs under the SOURCE's
    caps, recorded in the snapshot — not caps re-read from the arm's own configuration. Each
    arm here is launched with a far looser configuration than its source (`LOOSE`, or a request
    base ten times the source's) and still stops exactly where the source would have: the same
    echoes run, the same dispatch is refused, the same number of requests is made.

    The source halves are the D2 tests' own (their positive controls hold here too); only the
    arm's configuration differs."""
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    if cap == "tool-call cap":
        script = [S.append(CHUNKS[0]), *(S.echo(w) for w in ECHOES), S.done()]
        source = S.drive_source(tmp_path, script, limits=CAP)
        ran = _ran(source.main)
        assert ran and set(ran) != set(ECHOES), ran
        arm = S.drive_arm(tmp_path, S.spec_for(source, S.tool_calling_responses(source.store)[1]),
                          S.Recorder([*(S.echo(w) for w in ECHOES[1:]), S.done()]), limits=LOOSE)
        _arm_launched(arm)
        assert _ran(arm.main) == ran, f"the arm ran {_ran(arm.main)} under its own cap; the source ran {ran}"
    elif cap == "subagent-spawn cap":
        source = S.drive_source(tmp_path, SPAWN_SCRIPT, leads=QUIET_LEADS, limits=SPAWN_CAP)
        assert source.gather.asked == [S.CORRELATION_LEAD, "l-001", "l-002"], source.gather.asked
        arm = S.drive_arm(tmp_path, S.spec_for(source, S.tool_calling_responses(source.store)[2]),
                          S.Recorder(SPAWN_ARM), leads=QUIET_LEADS, limits=LOOSE)
        _arm_launched(arm)
        assert arm.gather.asked == ["l-002"], f"the arm's own cap admitted {arm.gather.asked}"
    else:
        source = S.drive_source(tmp_path, (), main=S.Forever(opening=[S.append(CHUNKS[0])]),
                                bounds=SMALL_CEILING)
        assert source.summary.get("truncated_by") == session_store.TRUNCATED_BY_REQUEST_LIMIT
        loose = challenge_gate.Bounds(extra_turns=1, base_request_limit=60)
        arm = S.drive_arm(tmp_path, S.spec_for(source, S.tool_calling_responses(source.store)[1]),
                          S.Forever(), bounds=loose)
        _arm_launched(arm)
        assert arm.main.calls == source.main.calls - 2, (
            f"the arm made {arm.main.calls} requests under its own ceiling; the source had "
            f"{source.main.calls - 2} left at the branch point")


def _faulting_query(verb: str, params: dict):
    """The elastic backend's answer: the correlation lead's `alerts` call is answered, a lead's
    `query` fails as an infrastructure fault (exit 2), which the breaker charges."""
    if verb == "query":
        raise TransportFault("docker exec failed")
    return envelope(S.DOCS)


LEAD_QUERY = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                         "params": {"native_query": "user.name:dev.dana"}})])


#: The breaker source: one faulting lead BEFORE the branch point (`echo after`) and one after it,
#: so the source's FINISHED breaker differs from its breaker at the cut.
BREAKER_SCRIPT = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("after"), S.dispatch("l-002"),
                  S.done())


def test_d2_the_circuit_breaker_is_restored(tmp_path):
    """D2: a lead's infrastructure failure charges `elastic`'s breaker before the branch point,
    and a second lead's failure charges it again AFTER it. The arm, branched between the two
    (`echo after`), holds the breaker AT THE CUT — one failure, not tripped — not the source's
    finished breaker (two failures, tripped), and not an empty one (today's).

    The count at the cut is derived from the script, not read from any snapshot: one faulting
    `query` precedes `echo after` (`l-001`'s) and one follows it (`l-002`'s), and the source's
    finished breaker pins one charge per failing query (two failures, two counted toward the
    run). Below `PER_SYSTEM_FAIL_LIMIT` a system record carries its count alone (`tripped_at` is
    stamped only at the limit), so the cut's breaker is a plain value."""
    from defender.runtime import circuit_breaker

    failed = Turn(text="the backend did not answer")
    source = S.drive_source(tmp_path, BREAKER_SCRIPT,
                            leads={"l-001": (LEAD_QUERY, failed), "l-002": (LEAD_QUERY, failed)},
                            answer=_faulting_query)
    finished = source.state.breaker_snapshot()
    assert finished["systems"].get("elastic", {}).get("failures") == 2, (
        f"the source's finished breaker is {finished}; the script charges elastic once per "
        "lead, twice in all")
    assert finished["total_failures"] == 2, finished
    assert circuit_breaker.PER_SYSTEM_FAIL_LIMIT > 1, "one failure would already trip the cut"
    cut = {"systems": {"elastic": {"failures": 1}}, "total_failures": 1}
    assert finished != cut, "the post-branch failure did not land — the cut is not told apart"
    point = S.tool_calling_responses(source.store)[2]
    (call,) = S.calls_of(S.message_at(source.store, point))
    assert call.args_as_dict().get("command") == "echo after", f"the branch point moved: {call}"

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.done()]))

    _arm_launched(arm)
    assert arm.state.breaker_snapshot() == cut, (
        f"the arm's breaker is {arm.state.breaker_snapshot()}; at the branch point the source's "
        f"was {cut} (its finished breaker is {finished})")


def _gap_on(target: str):
    """A review bundle whose composer finds a gap and asks for `target` every time."""
    return _review_bundle.bundle(composer=_review_bundle.composer_reply(
        "gap", review="the pivot rests on one unmeasured inference",
        ask={"target": target, "prose": "measure what it did"}))


@pytest.mark.parametrize(("state", "target", "extra_turns", "cause"), [
    # `v-001` is named again by the fence appended after the challenge, so the ask is not
    # spent; with one forced turn, the second close finds the turn budget gone.
    ("rounds", "v-001", 1, CAUSE_TURN_BUDGET_SPENT),
    # `h-001` is not named again, so the second close finds the ask already raised and
    # nothing new recorded — with a turn still left.
    ("raised asks", "h-001", 2, CAUSE_NOTHING_LEFT_TO_ASK),
], ids=["rounds", "raised-asks"])
def test_d2_the_challenge_gates_rounds_and_raised_asks_are_restored(
        tmp_path, state, target, extra_turns, cause):
    """D2 (G16): the source closes, the review challenges it (round 1, the ask recorded), it
    appends a fence (the branch point) and closes again — and the gate forces the close
    (`cause`). The arm, branched at that fence and closing the same way, is forced the same way
    with the same cause, because it holds the round count and the raised ask; and it inherits
    the source's `review_record.1.json` byte for byte (the review record is append-only, cut at
    the branch). Today the arm's gate restarts: its close is challenged again, and the record it
    writes is its own round 1.

    Positive control: the source's first record is the challenge and its report carries
    `cause`, so the second close is decided by exactly the state this test says is restored."""
    bounds = challenge_gate.Bounds(extra_turns=extra_turns)
    stages = _gap_on(target)
    head = CHUNKS[0] + CHUNKS[1]
    assert target in head and (target in CHUNKS[2]) == (state == "rounds"), (
        "the fixture's fences no longer name the target the way this arm needs")
    source = S.drive_source(
        tmp_path, (S.append(head), S.close(), S.append(CHUNKS[2]), S.close(), S.done()),
        review_stages=stages, bounds=bounds)
    first = S.read_text(source.paths.review_record(1))
    assert '"challenged"' in first, f"the source's first close was not challenged: {first[:200]}"
    report = S.read_text(source.paths.report)
    assert cause in report, f"the source's second close was not forced for `{cause}`: {report}"
    point = S.tool_calling_responses(source.store)[2]  # the fence appended after the challenge

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.close(), S.done()]),
                      review_stages=stages, bounds=bounds)

    _arm_launched(arm)
    assert S.read_bytes(arm.paths.review_record(1)) == S.read_bytes(source.paths.review_record(1)), (
        "the arm's review_record.1.json is not the source's — the arm's gate re-ran round 1")
    assert S.read_text(arm.paths.report) and cause in S.read_text(arm.paths.report), (
        f"the arm's close was not forced for `{cause}`: "
        f"{S.read_text(arm.paths.report)[:300] or '(no report: the close was challenged again)'}")


# --------------------------------------------------------------------------------------
# P2: model-readable files are restored up to the cut (append-only, write-once, rewritable).
# --------------------------------------------------------------------------------------


class _Withholding(FakeVerbs):
    """An injected registry whose grant withholds named pairs it still declares — so a lead's
    call to one is DENIED (and logged to the denials log), not undeclared."""

    def __init__(self, table, withheld: set[tuple[str, str]]):
        super().__init__(table)
        VerbRegistry.__init__(self, VerbGrant(role="fake", entries=tuple(
            (s, v, "r") for s, verbs in table.items() for v in verbs if (s, v) not in withheld)))


def _registry() -> _Withholding:
    rec = VerbRecorder()
    elastic = dict(elastic_backend(rec, answer_hits(S.DOCS)).verbs("elastic"))
    return _Withholding(
        {"elastic": elastic,
         "identity": {"get-user": lambda ctx, **kw: {"user": "dev.dana"},
                      "list-authorized-hosts": lambda ctx, **kw: {"hosts": []}}},
        {("identity", "list-authorized-hosts")})


DENIED = Turn(tool_calls=[("query", {"system": "identity", "verb": "list-authorized-hosts",
                                     "params": {}})])


def _planted_tree(root: Path) -> Path:
    """A defender tree the run reads (`defender_dir=`): this checkout, linked entry by entry,
    except `lessons/`, which holds only the three lessons below — so which lessons a write
    pushes is this test's, not the checked-in corpus's. Golden fence 1 leaves `v-001`'s
    (compute) and `v-002`'s (identity) `class` open, so the first two match it; only golden
    fence 2 opens contract `ac2` (anchor `approved-source-list`), so the third is pushed by
    that later write and no earlier one."""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in {".venv", "__pycache__", "tests", "fixtures-e2e", "lessons"}:
            continue
        (tree / entry.name).symlink_to(entry)
    (tree / "lessons").mkdir()
    _write_lesson(tree / "lessons", "compute-class-1255", nodes=("type: compute, slot: class",))
    _write_lesson(tree / "lessons", "identity-class-1255", nodes=("type: identity, slot: class",))
    _write_lesson(tree / "lessons", "approved-source-1255",
                  edges=("anchor_kind: approved-source-list",))
    return tree


def _lines(path: Path) -> list[bytes]:
    return S.read_bytes(path).splitlines(keepends=True)


def _rows(path: Path) -> list[dict]:
    """A log's rows with their timestamp dropped: the one field a re-made row may differ in
    (the run clock's restore is slice D's)."""
    return [{k: v for k, v in json.loads(line).items() if k != "ts"} for line in _lines(path)]


#: The source's script and the arm's: the arm re-runs `echo x` (its branch point) and then makes
#: exactly the calls the source made after it — a denied dispatch and the fence that pushes the
#: third lesson.
LOG_SCRIPT_HEAD = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("x"))
LOG_SCRIPT_TAIL = (S.dispatch("l-002"), S.append(CHUNKS[1]))
LOG_LEADS = {"l-001": (DENIED, Turn(text="l-001: denied")),
             "l-002": (DENIED, Turn(text="l-002: denied"))}


def test_p2_append_only_and_write_once_files_are_restored_up_to_the_cut(tmp_path):
    """P2 (reverses G7; R1-2 exact cut): before the branch point (`echo x`) the source's first
    fence pushes two lessons, a lead's denied call is logged, and the correlation lead's rows
    and files are written; AFTER it the source logs a second denial and its next fence pushes a
    third lesson. So both logs grow past the cut, and "restored up to the cut" has an exact
    oracle: the rows a run of the same script that STOPS at the branch point holds (`prefix`,
    driven separately — not production's answer). The arm, branched at `echo x` and making the
    source's later calls itself:

    - opens its lessons and denials logs on the source's rows through the cut, byte for byte,
      and holds after them exactly its own rows — the same rows (timestamps aside) the source
      wrote after the cut, once. A whole-file copy (the source's post-cut rows, then the arm's
      own again) or a restart (no inherited rows) is each a different log;
    - holds the source's query rows through the cut and the correlation lead's payload, claim
      and summary byte for byte (write-once evidence written before the cut);
    - holds them as COPIES: its own later rows land in its files, never the source's, and its
      run state holds the restored rows its table holds (#1235: the live run reads a lead's
      rows from the run state, so a table restored without them is two answers).

    Today the lessons and denials logs are not inherited at all (G7) — the arm's are its own."""
    tree = _planted_tree(tmp_path)
    prefix = S.drive_source(tmp_path / "prefix", (*LOG_SCRIPT_HEAD, S.done()), leads=LOG_LEADS,
                            verbs=_registry(), defender_dir=tree, run_id="prefix-1255")
    source = S.drive_source(tmp_path, (*LOG_SCRIPT_HEAD, *LOG_SCRIPT_TAIL, S.done()),
                            leads=LOG_LEADS, verbs=_registry(), defender_dir=tree)
    cut = {name: len(_lines(getattr(prefix.paths, name)))
           for name in ("lessons_loaded", "policy_denials")}
    for name, n in cut.items():
        ours = _rows(getattr(source.paths, name))
        assert ours[:n] == _rows(getattr(prefix.paths, name)), (
            f"the source's {name} does not open on the rows a run stopped at the branch point holds")
        assert n and len(ours) > n, (
            f"the source's {name} holds {len(ours)} row(s), {n} through the cut — it must grow on "
            "both sides of the branch point, or an exact cut is indistinguishable from a copy")
    queries_before = [line for line in _lines(source.paths.executed_queries)
                      if json.loads(line).get("lead_id") != "l-002"]  # everything before the cut
    point = S.tool_calling_responses(source.store)[2]  # `echo x`
    originals = {name: S.read_bytes(getattr(source.paths, name))
                 for name in ("executed_queries", "lessons_loaded", "policy_denials")}

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([*LOG_SCRIPT_TAIL, S.done()]),
                      leads={"l-002": LOG_LEADS["l-002"]}, verbs=_registry(), defender_dir=tree)

    _arm_launched(arm)
    for name, n in cut.items():
        theirs, ours = getattr(source.paths, name), getattr(arm.paths, name)
        assert _lines(ours)[:n] == _lines(theirs)[:n], (
            f"the arm's {name} does not open on the source's {n} row(s) through the cut, byte for byte")
        assert _rows(ours) == _rows(theirs), (
            f"the arm's {name} is not the source's rows through the cut plus its own, exactly: "
            f"{len(_rows(ours))} row(s) against the source's {len(_rows(theirs))}")
    assert _lines(arm.paths.executed_queries)[:len(queries_before)] == queries_before, (
        "the arm's queries table does not open on the source's rows through the cut")
    payload = source.paths.payload(S.CORRELATION_LEAD, 0)
    assert S.read_bytes(payload), f"the source has no payload for {S.CORRELATION_LEAD}"
    assert S.read_bytes(arm.paths.payload(S.CORRELATION_LEAD, 0)) == S.read_bytes(payload), (
        "the correlation lead's raw payload was not restored byte for byte")
    for name in ("lead_claim", "gather_summary"):
        theirs = getattr(source.paths, name)(S.CORRELATION_LEAD)
        assert S.read_bytes(theirs), f"the source has no {name} for {S.CORRELATION_LEAD}"
        assert S.read_bytes(getattr(arm.paths, name)(S.CORRELATION_LEAD)) == S.read_bytes(theirs), (
            f"the correlation lead's {name} was not restored byte for byte")
    for name, data in originals.items():
        assert S.read_bytes(getattr(source.paths, name)) == data, (
            f"the arm's own rows reached the SOURCE's {name} — the restore shared the file")
    restored = [json.loads(line) for line in queries_before
                if json.loads(line).get("lead_id") == S.CORRELATION_LEAD]
    assert restored and list(arm.state.lead_rows(S.CORRELATION_LEAD)) == restored, (
        "the arm's run state does not hold the correlation lead's restored rows")


def test_p2_the_investigation_document_is_restored_by_content(tmp_path):
    """P2: `investigation.md` is REWRITABLE (`fix_row` edits a flagged row in place), so it is
    restored by content, not by length. The source lands a block with a flagged row, repairs it
    (the branch point), then appends. The arm, branched at the repair and re-running it, gets
    the source's own answer to the repair ("repaired 1 flagged row(s)…") and ends holding the
    source's document.

    The violations it rejects: a cut by LENGTH (the post-repair document is longer than the one
    the repair was made against, so the cut keeps a torn tail and the re-run finds nothing to
    repair) and today's fence-count cut of the FINISHED document (it already holds the repair,
    so the re-run is refused with "nothing is currently flagged")."""
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.append(attr_block(WARN_ROW)),
                   Turn(tool_calls=[("fix_row", {"old_row": WARN_ROW, "new_row": REPAIRED_ROW_ATTRS})]),
                   S.append(CHUNKS[1]), S.done()))
    assert REPAIRED_ROW_ATTRS in source.document and WARN_ROW not in source.document, (
        "the source's repair did not land in place")
    point = S.tool_calling_responses(source.store)[2]  # the `fix_row`

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([S.append(CHUNKS[1]), S.done()]))

    _arm_launched(arm)
    natural = S.project(source.main.requests[3][-1:])[0][2]  # the repair's answer, as MAIN read it
    assert "repaired 1 flagged row" in repr(natural), natural
    answer = S.project(arm.main.requests[0][-1:])[0][2]
    assert answer == natural, f"the arm's re-run repair was answered {answer!r}, not {natural!r}"
    assert arm.document == source.document


# --------------------------------------------------------------------------------------
# Refusals at launch.
# --------------------------------------------------------------------------------------


def _truncate_last_line(path: Path) -> None:
    lines = _lines(path)
    assert len(lines) >= 1, f"{path.name} holds no row to cut"
    path.write_bytes(b"".join(lines[:-1]))


def _rewrite(path: Path) -> None:
    assert path.is_file(), f"{path} is not there to rewrite"
    path.write_bytes(path.read_bytes() + b"\n(rewritten after the run)\n")


#: Each way a source's files can stop matching what was recorded at the branch point, applied to
#: a file the branch point's snapshot covers (each exists, with content, before the cut).
TAMPERS = {
    "queries table shorter than recorded": lambda p: _truncate_last_line(p.executed_queries),
    "lessons log shorter than recorded": lambda p: _truncate_last_line(p.lessons_loaded),
    "denials log shorter than recorded": lambda p: _truncate_last_line(p.policy_denials),
    "gather summary rewritten": lambda p: _rewrite(p.gather_summary(S.CORRELATION_LEAD)),
    "raw payload rewritten": lambda p: _rewrite(p.payload(S.CORRELATION_LEAD, 0)),
}


@pytest.mark.parametrize("tamper", sorted(TAMPERS))
def test_p2_a_restore_that_does_not_match_refuses_the_arm_at_launch(tmp_path, tamper):
    """P2: "A restore that does not match refuses the arm at launch." The source finishes, one
    file its branch point's snapshot covers is changed (an append-only file left SHORTER than
    recorded, a write-once file rewritten), and the arm is refused before its model is asked
    for anything and before anything is forked. Positive control in the same test: the same
    branch point of the same source, untampered, launches."""
    tree = _planted_tree(tmp_path)
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("x"), S.done()),
        leads={"l-001": (DENIED, Turn(text="l-001: denied"))}, verbs=_registry(),
        defender_dir=tree)
    point = S.tool_calling_responses(source.store)[2]  # `echo x`, after every write above
    spec = S.spec_for(source, point)
    control = S.drive_arm(tmp_path, spec, S.Recorder([S.done()]), defender_dir=tree,
                          name="control", run_id="control-1255")
    _arm_launched(control)
    forked = len(S.child_sessions(source.store))

    TAMPERS[tamper](source.paths)
    arm = S.drive_arm(tmp_path, spec, S.Recorder([S.done()]), defender_dir=tree)

    assert not S.launched(arm), f"an arm launched over a source whose {tamper}"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert len(S.child_sessions(source.store)) == forked, "the refused arm still forked a session"


def test_n4_a_source_with_no_fork_snapshot_is_refused_at_launch(tmp_path, caplog):
    """N4: a source recorded before this change has no fork snapshot, and forking it is refused
    — at a branch point D1 admits (its trailing `bash` CALL, after its document landed:
    `_branch_947.LEGACY_BRANCH_CALL`), so nothing else about the branch is wrong. The fork
    command's own refusal of the same kind of source (rev 5 C2) is
    `tests/test_1255_snapshot_fork_command.py`. `legal_source` is exactly that run: its store rows were written directly, with no
    driver to record a snapshot. The refusal names the missing snapshot (a refusal names its
    reason). Positive control: a DRIVEN source branched at the same kind of point launches.

    TODAY this arm is refused too, but for the D1 reason ("unanswered"), so only the
    `snapshot` wording is red; the control is red on D1."""
    driven = S.drive_source(tmp_path / "driven", (S.append(CHUNKS[0]), S.echo("x"), S.done()))
    control = S.drive_arm(tmp_path / "driven", S.spec_for(driven, S.tool_calling_responses(driven.store)[1]),
                          S.Recorder([S.done()]))
    _arm_launched(control)

    store, run_dir, _session, path_ids = legal_source(
        tmp_path / "legacy", investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    call = path_ids[LEGACY_BRANCH_CALL]  # a tool-calling MAIN response after the document landed
    assert S.calls_of(S.message_at(store, call)), "the legacy fixture's call row moved"
    spec = spec_at(store, run_dir, call)
    store.close()
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path / "legacy", spec, S.Recorder([S.done()]))

    assert not S.launched(arm), "an arm was launched from a source with no fork snapshot"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert "snapshot" in caplog.text.lower(), (
        f"the refusal does not name the missing fork snapshot: {caplog.text[-400:]!r}")


# --------------------------------------------------------------------------------------
# P3: the snapshot lives outside the run folder (and outside every box mount).
# --------------------------------------------------------------------------------------


def _model_readable_records(paths: RunPaths) -> set[Path]:
    """The source's files an arm restores from — the model-readable records the snapshot
    describes — plus the case input. Everything else in the run folder is host bookkeeping."""
    keep = {paths.investigation, paths.executed_queries, paths.lessons_loaded,
            paths.policy_denials, paths.alert, paths.alert_record}
    return {p.resolve() for p in keep}


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.is_dir() else []


def test_p3_the_fork_snapshot_is_not_kept_in_the_run_folder_or_the_tenant_agent_half(tmp_path):
    """P3: the snapshot is host bookkeeping, kept where no box mount reaches. Observed by what
    still restores: after the source finishes, EVERY entry of its run folder that is not one of
    the model-readable records an arm restores from (the documents, the logs, the queries table,
    the gather folders, the case input) is deleted — today that is the wire-log folder and the
    tool trace; after #1255 it is also whatever else the run left there. The arm still launches
    and restores exactly (a snapshot kept in the run folder under any other name would be
    gone, and the arm refused as N4 — so a refusal HERE, unlike in the other tests, is the
    violation). And neither the source run nor the arm wrote into the tenant's agent half —
    the other mount besides the run folder and the checkout.

    What this is evidence for: only "the snapshot is not in the run folder". On its own it
    also passes over a branch with NO snapshot at all (bare D1 plus today's file-based seed),
    so it carries P3 only together with the N4 test, which shows a source without a snapshot
    is refused."""
    agent = _tenants1106.fixture_tenant().agent
    agent_before = _tree(agent)
    source = S.drive_source(tmp_path, (S.append(CHUNKS[0]), S.echo("x"), S.append(CHUNKS[1]),
                                       S.done()))
    assert _tree(agent) == agent_before, "the source run wrote into the tenant's agent half"
    point = S.tool_calling_responses(source.store)[1]  # `echo x`
    spec = S.spec_for(source, point)
    queries = S.read_bytes(source.paths.executed_queries)
    keep = _model_readable_records(source.paths)
    gather_dirs = {source.paths.gather_raw.resolve(), source.paths.gather_summaries.resolve()}
    removed = []
    for entry in sorted(source.run_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        resolved = entry.resolve()
        if resolved in keep or any(d == resolved or d in resolved.parents for d in gather_dirs):
            continue
        if any(resolved in k.parents for k in keep):
            continue  # a folder holding a kept record (the input folder)
        removed.append(str(entry.relative_to(source.run_dir)))
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    assert removed, "nothing but restorable records was in the run folder — the pruning tests nothing"

    arm = S.drive_arm(tmp_path, spec,
                      S.Recorder([S.append(CHUNKS[1]), S.done()]))

    _arm_launched(arm)
    assert _tree(agent) == agent_before, "the arm wrote into the tenant's agent half"
    assert S.read_bytes(arm.paths.executed_queries).startswith(queries)
    assert arm.document == source.document, (
        f"the arm did not restore exactly after the run folder lost {removed}")

