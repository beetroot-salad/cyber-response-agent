"""Forks restore files, counters, limits, and permanent refusals at the branch point."""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.investigation import challenge_gate  # noqa: E402
from defender.records import session_store  # noqa: E402
from defender.investigation.close_tool import (  # noqa: E402
    CAUSE_NOTHING_LEFT_TO_ASK,
    CAUSE_TURN_BUDGET_SPENT,
)
from defender.systems.verb_grant import VerbGrant  # noqa: E402
from defender.systems.verbs import VerbRegistry  # noqa: E402
from defender.kit.faults import TransportFault  # noqa: E402
from defender.tests.support.runtime.state import _1255_snapshot as S
from defender.tests.support.runtime.permissions import _review_bundle
from defender.tests.support.tenancy import _tenants1106
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.learning.branch._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION,
    LEGACY_BRANCH_CALL,
    legal_source,
    spec_at,
)
from defender.tests.support.invlang.validation._invlang_warn_836 import REPAIRED_ROW_ATTRS, WARN_ROW, attr_block  # noqa: E402
from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson  # noqa: E402
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


SMALL_CEILING = challenge_gate.Bounds(extra_turns=1, base_request_limit=6)


@pytest.mark.parametrize("k", [2, 4])
def test_d2_mains_request_count_enters_the_arm_as_its_starting_usage(tmp_path, k):
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


CAP = {**DEFAULT_LIMITS, "max_tool_calls": 5, "wall_clock_timeout": 3600, "grace_seconds": 600}
ECHOES = [f"ran-{i}" for i in range(1, 7)]


def _ran(model: S.Recorder) -> list[str]:
    """Echo words present in tool results; refused call arguments do not count."""
    return [word for word in ECHOES if word in model.seen[-1]]


def test_d2_the_tool_call_budget_is_restored(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    script = [S.append(CHUNKS[0]), *(S.echo(w) for w in ECHOES), S.done()]
    source = S.drive_source(tmp_path, script, limits=CAP)
    ran = _ran(source.main)
    assert ran, f"the cap did not split the source's echoes: {ran}"
    assert set(ran) != set(ECHOES), f"the cap did not split the source's echoes: {ran}"
    point = S.tool_calling_responses(source.store)[1]  # `echo ran-1`

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([*(S.echo(w) for w in ECHOES[1:]), S.done()]), limits=CAP)

    _arm_launched(arm)
    assert _ran(arm.main) == ran, (
        f"the arm ran {_ran(arm.main)}; the source, making the same calls, ran {ran}")
    assert _counters(arm.state) == _counters(source.state)


def _counters(state) -> dict:
    """Budget counters without run identity or clock stamps."""
    return {k: v for k, v in state.budget_snapshot().items()
            if k not in {"run_id", "created_at", "started_at"}}


SPAWN_CAP = {**DEFAULT_LIMITS, "max_subagent_spawns": 3, "wall_clock_timeout": 3600,
             "grace_seconds": 600}
QUIET_LEADS = {lead: (Turn(text=f"{lead}: nothing to add"),)
               for lead in ("l-001", "l-002", "l-003")}
SPAWN_SCRIPT = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("x"), S.dispatch("l-002"),
                S.dispatch("l-003"), S.done())
SPAWN_ARM = (S.dispatch("l-002"), S.dispatch("l-003"), S.done())


def test_d2_the_subagent_spawn_count_is_restored(tmp_path, monkeypatch):
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


LOOSE = {**DEFAULT_LIMITS, "max_tool_calls": 500, "max_subagent_spawns": 40,
         "wall_clock_timeout": 3600, "grace_seconds": 600}


@pytest.mark.parametrize("cap", ["tool-call cap", "subagent-spawn cap", "request ceiling"])
def test_c3_an_arm_runs_under_the_sources_caps_not_its_own(tmp_path, monkeypatch, cap):
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "true")
    if cap == "tool-call cap":
        script = [S.append(CHUNKS[0]), *(S.echo(w) for w in ECHOES), S.done()]
        source = S.drive_source(tmp_path, script, limits=CAP)
        ran = _ran(source.main)
        assert ran, ran
        assert set(ran) != set(ECHOES), ran
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
    """Answer correlation alerts; fail lead queries with a charged transport fault."""
    if verb == "query":
        raise TransportFault("docker exec failed")
    return envelope(S.DOCS)


LEAD_QUERY = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                         "params": {"native_query": "user.name:dev.dana"}})])


BREAKER_SCRIPT = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("after"), S.dispatch("l-002"),
                  S.done())


def test_d2_the_circuit_breaker_is_restored(tmp_path):
    from defender.systems import circuit_breaker

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
    ("rounds", "v-001", 1, CAUSE_TURN_BUDGET_SPENT),
    ("raised asks", "h-001", 2, CAUSE_NOTHING_LEFT_TO_ASK),
], ids=["rounds", "raised-asks"])
def test_d2_the_challenge_gates_rounds_and_raised_asks_are_restored(
        tmp_path, state, target, extra_turns, cause):
    bounds = challenge_gate.Bounds(extra_turns=extra_turns)
    stages = _gap_on(target)
    head = CHUNKS[0] + CHUNKS[1]
    assert target in head, "the fixture's fences no longer name the target the way this arm needs"
    assert (target in CHUNKS[2]) == (state == "rounds"), "the fixture's fences no longer name the target the way this arm needs"
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
    assert S.read_text(arm.paths.report), (f"the arm's close was not forced for `{cause}`: "
        f"{S.read_text(arm.paths.report)[:300] or '(no report: the close was challenged again)'}")
    assert cause in S.read_text(arm.paths.report), (f"the arm's close was not forced for `{cause}`: "
        f"{S.read_text(arm.paths.report)[:300] or '(no report: the close was challenged again)'}")


class _Withholding(FakeVerbs):
    """Registry declaring verbs while withholding selected pairs from its grant."""

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
    """Create a checkout mirror, and plant the scene's lessons for the restored file checks.

    #1108 P4 (O1, O4): the lessons a run matches its writes against are its TENANT's
    (`agent/lessons/`, from the export the run reads), never the checkout's — so the three
    lessons go into the fixture tenant's agent half (the replays run as that tenant, and the
    harness publishes its folder before each drive); the checkout mirror carries none."""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in {".venv", "__pycache__", "tests", "fixtures-e2e", "lessons"}:
            continue
        (tree / entry.name).symlink_to(entry)
    lessons = Path(location_path(_tenants1106.fixture_tenant().agent)) / "lessons"
    lessons.mkdir(exist_ok=True)
    _write_lesson(lessons, "compute-class-1255", nodes=("type: compute, slot: class",))
    _write_lesson(lessons, "identity-class-1255", nodes=("type: identity, slot: class",))
    _write_lesson(lessons, "approved-source-1255",
                  edges=("anchor_kind: approved-source-list",))
    return tree


def _lines(path: Path) -> list[bytes]:
    return S.read_bytes(path).splitlines(keepends=True)


def _rows(path: Path) -> list[dict]:
    """A log's rows with their timestamp dropped: the one field a re-made row may differ in (the run clock's restore is slice D's)."""
    return [{k: v for k, v in json.loads(line).items() if k != "ts"} for line in _lines(path)]


LOG_SCRIPT_HEAD = (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("x"))
LOG_SCRIPT_TAIL = (S.dispatch("l-002"), S.append(CHUNKS[1]))
LOG_LEADS = {"l-001": (DENIED, Turn(text="l-001: denied")),
             "l-002": (DENIED, Turn(text="l-002: denied"))}


def test_p2_append_only_and_write_once_files_are_restored_up_to_the_cut(tmp_path):
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
        assert n, (f"the source's {name} holds {len(ours)} row(s), {n} through the cut — it must grow on "
            "both sides of the branch point, or an exact cut is indistinguishable from a copy")
        assert len(ours) > n, (f"the source's {name} holds {len(ours)} row(s), {n} through the cut — it must grow on "
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
    assert restored, "the arm's run state does not hold the correlation lead's restored rows"
    assert list(arm.state.lead_rows(S.CORRELATION_LEAD)) == restored, "the arm's run state does not hold the correlation lead's restored rows"


def test_p2_the_investigation_document_is_restored_by_content(tmp_path):
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.append(attr_block(WARN_ROW)),
                   Turn(tool_calls=[("fix_row", {"old_row": WARN_ROW, "new_row": REPAIRED_ROW_ATTRS})]),
                   S.append(CHUNKS[1]), S.done()))
    assert REPAIRED_ROW_ATTRS in source.document, "the source's repair did not land in place"
    assert WARN_ROW not in source.document, "the source's repair did not land in place"
    point = S.tool_calling_responses(source.store)[2]  # the `fix_row`

    arm = S.drive_arm(tmp_path, S.spec_for(source, point),
                      S.Recorder([S.append(CHUNKS[1]), S.done()]))

    _arm_launched(arm)
    natural = S.project(source.main.requests[3][-1:])[0][2]  # the repair's answer, as MAIN read it
    assert "repaired 1 flagged row" in repr(natural), natural
    answer = S.project(arm.main.requests[0][-1:])[0][2]
    assert answer == natural, f"the arm's re-run repair was answered {answer!r}, not {natural!r}"
    assert arm.document == source.document


def _truncate_last_line(path: Path) -> None:
    lines = _lines(path)
    assert len(lines) >= 1, f"{path.name} holds no row to cut"
    path.write_bytes(b"".join(lines[:-1]))


def _rewrite(path: Path) -> None:
    assert path.is_file(), f"{path} is not there to rewrite"
    path.write_bytes(path.read_bytes() + b"\n(rewritten after the run)\n")


def _rewrite_in_place(path: Path, old: bytes | None = None, new: bytes = b"") -> None:
    """Replace file bytes without changing length, exposing size-only validation."""
    data = S.read_bytes(path)
    assert data, f"{path} is not there to rewrite"
    if old is None:
        i = next(i for i, c in enumerate(data) if chr(c).isascii() and chr(c).isalpha())
        old, new = data[i:i + 1], b"Q" if data[i:i + 1] != b"Q" else b"R"
    assert old in data, f"{path.name} does not hold {old!r}"
    changed = data.replace(old, new, 1)
    assert len(changed) == len(data), f"fixture: {old!r} -> {new!r} changes {path.name}'s length"
    assert changed != data, f"fixture: {old!r} -> {new!r} leaves {path.name}'s content as it was"
    path.write_bytes(changed)


TAMPERS = {
    "queries table shorter than recorded": lambda p: _truncate_last_line(p.executed_queries),
    "lessons log shorter than recorded": lambda p: _truncate_last_line(p.lessons_loaded),
    "denials log shorter than recorded": lambda p: _truncate_last_line(p.policy_denials),
    "gather summary rewritten": lambda p: _rewrite(p.gather_summary(S.CORRELATION_LEAD)),
    "raw payload rewritten": lambda p: _rewrite(p.payload(S.CORRELATION_LEAD, 0)),
    "gather summary rewritten at the same length": lambda p: _rewrite_in_place(
        p.gather_summary(S.CORRELATION_LEAD)),
    "raw payload rewritten at the same length": lambda p: _rewrite_in_place(
        p.payload(S.CORRELATION_LEAD, 0), b"dev.dana", b"eve.evil"),
}


@pytest.mark.parametrize("tamper", sorted(TAMPERS))
def test_p2_a_restore_that_does_not_match_refuses_the_arm_at_launch(tmp_path, tamper):
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


def _halve(path: Path) -> None:
    data = S.read_bytes(path)
    assert len(data) > 1, f"{path.name} holds nothing to cut"
    path.write_bytes(data[: len(data) // 2])


REVIEW_TAMPERS = {
    "review record shorter than recorded": lambda p: _halve(p.review_record(1)),
    "review record missing": lambda p: p.review_record(1).unlink(),
}


@pytest.mark.parametrize("tamper", sorted(REVIEW_TAMPERS))
def test_p2_a_review_record_that_does_not_match_refuses_the_arm_at_launch(tmp_path, tamper):
    bounds = challenge_gate.Bounds(extra_turns=1)
    stages = _gap_on("v-001")
    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0] + CHUNKS[1]), S.close(), S.append(CHUNKS[2]), S.close(),
                   S.done()),
        review_stages=stages, bounds=bounds)
    assert S.read_bytes(source.paths.review_record(1)), (
        "fixture: the source's first close left no review record")
    point = S.tool_calling_responses(source.store)[2]  # the fence appended after the challenge
    spec = S.spec_for(source, point)
    control = S.drive_arm(tmp_path, spec, S.Recorder([S.close(), S.done()]),
                          review_stages=stages, bounds=bounds, name="control",
                          run_id="control-1255")
    _arm_launched(control)
    forked = len(S.child_sessions(source.store))

    REVIEW_TAMPERS[tamper](source.paths)
    arm = S.drive_arm(tmp_path, spec, S.Recorder([S.close(), S.done()]),
                      review_stages=stages, bounds=bounds)

    assert not S.launched(arm), f"an arm launched over a source whose {tamper}"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert len(S.child_sessions(source.store)) == forked, "the refused arm still forked a session"


def test_n4_a_source_with_no_fork_snapshot_is_refused_at_launch(tmp_path, caplog):
    driven = S.drive_source(tmp_path / "driven", (S.append(CHUNKS[0]), S.echo("x"), S.done()))
    control = S.drive_arm(tmp_path / "driven", S.spec_for(driven, S.tool_calling_responses(driven.store)[1]),
                          S.Recorder([S.done()]))
    _arm_launched(control)

    store, run_dir, _session, path_ids = legal_source(
        tmp_path / "legacy", investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    call = path_ids[LEGACY_BRANCH_CALL]  # a tool-calling MAIN response after the document landed
    assert S.calls_of(S.message_at(store, call)), "the legacy fixture's call row moved"
    spec = spec_at(store, run_dir, call)
    store.connection.close()
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path / "legacy", spec, S.Recorder([S.done()]))

    assert not S.launched(arm), "an arm was launched from a source with no fork snapshot"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert "snapshot" in caplog.text.lower(), (
        f"the refusal does not name the missing fork snapshot: {caplog.text[-400:]!r}")


def _model_readable_records(paths: RunPaths) -> set[Path]:
    """The source's files an arm restores from — the model-readable records the snapshot describes — plus the case input."""
    keep = {paths.investigation, paths.executed_queries, paths.lessons_loaded,
            paths.policy_denials, paths.alert, paths.alert_record}
    rows = [json.loads(line) for line in _lines(paths.executed_queries) if line.strip()]
    leads = {str(r["lead_id"]) for r in rows if r.get("lead_id")}
    keep |= {paths.lead_claim(lead) for lead in leads} | {paths.gather_summary(lead)
                                                          for lead in leads}
    keep |= {paths.executed_queries.parent / str(r["payload_path"]) for r in rows
             if r.get("payload_path")}
    return {p.resolve() for p in keep}


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.is_dir() else []


def test_p3_the_fork_snapshot_is_not_kept_in_the_run_folder_or_the_tenant_agent_half(tmp_path):
    agent = _tenants1106.fixture_tenant().agent
    agent_before = _tree(agent)
    source = S.drive_source(tmp_path, (S.append(CHUNKS[0]), S.echo("x"), S.append(CHUNKS[1]),
                                       S.done()))
    assert _tree(agent) == agent_before, "the source run wrote into the tenant's agent half"
    point = S.tool_calling_responses(source.store)[1]  # `echo x`
    spec = S.spec_for(source, point)
    queries = S.read_bytes(source.paths.executed_queries)
    keep = _model_readable_records(source.paths)
    payload = source.paths.payload(S.CORRELATION_LEAD, 0).resolve()
    assert payload.is_file(), "fixture: the source has no correlation-lead payload"
    assert payload in keep, (
        "fixture: the correlation lead's payload is not among the records kept — the prune "
        "would take evidence the arm restores")
    removed = []
    for entry in sorted(source.run_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        resolved = entry.resolve()
        if resolved in keep:
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


def test_d2_a_call_time_configuration_fault_stays_down_after_the_fork(tmp_path):
    from pydantic_ai.messages import RetryPromptPart, ToolReturnPart

    from defender.kit.faults import ConfigFault

    reason = "FORK1255_REQUIRED_FEED_KEY"
    source_calls = []

    def fault_after_start(verb, params):
        source_calls.append(verb)
        if verb == "query":
            raise ConfigFault(f"{reason} is not set")
        return envelope(S.DOCS)

    source = S.drive_source(
        tmp_path, (S.append(CHUNKS[0]), S.dispatch("l-001"), S.echo("after-down"),
                   S.dispatch("l-002"), S.done()),
        leads={"l-001": (LEAD_QUERY, Turn(text="configuration is missing")),
               "l-002": (LEAD_QUERY, Turn(text="must not run"))},
        answer=fault_after_start)
    assert source_calls.count("query") == 1, "the source retried a permanently down adapter"
    assert "l-001" in source.gather.asked, "the faulting lead never ran"
    assert "l-002" not in source.gather.asked, "the source did not retain its escaped fault"
    point = S.tool_calling_responses(source.store)[2]
    (call,) = S.calls_of(S.message_at(source.store, point))
    assert call.args_as_dict().get("command") == "echo after-down"

    recovered_calls = []

    def healthy_again(verb, params):
        recovered_calls.append(verb)
        return envelope(S.DOCS)

    rec = VerbRecorder()
    arm = S.drive_arm(
        tmp_path, S.spec_for(source, point),
        S.Recorder([S.dispatch("l-002"), S.done()]),
        leads={"l-002": (LEAD_QUERY, Turn(text="must not run"))},
        verbs=elastic_backend(rec, healthy_again))
    _arm_launched(arm)
    assert "l-002" not in arm.gather.asked, "the fork reopened its source's down system"
    assert recovered_calls == [], "the recovered adapter ran despite the inherited refusal"
    assert len(arm.main.requests) >= 2, "the arm never observed its post-fork dispatch answer"
    answers = [str(part.content) for part in arm.main.requests[1][-1].parts
               if isinstance(part, ToolReturnPart | RetryPromptPart)
               and part.tool_name == "gather"]
    assert answers, "the arm never observed its post-fork dispatch refusal"
    refusal = "\n".join(answers)
    assert "not configured" in refusal.lower(), refusal
    assert reason in refusal, "the fork lost the original configuration-fault reason"
    assert "tripped" not in refusal.lower(), "configuration faults must not become breaker trips"
