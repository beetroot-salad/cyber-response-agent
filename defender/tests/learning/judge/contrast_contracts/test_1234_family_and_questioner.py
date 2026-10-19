"""#1234 judge contrast: family-scope call and questioner-queue routing."""
from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from defender.tests.learning.judge.contrast_contracts import _spec1234 as S


@pytest.fixture(autouse=True)
def _roomy_payload_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """No scenario here is about the default `JUDGE_PAYLOAD_CAP` except the two that set the knob
    themselves (d07b's second half, s_AM27), which override this inside the test body. With the
    cap out of reach, a reference trimmed or a world refused for size (A9) never decides a test
    about routing, commits or call counts."""
    monkeypatch.setenv(S.CAP_KNOB, "10000000")


#: The pass tables a reply keeps (main's names; #1234 does not rename them).
_PASS_TABLES = ("correlations", "scope_checks", "derivations")

SYSTEMS_KEY = S.RULED["row.systems"]
COMPLETED = S.RULED["row.completed_draws"]


def _lead(label: str) -> str:
    """A lead id only world `label`'s run uses (`l-<alnum>`, the lead-id grammar)."""
    return f"l-run{label}"


def _lead_triad(**extra: dict[str, Any]) -> list[S.World]:
    """The default triad with one distinctive lead per run, each lead querying a system or an
    entity a planted fact touches — so any per-run block of the computed context (contrast row,
    fact-surface hits) names that run's lead. `extra` adds or overrides worlds."""
    worlds: dict[str, dict[str, Any]] = {
        "a": {"calls": [S.CallRow(lead=_lead("a"))]},
        "b": {"calls": [S.CallRow(lead=_lead("b")),
                        S.oracle_call(fact_id="f-b", forged_id="fg-b-1", lead=_lead("b"))]},
        "c": {"calls": [S.CallRow(system="edr", params=S.query_params("host:db-1"),
                                  lead=_lead("c"))]},
    }
    worlds.update(extra)
    return S.triad(**worlds)


def _b_with_blocked_calls() -> list[S.CallRow]:
    """World b's calls: a passthrough (0), the altered answer (1), a grant refusal (2: a
    `∅.denied` table row and a `refused` ledger row) and an adapter fault (3: a `fault` row)."""
    return [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"), S.refused_call(),
            S.fault_call()]


def _asks(judge: S.RoutedJudge, label: str) -> list[tuple[Any, Any, int]]:
    """`(label, draw, attempt)` of every model call the fake recorded for `label`, in order."""
    return [S.parse_agent_id(a) for a in judge.calls_for(label)]


def _ids(rows: list[dict]) -> list[str]:
    return [str(r.get("finding_id")) for r in rows]


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {str(r.get("finding_id")): r for r in rows}


def _mentions(doc: Any, *tokens: str) -> bool:
    """Does any of `tokens` (a finding id, a claim marker) appear anywhere in `doc`?"""
    text = json.dumps(doc, sort_keys=True, default=str)
    return any(token in text for token in tokens)


def _all_keys(doc: Any) -> set[str]:
    """Every mapping key anywhere in `doc` (a record, a row list, a draw document)."""
    if isinstance(doc, dict):
        return {str(k) for k in doc} | {k for v in doc.values() for k in _all_keys(v)}
    if isinstance(doc, list):
        return {k for v in doc for k in _all_keys(v)}
    return set()


def _questioner_file(state: Any) -> Path:
    """Where the questioner channel's queue lives under `state`."""
    return Path(state.describe(S.sym(S.STATE, "QUESTIONER_FINDINGS")))


def _names_the_cap(row: dict) -> bool:
    text = json.dumps(row, default=str)
    return S.CAP_KNOB in text or re.search(r"\bcap\b", text, re.IGNORECASE) is not None


def _names_the_fault(row: dict) -> bool:
    """The P9 fault `RoutedJudge(fail=...)` raises: `RunUnprocessable` over a transport fault."""
    text = json.dumps(row, default=str)
    return "RunUnprocessable" in text or "TransportFault" in text


def _names_family_queueing(refused: BaseException) -> bool:
    """A refusal names the family row left `queueing`: the family's name and the row's state,
    each as a whole word (the bare word "family" alone is in nearly any message about it)."""
    text = str(refused)
    return bool(S.word_re(S.FAMILY).search(text) and S.word_re(S.QUEUEING).search(text))


def _lane(built: Any, finding_id: str) -> str | None:
    return S.lane_of(built, finding_id)


@pytest.mark.parametrize("retired", S.RETIRED_REPLY_WORDS)
def test_1234_family_reply_is_family_scope_world_findings_only(tmp_path: Path,
                                                               retired: str) -> None:
    built = S.family(tmp_path)
    claim = S.marker(S.FAMILY, "own-systems")
    finding = S.wf("unreachable", systems=("siem-x",), evidence=[S.plan_ptr()], claim=claim)
    carried = "survived" if retired == "verdict_word" else "gradable"
    old_shape = S.family_reply(world=[finding], **{retired: carried})
    judge = S.judge({S.FAMILY: [old_shape, S.family_reply(world=[finding])]})

    S.grade(built, judge, draws=1)

    assert _asks(judge, S.FAMILY) == [(S.FAMILY, 0, 0), (S.FAMILY, 0, 1)], (
        f"the reply carrying {retired!r} must be refused and draw 0 asked again once; the "
        f"family calls were {judge.calls_for(S.FAMILY)}")
    assert S.draw_files(built, S.FAMILY), "the family's accepted draw wrote no draw document"
    doc = S.draw_doc(built, S.FAMILY, 0)
    findings = doc.get(S.WORLD_FINDINGS)
    assert isinstance(findings, list), f"the family draw document holds {findings!r}"
    assert len(findings) == 1, f"the family draw document holds {findings!r}, not one finding"
    assert findings[0].get(SYSTEMS_KEY) == ["siem-x"], f"not its own systems: {findings[0]}"
    assert claim in json.dumps(findings[0])
    for table in _PASS_TABLES:
        assert table in doc, f"the family draw document lost its {table!r} pass table"
    for absent in (*S.RETIRED_REPLY_WORDS, S.INVESTIGATOR, S.GAPS, S.RULED["reply.bucket"],
                   S.RULED["reply.systems"]):
        assert absent not in doc, f"a family draw document carries {absent!r}"

    rows = S.from_world(S.questioner_queue(), S.FAMILY)
    assert [r.get(SYSTEMS_KEY) for r in rows] == [["siem-x"]], (
        f"the family finding's questioner row must carry its own systems, not the served "
        f"ones: {rows}")
    for what, written in (("judge.yaml", S.record(built)), ("the questioner rows", rows),
                          ("the draw document", doc)):
        assert retired not in _all_keys(written), f"{retired!r} is a field of {what}"
    assert retired in str(S.validate_refused(old_shape, scope=S.FAMILY)), (
        "the validator must refuse the retired word BY NAME")


def test_1234_family_prompt_carries_header_contrast_tables_and_fact_surfaces_for_every_run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    built = S.family(tmp_path, _lead_triad(), root=tmp_path / "whole")
    judge = S.judge()
    S.grade(built, judge, draws=1)

    assert judge.called(S.FAMILY), "the family call was never made"
    prompt = judge.prompt_for(S.FAMILY)
    for label in ("a", "b", "c"):
        assert S.marker(label, "story") in prompt, f"run {label}'s header is not in the prompt"
        assert _lead(label) in prompt, (
            f"run {label}'s contrast table / fact-surface hits are not in the family prompt")
    for label in ("b", "c"):
        assert S.marker(label, f"fact-f-{label}") in prompt, f"{label}'s fact surface is missing"

    monkeypatch.setenv(S.CAP_KNOB, "64")
    over = S.family(tmp_path, _lead_triad(), root=tmp_path / "over")
    small = S.judge()
    S.grade(over, small, draws=1)

    assert not small.called(S.FAMILY), "a family prompt over the cap still reached the model"
    family = S.family_row(over)
    assert family, "the refused family call left no family row naming why"
    assert family.get(S.STATE_KEY) != S.QUEUED, f"a refused family call is `queued`: {family}"
    assert not family.get(COMPLETED), f"a refused family call completed draws: {family}"
    assert _names_the_cap(family), f"the family row does not name the cap: {family}"


def test_1234_family_finding_citing_the_manifest_reaches_the_questioner_queue(
        tmp_path: Path) -> None:
    built = S.family(tmp_path)
    alone, serving, with_context = (S.marker(S.FAMILY, "plan-alone"),
                                    S.marker(S.FAMILY, "outcome-only"),
                                    S.marker(S.FAMILY, "plan-and-context"))
    draw0 = [S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()], claim=alone),
             S.wf("incoherent", systems=("edr",), evidence=[S.outcome_ptr()], claim=serving)]
    draw1 = [S.wf("mislabelled", systems=("siem-x",),
                  evidence=[S.plan_ptr("b"), S.outcome_ptr()], claim=with_context)]
    judge = S.judge({S.FAMILY: [S.family_reply(world=draw0), S.family_reply(world=draw1)]})

    S.grade(built, judge, draws=2)

    design = {built.finding_id(S.FAMILY, 0, 0): alone,
              built.finding_id(S.FAMILY, 1, 0): with_context}
    serving_id = built.finding_id(S.FAMILY, 0, 1)
    queued = _by_id(S.from_world(S.questioner_queue(), S.FAMILY))
    assert sorted(queued) == sorted(design), (
        f"the questioner channel holds {sorted(queued)}, wanted each design finding under its "
        f"own draw's id: {sorted(design)}")
    for finding_id, claim in design.items():
        assert claim in json.dumps(queued[finding_id])
        assert _lane(built, finding_id) == S.LANES["questioner"]
    assert _lane(built, serving_id) == S.LANES["user_record"]
    assert _mentions(S.serving_findings(built), serving_id, serving), (
        "the outcome.yaml-only family finding is not among the user record's serving findings")
    assert not _mentions(S.serving_findings(built), alone, with_context)
    assert not S.from_world(S.defender_queue(), S.FAMILY)


def test_1234_family_call_runs_once_and_a_rerun_only_without_a_completed_draw(
        tmp_path: Path) -> None:
    first = S.family_reply(world=[S.wf("unreachable", systems=("idp",),
                                       evidence=[S.plan_ptr()], claim=S.marker(S.FAMILY, "1"))])
    second = S.family_reply(world=[S.wf("incoherent", systems=("edr",),
                                        evidence=[S.plan_ptr()], claim=S.marker(S.FAMILY, "2"))])

    queued = S.family(tmp_path, root=tmp_path / "queued")
    S.grade(queued, S.judge(family_default=first), draws=1)
    assert S.family_row(queued).get(S.STATE_KEY) == S.QUEUED, (
        f"a completed family call must leave its row `queued`: {S.family_row(queued)}")
    before = S.queue_bytes()
    rerun = S.judge(family_default=second)
    S.grade(queued, rerun, draws=1)
    assert not rerun.called(S.FAMILY), "a `queued` family was asked again"
    assert S.queue_bytes() == before

    no_row = S.family(tmp_path, root=tmp_path / "no-row")
    S.grade(no_row, S.judge(fail={S.FAMILY}), draws=1)
    for label in ("b", "c"):
        assert S.row(no_row, label).get(S.STATE_KEY) == S.QUEUED, S.row(no_row, label)
    S.rewrite_record(no_row, lambda doc: doc.pop(S.FAMILY_ROW, None))
    asked = S.judge(family_default=first)
    S.grade(no_row, asked, draws=1)
    assert _asks(asked, S.FAMILY) == [(S.FAMILY, 0, 0)], (
        f"a family with no row must be asked once: {asked.calls_for(S.FAMILY)}")
    assert not asked.called("b"), "a `queued` world was re-graded"
    assert not asked.called("c"), "a `queued` world was re-graded"

    stuck = S.family(tmp_path, root=tmp_path / "queueing")
    S.grade(stuck, S.judge(family_default=first), draws=1)
    assert S.family_row(stuck).get(S.STATE_KEY) == S.QUEUED, S.family_row(stuck)

    def put_back(doc: dict) -> None:
        doc[S.FAMILY_ROW][S.STATE_KEY] = S.QUEUEING

    S.rewrite_record(stuck, put_back)
    before = S.queue_bytes()
    refused_judge = S.judge(family_default=second)
    refused = S.grade_refused(stuck, refused_judge, draws=1)
    assert _names_family_queueing(refused), f"the refusal does not name the family: {refused}"
    assert refused_judge.calls == 0, f"the refused re-run called {refused_judge.agent_ids}"
    assert S.queue_bytes() == before, "the refused re-run changed a queue"


def test_1234_family_findings_requeued_after_a_stopped_pass(tmp_path: Path) -> None:
    d0, d1 = (S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()],
                   claim=S.marker(S.FAMILY, "draw0")),
              S.wf("mislabelled", systems=("edr",), evidence=[S.plan_ptr("b")],
                   claim=S.marker(S.FAMILY, "draw1")))
    later = [S.wf("incoherent", systems=("siem-x",), evidence=[S.plan_ptr()],
                  claim=S.marker(S.FAMILY, f"later{n}")) for n in range(2)]

    stopped = S.family(tmp_path, root=tmp_path / "stopped")
    state_a = S.state_over(tmp_path / "state-stopped")
    queue_file = _questioner_file(state_a)
    S.plant_dir(queue_file)
    # How the refused append surfaces (a refusal, or the state handle's own StateRefused) is
    # s_AM17's; this test reads the record the stopped pass left.
    with contextlib.suppress(*S.stops()):
        S.grade(stopped, S.judge(family_default=S.family_reply(world=[d0])), draws=1,
                state=state_a)
    queue_file.rmdir()
    assert S.family_row(stopped).get(S.STATE_KEY) == S.QUEUEING, (
        "the family row must be written `queueing` before its append, and stay so when the "
        f"append is refused: {S.family_row(stopped)}")
    assert S.draw_files(stopped, S.FAMILY), "the family's completed draw left no file on disk"
    assert not S.from_world(S.questioner_queue(state_a), S.FAMILY)
    again = S.judge(family_default=S.family_reply(world=later))
    refused = S.grade_refused(stopped, again, draws=1, state=state_a)
    assert _names_family_queueing(refused), f"the refusal does not name the family: {refused}"
    assert not again.called(S.FAMILY), "complete draw files on disk counted as a completion"
    assert not S.from_world(S.questioner_queue(state_a), S.FAMILY)

    done = S.family(tmp_path, root=tmp_path / "done")
    state_b = S.state_over(tmp_path / "state-done")
    S.grade(done, S.judge({S.FAMILY: [S.family_reply(world=[d0]), S.family_reply(world=[d1])]}),
            draws=2, state=state_b)
    assert S.family_row(done).get(S.STATE_KEY) == S.QUEUED, S.family_row(done)
    wanted = sorted([done.finding_id(S.FAMILY, 0, 0), done.finding_id(S.FAMILY, 1, 0)])
    queued_ids = sorted(_ids(S.from_world(S.questioner_queue(state_b), S.FAMILY)))
    assert queued_ids == wanted, f"each family finding once: {queued_ids}"
    recorded = sorted(fid for fid, lanes in S.lanes(done).items()
                      if f"/{S.FAMILY}/" in fid and lanes == [S.LANES["questioner"]])
    assert recorded == queued_ids, "the record of what was queued disagrees with the queue"
    before = S.queue_bytes(state_b)
    rerun = S.judge({S.FAMILY: [S.family_reply(world=[w]) for w in later]})
    S.grade(done, rerun, draws=2, state=state_b)
    assert not rerun.called(S.FAMILY), "a `queued` family was asked again"
    assert S.queue_bytes(state_b) == before
    held = json.dumps(S.from_world(S.questioner_queue(state_b), S.FAMILY))
    assert d0["claim"] in held, "the first-written family finding of draw 0 is gone"
    assert d1["claim"] in held, "the first-written family finding of draw 1 is gone"
    assert not any(w["claim"] in held for w in later)


@pytest.mark.parametrize("failure", ["faulted", "completed-no-draw"])
def test_1234_family_call_failed_while_every_world_completed(tmp_path: Path,
                                                             failure: str) -> None:
    built = S.family(tmp_path)
    first = (S.judge(fail={S.FAMILY}) if failure == "faulted"
             else S.judge({S.FAMILY: S.family_reply(verdict_word="survived")}))
    S.grade(built, first, draws=1)

    assert first.called(S.FAMILY), "the first pass never asked the family"
    for label in ("b", "c"):
        assert S.row(built, label).get(S.STATE_KEY) == S.QUEUED, (
            f"world {label} completed and must be `queued`: {S.row(built, label)}")
    assert S.family_row(built).get(S.STATE_KEY) != S.QUEUED
    worlds_before = {label: S.row(built, label) for label in ("b", "c")}
    design = S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()],
                  claim=S.marker(S.FAMILY, "retried"))
    retry = S.judge(family_default=S.family_reply(world=[design]))
    S.grade(built, retry, draws=1)

    assert _asks(retry, S.FAMILY) == [(S.FAMILY, 0, 0)], (
        f"the family must be asked again on the next run: {retry.calls_for(S.FAMILY)}")
    assert not retry.called("b"), "a `queued` world was re-graded"
    assert not retry.called("c"), "a `queued` world was re-graded"
    assert S.family_row(built).get(S.STATE_KEY) == S.QUEUED, S.family_row(built)
    assert {label: S.row(built, label) for label in ("b", "c")} == worlds_before
    assert _ids(S.from_world(S.questioner_queue(), S.FAMILY)) == [
        built.finding_id(S.FAMILY, 0, 0)]


def test_1234_family_call_faults_after_the_worlds_rows_were_queued(tmp_path: Path) -> None:
    built = S.family(tmp_path)
    replies = {
        "b": S.world_reply("lead-quality", ["idp"],
                           investigator=[S.inv(claim=S.marker("b", "investigator"))]),
        "c": S.world_reply(S.NO_BUCKET, [], world=[S.wf(
            "mislabelled", systems=("edr",), evidence=[S.plan_ptr("c")],
            claim=S.marker("c", "design"))]),
    }
    S.grade(built, S.judge(replies, fail={S.FAMILY}), draws=1)

    for label in ("b", "c"):
        assert S.row(built, label).get(S.STATE_KEY) == S.QUEUED, S.row(built, label)
    defender, questioner = S.defender_queue(), S.questioner_queue()
    assert _ids(S.from_world(defender, "b")) == [built.finding_id("b", 0, 0)]
    assert _ids(S.from_world(questioner, "c")) == [built.finding_id("c", 0, 0)]
    assert not S.from_world(defender, S.FAMILY), "a family row reached the defender queue"
    assert not S.from_world(questioner, S.FAMILY), "the faulted family queued a row"
    family = S.family_row(built)
    assert family.get(S.STATE_KEY) != S.QUEUED
    assert _names_the_fault(family), f"judge.yaml's family row does not record the fault: {family}"

    defender_before, c_rows = S.queue_bytes()[0], S.from_world(questioner, "c")
    design = S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()],
                  claim=S.marker(S.FAMILY, "retry"))
    retry = S.judge(family_default=S.family_reply(world=[design]))
    S.grade(built, retry, draws=1)

    assert _asks(retry, S.FAMILY) == [(S.FAMILY, 0, 0)]
    assert not retry.called("b"), "a `queued` world was re-graded"
    assert not retry.called("c"), "a `queued` world was re-graded"
    assert S.family_row(built).get(S.STATE_KEY) == S.QUEUED, S.family_row(built)
    assert S.queue_bytes()[0] == defender_before, "the defender queue changed on the retry"
    assert S.from_world(S.questioner_queue(), "c") == c_rows


def _unusable_world(kind: str) -> dict[str, Any]:
    """World `zulu` (role D, its own lead) made O5-failed by its own world record (archive kept,
    a detail that must never be shown), or cut short. `malformed` is planted after the build."""
    spec: dict[str, Any] = {"role": "D", "calls": [S.CallRow(lead=_lead("zulu"))]}
    if kind == "o5-failed":
        spec.update(world_record=S.sym(S.OUTCOME, "ORACLE_UNSERVABLE"),
                    world_record_detail=S.marker("zulu", "detail"))
    elif kind == "cut-short":
        spec["run_end"] = {"truncated_by": "budget", "closed_before_cut": False}
    return spec


@pytest.mark.parametrize("kind", ["o5-failed", "cut-short", "malformed"])
def test_1234_family_prompt_lists_each_unusable_world_once_and_never_as_a_reference(
        tmp_path: Path, kind: str) -> None:
    built = S.family(tmp_path, _lead_triad(zulu=_unusable_world(kind)))
    if kind == "malformed":
        S.second_disposition(built.world_dir("zulu") / "report.md")
    judge = S.judge()
    S.grade(built, judge, draws=1)

    assert not judge.called("zulu"), "an unusable world was judged"
    for label in (S.FAMILY, "b", "c"):
        assert judge.called(label), f"{label}'s call was never made"
    family_prompt = judge.prompt_for(S.FAMILY)
    focus = {label: judge.prompt_for(label) for label in ("b", "c")}
    for label in ("a", "b", "c"):
        assert _lead(label) in family_prompt, f"usable run {label} is not a run of the family"
    for label, references in (("b", ("a", "c")), ("c", ("a", "b"))):
        for ref in references:
            assert S.marker(ref, "report") in focus[label], (
                f"{label}'s prompt does not carry reference run {ref}")
    hidden = (_lead("zulu"), S.marker("zulu", "report"), S.marker("zulu", "investigation"),
              S.marker("zulu", f"summary-{_lead('zulu')}"))
    leaked = [(where, token) for where, prompt in (("family", family_prompt), *focus.items())
              for token in hidden if token in prompt]
    assert not leaked, f"the {kind} world zulu reached a prompt as a run or reference: {leaked}"
    assert re.search(r"\bzulu\b", family_prompt), f"the {kind} world is not listed at all"
    if kind == "o5-failed":
        reason = S.sym(S.OUTCOME, "ORACLE_UNSERVABLE")
        assert family_prompt.count(reason) == 1, "the failed world is not listed exactly once"
        S.assert_wrapped_untrusted(family_prompt, reason, "world zulu's failure reason")
        assert S.marker("zulu", "detail") not in family_prompt, "a failed world's detail shown"


def test_1234_am_family_prompt_computed_sections_exceed_the_cap(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    head, tail = S.marker("c", "story-head"), S.marker("c", "story-tail")
    story = " ".join([head, *(["the second analyst re-read every host log before closing"]
                              * 1500), tail])
    worlds = S.triad(c={"story": story})

    monkeypatch.setenv(S.CAP_KNOB, "10000000")
    whole = S.family(tmp_path, worlds, root=tmp_path / "whole")
    roomy = S.judge()
    S.grade(whole, roomy, draws=1)
    assert roomy.called(S.FAMILY), "under a roomy cap the family call was never made"
    prompt = roomy.prompt_for(S.FAMILY)
    assert head in prompt, "the family's computed sections were trimmed"
    assert tail in prompt, "the family's computed sections were trimmed"

    monkeypatch.setenv(S.CAP_KNOB, "20000")
    over = S.family(tmp_path, worlds, root=tmp_path / "over")
    tight = S.judge()
    S.grade(over, tight, draws=1)
    assert not tight.called(S.FAMILY), "a family prompt over the cap was sent (trimmed?)"
    family = S.family_row(over)
    assert family, "the refused family call left no family row naming why"
    assert family.get(S.STATE_KEY) != S.QUEUED, f"a refused family call is `queued`: {family}"
    assert not family.get(COMPLETED), f"a refused family call completed draws: {family}"
    assert _names_the_cap(family), f"the family row does not name the cap: {family}"


def test_1234_questioner_row_is_design_only_with_systems(tmp_path: Path) -> None:
    built = S.family(tmp_path, S.triad(b={"calls": _b_with_blocked_calls()}))
    claims = {k: S.marker("b", k) for k in ("design", "serving", "gap")}
    b_findings = [
        S.wf("mislabelled", systems=("idp",), evidence=[S.plan_ptr("b")],
             claim=claims["design"]),
        S.wf("incoherent", systems=("edr",),
             evidence=[S.samples_ptr("idp"), built.served("b", built.served_row("b", 1))],
             claim=claims["serving"]),
        S.wf("unreachable", systems=("edr",),
             evidence=[S.plan_ptr("b"), built.table("b", built.own_row("b", 2)),
                       built.served("b", built.served_row("b", 2))],
             claim=claims["gap"]),
    ]
    c_finding = S.wf("mislabelled", systems=("edr", "idp"), evidence=[S.plan_ptr("c")],
                     claim=S.marker("c", "design"))
    family_finding = S.wf("unreachable", systems=("siem-x",), evidence=[S.plan_ptr()],
                          claim=S.marker(S.FAMILY, "design"))
    judge = S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=b_findings),
                     "c": S.world_reply(S.NO_BUCKET, [], world=[c_finding])},
                    family_default=S.family_reply(world=[family_finding]))

    S.grade(built, judge, draws=1)

    rows = _by_id(S.questioner_queue())
    expected = {built.finding_id("b", 0, 0): ["idp"], built.finding_id("c", 0, 0): ["edr", "idp"],
                built.finding_id(S.FAMILY, 0, 0): ["siem-x"]}
    assert sorted(rows) == sorted(expected), (
        f"the questioner channel holds {sorted(rows)}; only the design findings belong there")
    for finding_id, systems in expected.items():
        assert rows[finding_id].get(SYSTEMS_KEY) == systems, (
            f"{finding_id} carries {rows[finding_id].get(SYSTEMS_KEY)!r}, not its own systems")
    assert not _mentions(list(rows.values()), claims["serving"], claims["gap"])
    for row in rows.values():
        for retired in S.RETIRED_RECORD_FIELDS:
            assert retired not in row, f"a questioner row carries {retired!r}: {row}"


def test_1234_serving_only_world_finding_reaches_the_user_record_not_the_questioner_queue(
        tmp_path: Path) -> None:
    built = S.family(tmp_path)
    samples_only, served_too, control = (S.marker("b", "samples-only"),
                                         S.marker("b", "served-answer"), S.marker("b", "plan"))
    findings = [
        S.wf("incoherent", systems=("idp",), evidence=[S.samples_ptr("idp")], claim=samples_only),
        S.wf("incoherent", systems=("idp",),
             evidence=[S.samples_ptr("idp"), built.served("b", built.served_row("b", 1))],
             claim=served_too),
        S.wf("mislabelled", systems=("idp",), evidence=[S.plan_ptr("b")], claim=control),
    ]
    S.grade(built, S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=findings)}), draws=1)

    questioner, defender = S.questioner_queue(), S.defender_queue()
    assert built.finding_id("b", 0, 2) in _ids(questioner), (
        "the plan-citing control did not reach the questioner channel, so the channel's "
        "silence below would prove nothing")
    for i, claim in ((0, samples_only), (1, served_too)):
        finding_id = built.finding_id("b", 0, i)
        for name, queue in (("questioner", questioner), ("defender", defender)):
            assert not _mentions(queue, finding_id, claim), f"{claim} reached the {name} queue"
        assert _lane(built, finding_id) == S.LANES["user_record"]
        assert _mentions(S.serving_findings(built), finding_id, claim), (
            f"{claim} is not among the user record's serving findings")
    assert not _mentions(S.serving_findings(built), control)
