"""#1234 slice `family_and_questioner`: the family-level call and the questioner channel.

Twenty-three demands of `spec-flow/specs/spec_graph_1234.yaml` (80-survey.md, slice 9):

* the family call (design M6 as amended): its reply is family-scope world findings only, each
  carrying its own systems, with no verdict word (A4, A5, FX-reply-retired-names); its prompt
  reads no per-world reply, so it is identical before, between and after the world calls
  (P-c, A3); it carries every usable run's computed header, contrast table and fact surfaces,
  charged whole under `JUDGE_PAYLOAD_CAP` (A9, NA06); it commits like a world, `queueing` ->
  append -> `queued`, and a re-run asks it only when it has no row (A6); its draws combine by
  union (A13); and a pass makes one model call per planted world per draw plus the family's;
* routing (A1, A15, M5 residual (i)): a world or family finding that is not gap-only and has a
  resolving plan pointer is design and reaches the questioner channel under its own finding id
  with its own systems; a serving finding goes to the user record; a gap-only one goes to the
  user record whatever else it cites; a samples citation of an unshown section is dropped
  first (O16).

Every scenario drives the judge's one entry point, `grade_episode`, through `S.grade` over a
hand-built archived family (`S.family`), with the model seam `S.RoutedJudge` entering through
`judge=`. A model failure is #921's P9 `RunUnprocessable` (`RoutedJudge(fail=...)`); a refused
reply is scripted content in a retired shape the rulings refuse (A4, HOLE-2); a refused queue
write is a directory planted at the queue's name (`S.plant_dir`). Coined names come from
`S.COINED` / `S.RULED` only.
"""
from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S

# --------------------------------------------------------------------------------------
# Local helpers (requested as shared machinery in 82-writer-family_and_questioner.md).
# --------------------------------------------------------------------------------------

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


def _entry(built: Any, finding_id: str) -> dict:
    found = [e for e in S.ledger(built) if e.get("finding_id") == finding_id]
    assert len(found) == 1, f"{finding_id}: {len(found)} ledger entries, wanted one"
    return found[0]


def _names_run(entry: dict, built: Any, label: str) -> bool:
    """A found-gap entry's run names world `label` (by label, or by its world token)."""
    run = entry.get(S.COINED["found.run"])
    return run in (label, S.world_token(label, episode_token=built.token))


def _instructions(judge: S.RoutedJudge, label: str) -> str:
    """The host text a world's call was given: its user prompt outside the untrusted frames,
    plus the system turn its wiring names."""
    texts = [S.outside_untrusted_frames(judge.prompt_for(label))]
    for agent, kw in zip(judge.agent_ids, judge.kwargs, strict=True):
        path = getattr(kw.get("wiring"), "prompt_path", None)
        if S.parse_agent_id(agent)[0] == label and path is not None and Path(path).is_file():
            texts.append(Path(path).read_text(encoding="utf-8"))
            break
    return "\n".join(texts)


# --------------------------------------------------------------------------------------
# The family reply and its prompt.
# --------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _roomy_payload_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """No scenario here is about the default `JUDGE_PAYLOAD_CAP` except the two that set the knob
    themselves (d07b's second half, s_AM27), which override this inside the test body. With the
    cap out of reach, a reference trimmed or a world refused for size (A9) never decides a test
    about routing, commits or call counts."""
    monkeypatch.setenv(S.CAP_KNOB, "10000000")


@pytest.mark.parametrize("retired", S.RETIRED_REPLY_WORDS)
def test_1234_family_reply_is_family_scope_world_findings_only(tmp_path: Path,
                                                               retired: str) -> None:
    """d00c_family_reply_contract — validate_reply over a family_reply, written by the family
    call's draw loop.

    A family draw document holds family-scope world findings, each carrying its own systems
    (A5; the manifest's served systems are never stamped on), and the pass tables only; it
    carries no verdict_word and no episode_outcome, and a family reply carrying a retired
    verdict_word is refused at validation by that name and re-asked within _REPLY_ATTEMPTS
    (A4, A5), so no such word is read by anything the pass writes.

    How: the family's first ask returns a reply carrying the retired word (parametrized over
    both retired reply words, HOLE-2), the second the same findings without it. The finding
    names `siem-x` alone, so a row stamped with the served systems is told apart."""
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


def test_1234_family_prompt_reads_no_per_world_reply(tmp_path: Path) -> None:
    """d07a_family_reads_no_world_reply — _build_family_prompt reads no JudgeReply (the family
    call's prompt, built beside the family_reply it asks for).

    A marker planted in world b's reply (its bucket text and a finding claim) never reaches the
    family prompt, and the family prompt is identical whether b's draw succeeded, was refused
    or failed (today it carries b's bucket, E-05).

    How: three episodes off one builder; b's reply succeeds (a discipline bucket, an
    investigator and a world finding, a noise note, each carrying a marker), is refused on
    every ask (the retired episode_outcome shape), or fails (P9). Positive control: in the
    succeeded run the marker is in b's draw document, so the reply was read and recorded; and
    every family prompt carries b's archive-derived story, so the channel sees b at all."""
    claim, world_claim, noise = (S.marker("b", "reply-claim"), S.marker("b", "reply-world"),
                                 S.marker("b", "reply-noise"))
    answered = S.world_reply(
        "decision-discipline", ["idp"],
        investigator=[S.inv("decision-discipline", claim=claim)],
        world=[S.wf("mislabelled", evidence=[S.plan_ptr("b")], claim=world_claim)],
        noise_floor_note=noise)
    refused_shape = S.world_reply("decision-discipline", ["idp"], episode_outcome="gradable")
    scenarios = {"succeeded": S.judge({"b": answered}),
                 "refused": S.judge({"b": refused_shape}),
                 "failed": S.judge(fail={"b"})}

    built_of: dict[str, S.Built] = {}
    for name, judge in scenarios.items():
        built = S.family(tmp_path, root=tmp_path / name)
        S.grade(built, judge, draws=1)
        built_of[name] = built

    succeeded = built_of["succeeded"]
    assert S.draw_files(succeeded, "b"), "world b's accepted reply wrote no draw document"
    assert claim in json.dumps(S.draw_doc(succeeded, "b", 0), default=str), (
        "the marker never reached what the pass recorded for b, so its absence below would "
        "prove nothing")
    prompts: dict[str, str] = {}
    for name, judge in scenarios.items():
        assert judge.called(S.FAMILY), f"{name}: the family call was never made"
        prompts[name] = judge.prompt_for(S.FAMILY)
    for name, prompt in prompts.items():
        assert S.marker("b", "story") in prompt, f"{name}: the family prompt never shows b"
        for planted in (claim, world_claim, noise):
            assert planted not in prompt, f"{name}: b's reply text {planted} reached the family"
    normalized = {name: S.normalized_prompt(p, built_of[name]) for name, p in prompts.items()}
    assert normalized["succeeded"] == normalized["refused"] == normalized["failed"], (
        "the family prompt changed with how b's draw went, so it reads b's reply")


def test_1234_family_prompt_carries_header_contrast_tables_and_fact_surfaces_for_every_run(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """d07b_family_input — _build_family_prompt over the JudgeContext of every run, under
    JUDGE_PAYLOAD_CAP (its small value), for the family_reply.

    The family prompt carries the computed header, a contrast table and the fact surfaces for
    every run, the control included, each whole; a family prompt whose computed sections exceed
    the cap is refused with its reason named on the family row, and no family call runs.

    How: each run has its own lead (`l-run<X>`) querying a system or entity a planted fact
    touches, so the run's contrast row and fact-surface hits name it; the header carries each
    run's story marker and the fact surfaces each planted fact. Then the same family under a
    64-character cap."""
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


def test_1234_family_call_returns_findings_and_no_verdict_word(tmp_path: Path) -> None:
    """d07c_family_returns_no_word — _build_family_prompt, validate_reply, family_reply,
    EpisodeGrade.

    The family prompt asks for family-scope world findings and names no verdict word; a family
    reply carrying a retired verdict_word is refused at validation and re-asked (A4, A5); after
    the call judge.yaml carries no family word.

    How: the prompt's host text (outside the untrusted frames) names the three world-finding
    buckets and none of the family word vocabulary; the first ask's reply carries `survived`, the second does not, and its
    finding reaches the questioner channel."""
    built = S.family(tmp_path)
    claim = S.marker(S.FAMILY, "finding")
    finding = S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()], claim=claim)
    judge = S.judge({S.FAMILY: [S.family_reply(world=[finding], verdict_word="survived"),
                                S.family_reply(world=[finding])]})

    S.grade(built, judge, draws=1)

    assert judge.called(S.FAMILY), "the family call was never made"
    prompt = judge.prompt_for(S.FAMILY)
    host = S.outside_untrusted_frames(prompt)
    for bucket in S.WORLD_FINDING_BUCKETS:
        assert bucket in host, f"the family prompt does not ask for {bucket!r} world findings"
    for word in S.RETIRED_FAMILY_WORDS:
        assert not S.word_re(word).search(host), f"the family prompt names {word!r}"
    assert _asks(judge, S.FAMILY) == [(S.FAMILY, 0, 0), (S.FAMILY, 0, 1)], (
        f"a verdict_word reply must be refused and re-asked: {judge.calls_for(S.FAMILY)}")
    assert _mentions(S.questioner_queue(), claim), "the accepted family finding was not queued"
    record = S.record(built)
    assert record, "the pass wrote no judge.yaml"
    for retired in S.RETIRED_RECORD_FIELDS:
        assert retired not in record, f"judge.yaml carries {retired!r}"
        assert retired not in S.family_row(built), f"the family row carries {retired!r}"
    assert not S.word_re("survived").search(S.record_text(built)), (
        "judge.yaml carries the family word the refused reply offered")


# --------------------------------------------------------------------------------------
# Family findings: routing, systems, union across draws.
# --------------------------------------------------------------------------------------


def test_1234_family_finding_citing_the_manifest_reaches_the_questioner_queue(
        tmp_path: Path) -> None:
    """d07d_family_manifest_allowlist — _resolves over family_manifest.access[pointer];
    route_finding; append_world_rows -> QUESTIONER_FINDINGS.

    Each completed family draw's family-scope finding that is not gap-only and has a resolving
    plan pointer (family.yaml#..., alone or with context) routes design and is queued on the
    questioner channel under its own draw's finding id (A13: the family combines by union),
    while one citing only outcome.yaml routes serving to the user record.

    How: two family draws. Draw 0 files a finding citing the family-level part of the plan
    alone and one citing only pre-flight's record; draw 1 files one citing world b's plan entry
    beside pre-flight's record."""
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


def test_1234_family_scope_design_finding_naming_no_served_system(tmp_path: Path) -> None:
    """s_A54 — validate_reply over a family_reply; the append_world_rows ->
    QUESTIONER_FINDINGS payload.

    Family findings carry their own systems (A5); one with empty systems or a name failing the
    system-token grammar is refused at reply validation and re-asked within
    `_REPLY_ATTEMPTS`; the manifest's served systems are not stamped on.

    How: for each refused shape (an empty list; `IDP`, outside the lower-case token grammar),
    the family's first ask files the finding with it and the second files the same design
    finding naming `netflow` — a grammar-valid system the tenant does not serve, which is the
    situation's 'no served system settles the predicate' and is NOT refused (names are checked
    against the grammar, not the served set)."""
    for case, bad in (("empty", []), ("grammar", ["IDP"])):
        built = S.family(tmp_path, root=tmp_path / case)
        state = S.state_over(tmp_path / f"state-{case}")
        refused_claim, kept_claim = S.marker(S.FAMILY, f"{case}-bad"), S.marker(S.FAMILY, case)
        bad_doc = S.family_reply(world=[S.wf("unreachable", systems=bad,
                                             evidence=[S.plan_ptr()], claim=refused_claim)])
        good_doc = S.family_reply(world=[S.wf("unreachable", systems=("netflow",),
                                              evidence=[S.plan_ptr()], claim=kept_claim)])
        judge = S.judge({(S.FAMILY, 0, 0): bad_doc, (S.FAMILY, 0, 1): good_doc})

        S.grade(built, judge, draws=1, state=state)

        assert _asks(judge, S.FAMILY) == [(S.FAMILY, 0, 0), (S.FAMILY, 0, 1)], (
            f"{case}: the family finding with systems {bad!r} must be refused and re-asked; "
            f"calls were {judge.calls_for(S.FAMILY)}")
        rows = S.from_world(S.questioner_queue(state), S.FAMILY)
        assert _ids(rows) == [built.finding_id(S.FAMILY, 0, 0)]
        assert rows[0].get(SYSTEMS_KEY) == ["netflow"], (
            f"{case}: the questioner row must carry the finding's own systems, never the "
            f"manifest's served systems: {rows[0].get(SYSTEMS_KEY)!r}")
        assert kept_claim in json.dumps(rows)
        assert refused_claim not in json.dumps(rows), f"{case}: the refused finding was queued"
        S.validate_refused(bad_doc, scope=S.FAMILY)


def test_1234_am_family_draws_combining(tmp_path: Path) -> None:
    """s_AM26 — _world_answers over the family_reply draws (JUDGE_DRAWS at 3);
    append_world_rows -> QUESTIONER_FINDINGS.

    Every completed family draw's kept findings route by class under their own finding_id
    (A13, no cross-draw matching): two draws filing the same design finding yield two
    questioner rows, the third draw's different finding a third; a draw filing nothing adds
    none. The family row records its completed draws."""
    same = S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr()],
                claim=S.marker(S.FAMILY, "same"))
    other = S.wf("mislabelled", systems=("edr",), evidence=[S.plan_ptr("b")],
                 claim=S.marker(S.FAMILY, "other"))
    cases = {"repeated": [[same], [same], [other]], "one-draw-empty": [[same], [], [other]]}
    for case, per_draw in cases.items():
        built = S.family(tmp_path, root=tmp_path / case)
        state = S.state_over(tmp_path / f"state-{case}")
        judge = S.judge({S.FAMILY: [S.family_reply(world=w) for w in per_draw]})

        S.grade(built, judge, draws=3, state=state)

        expected = {built.finding_id(S.FAMILY, n, 0): w[0] for n, w in enumerate(per_draw) if w}
        rows = S.from_world(S.questioner_queue(state), S.FAMILY)
        assert sorted(_ids(rows)) == sorted(expected), (
            f"{case}: the questioner channel holds {sorted(_ids(rows))}, wanted one row per "
            f"filed finding per draw: {sorted(expected)}")
        by_id = _by_id(rows)
        for finding_id, finding in expected.items():
            assert finding["claim"] in json.dumps(by_id[finding_id])
            assert _lane(built, finding_id) == S.LANES["questioner"]
        assert S.family_row(built).get(COMPLETED) == 3, (
            f"{case}: the family row must record its three completed draws: "
            f"{S.family_row(built)}")


def test_1234_family_call_sees_one_gap_that_blocked_every_world(tmp_path: Path) -> None:
    """s_A73 — _build_family_prompt, family_reply, user_record, route_finding.

    The observation goes to the user record, filed by the code's gap computation; the family
    reply carries no gap list, and a family finding resting only on it is gap-only and refused
    onto the user record (also when the one blocked system is J3's inherited pre-branch
    denial, A14).

    How: two families — every world (control included) refused the same `edr lookup` on its
    own (a `∅.denied` table row joined to a `refused` ledger row), or every world inherited the
    one pre-branch denial. The family files a finding citing only those rows and, as the
    control of the classifier, one citing b's ordinary passthrough row beside the plan."""
    for source in ("own-refusals", "inherited-denial"):
        if source == "own-refusals":
            worlds = S.triad(
                a={"calls": [S.CallRow(), S.refused_call()]},
                b={"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"),
                             S.refused_call()]},
                c={"calls": [S.CallRow(system="edr", params=S.query_params("host:db-1")),
                             S.refused_call()]})
            built = S.family(tmp_path, worlds, root=tmp_path / source)
            refusal = {"a": 1, "b": 2, "c": 1}
            blocked = [p for label, i in refusal.items()
                       for p in (built.table(label, built.own_row(label, i)),
                                 built.served(label, built.served_row(label, i)))]
        else:
            built = S.family(tmp_path, root=tmp_path / source, inherited=[S.inherited_denial()])
            blocked = [built.table(label, 0) for label in ("a", "b", "c")]
        state = S.state_over(tmp_path / f"state-{source}")
        gap_claim, design_claim = S.marker(S.FAMILY, f"{source}-gap"), S.marker(S.FAMILY, source)
        reply = S.family_reply(world=[
            S.wf("unreachable", systems=("edr",), evidence=blocked, claim=gap_claim),
            S.wf("incoherent", systems=("idp",),
                 evidence=[built.table("b", built.own_row("b", 0)), S.plan_ptr()],
                 claim=design_claim)])

        S.grade(built, S.judge(family_default=reply), draws=1, state=state)

        found = [e for e in S.found_gaps(built)
                 if e.get(S.COINED["found.system"]) == "edr"
                 and e.get(S.COINED["found.verb"]) == "lookup"]
        assert found, f"{source}: the code's gap computation did not file the blocked call"
        if source == "own-refusals":
            for label in ("a", "b", "c"):
                assert any(_names_run(e, built, label) for e in found), (
                    f"run {label}'s refused call is not among the found gaps: {found}")
        assert S.draw_files(built, S.FAMILY), f"{source}: the family call wrote no draw"
        assert S.GAPS not in S.draw_doc(built, S.FAMILY, 0), "a family reply carries gaps"
        gap_id, design_id = (built.finding_id(S.FAMILY, 0, 0), built.finding_id(S.FAMILY, 0, 1))
        assert _lane(built, gap_id) == S.LANES["user_record"], (
            f"{source}: a family finding resting only on blocked calls is gap-only")
        assert _mentions(S.user(built), gap_id, gap_claim), (
            f"{source}: the gap-only family finding is not on the user record")
        for queue in (S.questioner_queue(state), S.defender_queue(state)):
            assert not _mentions(queue, gap_id, gap_claim), "a gap reached a lesson queue (P-a)"
        assert _lane(built, design_id) == S.LANES["questioner"]
        assert design_id in _ids(S.questioner_queue(state))


# --------------------------------------------------------------------------------------
# The family's commit (A6) and the call count.
# --------------------------------------------------------------------------------------


def test_1234_family_call_runs_once_and_a_rerun_only_without_a_completed_draw(
        tmp_path: Path) -> None:
    """d07e_family_runs_once — grade_episode, family_reply, EpisodeGrade, with the family row's
    world_row_state at `queued` and at `queueing`.

    A bare re-run makes no family call when judge.yaml's family row is `queued`, makes one when
    the family has no row, and refuses naming the family when its row is left `queueing` (A6).

    How: three families. `queued` is what a completed pass leaves. No row: a pass whose family
    call failed (P9) appended nothing of the family; its family row, if any, is removed — the
    state a pass stopped before the family's first write leaves. `queueing`: a completed
    pass's family row put back to `queueing` — the state a stop between the family's append and
    its flip leaves."""
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
    """s_A2 — grade_episode, family_reply, the family row's world_row_state `queueing` then
    `queued`, append_world_rows -> QUESTIONER_FINDINGS.

    The family call commits the same way (A6): `queueing`, append, `queued`. A family row left
    `queueing` refuses the re-run naming the family; a `queued` family row is skipped, so the
    family call is not asked again and the questioner queue holds each family-scope finding
    once. judge.yaml, not draw files on disk, decides whether the family call has completed;
    the record of what was queued agrees with the queue.

    How: (1) the pass stops at the family's append — a directory planted at the questioner
    queue's name refuses the write. The family row is left `queueing` though its draw is
    complete on disk, and the re-run refuses naming the family. (2) A completed two-draw pass;
    the re-run would answer different findings at the same coordinates and is never asked."""
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
    """s_L5 — grade_episode, family_reply, the family call's draws, world_row_state `queued`.

    A family call that faulted or completed no draw leaves the family row without `queued`;
    the next run asks it again (A6: no row, regrade); `queued` worlds stay skipped.

    How: the family call faults (P9), or every ask returns the retired verdict_word shape and
    is refused; both planted worlds complete. The re-run answers the family with one design
    finding."""
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
    """s_L12 — grade_episode, family_reply, world_row_state `queued`.

    The family fault is recorded; the family row is not `queued`, so the next run retries the
    family call; queued world rows stay (A6).

    How: b files an investigator finding (a defender row), c a design world finding (a
    questioner row), and the family call faults (P9). The retry files one family finding."""
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


def test_1234_model_call_count_is_one_per_world_per_draw_plus_one_family_call(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """g02_model_call_count_per_pass — grade_episode, _run_world_draws, JUDGE_DRAWS at 3.

    With JUDGE_DRAWS=3 over a triad (control and two planted worlds) a fresh pass makes exactly
    one model call per planted world per draw plus the family call's draws (six world calls
    and three family calls), however many reference runs each prompt carries; a stamped pass
    and a fully queued re-run make none.

    How: a pair, the triad and a four-world family, each read from the knob; then a re-run of
    each, and a family without its family stamp (not comparable)."""
    monkeypatch.setenv(S.DRAWS_KNOB, "3")
    for shape, planted in (("pair", ("b",)), ("triad", ("b", "c")),
                           ("quad", ("b", "c", "d"))):
        worlds = [w for w in S.triad(d={"role": "D", "forged_system": "siem-x",
                                         "calls": [S.CallRow()]})
                  if w.is_control or w.label in planted]
        built = S.family(tmp_path, worlds, root=tmp_path / shape)
        judge = S.judge()
        S.grade(built, judge, draws=None)

        for label in planted:
            assert _asks(judge, label) == [(label, n, 0) for n in range(3)], (
                f"{shape}: world {label} calls {judge.calls_for(label)}")
        assert _asks(judge, S.FAMILY) == [(S.FAMILY, n, 0) for n in range(3)]
        assert not judge.called("a"), "the control is a reference, never a judged world"
        assert judge.calls == 3 * len(planted) + 3, f"{shape}: {judge.agent_ids}"

        rerun = S.judge()
        S.grade(built, rerun, draws=None)
        assert rerun.calls == 0, f"{shape}: a fully queued re-run called {rerun.agent_ids}"

    stamped = S.family(tmp_path, S.triad(), root=tmp_path / "stamped", family_stamp=False)
    unpaid = S.judge()
    S.grade(stamped, unpaid, draws=None)
    assert unpaid.calls == 0, f"a stamped pass called {unpaid.agent_ids}"


# --------------------------------------------------------------------------------------
# What the family prompt carries about each world.
# --------------------------------------------------------------------------------------


def test_1234_family_prompt_per_world_status_before_and_after_world_calls(
        tmp_path: Path) -> None:
    """s_A72 — _build_family_prompt over JudgeContext.

    The family prompt reads no per-world reply (M6), so it carries only code-derived status,
    identical in every position; model-derived status (not measured, bucket) never enters it.

    How: one family (with a cut-short world `zulu`: code-derived status) graded three ways —
    a fresh pass whose worlds give a bucket (b) and a not-measured world finding (c); a fresh
    pass whose every world call fails (no model status anywhere); and a re-run that asks the
    family AFTER both worlds' model status is on judge.yaml (the first pass's family call
    failed, P9). Positive control: that model status is on judge.yaml before the family call
    of the third run, and the cut-short world's label does reach the family prompt."""
    worlds = S.triad(zulu={"role": "D",
                           "run_end": {"truncated_by": "budget", "closed_before_cut": False}})
    investigator_claim, world_claim = S.marker("b", "status-claim"), S.marker("c", "status-wf")
    statuses = {
        "b": S.world_reply("lead-quality", ["idp"], investigator=[S.inv(claim=investigator_claim)]),
        "c": S.world_reply(S.NO_BUCKET, [], world=[S.wf("unreachable", evidence=[S.plan_ptr("c")],
                                                        claim=world_claim)]),
    }

    fresh = S.family(tmp_path, worlds, root=tmp_path / "fresh")
    with_status = S.judge(statuses)
    S.grade(fresh, with_status, draws=1)

    silent = S.family(tmp_path, worlds, root=tmp_path / "no-status")
    no_status = S.judge(fail={"b", "c"})
    S.grade(silent, no_status, draws=1)

    after = S.family(tmp_path, worlds, root=tmp_path / "after")
    S.grade(after, S.judge(statuses, fail={S.FAMILY}), draws=1)
    assert S.row(after, "b").get(S.RULED["reply.bucket"]) == "lead-quality", S.row(after, "b")
    assert S.row(after, "c").get(S.COINED["row.measured"]) is False, S.row(after, "c")
    late = S.judge()
    S.grade(after, late, draws=1)

    for position, asked in (("between", with_status), ("without-status", no_status),
                            ("after", late)):
        assert asked.called(S.FAMILY), f"{position}: the family call was never made"
    prompts = {"between": (with_status.prompt_for(S.FAMILY), fresh),
               "without-status": (no_status.prompt_for(S.FAMILY), silent),
               "after": (late.prompt_for(S.FAMILY), after)}
    for position, (prompt, _built) in prompts.items():
        assert re.search(r"\bzulu\b", prompt), f"{position}: the cut-short world is not listed"
        for planted in (investigator_claim, world_claim):
            assert planted not in prompt, f"{position}: a world reply's text reached the family"
    normalized = {position: S.normalized_prompt(p, b) for position, (p, b) in prompts.items()}
    assert normalized["between"] == normalized["without-status"] == normalized["after"], (
        "the family prompt differs with the worlds' model status, so it carries it")


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
    """g17_family_prompt_account_of_failed_worlds_agrees_with_the_references —
    render_family_text over the outcome_record, into the family prompt.

    The family prompt's account of pre-flight outcomes (render_family_text: failed worlds with
    reason and call, never detail) lists each O5-failed, cut-short and malformed world once,
    with its reason in an untrusted frame, and none of them as a reference run or fact
    surface; it agrees with the per-world prompts' reference sets for the same family. The
    control is a usable world, listed as a reference.

    How: the lead triad plus a fourth world `zulu` that is O5-failed (its own world record,
    archive present), cut short, or malformed (a report with two `disposition:` keys), one per
    case so O5's two-world bar is never reached. Every run's lead names it wherever its
    computed context appears."""
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
    """s_AM27 — _build_family_prompt under JUDGE_PAYLOAD_CAP (its small value), for the
    family_reply.

    The family prompt has none of the sections A9 trims first, and A9 never cuts sections 1-4:
    its computed sections (every run's header, contrast table and fact surfaces) are charged
    whole and never trimmed; a family prompt over the cap is refused with its reason named on
    the family row, and no family call runs (NA06).

    How: world c's story (header material) is ~85K characters between two markers. Under a
    10M cap the family prompt carries it whole; under the default 20000 the family call is
    refused rather than sent trimmed."""
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


# --------------------------------------------------------------------------------------
# World findings: design to the questioner channel, serving and gaps to the user record.
# --------------------------------------------------------------------------------------


def test_1234_questioner_row_is_design_only_with_systems(tmp_path: Path) -> None:
    """d00e_questioner_row_contract — build_finding_row, the append_world_rows ->
    QUESTIONER_FINDINGS payload.

    A questioner row is built only from a design world finding (world or family scope: not
    gap-only, with a resolving plan pointer, A1/A15), carries that finding's own systems (A5),
    and has no judge_outcome key.

    How: b files a design, a serving and a gap-only world finding; c a design one naming two
    systems; the family a design one. Read off what the appender wrote to the channel."""
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


def test_1234_world_finding_citing_the_manifest_goes_to_the_questioner_queue(
        tmp_path: Path) -> None:
    """d06a_design_finding_to_questioner — route_finding over family_manifest.access[pointer];
    append_world_rows -> QUESTIONER_FINDINGS.

    A world finding that is not gap-only and has at least one resolving plan pointer
    (family.yaml#..., alone or beside context pointers) is routed design and queued on the
    questioner channel with its own systems (A1, A15; M5 residual (i)).

    How: b files three: its own plan entry alone; its plan entry beside a samples section and
    pre-flight's record; the family-level part of the plan alone (names no run, so it counts
    for b)."""
    built = S.family(tmp_path)
    findings = [
        S.wf("mislabelled", systems=("idp",), evidence=[S.plan_ptr("b")],
             claim=S.marker("b", "plan")),
        S.wf("unreachable", systems=("edr",),
             evidence=[S.plan_ptr("b"), S.samples_ptr("idp"), S.outcome_ptr()],
             claim=S.marker("b", "plan-context")),
        S.wf("incoherent", systems=("siem-x",), evidence=[S.plan_ptr()],
             claim=S.marker("b", "family-part")),
    ]
    S.grade(built, S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=findings)}), draws=1)

    rows = _by_id(S.from_world(S.questioner_queue(), "b"))
    for i, finding in enumerate(findings):
        finding_id = built.finding_id("b", 0, i)
        assert finding_id in rows, f"design finding {finding['claim']} is not queued: {rows}"
        assert rows[finding_id].get(SYSTEMS_KEY) == finding["systems"]
        assert finding["claim"] in json.dumps(rows[finding_id])
        assert _lane(built, finding_id) == S.LANES["questioner"]
    assert not _mentions(S.serving_findings(built), *(f["claim"] for f in findings))
    assert not S.from_world(S.defender_queue(), "b")


def test_1234_serving_only_world_finding_reaches_the_user_record_not_the_questioner_queue(
        tmp_path: Path) -> None:
    """d06b_serving_finding_to_user_record — route_finding, user_record, append_world_rows ->
    QUESTIONER_FINDINGS.

    A world finding with no resolving plan pointer (one citing only samples.yaml#<system> and
    served answers included) is absent from the questioner channel and listed among the user
    record's serving findings.

    How: b files a finding citing only a samples section, one citing a samples section and
    b's own altered served answer, and — the positive control on the same reply — one citing
    b's plan entry. Every surface a serving finding could reach is read: both queues, the
    ledger, the user record."""
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


def test_1234_serving_flaw_finding_also_cites_the_manifest_for_context(tmp_path: Path) -> None:
    """s_A52 — route_finding over family_manifest.access[pointer]; user_record;
    append_world_rows -> QUESTIONER_FINDINGS.

    Routing is mechanical (A1): a serving flaw that cites `family.yaml` for context has a
    resolving plan pointer and is not gap-only, so it is design and reaches the questioner
    queue; the prompt instruction 'cite family.yaml only where the flaw is in the plan' bounds
    the leak, which the human accepted (70-resolutions, M5 residual (i)).

    How: b's finding about an altered answer that does not hang together cites the served
    answer, the oracle store's forged row, and b's plan entry; b's call carries the
    instruction in its host text."""
    built = S.family(tmp_path)
    claim = S.marker("b", "serving-flaw")
    finding = S.wf("incoherent", systems=("idp",),
                   evidence=[built.served("b", built.served_row("b", 1)),
                             built.oracle("b", "forged.jsonl", "0"), S.plan_ptr("b")],
                   claim=claim)
    judge = S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=[finding])})
    S.grade(built, judge, draws=1)

    finding_id = built.finding_id("b", 0, 0)
    rows = _by_id(S.questioner_queue())
    assert finding_id in rows, "the plan-citing serving flaw did not route design"
    assert rows[finding_id].get(SYSTEMS_KEY) == ["idp"]
    assert _lane(built, finding_id) == S.LANES["questioner"]
    assert not _mentions(S.serving_findings(built), finding_id, claim)
    assert re.search(S.COINED["re.plan_cite_rule"], _instructions(judge, "b"),
                     re.IGNORECASE | re.DOTALL), (
        "the judge is not told to cite family.yaml only where the flaw is in the plan")


def test_1234_world_finding_citing_the_manifest_and_otherwise_only_refusals(
        tmp_path: Path) -> None:
    """s_A53 — route_finding, user_record, served_ledger, append_world_rows ->
    QUESTIONER_FINDINGS.

    Gap-only is checked first (A1 rule 3, A15): when at least one resolving conduct pointer
    exists and every one is a blocked-call row the finding is gap-only and goes to the user
    record; design needs 'not gap-only' (rule 4), so a manifest pointer beside refusal rows
    does not make it design.

    How: b refused one call and faulted one. b files: the plan beside the refusal's table and
    ledger rows and the fault's ledger row; the plan beside the refusal's table row and a
    samples section (context is set aside); and, as the control, the plan beside b's ordinary
    passthrough row, which is design."""
    built = S.family(tmp_path, S.triad(b={"calls": _b_with_blocked_calls()}))
    refused_row, refused_led = built.own_row("b", 2), built.served_row("b", 2)
    claims = [S.marker("b", k) for k in ("refusals", "refusal-and-context", "passthrough")]
    findings = [
        S.wf("unreachable", systems=("edr",),
             evidence=[S.plan_ptr("b"), built.table("b", refused_row),
                       built.served("b", refused_led),
                       built.served("b", built.served_row("b", 3))], claim=claims[0]),
        S.wf("unreachable", systems=("edr",),
             evidence=[S.plan_ptr("b"), built.table("b", refused_row), S.samples_ptr("idp")],
             claim=claims[1]),
        S.wf("mislabelled", systems=("idp",),
             evidence=[S.plan_ptr("b"), built.table("b", built.own_row("b", 0))],
             claim=claims[2]),
    ]
    S.grade(built, S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=findings)}), draws=1)

    questioner, defender = S.questioner_queue(), S.defender_queue()
    for i in (0, 1):
        finding_id = built.finding_id("b", 0, i)
        assert _lane(built, finding_id) == S.LANES["user_record"], (
            f"{claims[i]}: a plan pointer beside only blocked-call rows made it design")
        assert _mentions(S.user(built), finding_id, claims[i]), f"{claims[i]} not on the record"
        for queue in (questioner, defender):
            assert not _mentions(queue, finding_id, claims[i]), "a gap reached a lesson queue"
    control_id = built.finding_id("b", 0, 2)
    assert _lane(built, control_id) == S.LANES["questioner"]
    assert control_id in _ids(questioner)


def test_1234_design_finding_also_citing_an_unshown_samples_section(tmp_path: Path) -> None:
    """s_A56 — _draw_document, LEDGER_LANES at `unqueueable`, samples_record.

    A design-routed world finding citing an unshown or unavailable samples section: the
    sample-citation drop (O16) applies first, the finding is dropped for citing an unshown
    section; M5 routing applies only to kept findings. The drop is per-world: the family call
    is shown no samples record, so a family finding's samples pointer is set aside as
    unresolved instead (R4 (3), human 2026-10-12; s_AM1).

    How: the samples record marks `edr` unavailable and holds real answers for `netflow`, a
    system the tenant does not serve. b files three plan-citing findings, beside the `edr`
    section, the `netflow` section, and (the control) the served `idp` section. A dropped
    finding keeps today's `unqueueable` lane with its reason."""
    answers = {"verbs": {"query": [json.dumps({"rows": []})]}}
    samples = {"idp": answers, "siem-x": answers, "netflow": answers,
               "edr": {"unavailable": "no answers were captured for this system"}}
    built = S.family(tmp_path, samples=samples)
    claims = [S.marker("b", k) for k in ("unavailable", "unserved", "shown")]
    findings = [S.wf("unreachable", systems=("idp",),
                     evidence=[S.plan_ptr("b"), S.samples_ptr(system)], claim=claim)
                for system, claim in zip(("edr", "netflow", "idp"), claims, strict=True)]
    S.grade(built, S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=findings)}), draws=1)

    questioner, defender = S.questioner_queue(), S.defender_queue()
    control_id = built.finding_id("b", 0, 2)
    assert control_id in _ids(questioner), (
        "the finding citing the served `idp` section did not route design, so the drops below "
        "would prove nothing")
    assert _lane(built, control_id) == S.LANES["questioner"]
    for i in (0, 1):
        finding_id = built.finding_id("b", 0, i)
        entry = _entry(built, finding_id)
        assert entry.get("lane") == S.LANES["unqueueable"], (
            f"{claims[i]}: the O16 drop must come before routing: {entry}")
        assert S.word_re(S.COINED["reason.samples"]).search(str(entry.get("reason"))), (
            f"the drop names no samples reason: {entry}")
        for doc in (questioner, defender, S.serving_findings(built)):
            assert not _mentions(doc, finding_id, claims[i]), f"{claims[i]} was routed"


def test_1234_am_world_finding_citing_only_the_plan_and_context(tmp_path: Path) -> None:
    """s_AM1 — route_finding over family_manifest.access[pointer]; _resolves over the
    samples_record; append_world_rows -> QUESTIONER_FINDINGS.

    A finding with no resolving conduct pointer is not gap-only (A15): rule 3 needs at least
    one resolving conduct pointer and every one blocked. A world or family finding citing
    `family.yaml` and `samples.yaml` only has a resolving plan pointer, is design, and reaches
    the questioner queue (I5). The family call is shown no samples record (M6), so a family
    finding's `samples.yaml` pointer is unresolved and set aside: the finding routes on its plan
    pointer alone and its row cites only that, while a world finding's samples pointer, whose
    section the world prompt shows, resolves and is cited (R4 (3), human 2026-10-12: O16's
    sample-citation drop stays per-world).

    How: b files one citing the family-level plan and a samples section, and one citing its
    plan entry, a samples section and its own oracle-store row (built layer, not conduct); the
    family files one of the first shape. The idp samples section's marker is in b's prompt
    (the positive control) and not in the family prompt."""
    built = S.family(tmp_path)
    world_findings = [
        S.wf("unreachable", systems=("idp",), evidence=[S.plan_ptr(), S.samples_ptr("idp")],
             claim=S.marker("b", "plan-samples")),
        S.wf("mislabelled", systems=("idp",),
             evidence=[S.plan_ptr("b"), S.samples_ptr("idp"),
                       built.oracle("b", "forged.jsonl", "0")],
             claim=S.marker("b", "plan-samples-oracle")),
    ]
    family_finding = S.wf("unreachable", systems=("idp",),
                          evidence=[S.plan_ptr(), S.samples_ptr("idp")],
                          claim=S.marker(S.FAMILY, "plan-samples"))
    judge = S.judge({"b": S.world_reply(S.NO_BUCKET, [], world=world_findings)},
                    family_default=S.family_reply(world=[family_finding]))
    S.grade(built, judge, draws=1)

    queued = _ids(S.questioner_queue())
    for finding_id, finding in ((built.finding_id("b", 0, 0), world_findings[0]),
                                (built.finding_id("b", 0, 1), world_findings[1]),
                                (built.finding_id(S.FAMILY, 0, 0), family_finding)):
        assert _lane(built, finding_id) == S.LANES["questioner"], (
            f"{finding['claim']}: a finding with no conduct pointer is not gap-only")
        assert finding_id in queued, f"{finding['claim']} did not reach the questioner queue"
        assert not _mentions(S.user(built), finding_id, finding["claim"])

    samples_mark = S.marker("idp", "samples")
    assert samples_mark in judge.prompt_for("b"), "control: b's prompt shows no idp samples"
    assert samples_mark not in judge.prompt_for(S.FAMILY), "the family call was shown samples"
    rows = _by_id(S.questioner_queue())
    citations = S.RULED["row.citations"]
    world_cites = set(rows[built.finding_id("b", 0, 0)].get(citations) or [])
    assert world_cites == {S.plan_ptr(), S.samples_ptr("idp")}, (
        f"the world finding's shown samples section does not resolve: {world_cites}")
    family_cites = set(rows[built.finding_id(S.FAMILY, 0, 0)].get(citations) or [])
    assert family_cites == {S.plan_ptr()}, (
        f"the family finding's samples pointer was not set aside: {family_cites}")
