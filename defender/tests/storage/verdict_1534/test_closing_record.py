"""#1534 records layer: the `ClosingRecord` invariant and vocabularies, `OPENERS`, and the lookup `for_run` (V-ONE, V-LOOK).

Valid rows are planted through the production write; faults with real primitives (`_spec1534`): a scalar column UPDATE,
a dropped table, a deleted file, a non-JSON pointer, a pragma. The invariant is classified by the design's own table."""
from __future__ import annotations

import itertools
import json
import sqlite3
import typing

import pytest

from defender._filesystem.bound import RefusalKind

from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.shared._fixture_uuid import fixture_uuid

RUN = fixture_uuid("closing-1534-run")
CASE = "c1534"
WINDOW = ("2026-03-01T10:00:00Z", "2026-03-01T11:00:00Z")
#: Canonical instants: UTC with `Z`, microseconds present exactly when non-zero.
MICRO_WINDOW = ("2026-03-01T10:00:00.250000Z", "2026-03-01T11:00:00.000500Z")


def _entries():
    """Two entries of each kind, with optional parts present and absent, so order and `None` survive a round trip."""
    from defender.records import closing as C

    ceiling = (C.CeilingEntry(state=C.CEILING_STATES[0], ref="l-001", cap=None, note="EDR logs never came back"),
               C.CeilingEntry(state=C.CEILING_STATES[-1], ref=None, cap="no host telemetry", note="nothing to try"))
    baselines = (C.BaselineEntry(lead="l-001", anchor_kind=C.ANCHOR_KINDS[0], grounding_kind=C.GROUNDING_KINDS[0],
                                 anchor_id="policy-7", window_start=WINDOW[0], window_end=WINDOW[1],
                                 result="hit: allowed", reasoning="the policy permits it"),
                 C.BaselineEntry(lead="l-002", anchor_kind=C.ANCHOR_KINDS[-1], grounding_kind=C.GROUNDING_KINDS[-1],
                                 anchor_id="x", window_start=MICRO_WINDOW[0], window_end=MICRO_WINDOW[1], result="miss",
                                 reasoning="r"))
    return ceiling, baselines


# --- the design's invariant, as a table ------------------------------------------------------------------------------

def _design_allows(outcome, cause, failure_kind, draft, disposition) -> bool:
    """The design's "Invariant, per outcome", as data (`C` names resolved by the caller through `_table`)."""
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    stands_cause = {"unresolved": C.CAUSE_NOT_REVIEWED, "inconclusive": C.CAUSE_CEILING_EXAMINED}
    forced_causes = {(C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, None), (C.CAUSE_TURN_BUDGET_SPENT, None),
                     (C.CAUSE_NOTHING_LEFT_TO_ASK, None), *((C.CAUSE_REVIEW_INCOMPLETE, k) for k in C.FAILURE_KINDS)}
    if outcome == C.STANDS:
        return draft is None and failure_kind is None and cause == stands_cause.get(disposition, C.CAUSE_STORY_SETTLED)
    if outcome == C.FORCED_INCONCLUSIVE:
        return (disposition == "unresolved" and draft in DISPOSITION_VALUES and draft != "unresolved"
                and (cause, failure_kind) in forced_causes)
    return False


def _every_combination():
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    return itertools.product(C.OUTCOMES, C.CAUSES, (None, *C.FAILURE_KINDS), (None, *DISPOSITION_VALUES), DISPOSITION_VALUES)


def _record(outcome, cause, failure_kind, draft, disposition, run_id=RUN, **more):
    from defender.records import closing as C

    fields = {"ceiling_test": (), "runtime_evidence": (), "summary": "s"} | more
    return C.ClosingRecord(run_id=run_id, disposition=disposition, outcome=outcome, cause=cause, failure_kind=failure_kind,
                           drafted_disposition=draft, **fields)


def test_v_fields_the_outcome_cause_failure_draft_and_disposition_combinations_construct_exactly_when_the_design_allows():
    """All outcome x cause x failure kind x draft x disposition combinations: the allowed ones build, the rest raise. (V-FIELDS)"""
    allowed = refused = 0
    wrong: list[tuple] = []
    for combo in _every_combination():
        want = _design_allows(*combo)
        try:
            built = _record(*combo)
        except ValueError:
            built = None
        if (built is not None) != want:
            wrong.append((combo, "built" if built is not None else "refused"))
        allowed += want
        refused += not want
    assert wrong == []
    assert (allowed, refused) == (_allowed_count(), _combination_count() - _allowed_count()), (allowed, refused)


def _combination_count() -> int:
    """Every outcome x cause x failure kind (or none) x draft (or none) x disposition, from the vocabularies' sizes."""
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    return len(C.OUTCOMES) * len(C.CAUSES) * (1 + len(C.FAILURE_KINDS)) * (1 + len(DISPOSITION_VALUES)) * len(DISPOSITION_VALUES)


def _allowed_count() -> int:
    """The design's table counted from the vocabularies, not from `_design_allows`: one standing row per disposition, and
    for each draft other than `unresolved` the three overrule causes plus `review incomplete` once per failure kind."""
    from defender._vocab import DISPOSITION_VALUES
    from defender.records import closing as C

    return len(DISPOSITION_VALUES) + (len(DISPOSITION_VALUES) - 1) * (3 + len(C.FAILURE_KINDS))


@pytest.mark.parametrize("field", ["outcome", "cause", "failure_kind", "drafted_disposition", "disposition"])
def test_v_fields_a_value_outside_each_vocabulary_is_refused_and_the_valid_neighbour_builds(field):
    """One field set outside its vocabulary on an otherwise valid forced close raises; the valid one builds. (V-FIELDS)"""
    from defender.records import closing as C

    base = {"outcome": C.FORCED_INCONCLUSIVE, "cause": C.CAUSE_REVIEW_INCOMPLETE, "failure_kind": C.TIMEOUT,
            "drafted_disposition": "benign", "disposition": "unresolved"}
    assert _record(*(base[k] for k in ("outcome", "cause", "failure_kind", "drafted_disposition", "disposition")))
    with pytest.raises((ValueError, TypeError)):
        _record(*({**base, field: "not-a-member"}[k] for k in ("outcome", "cause", "failure_kind", "drafted_disposition",
                                                                "disposition")))


def test_v_fields_the_record_and_its_entries_are_frozen():
    """Assigning to a built record or entry raises. (V-FIELDS)"""
    from defender.records import closing as C

    ceiling, baselines = _entries()
    record = V.a_record(RUN, ceiling_test=ceiling, runtime_evidence=baselines)
    with pytest.raises((TypeError, ValueError, AttributeError)):
        record.disposition = "benign"
    with pytest.raises((TypeError, ValueError, AttributeError)):
        ceiling[0].note = "changed"
    assert isinstance(record, C.ClosingRecord)


def test_v_fields_entry_values_must_be_members_of_the_moved_vocabularies():
    """Every ceiling state, anchor kind and grounding kind builds; a value outside each raises. (V-FIELDS)"""
    from defender.records import closing as C

    for state in C.CEILING_STATES:
        assert C.CeilingEntry(state=state, ref=None, cap=None, note="n")
    for kind in C.ANCHOR_KINDS:
        assert C.BaselineEntry(lead="l-001", anchor_kind=kind, grounding_kind=C.GROUNDING_KINDS[0], anchor_id="a",
                               window_start=WINDOW[0], window_end=WINDOW[1], result="r", reasoning="r")
    for kind in C.GROUNDING_KINDS:
        assert C.BaselineEntry(lead="l-001", anchor_kind=C.ANCHOR_KINDS[0], grounding_kind=kind, anchor_id="a",
                               window_start=WINDOW[0], window_end=WINDOW[1], result="r", reasoning="r")
    with pytest.raises((ValueError, TypeError)):
        C.CeilingEntry(state="not-a-state", ref=None, cap=None, note="n")
    for bad in ({"anchor_kind": "not-a-kind"}, {"grounding_kind": "not-a-grounding"}):
        fields = {"lead": "l-001", "anchor_kind": C.ANCHOR_KINDS[0], "grounding_kind": C.GROUNDING_KINDS[0], "anchor_id": "a",
                  "window_start": WINDOW[0], "window_end": WINDOW[1], "result": "r", "reasoning": "r", **bad}
        with pytest.raises((ValueError, TypeError)):
            C.BaselineEntry(**fields)


def test_v_fields_the_moved_vocabularies_are_the_ones_invlang_checks_with():
    """`ANCHOR_KINDS`, `GROUNDING_KINDS` and `CEILING_STATES` equal the invlang vocabularies they moved from. (V-FIELDS)"""
    from defender.records import closing as C
    from defender.skills.invlang import vocab
    from defender.skills.invlang.validate import _ceiling

    assert C.ANCHOR_KINDS == vocab.ANCHOR_KINDS
    assert C.GROUNDING_KINDS == vocab.CONSULTATION_GROUNDING
    assert tuple(C.CEILING_STATES) == tuple(_ceiling.CEILING_STATES)


def test_v_fields_the_column_vocabularies_are_the_designs():
    """Outcomes, failure kinds, the seven causes with a sentence each, and the numeric bounds. (V-FIELDS, V-TEXT)"""
    from defender.records import closing as C

    assert (C.STANDS, C.FORCED_INCONCLUSIVE) == ("stands", "forced-inconclusive")
    assert tuple(C.OUTCOMES) == (C.STANDS, C.FORCED_INCONCLUSIVE)
    assert (C.TIMEOUT, C.STAGE_ERROR, C.UNREADABLE) == ("timeout", "error", "unreadable")
    assert set(C.FAILURE_KINDS) == {C.TIMEOUT, C.STAGE_ERROR, C.UNREADABLE}
    assert len(set(C.CAUSES)) == 7
    assert set(C.CAUSE_SENTENCES) == set(C.CAUSES)
    assert set(C.CAUSE_SENTENCES.values()) == {
        "the disposition was recorded without a challenge review",
        "the challenge review ran and left nothing about the finding unsettled",
        "the challenge review did not complete",
        "the evidence gathered cannot discriminate what the challenge review left unsettled",
        "the forced-turn budget was spent without settling what the challenge review raised",
        "nothing discriminating remains that the investigation was not already asked for",
        "the challenge review examined the ceiling claim and found nothing further measurable",
    }
    assert (C.SUMMARY_BOUND, C.NOTE_BOUND, C.ANCHOR_ID_BOUND, C.LEAD_BOUND, C.RESULT_BOUND, C.REASONING_BOUND) == (
        1500, 400, 200, 64, 400, 400)
    assert (C.CEILING_COUNT_CAP, C.CEILING_LINES_BOUND, C.BASELINE_LINES_BOUND) == (16, 2048, 2048)
    assert not hasattr(C, "BASELINE_COUNT_CAP"), "the baseline count cap is retired; the aggregate binds"


def test_v_fields_each_entry_renders_to_one_line_and_a_baseline_line_carries_its_window_as_start_over_end():
    """`ceiling_line` and `baseline_line` give one line; a baseline's window is its canonical `start/end`. (V-FIELDS)"""
    from defender.records import closing as C

    ceiling, baselines = _entries()
    for entry in ceiling:
        assert "\n" not in C.ceiling_line(entry)
    for entry in baselines:
        line = C.baseline_line(entry)
        assert "\n" not in line
        assert f"{entry.window_start}/{entry.window_end}" in line


def test_v_fields_a_window_with_microseconds_round_trips_canonical_with_them(tmp_path):
    """A window instant with non-zero microseconds reads back as written (`...:00.250000Z`), a whole-second one without. (V-FIELDS)"""
    from defender.records import closing as C

    ceiling, baselines = _entries()
    run_dir, _db = V.closed_run(tmp_path, {"ceiling_test": ceiling, "runtime_evidence": baselines})
    got = C.for_run(V.handle(run_dir))
    assert isinstance(got, C.Record)
    assert [(b.window_start, b.window_end) for b in got.record.runtime_evidence] == [WINDOW, MICRO_WINDOW]


# --- construction-time treatment (L-1) -------------------------------------------------------------------------------

def _model_text_fields():
    """`(name, bound, builder)`: each bounded model-text field, built into its record or entry with a given text."""
    from defender.records import closing as C

    def baseline(**kw):
        fields = {"lead": "l-001", "anchor_kind": C.ANCHOR_KINDS[0], "grounding_kind": C.GROUNDING_KINDS[0], "anchor_id": "a",
                  "window_start": WINDOW[0], "window_end": WINDOW[1], "result": "r", "reasoning": "r", **kw}
        return C.BaselineEntry(**fields)

    return [
        ("summary", C.SUMMARY_BOUND, lambda t: V.a_record(RUN, summary=t).summary),
        ("note", C.NOTE_BOUND, lambda t: C.CeilingEntry(state=C.CEILING_STATES[0], ref=None, cap=None, note=t).note),
        ("anchor_id", C.ANCHOR_ID_BOUND, lambda t: baseline(anchor_id=t).anchor_id),
        ("lead", C.LEAD_BOUND, lambda t: baseline(lead=t).lead),
        ("result", C.RESULT_BOUND, lambda t: baseline(result=t).result),
        ("reasoning", C.REASONING_BOUND, lambda t: baseline(reasoning=t).reasoning),
    ]


@pytest.mark.parametrize("name", ["summary", "note", "anchor_id", "lead", "result", "reasoning"])
def test_l1_a_model_text_field_holds_its_treated_value_or_the_construction_refuses(name):
    """Treated text is kept as is; untreated or oversize text builds as `treat(text, bound)` or raises, never else. (L-1, V-TEXT)"""
    from defender.records import closing as C

    _name, bound, build = next(f for f in _model_text_fields() if f[0] == name)
    treated = C.treat("see https://evil.example/x ok", bound)
    assert build(treated) == treated, "already-treated text was altered"
    untreated = ["see https://evil.example/x\tand  more", "a\u200bb\x00c d", "word " * (bound + 5), "x" * (bound + 1)]
    outcomes = set()
    for text in untreated:
        try:
            got = build(text)
        except ValueError:
            outcomes.add("refused")
            continue
        assert got == C.treat(text, bound), (name, text, got)
        outcomes.add("treated")
    assert outcomes


def test_l1_an_unresolved_record_with_no_summary_is_refused_and_the_same_with_a_summary_builds():
    """`unresolved` with summary None raises `ValueError`; every other disposition may carry none. (L-1, V-FIELDS)"""
    from defender._vocab import DISPOSITION_VALUES

    assert V.a_record(RUN, disposition="unresolved", cause=_not_reviewed(), summary="s")
    with pytest.raises(ValueError, match="summary"):
        V.a_record(RUN, disposition="unresolved", cause=_not_reviewed(), summary=None)
    for disposition in DISPOSITION_VALUES:
        if disposition != "unresolved":
            assert V.a_record(RUN, disposition=disposition, cause=_stands_cause(disposition), summary=None)


def _not_reviewed():
    from defender.records import closing as C

    return C.CAUSE_NOT_REVIEWED


def _stands_cause(disposition):
    from defender.records import closing as C

    return C.CAUSE_CEILING_EXAMINED if disposition == "inconclusive" else C.CAUSE_STORY_SETTLED


# --- the openers -----------------------------------------------------------------------------------------------------

OD14 = {
    ("NOT_REVIEWED", None): "The run was cut short before the investigation closed, so the host recorded it unresolved.",
    ("REVIEW_INCOMPLETE", "TIMEOUT"): "The challenge review did not finish in time, so the drafted verdict was not allowed to stand.",
    ("REVIEW_INCOMPLETE", "STAGE_ERROR"): "The challenge review could not run, so the drafted verdict was not allowed to stand.",
    ("REVIEW_INCOMPLETE", "UNREADABLE"): "The challenge review's answer could not be read, so the drafted verdict was not allowed to stand.",
    ("EVIDENCE_CANNOT_DISCRIMINATE", None): "The challenge review raised a question the gathered evidence cannot settle, so the drafted verdict was overruled.",
    ("TURN_BUDGET_SPENT", None): "The investigation ran out of turns before settling what the challenge review raised.",
    ("NOTHING_LEFT_TO_ASK", None): "The challenge review's open questions had already been asked without being settled, so the drafted verdict was overruled.",
}


def test_od14_the_openers_are_exactly_the_seven_accepted_sentences_keyed_by_cause_and_failure_kind():
    """`OPENERS` has the seven (cause, failure kind) pairs, each with the accepted wording verbatim. (OD14)"""
    from defender.records import closing as C

    want = {(getattr(C, f"CAUSE_{cause}"), getattr(C, kind) if kind else None): text for (cause, kind), text in OD14.items()}
    assert dict(C.OPENERS) == want


def test_od14_the_openers_cover_every_pair_a_constructible_unresolved_record_can_carry_and_no_other():
    """The (cause, failure kind) pairs of every buildable `unresolved` record are exactly the opener keys. (OD14)"""
    from defender.records import closing as C

    pairs = set()
    for combo in _every_combination():
        outcome, cause, failure_kind, _draft, disposition = combo
        if disposition == "unresolved" and _design_allows(*combo):
            _record(*combo)
            pairs.add((cause, failure_kind))
    assert pairs == set(C.OPENERS)


# --- the lookup: the record ------------------------------------------------------------------------------------------

def _plant_all_valid(tmp_path):
    """One run folder, pointer and row per allowed combination, all in one database. Returns `[(run_dir, record)]`."""
    base = V.runs_base(tmp_path)
    ceiling, baselines = _entries()
    made = []
    with V.run_store(base, CASE) as store:
        store.new_session(agent_id="main")
        for n, combo in enumerate(c for c in _every_combination() if _design_allows(*c)):
            run_dir = base / fixture_uuid(f"closing-1534-all-{n}")
            (run_dir / "gather_raw").mkdir(parents=True)
            V.point(run_dir, store)
            record = _record(*combo, run_id=run_dir.name, ceiling_test=ceiling, runtime_evidence=baselines)
            V.plant(store, record)
            made.append((run_dir, record))
    return made


def test_v_look_every_valid_record_reads_back_whole_from_its_own_run_handle(tmp_path):
    """Each valid record (all the design's table allows), with ceiling receipts and baselines, reads as `Record` equal to
    what was written. (V-LOOK)"""
    from defender.records import closing as C

    made = _plant_all_valid(tmp_path)
    assert len(made) == _allowed_count()
    for run_dir, record in made:
        got = C.for_run(V.handle(run_dir))
        assert isinstance(got, C.Record), (record.outcome, record.cause, got)
        assert got.record == record


def test_v_look_a_record_with_no_entries_and_no_summary_reads_back_as_written(tmp_path):
    """Empty entry columns and a null summary survive the round trip. (V-LOOK)"""
    from defender.records import closing as C

    run_dir, _db = V.closed_run(tmp_path, {"summary": None, "disposition": "benign"})
    got = C.for_run(V.handle(run_dir))
    assert isinstance(got, C.Record)
    assert got.record.summary is None
    assert got.record.ceiling_test == ()
    assert got.record.runtime_evidence == ()


def test_v_one_two_runs_in_one_database_each_read_their_own_record(tmp_path):
    """A source and its arm share a database; each reads its own row, and a third run of it with no row reads `NeverClosed`. (V-ONE, V-LOOK)"""
    from defender.records import closing as C

    base = V.runs_base(tmp_path)
    source, arm, third = (base / fixture_uuid(n) for n in ("closing-1534-source", "closing-1534-arm", "closing-1534-third"))
    with V.run_store(base, CASE) as store:
        store.new_session(agent_id="main")
        for run_dir, disposition in ((source, "malicious"), (arm, "benign")):
            (run_dir / "gather_raw").mkdir(parents=True)
            V.point(run_dir, store)
            V.plant(store, V.a_record(run_dir.name, disposition=disposition, summary=f"{disposition} close"))
        (third / "gather_raw").mkdir(parents=True)
        V.point(third, store)

    got = {name: C.for_run(V.handle(d)) for name, d in (("source", source), ("arm", arm), ("third", third))}
    assert (got["source"].record.disposition, got["source"].record.summary) == ("malicious", "malicious close")
    assert (got["arm"].record.disposition, got["arm"].record.summary) == ("benign", "benign close")
    assert isinstance(got["third"], C.NeverClosed)


# --- the lookup: never closed ----------------------------------------------------------------------------------------

def test_v_look_a_database_with_the_table_and_no_row_for_the_run_reads_never_closed(tmp_path):
    """The table is present (another run closed) and this run has no row: `NeverClosed`, with a `Record` beside it. (V-LOOK)"""
    from defender.records import closing as C

    base = V.runs_base(tmp_path)
    mine, other = base / fixture_uuid("closing-1534-mine"), base / fixture_uuid("closing-1534-other")
    with V.run_store(base, CASE) as store:
        store.new_session(agent_id="main")
        for run_dir in (mine, other):
            (run_dir / "gather_raw").mkdir(parents=True)
            V.point(run_dir, store)
        V.plant(store, V.a_record(other.name))

    assert isinstance(C.for_run(V.handle(mine)), C.NeverClosed)
    assert isinstance(C.for_run(V.handle(other)), C.Record)


def test_v_look_a_run_with_no_pointer_reads_never_closed_while_a_missing_database_does_not(tmp_path):
    """No pointer: `NeverClosed`. The same run with a pointer whose database was deleted: `database-missing`, never absence. (V-LOOK)"""
    from defender.records import closing as C

    base = V.runs_base(tmp_path)
    bare = base / fixture_uuid("closing-1534-bare")
    (bare / "gather_raw").mkdir(parents=True)
    assert isinstance(C.for_run(V.handle(bare)), C.NeverClosed)

    run_dir, database = V.closed_run(tmp_path, {})
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record)
    database.unlink()
    got = C.for_run(V.handle(run_dir))
    assert isinstance(got, C.CouldNotLook), "a missing database was read as an absence"
    assert got.kind == "database-missing"


# --- the lookup: each fault kind -------------------------------------------------------------------------------------

def _assert_fault(got, kind, database):
    from defender.records import closing as C

    assert isinstance(got, C.CouldNotLook), got
    assert got.kind == kind
    assert kind in C.FAULT_KINDS
    assert got.detail not in C.FAULT_WORDING.values(), "the detail is the outward wording"
    assert str(database) not in C.FAULT_WORDING[kind], "the outward wording names the database"


def test_v_look_the_fault_kinds_and_their_fixed_wording_are_a_closed_set():
    """`FAULT_KINDS` is the design's nine; `FAULT_WORDING` holds them and the worker's `committed-without-record`, each a
    distinct non-empty wording. (V-LOOK, r3.2 M4 ii)"""
    from defender.records import closing as C

    assert set(C.FAULT_KINDS) == {"database-missing", "pointer-unreadable", "store-unreadable", "schema-version",
                                  "recorded-before-1534", "legacy-link", "roster-gone", "arm-refused", "row-invalid"}
    assert "committed-without-record" not in C.FAULT_KINDS
    assert set(C.FAULT_WORDING) == {*C.FAULT_KINDS, "committed-without-record"}
    assert all(isinstance(w, str) and w for w in C.FAULT_WORDING.values())
    assert len(set(C.FAULT_WORDING.values())) == len(C.FAULT_WORDING)


def _pointer_path(run_dir):
    return V.handle(run_dir).observability.session_pointer.path


@pytest.mark.parametrize("pointer", [
    pytest.param("this is not json {", id="not-json"),
    pytest.param("{}", id="no-store-path"),
    pytest.param('{"case_id": "c1534"}', id="no-store-path-with-case"),
    pytest.param('{"store_path": "%(db)s"}', id="no-case-id"),
    pytest.param('{"case_id": 7, "store_path": "%(db)s"}', id="case-id-not-a-string"),
    pytest.param('{"case_id": "../escape", "store_path": "%(db)s"}', id="case-id-unusable"),
])
def test_v_look_a_pointer_that_cannot_be_used_is_pointer_unreadable_and_a_good_one_reads(tmp_path, pointer):
    """Non-JSON, no `store_path`, or no usable case id: `pointer-unreadable`; the repaired pointer reads the record. (V-LOOK)"""
    from defender.records import closing as C

    run_dir, database = V.closed_run(tmp_path, {})
    path = _pointer_path(run_dir)
    path.write_text(pointer % {"db": str(database)}, encoding="utf-8")
    _assert_fault(C.for_run(V.handle(run_dir)), "pointer-unreadable", database)

    path.write_text(json.dumps({"case_id": CASE, "store_path": str(database)}), encoding="utf-8")
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record)


def _alias(path, good):
    (target := path.with_name("pointer-target.json")).write_text(good, encoding="utf-8")
    path.symlink_to(target)


def _oversize(path, _good):
    from defender._filesystem.bound import READ_LIMIT

    with path.open("wb") as f:
        f.truncate(READ_LIMIT + 1)


#: One way to make the pointer's bounded read refuse, per `RefusalKind` (a new kind fails the lookup below).
_POINTER_REFUSALS = {
    "alias": _alias,
    "not_file": lambda path, _good: path.mkdir(),
    "undecodable": lambda path, _good: path.write_bytes(b'{"case_id": "\xff\xfe"}'),
    "fault": _oversize,
}


@pytest.mark.parametrize("kind", typing.get_args(RefusalKind))
def test_v_look_a_pointer_the_bounded_read_refuses_is_pointer_unreadable_for_every_refusal_kind(tmp_path, kind):
    """Each refusal of the pointer's read (link, folder, non-UTF-8, oversize) is `pointer-unreadable`, never absence; the
    good pointer back reads the record. (V-LOOK)"""
    from defender.records import closing as C

    assert set(_POINTER_REFUSALS) == set(typing.get_args(RefusalKind))
    run_dir, database = V.closed_run(tmp_path, {})
    path = _pointer_path(run_dir)
    good = path.read_text(encoding="utf-8")
    path.unlink()
    _POINTER_REFUSALS[kind](path, good)
    read = V.handle(run_dir).observability.session_pointer.read_result()
    assert (read.absent, read.refused_by) == (False, kind), "fixture control: the read refuses as this kind"
    _assert_fault(C.for_run(V.handle(run_dir)), "pointer-unreadable", database)

    if path.is_dir() and not path.is_symlink():
        path.rmdir()
    else:
        path.unlink()
    path.write_text(good, encoding="utf-8")
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record)


def test_v_look_a_file_that_is_not_a_database_is_store_unreadable(tmp_path):
    """The pointer names a file that is not SQLite: `store-unreadable`. (V-LOOK)"""
    from defender.records import closing as C

    run_dir, database = V.closed_run(tmp_path, {})
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record)
    database.write_bytes(b"this is not a sqlite database " * 64)
    _assert_fault(C.for_run(V.handle(run_dir)), "store-unreadable", database)


@pytest.mark.parametrize("breakage", [
    pytest.param("view-over-missing-table", id="view-over-a-missing-table"),
    pytest.param("table-without-a-column", id="table-lacking-a-column"),
])
def test_v_look_a_row_query_that_errors_at_read_time_is_store_unreadable(tmp_path, breakage):
    """The schema version and table name are intact but the row query fails: `store-unreadable`, not another kind. (V-LOOK)"""
    from defender.records import closing as C

    run_dir, database = V.closed_run(tmp_path, {})
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record), "premise: the intact database reads"
    conn = sqlite3.connect(database)
    try:
        conn.execute(f"DROP TABLE {V.TABLE}")
        if breakage == "view-over-missing-table":
            conn.execute(f"CREATE VIEW {V.TABLE} AS SELECT * FROM no_such_table_1534")
        else:
            conn.execute(f"CREATE TABLE {V.TABLE} (run_id TEXT PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()
    _assert_fault(C.for_run(V.handle(run_dir)), "store-unreadable", database)


@pytest.mark.parametrize("version", [0, 3, 99])
def test_v_look_a_database_at_another_schema_version_is_schema_version(tmp_path, version):
    """`PRAGMA user_version` other than the writer's: `schema-version`. (V-LOOK)"""
    from defender.records import closing as C
    from defender.records import session_store as ss

    run_dir, database = V.closed_run(tmp_path, {})
    assert version != ss.SCHEMA_VERSION
    conn = sqlite3.connect(database)
    try:
        conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()
    _assert_fault(C.for_run(V.handle(run_dir)), "schema-version", database)


def test_v_look_a_database_without_the_table_is_recorded_before_1534_and_the_read_does_not_make_it(tmp_path):
    """No `closing_record` table: `recorded-before-1534`, a fault and not an absence; the reader leaves it absent. (V-LOOK)"""
    from defender.records import closing as C

    run_dir, database = V.closed_run(tmp_path, {})
    V.drop_table(database)
    _assert_fault(C.for_run(V.handle(run_dir)), "recorded-before-1534", database)
    conn = sqlite3.connect(database)
    try:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (V.TABLE,)).fetchone() is None
    finally:
        conn.close()


def test_v_look_a_pre_1235_link_in_the_run_folder_is_legacy_link_only_when_no_pointer_sits_beside_it(tmp_path):
    """A legacy link and no pointer: `legacy-link`; the same link beside a pointer: the pointer's `Record`; neither: `NeverClosed`. (V-LOOK)"""
    from defender.records import closing as C
    from defender.records.session_store._schema import _LEGACY_LINK_NAME

    base = V.runs_base(tmp_path)
    neither, legacy = base / fixture_uuid("closing-1534-neither"), base / fixture_uuid("closing-1534-legacy")
    for run_dir in (neither, legacy):
        (run_dir / "gather_raw").mkdir(parents=True)
    (legacy / _LEGACY_LINK_NAME).write_text(CASE, encoding="utf-8")

    assert isinstance(C.for_run(V.handle(neither)), C.NeverClosed)
    _assert_fault(C.for_run(V.handle(legacy)), "legacy-link", base)

    pointed, _database = V.closed_run(tmp_path, {}, run_name="closing-1534-pointed")
    assert isinstance(C.for_run(V.handle(pointed)), C.Record), "premise: the pointer reads"
    (pointed / _LEGACY_LINK_NAME).write_text(CASE, encoding="utf-8")
    got = C.for_run(V.handle(pointed))
    assert isinstance(got, C.Record), "a link a box can write hid the run's own record"
    assert got.record.run_id == pointed.name


#: `id: (record fields, column, stored value)`; the fields are resolved against `C` when the case runs.
ROW_FAULTS = {
    "disposition-out-of-vocabulary": ({}, "disposition", "not-a-disposition"),
    "outcome-out-of-vocabulary": ({}, "outcome", "not-an-outcome"),
    "cause-out-of-vocabulary": ({}, "cause", "not-a-cause"),
    "failure-kind-out-of-vocabulary": ({}, "failure_kind", "not-a-kind"),
    "draft-out-of-vocabulary": ({}, "drafted_disposition", "not-a-disposition"),
    "stands-with-a-draft": ({}, "drafted_disposition", "benign"),
    "stands-with-a-failure-kind": ({}, "failure_kind", "timeout"),
    "stands-with-another-outcomes-cause": ({}, "cause", "CAUSE_NOT_REVIEWED"),
    "stands-unresolved-with-a-settled-cause": ({}, "disposition", "unresolved"),
    "unresolved-with-no-summary": ("unresolved-stands", "summary", None),
    "forced-with-a-disposition-that-is-not-unresolved": ("forced", "disposition", "benign"),
    "forced-draft-cleared": ("forced", "drafted_disposition", None),
    "forced-draft-unresolved": ("forced", "drafted_disposition", "unresolved"),
    "forced-review-incomplete-with-no-failure-kind": ("forced", "failure_kind", None),
    "forced-failure-kind-with-another-cause": ("forced-undecided", "failure_kind", "error"),
}


@pytest.mark.parametrize("name", list(ROW_FAULTS))
def test_v_look_a_stored_row_outside_the_vocabulary_or_breaking_the_invariant_is_row_invalid(tmp_path, name):
    """Each corrupted scalar column of a valid row reads `row-invalid`; the same row uncorrupted reads `Record`. (V-LOOK)"""
    from defender.records import closing as C

    fields, column, value = ROW_FAULTS[name]
    if fields == "forced":
        fields = {"disposition": "unresolved", "outcome": C.FORCED_INCONCLUSIVE, "cause": C.CAUSE_REVIEW_INCOMPLETE,
                  "failure_kind": C.TIMEOUT, "drafted_disposition": "benign"}
    elif fields == "unresolved-stands":
        fields = {"disposition": "unresolved", "cause": C.CAUSE_NOT_REVIEWED, "summary": "The run was cut short."}
    elif fields == "forced-undecided":
        fields = {"disposition": "unresolved", "outcome": C.FORCED_INCONCLUSIVE,
                  "cause": C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, "failure_kind": None, "drafted_disposition": "benign"}
    if isinstance(value, str) and value.startswith("CAUSE_"):
        value = getattr(C, value)
    run_dir, database = V.closed_run(tmp_path, fields)
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record), "premise: the uncorrupted row reads"

    V.corrupt(database, run_dir.name, column, value)

    _assert_fault(C.for_run(V.handle(run_dir)), "row-invalid", database)


# --- #1545 over #1534: a benign close's committed confidence ---------------------------------------------------------
# Owner ruling: the record carries a nullable `confidence`, set only beside `benign` and only to a `CONFIDENCE_VALUES`
# member; the record type refuses anything else, so a stored row that breaks it reads `row-invalid`.

def _standing(disposition: str) -> dict:
    from defender.records import closing as C

    cause = {"unresolved": C.CAUSE_NOT_REVIEWED, "inconclusive": C.CAUSE_CEILING_EXAMINED}.get(
        disposition, C.CAUSE_STORY_SETTLED)
    return {"outcome": C.STANDS, "cause": cause, "failure_kind": None, "draft": None, "disposition": disposition}


def test_v_fields_a_confidence_builds_exactly_beside_benign_and_only_from_the_vocabulary():
    """Every disposition x (none, each `CONFIDENCE_VALUES` member, values outside it): the record builds exactly when the
    confidence is none, or a member beside `benign`; a forced close of a benign draft carries none. (V-FIELDS, #1545)"""
    from defender._vocab import BENIGN_DISPOSITION, CONFIDENCE_VALUES, DISPOSITION_VALUES
    from defender.records import closing as C

    assert BENIGN_DISPOSITION in DISPOSITION_VALUES
    wrong = []
    for disposition in DISPOSITION_VALUES:
        for confidence in (None, *CONFIDENCE_VALUES, "certain", "", CONFIDENCE_VALUES[0].upper(), f" {CONFIDENCE_VALUES[0]}"):
            want = confidence is None or (disposition == BENIGN_DISPOSITION and confidence in CONFIDENCE_VALUES)
            try:
                built = _record(**_standing(disposition), confidence=confidence)
            except ValueError:
                built = None
            if (built is not None) != want:
                wrong.append((disposition, confidence, "built" if built is not None else "refused"))
            elif built is not None:
                assert built.confidence == confidence
    assert wrong == []
    forced = {"outcome": C.FORCED_INCONCLUSIVE, "cause": C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, "failure_kind": None,
              "draft": BENIGN_DISPOSITION, "disposition": "unresolved"}
    assert _record(**forced).confidence is None
    with pytest.raises(ValueError, match="confidence"):
        _record(**forced, confidence=CONFIDENCE_VALUES[0])


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_v_look_a_benign_records_confidence_reads_back_through_the_lookup(tmp_path, confidence):
    """A benign record with each confidence reads back as `Record` with that confidence, equal to what was written; one
    with none reads none. (V-LOOK, #1545)"""
    from defender._vocab import CONFIDENCE_VALUES
    from defender.records import closing as C

    assert set(CONFIDENCE_VALUES) == {"high", "medium", "low"}, "the parametrization follows the vocabulary"
    run_dir, _db = V.closed_run(tmp_path, {"disposition": "benign", "confidence": confidence})
    got = C.for_run(V.handle(run_dir))
    assert isinstance(got, C.Record), got
    assert got.record.confidence == confidence
    assert got.record == V.a_record(run_dir.name, disposition="benign", confidence=confidence)

    bare, _db = V.closed_run(tmp_path / "bare", {"disposition": "benign"})
    got = C.for_run(V.handle(bare))
    assert isinstance(got, C.Record), got
    assert got.record.confidence is None


@pytest.mark.parametrize(("disposition", "stored"), [
    ("benign", "certain"), ("benign", "HIGH"), ("benign", ""), ("malicious", "high"), ("unresolved", "low")],
    ids=["off-vocabulary", "wrong-case", "empty", "beside-malicious", "beside-unresolved"])
def test_v_look_a_stored_confidence_the_record_refuses_is_row_invalid(tmp_path, disposition, stored):
    """The `confidence` column of a valid row set outside the vocabulary, or set at all beside another disposition,
    reads `row-invalid`; the uncorrupted row reads `Record`. (V-LOOK, #1545)"""
    from defender.records import closing as C

    fields = {"disposition": disposition, **({"cause": C.CAUSE_NOT_REVIEWED, "summary": "cut short"}
                                            if disposition == "unresolved" else {})}
    run_dir, database = V.closed_run(tmp_path, fields)
    assert isinstance(C.for_run(V.handle(run_dir)), C.Record), "premise: the uncorrupted row reads"

    V.corrupt(database, run_dir.name, "confidence", stored)

    _assert_fault(C.for_run(V.handle(run_dir)), "row-invalid", database)
