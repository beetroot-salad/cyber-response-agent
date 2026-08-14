"""Pins for the slimmed case-tree linter (#711 §9.4).

The label-shaped checks went with `label.py`. What is pinned here is what survives any
change to how a lead is graded: the structural facts, the story-leak guard, the
split/unit inheritance, and the append-only held-out ledger — plus the coverage report,
whose job is to make the instrument's limits visible rather than to assert they are zero.
"""
from __future__ import annotations

import hashlib
import json

import pytest
import yaml

from defender.evals.oracle_golden import validate_cases


def _case(root, name, *, kind="observed", split="dev", story="An operation ran.",
          leads=("l-001",), manifest_extra=None, environment=True):
    d = root / name
    (d / "oracle_visible").mkdir(parents=True)
    (d / "oracle_visible" / "story.md").write_text(story, encoding="utf-8")
    (d / "oracle_visible" / "leads.jsonl").write_text(
        "".join(json.dumps({"lead_id": lid, "queries": []}) + "\n" for lid in leads),
        encoding="utf-8")
    manifest = {"case_id": name, "kind": kind, "split": split,
                "unit": {"activity_family": "brute-force/T1110.001", "host_pair": "a->b"},
                "capture_environment": "playground-v2@1"}
    manifest.update(manifest_extra or {})
    (d / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    if environment:
        validate_cases_environment(d)
    if kind == "observed":
        obs = d / "hidden" / "observed" / leads[0]
        obs.mkdir(parents=True)
        (obs / "0.json").write_text(json.dumps({"query": "q", "values": []}), encoding="utf-8")
    return d


def validate_cases_environment(case_dir):
    (case_dir / "environment.yaml").write_text(yaml.safe_dump({
        "capture_environment": "playground-v2@1",
        "unstable_identifiers": {"columns": ["source.ip"]},
        "baseline_construction": {"liveness": "window_live false means not measured"},
    }), encoding="utf-8")


# ------------------------------------------------------------------- structure

def test_a_case_missing_a_required_file_is_a_problem(tmp_path):
    d = _case(tmp_path, "case-x")
    (d / "manifest.yaml").unlink()
    assert any("missing manifest.yaml" in p for p in validate_cases.check_case(d, {}))


def test_environment_notes_are_required_because_the_judge_reads_them(tmp_path):
    """Not documentation — `load_lead_inputs` reads it, and it carries what decides
    whether a cross-window difference is real at all."""
    d = _case(tmp_path, "case-x", environment=False)
    assert any("missing environment.yaml" in p for p in validate_cases.check_case(d, {}))


def test_environment_notes_without_the_unstable_columns_are_a_problem(tmp_path):
    d = _case(tmp_path, "case-x")
    (d / "environment.yaml").write_text(yaml.safe_dump({
        "capture_environment": "playground-v2@1",
        "baseline_construction": {"liveness": "x"}}), encoding="utf-8")
    problems = validate_cases.check_environment(d)
    assert any("unstable_identifiers" in p for p in problems)


def test_a_case_whose_manifest_names_another_case_is_a_problem(tmp_path):
    d = _case(tmp_path, "case-x", manifest_extra={"case_id": "case-y"})
    assert any("manifest case_id" in p for p in validate_cases.check_identity(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))))


def test_an_observed_case_with_no_telemetry_is_a_problem(tmp_path):
    d = _case(tmp_path, "case-x")
    for p in (d / "hidden" / "observed").rglob("*.json"):
        p.unlink()
    (d / "hidden" / "observed" / "l-001").rmdir()
    problems = validate_cases.check_identity(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
    assert any("no hidden/observed payloads" in p for p in problems)


@pytest.mark.parametrize("kind", ["mutation", "negative-control"])
def test_a_derived_case_needs_no_telemetry(kind, tmp_path):
    """It reuses its base's envelopes and changes only the story, so `hidden/` is absent
    by design — its absence is not a gap."""
    d = _case(tmp_path, "case-x", kind=kind)
    problems = validate_cases.check_identity(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
    assert problems == []


# --------------------------------------------------------------- story hygiene

def test_a_story_that_states_the_expected_result_is_caught(tmp_path):
    """The one leak the hidden/visible split cannot catch, because `story.md` is
    deliberately an oracle input."""
    d = _case(tmp_path, "case-x",
              story="This is a negative control; every lead must return 0.")
    assert any("leaks the evaluation frame" in p for p in validate_cases.check_case(d, {}))


# ------------------------------------------------------------- split and unit

def test_a_derived_case_may_not_sit_on_the_other_side_of_the_split():
    """It reuses the base's envelope, so a differing split puts one capture on both."""
    base = {"split": "dev", "unit": {"activity_family": "f", "host_pair": "a->b"}}
    manifest = {"split": "held-out", "base_case": "base",
                "unit": {"activity_family": "f", "host_pair": "a->b"},
                "capture_environment": "e"}
    problems = validate_cases.check_split_and_unit("mut-x", manifest, {"base": base})
    assert any("one capture on both sides" in p for p in problems)


def test_a_derived_case_is_not_a_second_unit():
    base = {"split": "dev", "unit": {"activity_family": "f", "host_pair": "a->b"}}
    manifest = {"split": "dev", "base_case": "base",
                "unit": {"activity_family": "other", "host_pair": "a->b"},
                "capture_environment": "e"}
    problems = validate_cases.check_split_and_unit("mut-x", manifest, {"base": base})
    assert any("not a new one" in p for p in problems)


@pytest.mark.parametrize(("manifest", "why"), [
    ({"split": "maybe", "unit": {"activity_family": "f", "host_pair": "a->b"},
      "capture_environment": "e"}, "split outside the vocabulary"),
    ({"split": "dev", "unit": {}, "capture_environment": "e"}, "no unit"),
    ({"split": "dev", "unit": {"activity_family": "f", "host_pair": "a->b"}}, "no environment"),
])
def test_a_case_missing_its_calibration_metadata_is_a_problem(manifest, why):
    assert validate_cases.check_split_and_unit("case-x", manifest, {})


# ------------------------------------------------------------ held-out ledger

def _ledger(tmp_path, entries):
    p = tmp_path / "ledger.yaml"
    p.write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")
    return p


def test_a_held_out_score_with_no_ledger_entry_is_a_problem(tmp_path):
    d = _case(tmp_path, "case-h", split="held-out")
    (d / "scores").mkdir()
    (d / "scores" / "tag.json").write_text("{}", encoding="utf-8")
    manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
    problems = validate_cases.check_held_out_ledger([(d, manifest)], _ledger(tmp_path, []))
    assert any("no ledger entry" in p for p in problems)


def test_a_rewritten_held_out_score_is_caught(tmp_path):
    """A held-out result is recorded once per tag. Re-running one for a better number is
    the failure the hash exists to detect."""
    d = _case(tmp_path, "case-h", split="held-out")
    (d / "scores").mkdir()
    (d / "scores" / "tag.json").write_text('{"rows": []}', encoding="utf-8")
    manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
    ledger = _ledger(tmp_path, [{"case": "case-h", "tag": "tag", "sha256": "0" * 64}])
    problems = validate_cases.check_held_out_ledger([(d, manifest)], ledger)
    assert any("does not match its ledger hash" in p for p in problems)


def test_a_matching_held_out_score_passes(tmp_path):
    d = _case(tmp_path, "case-h", split="held-out")
    (d / "scores").mkdir()
    body = b'{"rows": []}'
    (d / "scores" / "tag.json").write_bytes(body)
    manifest = yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8"))
    ledger = _ledger(tmp_path, [{"case": "case-h", "tag": "tag",
                                 "sha256": hashlib.sha256(body).hexdigest()}])
    assert validate_cases.check_held_out_ledger([(d, manifest)], ledger) == []


def test_a_deleted_held_out_result_needs_a_retirement_reason(tmp_path):
    """Retiring a defective case is a recorded act; deleting one you disliked is not."""
    ledger = _ledger(tmp_path, [{"case": "gone", "tag": "tag", "sha256": "x"}])
    problems = validate_cases.check_held_out_ledger([], ledger)
    assert any("carries no `retired:` reason" in p for p in problems)

    retired = _ledger(tmp_path, [{"case": "gone", "tag": "tag", "sha256": "x",
                                  "retired": "its story named two targets"}])
    assert validate_cases.check_held_out_ledger([], retired) == []


# ---------------------------------------------------------------- the boundary

def test_the_replay_boundary_check_is_not_vacuous():
    """It asserts replay.py names no `hidden/` path — worthless if it found no paths."""
    assert validate_cases.check_replay_boundary() == []


# --------------------------------------------------------------- completeness

def test_coverage_counts_what_a_case_actually_holds(tmp_path):
    d = _case(tmp_path, "case-x", leads=("l-001", "l-002"))
    row = validate_cases.coverage(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
    assert row["leads"] == 2
    assert row["observed"] == 1, "only l-001 was captured"
    assert row["baselined"] == 0


def test_coverage_counts_errored_payloads_separately_from_empty_ones(tmp_path):
    """A zero-byte payload is a query that ERRORED at capture — `query_tool.py` writes ""
    on a non-zero exit. Counting it as an empty result set would turn a missing
    measurement into evidence of absence."""
    d = _case(tmp_path, "case-x")
    (d / "hidden" / "observed" / "l-001" / "1.json").write_text("", encoding="utf-8")
    row = validate_cases.coverage(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
    assert row["errored_payloads"] == 1


def test_coverage_counts_dead_control_windows(tmp_path):
    """A control on a window where the stack was not running measures nothing. The
    default 7-day offset put 76 of them in this tree."""
    d = _case(tmp_path, "case-x")
    ctl = d / "hidden" / "controls" / "l-001"
    ctl.mkdir(parents=True)
    (ctl / "0.json").write_text(json.dumps({"lead_id": "l-001", "seq": 0, "controls": [
        {"name": "C-7d", "live": False, "payload": None},
        {"name": "C-14d", "live": True, "payload": {"values": []}},
    ]}), encoding="utf-8")
    row = validate_cases.coverage(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
    assert row["controls_dead"] == 1
    assert row["controls_live"] == 1
    assert "not running" in validate_cases.render_coverage([row])


def test_coverage_survives_a_half_built_case(tmp_path):
    """A recruitment still running has no lead set yet. `check_case` reports it as
    missing a required file; the coverage report must stay readable beside that."""
    d = tmp_path / "case-partial"
    d.mkdir()
    assert validate_cases.coverage(d, {})["leads"] == 0


def test_a_defective_case_is_excluded_from_the_totals_and_named(tmp_path):
    """A capture whose leads cannot contain the activity is not coverage. Leaving it in
    the split totals inflates the unit count with a unit nothing was measured for —
    which is exactly how case-006 and case-007 briefly made dev look like six units."""
    _case(tmp_path, "case-good")
    _case(tmp_path, "case-bad", manifest_extra={"defective": "leads point at the wrong host"})
    rows = [validate_cases.coverage(
        d, yaml.safe_load((d / "manifest.yaml").read_text(encoding="utf-8")))
        for d in sorted(tmp_path.iterdir())]
    rendered = validate_cases.render_coverage(rows)
    assert "dev: 1 cases" in rendered, "the defective case must not be counted"
    assert "case-bad is EXCLUDED" in rendered
    assert "wrong host" in rendered, "the reason travels with the exclusion"


def test_the_case_vocabulary_is_read_from_its_owners_not_restated():
    """The two vocabularies this linter checks against are read from the modules that own
    them: the derived-kind set from `score`, the eval-tells list from `story_from_run`.

    Both used to be declared here as well. `DERIVED_KINDS` carried two *different*
    justifications for one set — "no capture of its own, so `hidden/` is absent by design"
    here, "story never fired, so nothing was measured" in `score` — which is how a sixth kind
    gets added to one list and not the other and the linter starts calling a legitimate case
    malformed. `EVAL_TELLS` carried a keep-in-sync note naming `_EVAL_TELLS`, a symbol in
    neither file (it is the *test's* private name), so the note pointed nowhere.

    Identity, not equality: a re-declared tuple with the same contents compares equal and is
    exactly the drift this closes."""
    from defender.evals.oracle_golden import score, story_from_run

    assert validate_cases.DERIVED_KINDS is score.DERIVED_KINDS
    assert validate_cases.eval_tells_in is story_from_run.eval_tells_in
    assert not hasattr(validate_cases, "EVAL_TELLS"), (
        "the tells list is back as a second declaration")


def test_a_story_that_leaks_the_evaluation_frame_is_caught_case_insensitively(tmp_path):
    """The leak check is what the shared list is FOR, and it must survive the story being
    read in its own case: the owner lowercases internally, so the caller hands it the raw
    text. Passing an already-lowered string worked too — which is why this could have been
    broken by the move without a test noticing."""
    _case(tmp_path, "case-leaky", story="This is the NEGATIVE CONTROL for the burst.")
    problems = validate_cases.check_case(tmp_path / "case-leaky", {})
    assert any("leaks the evaluation frame" in p for p in problems), problems

    _case(tmp_path, "case-clean", story="An operator ran a routine backup.")
    assert not any("leaks the evaluation frame" in p
                   for p in validate_cases.check_case(tmp_path / "case-clean", {}))


# ------------------------------------------------------------------- controls

#: A lead query with no `@timestamp` bound of its own, written on ONE line — ES|QL
#: separates commands with `|`, not with newlines, and the defender model writes both
#: shapes. This is the shape `add_esql_window` used to splice wrongly (#882 F-20).
_UNBOUNDED = "FROM logs-zeek.ssh-* | LIMIT 1"
_WINDOW = ["2026-07-12T19:36:22.000Z", "2026-07-12T20:36:22.000Z"]


def _controlled_case(root, name, *, lead_query, control_query, window=None,
                     seq=0, record_seq=None):
    """A case whose one lead carries `lead_query`, controlled by `control_query`."""
    d = _case(root, name)
    (d / "oracle_visible" / "leads.jsonl").write_text(
        json.dumps({"lead_id": "l-001", "queries": [
            {"query_id": "elastic.ad-hoc", "params": {"query": lead_query}, "seq": seq}]})
        + "\n", encoding="utf-8")
    cd = d / "hidden" / "controls" / "l-001"
    cd.mkdir(parents=True)
    (cd / f"{seq}.json").write_text(json.dumps({
        "lead_id": "l-001",
        "seq": seq if record_seq is None else record_seq,
        "controls": [{"name": "C-14d", "window": window or _WINDOW,
                      "query": control_query, "live": True,
                      "payload": {"row_count": 0, "columns": [], "values": []}}],
    }), encoding="utf-8")
    return d


def test_an_added_window_behind_another_command_is_a_problem(tmp_path):
    """#882 F-20, against the artifact. The clause belongs immediately after the source
    command, where it narrows the row set and CANNOT widen it — that property is the
    only thing that makes an added window a control. Behind a `LIMIT`, one arbitrary row
    is taken first and then filtered by time, so the control reads zero rows.

    Zero rows is exactly what nothing downstream can interpret: `judge._control` drops
    the query string, so the label pass sees a live window that observed nothing and
    grades every observed row `present` against it.
    """
    d = _controlled_case(
        tmp_path, "case-x", lead_query=_UNBOUNDED,
        control_query=f'FROM logs-zeek.ssh-* | LIMIT 1 | WHERE @timestamp >= "{_WINDOW[0]}" '
                      f'AND @timestamp < "{_WINDOW[1]}"')
    problems = validate_cases.check_controls(d)
    assert any("landed at command 2" in p for p in problems), problems
    assert any("LIMIT 1" in p for p in problems), "the commands that ran first must be named"


def test_a_correctly_placed_added_window_is_not_a_problem(tmp_path):
    """The same lead, spliced the way `add_esql_window` splices it now. Pinned beside the
    failure so the check is known to discriminate rather than to flag every added
    window."""
    d = _controlled_case(
        tmp_path, "case-x", lead_query=_UNBOUNDED,
        control_query=f'FROM logs-zeek.ssh-*\n| WHERE @timestamp >= "{_WINDOW[0]}" '
                      f'AND @timestamp < "{_WINDOW[1]}"\n| LIMIT 1')
    assert validate_cases.check_controls(d) == []


def test_a_bound_on_the_wrong_end_of_the_window_is_a_problem(tmp_path):
    """#882 F-32, against the artifact. A shifted pair bound by POSITION rather than by
    each match's operator crosses an upper-bound-first query into `< start AND >= end` —
    unsatisfiable. ES|QL runs it happily and returns nothing, and `window_is_live` probes
    the window separately, so the record stores `live: true` with zero rows: the same
    empty baseline the misplaced splice produces."""
    d = _controlled_case(
        tmp_path, "case-x",
        lead_query=('FROM logs-system.auth-* | WHERE @timestamp < "2026-07-26T20:30:00.000Z" '
                    'AND @timestamp >= "2026-07-26T20:00:00.000Z"'),
        control_query=(f'FROM logs-system.auth-* | WHERE @timestamp < "{_WINDOW[0]}" '
                       f'AND @timestamp >= "{_WINDOW[1]}"'))
    problems = validate_cases.check_controls(d)
    assert any("the `<` bound is" in p for p in problems), problems
    assert any("the `>=` bound is" in p for p in problems), problems


def test_a_correctly_shifted_upper_first_query_is_not_a_problem(tmp_path):
    """The same upper-first lead, shifted the way `shift_esql_window` shifts it now:
    `>=`/`>` takes the window's start and `<=`/`<` its end, wherever they were written.
    Source order is preserved — only the literals move."""
    d = _controlled_case(
        tmp_path, "case-x",
        lead_query=('FROM logs-system.auth-* | WHERE @timestamp < "2026-07-26T20:30:00.000Z" '
                    'AND @timestamp >= "2026-07-26T20:00:00.000Z"'),
        control_query=(f'FROM logs-system.auth-* | WHERE @timestamp < "{_WINDOW[1]}" '
                       f'AND @timestamp >= "{_WINDOW[0]}"'))
    assert validate_cases.check_controls(d) == []


def test_a_control_that_pairs_with_no_query_is_a_problem(tmp_path):
    """#882 F-21's failure mode, against the artifact. Control records and observed
    payloads are joined on `seq`; a control keyed to a seq the lead set does not have is
    a baseline for nothing, and `judge._control` drops the query string, so no reader
    downstream can notice the mispairing."""
    d = _controlled_case(tmp_path, "case-x", lead_query=_UNBOUNDED, seq=0, record_seq=3,
                         control_query=f'FROM logs-zeek.ssh-*\n| WHERE @timestamp >= '
                                       f'"{_WINDOW[0]}" AND @timestamp < "{_WINDOW[1]}"\n'
                                       f'| LIMIT 1')
    assert any("not a query in leads.jsonl" in p for p in validate_cases.check_controls(d))


def test_a_case_with_no_controls_is_not_a_problem(tmp_path):
    """A lookup lead has no `@timestamp` bound to move, so it has no baseline by
    construction — the coverage report's job, not a defect."""
    assert validate_cases.check_controls(_case(tmp_path, "case-x")) == []
