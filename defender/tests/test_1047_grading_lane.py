"""#1047 O1 — a world whose run the host cut short is never graded as a verdict about the case."""
from __future__ import annotations

import json


from defender.tests import _spec1047 as S

#: The host's own forced close, as `_close_a_run_cut_short` writes it — `unresolved`, `stands`,
FORCED_REPORT = S.report_text("unresolved")


def _forced_close(episode_dir, label="b"):
    """Overwrite one archived world's report with the host's forced `unresolved` close — claim
    h2's configuration, reproduced as a real document through the real reader."""
    (episode_dir / "worlds" / label / "report.md").write_text(FORCED_REPORT, encoding="utf-8")


# the third row shape


def test_a_cut_short_world_files_the_third_row_shape(tmp_path):
    """A world whose archived run_end.json says its run was truncated — and whose model had NOT
    already closed — returns the third row shape: `ungradable: True`, `cut_short` carrying the
    normalized exit value, `closed_before_cut` False on the record it was read from, and an
    `ungradable_reason` naming the exit — with no `malformed` key, so tier 1 still means absent
    and tier 2 still means malformed."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    row = S.graded(ep)["b"]
    assert row.get("ungradable") is True, "a cut-short world was still graded as a verdict"
    assert row.get("cut_short") == "request-limit", (
        "the row does not carry the exit class as a top-level key beside `ungradable` "
        "(F1 reading A); a reader cannot tell this row from tier 1 without it")
    assert "malformed" not in row, (
        "the cut-short row was marked malformed — tier 2 means 'the input is there and wrong', "
        "and this world's inputs are neither")
    reason = row.get("ungradable_reason") or ""
    assert "b" in reason, f"the reason does not name the world: {reason!r}"
    assert "request-limit" in reason, f"the reason does not name the exit class: {reason!r}"


def test_a_cut_short_world_does_not_reach_the_family_call_as_a_verdict(tmp_path):
    """A cut-short world's host-forced `unresolved` report never reaches the family-scope call as
    that world's verdict: where today a host-forced unresolved report on b flips caught to
    survived (claim h2, executed), the family's word — decided by that call since #1224 — is
    decided from a line saying b was NOT JUDGED, and b's own world call is never made."""
    control = S.family_view(S.cut_short_episode(tmp_path / "control"))
    assert "verdict='malicious'" in control["b"], control

    bug_ep = S.cut_short_episode(tmp_path / "bug")
    _forced_close(bug_ep)
    bug = S.family_view(bug_ep)
    assert "verdict='unresolved'" in bug["b"], (
        "the observation channel cannot see the difference: a host-forced `unresolved` report "
        "on world b did not reach the family call as b's verdict, so the assertion below proves "
        f"nothing (claim h2 observed caught -> survived on exactly this configuration): {bug}")

    fixed_ep = S.cut_short_episode(tmp_path / "fixed", cut={"b": "request-limit"})
    _forced_close(fixed_ep)
    judge = S.scripted_judge()
    assert S.graded(fixed_ep, judge=judge)["b"].get("verdict") is None
    assert S.judge_calls_for(judge, "b") == [], (
        "world b's run was cut short and still bought a world call")
    fixed = S.family_view(fixed_ep)
    assert fixed["b"] == "NOT JUDGED", (
        "world b's run being cut short still put the host's forced close in front of the family "
        f"call as a verdict; a run stopped before the model could decide is not a measurement: "
        f"{fixed['b']!r}")
    assert fixed["c"] == control["c"], "world b's cut moved what the family is shown of world c"


def test_the_third_row_shape_keeps_the_two_tiers_separable(tmp_path):
    """The cut-short row carries no `malformed` key and an absent input still carries none either,
    so `test_921_family_facts.py:631`'s absent-vs-malformed split reads the same after the
    change as before it."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / "c" / "report.md").unlink()
    graded = S.graded(ep)
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("ungradable") is True
    assert graded["c"].get("malformed") is not True, (
        "an absent input was recorded as a malformed one; tier 1 skips and tier 2 refuses, and "
        "the record is where the difference has to survive")
    assert graded["c"].get("cut_short") is None, (
        "a world ungradable for an absent report acquired a cut_short key")


def test_an_aborted_budget_or_store_world_names_its_exit_not_a_missing_report(tmp_path):
    """A world whose run ended aborted, budget or store — none of which write a report.md — still
    returns the third row shape naming that exit class, rather than the generic tier-1 reason
    "missing its report.md"; the cut-short check runs first for all five exit classes, not only
    the two that also produce a forced report."""
    for exit_class in S.NO_REPORT_EXITS:
        ep = S.cut_short_episode(tmp_path / exit_class, cut={"b": exit_class})
        (ep / "worlds" / "b" / "report.md").unlink()
        row = S.graded(ep)["b"]
        assert row.get("cut_short") == exit_class, (
            f"{exit_class}: the row does not name the exit class")
        reason = row.get("ungradable_reason") or ""
        assert exit_class in reason, (
            f"{exit_class}: the reason is {reason!r} — the generic missing-report reason won, "
            "so the cut-short check did not run first")
        assert "report.md" not in reason, (
            f"{exit_class}: the reason blames a missing report.md for a class that never "
            "writes one")


# F-A — a model that closed, and a run cut short afterwards


def test_a_world_whose_model_closed_and_was_then_cut_short(tmp_path):
    """A world whose model had ALREADY CLOSED when the exit class was stamped keeps its verdict:
    the row is graded normally, carries no `cut_short` key, and still counts toward the family's
    verdict word."""
    decided = S.cut_short_episode(tmp_path / "decided", cut={"b": "request-limit"},
                                  closed=("b",))
    row = S.graded(decided)["b"]
    assert row.get("cut_short") is None, (
        "a world that produced its own verdict before the run was cut short was filed as "
        "cut short; the host's report is not what this world's report is")
    assert row.get("ungradable") is not True, (
        "a genuine model-authored verdict was discarded because the run was later cut short")

    undecided = S.cut_short_episode(tmp_path / "undecided", cut={"b": "request-limit"})
    assert S.graded(undecided)["b"].get("cut_short") == "request-limit", (
        "the control failed: a world cut short WITHOUT deciding no longer files the third row "
        "shape, so the assertion above is not about `closed_before_cut`")

    control = S.cut_short_episode(tmp_path / "control")
    assert S.family_view(decided) == S.family_view(control), (
        "a world that decided before it was cut short stopped counting as a measuring world")


def test_the_record_must_distinguish_a_host_written_close_from_the_models_own(tmp_path):
    """The run-end record carries a second field — `closed_before_cut` — and it is what separates a
    host-written close from the model's own: two worlds carrying the SAME exit class and the
    SAME report differ in their rows only because the record says whether the model had already
    decided."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "aborted", "c": "aborted"}, closed=("c",))
    for label in ("b", "c"):
        (ep / "worlds" / label / "report.md").write_text(
            S.report_text("malicious"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "aborted", (
        "the world whose model never closed was not filed as cut short")
    assert graded["c"].get("cut_short") is None, (
        "the world whose model HAD closed was filed as cut short; the two worlds are "
        "identical apart from the record's second field, so the record is not distinguishing "
        "a host-written close from the model's own")
    assert graded["c"].get("verdict") is not None, (
        "the world that decided before it was cut short recorded no verdict at all")

    record = json.loads(
        (ep / "worlds" / "c" / S.run_end_name()).read_text(encoding="utf-8"))
    assert record["closed_before_cut"] is True
    assert set(record) >= {"truncated_by", "closed_before_cut"}, (
        "the record's field set is short of what F-A reading B requires")


# what the judge's read of the archived record does with each state it can meet


def _cut_short_of(episode_dir, label="b"):
    """What the grading pass made of one world's archived run-end record: the `cut_short` the
    row carries, or `None` — the judge's one read of the record (`family._read_run_end_record`,
    through `run_end.parse_record`) feeds the row and nothing else."""
    return S.graded(episode_dir)[label].get("cut_short")


def test_read_world_facts_given_an_empty_run_end_json(tmp_path):
    """A zero-byte archived record reads as None (unreadable) and the world grades as today, by
    `missing_run_end_grades_as_today`'s own rule."""
    ep = S.cut_short_episode(tmp_path)
    S.plant_archived_record(ep, "b", raw="")
    assert _cut_short_of(ep) is None
    assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_a_mapping_with_truncated_by_explicitly_null(tmp_path):
    """An explicit null is indistinguishable from key-absent and from file-absent: all three mean
    "not cut short"."""
    absent = S.cut_short_episode(tmp_path / "absent")
    explicit = S.cut_short_episode(tmp_path / "explicit")
    S.plant_archived_record(explicit, "b", truncated_by=None)
    no_key = S.cut_short_episode(tmp_path / "nokey")
    S.plant_archived_record(no_key, "b", raw=json.dumps({}))
    answers = [_cut_short_of(e) for e in (absent, explicit, no_key)]
    assert answers == [None, None, None], f"the three absent-shaped records disagreed: {answers}"
    rows = [S.graded(e)["b"] for e in (absent, explicit, no_key)]
    assert all(r.get("ungradable") is not True for r in rows), (
        "a record meaning 'not cut short' made a world ungradable")


def test_read_world_facts_given_a_wrong_typed_truncated_by_value(tmp_path):
    """A non-string `truncated_by` value normalises to None at the owner and reads as "not cut
    short" — the judge carries no type check of its own."""
    ep = S.cut_short_episode(tmp_path)
    for value in (7, True, ["aborted"], {"value": "aborted"}):
        S.plant_archived_record(ep, "b", raw=json.dumps({"truncated_by": value}))
        assert _cut_short_of(ep) is None, f"{value!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_truncated_json_or_a_json_list(tmp_path):
    """Invalid JSON, truncated JSON and a JSON list where a mapping belongs each read as None and
    the world grades as today (fork F-Y, §7 round 2, convergent on the demand's own pinned
    language)."""
    ep = S.cut_short_episode(tmp_path)
    for raw in ('{"truncated_by": "abort', '[{"truncated_by": "aborted"}]', '"aborted"', "null"):
        S.plant_archived_record(ep, "b", raw=raw)
        assert _cut_short_of(ep) is None, f"{raw!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True, f"{raw!r} made the world ungradable"


# the absent record, and every route to it


# the cut-short check runs before every artifact-presence check, not just the report's


# families: several worlds, several shapes, one pass


def test_a_cut_short_world_and_a_malformed_world_in_the_same_episode(tmp_path):
    """The three row shapes coexist in one episode without interference — `tier_split_survives`'s
    own stated purpose, driven over a real family."""
    ep = S.cut_short_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={"b": [S.staged_row("b")], "c": [], "d": []},
        cut={"b": "request-limit"})
    (ep / "worlds" / "c" / "report.md").write_text(
        S.report_text("not-a-disposition"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("malformed") is True, "the malformed world lost its tier-2 mark"
    assert graded["c"].get("cut_short") is None, "the malformed world acquired cut_short"
    assert graded["d"].get("ungradable") is not True
