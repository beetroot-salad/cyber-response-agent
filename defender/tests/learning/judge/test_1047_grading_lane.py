"""#1047 — a world whose run the host cut short is never graded as a verdict about the case."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import json


from defender.tests.support.shared.filesystem import _spec1047 as S

#: The host's forced close as `_close_a_run_cut_short` leaves it: an `unresolved` report.
FORCED_REPORT = S.report_text("unresolved")


def _forced_close(episode_dir):
    """Overwrite world b's archived report with the host's forced `unresolved` close."""
    (episode_dir / "worlds" / T.world_id(episode_dir, "b") / "report.md").write_text(FORCED_REPORT, encoding="utf-8")


# the third row shape


def test_a_cut_short_world_files_the_third_row_shape(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    row = S.graded(ep)["b"]
    assert row.get("ungradable") is True, "a cut-short world was still graded as a verdict"
    assert row.get("cut_short") == "request-limit", (
        "the row does not carry the exit class as a top-level key beside `ungradable`")
    assert "malformed" not in row, "the cut-short row was marked malformed"
    reason = row.get("ungradable_reason") or ""
    assert "b" in reason, f"the reason does not name the world: {reason!r}"
    assert "request-limit" in reason, f"the reason does not name the exit class: {reason!r}"


def test_a_cut_short_world_does_not_reach_the_family_call_as_a_verdict(tmp_path):
    control = S.family_view(S.cut_short_episode(tmp_path / "control"))
    assert "verdict='malicious'" in control["b"], control

    bug_ep = S.cut_short_episode(tmp_path / "bug")
    _forced_close(bug_ep)
    bug = S.family_view(bug_ep)
    assert "verdict='unresolved'" in bug["b"], (
        f"a host-forced `unresolved` report on world b did not reach the family call: {bug}")

    fixed_ep = S.cut_short_episode(tmp_path / "fixed", cut={"b": "request-limit"})
    _forced_close(fixed_ep)
    judge = S.scripted_judge()
    assert S.graded(fixed_ep, judge=judge)["b"].get("verdict") is None
    assert S.judge_calls_for(judge, "b", episode_dir=fixed_ep) == [], (
        "world b's run was cut short and still bought a world call")
    fixed = S.family_view(fixed_ep)
    assert fixed["b"] == "NOT JUDGED", (
        f"the family call was shown cut-short world b's forced close as a verdict: {fixed['b']!r}")
    assert fixed["c"] == control["c"], "world b's cut moved what the family is shown of world c"


def test_the_third_row_shape_keeps_the_two_tiers_separable(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / T.world_id(ep, "c") / "report.md").unlink()
    graded = S.graded(ep)
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("ungradable") is True
    assert graded["c"].get("malformed") is not True, (
        "an absent input was recorded as a malformed one")
    assert graded["c"].get("cut_short") is None, (
        "a world ungradable for an absent report acquired a cut_short key")


def test_an_aborted_budget_or_store_world_names_its_exit_not_a_missing_report(tmp_path):
    for exit_class in S.NO_REPORT_EXITS:
        ep = S.cut_short_episode(tmp_path / exit_class, cut={"b": exit_class})
        (ep / "worlds" / T.world_id(ep, "b") / "report.md").unlink()
        row = S.graded(ep)["b"]
        assert row.get("cut_short") == exit_class, (
            f"{exit_class}: the row does not name the exit class")
        reason = row.get("ungradable_reason") or ""
        assert exit_class in reason, (
            f"{exit_class}: the generic missing-report reason won: {reason!r}")
        assert "report.md" not in reason, (
            f"{exit_class}: the reason blames a missing report.md for a class that never "
            "writes one")


# a model that closed, and a run cut short afterwards


def test_a_world_whose_model_closed_and_was_then_cut_short(tmp_path):
    decided = S.cut_short_episode(tmp_path / "decided", cut={"b": "request-limit"},
                                  closed=("b",))
    row = S.graded(decided)["b"]
    assert row.get("cut_short") is None, (
        "a world that produced its own verdict before the run was cut short was filed as "
        "cut short")
    assert row.get("ungradable") is not True, (
        "a genuine model-authored verdict was discarded because the run was later cut short")

    undecided = S.cut_short_episode(tmp_path / "undecided", cut={"b": "request-limit"})
    assert S.graded(undecided)["b"].get("cut_short") == "request-limit", (
        "control: a world cut short without deciding did not file the third row shape")

    control = S.cut_short_episode(tmp_path / "control")
    assert S.family_view(decided) == S.family_view(control), (
        "a world that decided before it was cut short stopped counting as a measuring world")


def test_the_record_must_distinguish_a_host_written_close_from_the_models_own(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "aborted", "c": "aborted"}, closed=("c",))
    for label in ("b", "c"):
        (ep / "worlds" / T.world_id(ep, label) / "report.md").write_text(
            S.report_text("malicious"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "aborted", (
        "the world whose model never closed was not filed as cut short")
    assert graded["c"].get("cut_short") is None, (
        "the world whose model had closed was filed as cut short")
    assert graded["c"].get("verdict") is not None, (
        "the world that decided before it was cut short recorded no verdict at all")

    record = json.loads(
        (ep / "worlds" / T.world_id(ep, "c") / S.run_end_name()).read_text(encoding="utf-8"))
    assert record["closed_before_cut"] is True
    assert set(record) >= {"truncated_by", "closed_before_cut"}, (
        f"the record lacks `truncated_by` or `closed_before_cut`: {sorted(record)}")


# what the judge's read of the archived record does with each state it can meet


def _cut_short_of(episode_dir):
    """The `cut_short` world b's graded row carries, or `None`: the judge's one read of the
    run-end record (`family._read_run_end_record`) feeds the row and nothing else."""
    return S.graded(episode_dir)["b"].get("cut_short")


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
    ep = S.cut_short_episode(tmp_path)
    for raw in ("", '{"truncated_by": "abort', '[{"truncated_by": "aborted"}]', '"aborted"',
                "null"):
        S.plant_archived_record(ep, "b", raw=raw)
        assert _cut_short_of(ep) is None, f"{raw!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True, f"{raw!r} made the world ungradable"


# families: several worlds, several shapes, one pass


def test_a_cut_short_world_and_a_malformed_world_in_the_same_episode(tmp_path):
    """The three row shapes coexist in one episode without interference."""
    ep = S.cut_short_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={"b": [S.staged_row("b")], "c": [], "d": []},
        cut={"b": "request-limit"})
    (ep / "worlds" / T.world_id(ep, "c") / "report.md").write_text(
        S.report_text("not-a-disposition"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("malformed") is True, "the malformed world lost its tier-2 mark"
    assert graded["c"].get("cut_short") is None, "the malformed world acquired cut_short"
    assert graded["d"].get("ungradable") is not True
