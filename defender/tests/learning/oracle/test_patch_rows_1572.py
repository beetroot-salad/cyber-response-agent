"""PR #1572 review: the host reads the patch once, row by row, and everything derives from that.

One pass over the patch yields the served answer and each change whole. A whole-row replace
is a forged row, a frozen row is served in the shape its table serves, a value edit keeps the
answer's shape, and the ledger label reads the uncut rows.
"""
from __future__ import annotations

from types import SimpleNamespace

from defender.learning.branch.estate.checks import (
    CheckStore,
    RealData,
    apply_handin,
    check_submission,
    parse_handin,
    render_changes,
    shown_changes,
)
from defender.learning.branch.estate.registry import ORACLE, served_label

WORLD = SimpleNamespace(facts=[SimpleNamespace(fact_id="F")])
ESQL = {"columns": [{"name": "user", "type": "keyword"}, {"name": "n", "type": "long"}],
        "values": [["alice", 3], ["bob", 5]]}


def _store(*, staged: dict | None = None, frozen: dict | None = None) -> CheckStore:
    return CheckStore(frozen=frozen or {}, staged=staged or {}, facts={}, rerun=lambda *a: {})


def _check(base, patch, store=None) -> list[str]:
    return check_submission(base, {"patch": patch, "entity_refs": [], "proofs": []},
                            world=WORLD, store=store or _store(), real_data=RealData())


def _record(fid: str, row) -> dict:
    return {fid: {"forged_id": fid, "fact_id": "F", "system": "s", "row": row}}


def test_a_whole_row_replace_without_a_forged_id_is_refused():
    base = {"rows": [{"event_id": "e-1", "user": "alice"}]}

    failures = _check(base, [{"op": "replace", "path": "/rows/0", "fact_id": "F",
                              "value": {"event_id": "e-1", "user": "mallory"}}])

    assert any("replaces the whole row" in f and "forged_id" in f for f in failures), failures


def test_a_whole_row_replace_is_a_forged_row_held_to_check_3():
    """The replaced row reuses a real id: as a forged row it fails check 3, and the row it
    stands in for counts as removed."""
    real = {"event_id": "e-1", "user": "alice"}
    new = {"event_id": "e-1", "user": "mallory"}
    store = _store(staged=_record("fg-1", new))

    failures = check_submission(
        {"rows": [real]},
        {"patch": [{"op": "replace", "path": "/rows/0", "value": new, "forged_id": "fg-1",
                    "fact_id": "F"}], "entity_refs": [], "proofs": []},
        world=WORLD, store=store, real_data=RealData(answers=[("s", {"rows": [real]})]))

    assert any(f.startswith("check 3") and "event_id" in f for f in failures), failures
    handin = parse_handin({"patch": [{"op": "replace", "path": "/rows/0", "value": new,
                                      "forged_id": "fg-1", "fact_id": "F"}]})[0]
    applied = apply_handin({"rows": [real]}, handin)
    assert applied.removed == [(real, None)]
    assert [c.op["forged_id"] for c in applied.forged] == ["fg-1"]


def test_a_value_edit_keeps_its_kind_and_a_key_cannot_be_removed():
    base = {"total": 2, "rows": [{"user": "alice", "tags": ["a", "b"]}]}

    assert any("another shape" in f for f in _check(
        base, [{"op": "replace", "path": "/total", "value": {"n": 2}, "fact_id": "F"}]))
    assert any("a key, an ES|QL cell" in f for f in _check(
        base, [{"op": "remove", "path": "/rows/0/user", "fact_id": "F"}]))
    assert _check(base, [{"op": "remove", "path": "/rows/0/tags/1", "fact_id": "F"}]) == []


def test_an_operation_may_not_edit_a_row_the_patch_forges():
    row = {"user": "carol", "n": 1}
    failures = _check({"rows": []}, [
        {"op": "add", "path": "/rows/-", "value": row, "forged_id": "fg-1", "fact_id": "F"},
        {"op": "replace", "path": "/rows/0/user", "value": "dave", "fact_id": "F"}],
        _store(staged=_record("fg-1", row)))

    assert any("changes a row this patch forges" in f for f in failures), failures


def test_a_frozen_row_is_served_as_a_value_array_where_its_table_has_its_columns():
    frozen = _record("fg-1", {"user": "carol", "n": 7})
    handin = parse_handin({"patch": [{"op": "add", "path": "/values/-", "forged_id": "fg-1",
                                      "fact_id": "F"}]})[0]
    from defender.learning.branch.estate.checks import frozen_stage

    applied = apply_handin(ESQL, handin, stage=frozen_stage(_store(frozen=frozen)))

    assert applied.served["values"][-1] == ["carol", 7]


def test_a_frozen_row_is_refused_where_the_query_projects_other_columns():
    frozen = _record("fg-1", {"user": "carol", "n": 7, "host": "web-1"})

    failures = _check(ESQL, [{"op": "add", "path": "/values/-", "forged_id": "fg-1",
                              "fact_id": "F"}], _store(frozen=frozen))

    assert any("projects exactly its columns" in f for f in failures), failures


def test_a_forged_mapping_in_an_esql_table_is_served_as_a_value_array():
    row = {"n": 1, "user": "carol"}
    handin = parse_handin({"patch": [{"op": "add", "path": "/values/-", "value": row,
                                      "forged_id": "fg-1", "fact_id": "F"}]})[0]

    applied = apply_handin(ESQL, handin)

    assert applied.served["values"][-1] == ["carol", 1]


def test_the_label_reads_the_whole_row_not_the_cut_one():
    """A removed event over the display cap still names the fact's entity to the label."""
    event = {"message": "x" * 5000, "host": "web-7"}
    base = {"hits": [event]}
    handin = parse_handin({"patch": [{"op": "remove", "path": "/hits/0", "fact_id": "F"}]})[0]
    applied = apply_handin(base, handin)
    whole = render_changes(applied, handin, query={}, base_was="live")
    facts = [{"fact_id": "F", "entities": ["web-7"]}]

    assert served_label(base, applied.served, whole, facts) == ORACLE
    assert "[cut:" in shown_changes(whole)["changes"][0]["row_before"]


def test_a_serving_keeps_how_it_was_made_and_one_that_changed_nothing_is_not_kept():
    from defender.learning.branch.estate.registry import serving_row

    made = serving_row("s", "v", {}, {"changes": []}, SimpleNamespace(code="print(1)"))
    assert made is not None
    assert made["code"] == "print(1)"
    assert "served" not in made
    assert serving_row("s", "v", {}, {"changes": []}, SimpleNamespace(code=None)) is None


def test_long_code_does_not_bury_a_serving_whose_query_matches():
    from defender.learning.branch.estate.oracle import similar_servings

    code = " ".join(f"token{i}" for i in range(300))
    servings = [{"system": "idp", "verb": "query", "params": {"q": "user:alice host:web-1"},
                 "code": code},
                {"system": "idp", "verb": "query", "params": {"q": "user:carol"}, "code": None}]

    ranked = similar_servings(servings, ("idp", "query", {"q": "user:alice host:web-1"}), k=1)

    assert ranked[0]["code"] == code


def test_an_esql_answer_s_columns_are_never_patched():
    """Reproduced: removing a column entry served a column list out of line with its values."""
    for op in ({"op": "remove", "path": "/columns/1", "fact_id": "F"},
               {"op": "replace", "path": "/columns/1/name", "value": "x", "fact_id": "F"}):
        failures = _check(ESQL, [op])
        assert any("columns" in f and "follow the query" in f for f in failures), failures


def test_a_table_under_a_number_like_key_is_named_as_real_rows_name_it():
    """Reproduced: a forged row under `agents/001/events` skipped check 2 for want of real rows."""
    base = {"agents": {"001": {"events": [{"id": "e-1", "x": 1}]}}}
    row = {"totally": "other"}
    store = _store(staged=_record("fg-1", row))

    failures = check_submission(
        base, {"patch": [{"op": "add", "path": "/agents/001/events/-", "value": row,
                          "forged_id": "fg-1", "fact_id": "F"}], "entity_refs": [], "proofs": []},
        world=WORLD, store=store, real_data=RealData(answers=[("s", base)]))

    assert any(f.startswith("check 2") for f in failures), failures


def test_a_list_item_that_is_no_row_is_not_removed_as_a_value():
    base = {"meta": {"pairs": [[1, 2], [3, 4]]}, "rows": [{"a": 1}]}

    assert any("no row" in f for f in _check(
        base, [{"op": "remove", "path": "/meta/pairs/0", "fact_id": "F"}]))


def test_a_forged_row_replace_is_labelled_as_showing_the_difference():
    base = {"hits": [{"event_id": "e-1", "user": "carol"}]}
    new = {"event_id": "e-9", "user": "dave"}
    handin = parse_handin({"patch": [{"op": "replace", "path": "/hits/0", "value": new,
                                      "forged_id": "fg-1", "fact_id": "F"}]})[0]
    applied = apply_handin(base, handin)
    whole = render_changes(applied, handin, query={}, base_was="live")

    assert served_label(base, applied.served, whole,
                        [{"fact_id": "F", "entities": ["web-7"]}]) == ORACLE


def test_shown_changes_are_capped_in_all_and_say_how_many_were_left_out():
    rows = [{"n": i, "pad": "x" * 1500} for i in range(100)]
    handin = parse_handin({"patch": [{"op": "remove", "path": f"/rows/{i}", "fact_id": "F"}
                                     for i in range(99, -1, -1)]})[0]
    applied = apply_handin({"rows": rows}, handin)

    shown = shown_changes(render_changes(applied, handin, query={}, base_was="live"))

    assert 0 < len(shown["changes"]) < 100
    assert shown["changes_not_shown"] == 100 - len(shown["changes"])
