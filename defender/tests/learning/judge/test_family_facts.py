"""#921 — a world's row: the facts read off X's own archived record (`family.read_world`)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

import json
from pathlib import Path

import pytest

from defender.tests.support.learning.judge import _judge_921 as J


def _family():
    return J.mod("learning.judge.family")


def _grade(ep):
    """Grade `ep` afresh: a final `judge.yaml` short-circuits a second pass, so a scenario that
    changes the archive and grades again removes it first."""
    (ep / "judge.yaml").unlink(missing_ok=True)
    return J.grade(ep)


def _rows(ep):
    return J.rows(_grade(ep))


def test_921_family_record_carries_a_row_per_graded_world(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [J.oracle_row("b")],
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    rows = J.rows(_grade(ep))

    assert "a" not in rows, "the control world was given a bucket row"
    assert sorted(rows) == ["b", "c"], "a graded non-control world has no row in the record"
    for label, row in rows.items():
        missing = [fact for fact in J.PER_WORLD_FACTS if fact not in row]
        assert not missing, f"world {label} is missing per-world facts: {missing}"
        assert "bucket" in row, f"world {label} carries no bucket"
        assert row["declared"] in ("benign", "malicious"), (
            "the ground truth known by construction is not on the row")


def test_921_served_nothing_reads_x_own_rows_off_the_composed_token(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={
        # b: one family-tier base row and nothing of its own.
        "b": [J.ledger_row(source="base", world_label=None)],
        # c: the same call, this time as the world's own decision row.
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    rows = _rows(ep)
    assert rows["b"].get("served_nothing") is not False, (
        "a family-tier `base` row was counted as the world's own served call")
    assert rows["b"]["malformed"] is True
    assert "names another run" in rows["b"]["ungradable_reason"], rows["b"]["ungradable_reason"]
    assert rows["c"]["served_nothing"] is False

    # And the file the reader must open is the COMPOSED token's, not the label's.
    J.write_ledger(ep, "c", [])
    stray = ep / "served" / "c.jsonl"
    stray.write_text(json.dumps(J.ledger_row(source="oracle", world_label="c")) + "\n",
                     encoding="utf-8")
    assert _rows(ep)["c"]["served_nothing"] is True, (
        "a file named by the short archive label was read as the world's ledger")


def test_921_an_empty_or_absent_ledger_is_a_world_that_served_nothing(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [], "c": []})
    rows = _rows(ep)
    assert rows["b"]["served_nothing"] is True
    assert rows["b"].get("ungradable") is not True, "an EMPTY ledger was read as a missing input"

    (ep / "served" / f"{J.fixture_world_id('c')}.jsonl").unlink()
    absent = _rows(ep)["c"]
    assert absent.get("ungradable") is not True, (
        "an absent ledger set the world aside instead of making it a world no call reached")
    assert absent["served_nothing"] is True


def test_921_a_served_call_with_no_row_is_invisible_to_the_mechanical_half(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={"b": []})
    quiet = _rows(ep)["b"]
    assert quiet["served_nothing"] is True
    assert quiet.get("errors") in (None, [], ()), (
        "the pass raised or recorded an error about a call it simply cannot see")

    J.write_ledger(ep, "b", [J.ledger_row(source="passthrough", world_label="b")])
    assert _rows(ep)["b"]["served_nothing"] is False


def test_921_resolution_moved_needs_a_row_past_fences_at_with_before_ne_after(tmp_path):
    ep = J.accepted_episode(tmp_path, fences_at=1)
    # `b` oscillates: row 1 moves the lead, row 2 moves it back. ANY qualifying row counts.
    rows = _rows(ep)
    assert rows["b"]["resolution_moved"] is True, (
        "an oscillating lead's first qualifying row was discarded in favour of the net state")

    # A document whose row does not move: false by construction, not an error.
    (ep / "worlds" / T.world_id(ep, "c") / "investigation.md").write_text(
        J.investigation_document("c", moved=False), encoding="utf-8")
    unmoved = _rows(ep)["c"]
    assert unmoved["resolution_moved"] is False
    assert unmoved.get("ungradable") is not True


#: Text that must never reach a world's row or the written record: where the database sits, and a pointer's target.
_DETAIL_TOKENS = ("closing-1534-source", "gone.db")


def _leaks(ep, row) -> list[str]:
    """Which planted detail tokens appear in `row` or the written `judge.yaml`."""
    said = json.dumps(row) + (ep / "judge.yaml").read_text(encoding="utf-8")
    return [token for token in _DETAIL_TOKENS if token in said]


def test_921_each_worlds_verdict_is_its_arms_closing_record_read_through_the_roster(tmp_path):
    """Reached is the arm's committed record, not the archive tree's and not the source's own row. (OD5, V-LOOK)"""
    from defender.tests.storage.verdict_1534 import _spec1534 as V
    ep = J.accepted_episode(tmp_path, dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    J.set_closing(ep, "b", disposition="benign")
    # A leftover report in the archive tree disagrees with b's record, and the source run holds its own row in the same
    # database: neither is b's.
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(  # lint-run-records: ok — a planted decoy
        "---\ndisposition: malicious\n---\n", encoding="utf-8")
    database = J.arm_database(ep)
    with V.run_store(tmp_path / "closing-source-runs", "closing-1534-source") as store:
        V.plant(store, V.a_record(T.SOURCE_RUN_ID, disposition="suspicious"))
    assert database == Path(store.path)

    rows = _rows(ep)
    assert rows["b"]["verdict"] == "benign", rows["b"]
    assert rows["b"]["declared"] == "malicious", rows["b"]
    assert rows["c"]["verdict"] == rows["c"]["declared"] == "malicious", rows["c"]
    assert not rows["b"].get("ungradable"), rows
    assert not rows["c"].get("ungradable"), rows


def test_921_reached_is_the_committed_disposition_never_the_drafted_one(tmp_path):
    """A forced-inconclusive close whose draft equals the declared disposition still reads `unresolved`. (V-FIELDS)"""
    from defender.records import closing as C

    ep = J.accepted_episode(tmp_path, dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    J.set_closing(ep, "b", disposition="unresolved", outcome=C.FORCED_INCONCLUSIVE,
                  cause=C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, drafted_disposition="malicious")
    rows = _rows(ep)
    assert rows["b"]["verdict"] == "unresolved", rows["b"]
    assert rows["b"]["declared"] == "malicious", rows["b"]
    assert rows["c"]["verdict"] == "malicious", rows["c"]


def test_921_a_world_that_never_closed_is_ungradable_as_a_missing_input_not_malformed_and_wears_no_fault_wording(
        tmp_path):
    """`NeverClosed` leaves the world ungradable without `malformed`, beside a graded sibling. (V-READERS)"""
    from defender.records import closing as C

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    J.no_closing(ep, "b")
    grade = _grade(ep)
    row = J.rows(grade)["b"]
    assert row["ungradable"] is True, row
    assert row.get("malformed") is not True, row
    assert row.get("ungradable_reason"), "the exclusion carries no reason"
    assert "b" not in grade.graded_worlds
    assert not any(wording in json.dumps(row) for wording in C.FAULT_WORDING.values()), (
        "an absence was worded as a fault")
    assert J.rows(grade)["c"].get("ungradable") is not True, "the sibling lost its grade to b's absence"

    # One arm whose folder is gone, with the container and roster present, never ran: absent, not a fault.
    gone = J.accepted_episode(tmp_path / "arm-folder-gone", ledgers={"b": [J.oracle_row("b")], "c": []})
    J.drop_arm_folder(gone, "b")
    gone_row = J.rows(_grade(gone))["b"]
    assert gone_row["ungradable"] is True, gone_row
    assert gone_row.get("malformed") is not True, gone_row
    assert not any(wording in json.dumps(gone_row) for wording in C.FAULT_WORDING.values()), gone_row


@pytest.mark.parametrize("kind", ["row-invalid", "pointer-unreadable", "database-missing", "legacy-link",
                                  "arm-refused"])
def test_921_an_arm_that_could_not_be_looked_at_is_ungradable_with_its_kinds_wording_and_no_detail(tmp_path, kind):
    """A `CouldNotLook` arm: ungradable, not `malformed`, `FAULT_WORDING[kind]`, no path outward; siblings grade. (V-LOOK)"""
    from defender.records import closing as C

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    control = _rows(J.accepted_episode(tmp_path / "control", ledgers={"b": [J.oracle_row("b")], "c": []}))
    assert control["b"].get("ungradable") is not True, "the intact twin did not grade"

    J.fault_arm(ep, "b", kind)
    grade = _grade(ep)
    row = J.rows(grade)["b"]
    assert row["ungradable"] is True, row
    assert row.get("malformed") is not True, row
    assert C.FAULT_WORDING[kind] in row["ungradable_reason"], (kind, row)
    assert not [other for other in set(C.FAULT_WORDING.values()) - {C.FAULT_WORDING[kind]}
                if other in row["ungradable_reason"]], "another kind's wording rode along"
    assert _leaks(ep, row) == [], f"the fault's detail reached the outward record: {_leaks(ep, row)}"
    assert J.rows(grade)["c"].get("ungradable") is not True, "b's fault cost world c its grade"


@pytest.mark.parametrize("kind", ["recorded-before-1534", "schema-version", "store-unreadable"])
def test_921_a_database_that_cannot_be_read_leaves_every_world_ungradable_with_its_kinds_wording(tmp_path, kind):
    """A database fault is every arm's: each non-control world is ungradable with the kind's wording. (V-LOOK)"""
    from defender.records import closing as C

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    J.fault_database(ep, kind)
    rows = _rows(ep)
    for label in ("b", "c"):
        assert rows[label]["ungradable"] is True, rows[label]
        assert rows[label].get("malformed") is not True, rows[label]
        assert C.FAULT_WORDING[kind] in rows[label]["ungradable_reason"], (kind, rows[label])
        assert _leaks(ep, rows[label]) == []


@pytest.mark.parametrize("how", ["roster-gone", "arm-container-gone"])
def test_921_a_missing_roster_refuses_the_whole_pass_and_a_gone_arm_container_leaves_every_world_unlooked(
        tmp_path, how):
    """No roster: the pass is refused with the kind's wording and asks the model nothing; roster present, container
    gone: `arm-refused` for every world. (OD12, V-LOOK)"""
    from defender.records import closing as C

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    judge = J.scripted_judge()
    if how == "roster-gone":
        J.drop_roster(ep)
        with pytest.raises(J.refusals()) as raised:
            J.grade(ep, judge=judge)
        assert C.FAULT_WORDING["roster-gone"] in str(raised.value)
        assert judge.prompts == [], "the judge was asked about a family whose roster is gone"
        assert not (ep / "judge.yaml").exists()
        return
    J.drop_arm_container(ep)
    rows = J.rows(J.grade(ep, judge=judge))
    for label in ("b", "c"):
        assert rows[label]["ungradable"] is True, rows[label]
        assert rows[label].get("malformed") is not True, rows[label]
        assert C.FAULT_WORDING["arm-refused"] in rows[label]["ungradable_reason"], rows[label]


def test_921_a_world_missing_an_input_is_ungradable_named_and_excluded_from_the_verdict_word(
        tmp_path):
    import yaml

    fresh = J.accepted_episode(tmp_path / "gone-investigation",
                               ledgers={"b": [J.oracle_row("b")], "c": []})
    (fresh / "worlds" / T.world_id(fresh, "c") / "investigation.md").unlink()
    gone = J.rows(_grade(fresh))["c"]
    assert gone["ungradable"] is True
    assert "investigation" in json.dumps(gone)

    both = J.accepted_episode(tmp_path / "no-declared")
    doc = yaml.safe_load((both / "family.yaml").read_text(encoding="utf-8"))
    for world in doc["worlds"]:
        if world["label"] != "a":
            world.pop("disposition_declared", None)
    (both / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(J.refusals()) as raised:
        _grade(both)
    assert "disposition_declared" in str(raised.value), (
        "a manifest whose worlds declare no ground truth was refused without naming the field")


def test_921_a_malformed_input_excludes_its_own_world_loudly_and_grades_the_rest(tmp_path):
    def _malform(name, mutate):
        """One episode with world `b`'s archive malformed, graded. Returns b's row."""
        ep = J.accepted_episode(tmp_path / name, ledgers={"b": [J.oracle_row("b")], "c": []})
        assert _rows(ep)["b"].get("ungradable") is not True, (
            f"the {name} control failed: the intact episode did not grade world b")
        mutate(ep)
        rows = _rows(ep)
        assert rows["c"].get("ungradable") is not True, (
            f"{name}: world b's malformed archive cost world c its grade")
        return rows["b"]

    for name, mutate in (
        ("truncated", lambda ep: (ep / "worlds" / T.world_id(ep, "b") / "investigation.md").write_text(
            "# investigation b\n\n```invlang\n:T resolutions\n"
            "h-001  open → held    [l-001 r1 severe ⟂ e-001 :: cut off here\n",
            encoding="utf-8")),
        # The partially archived world.
        ("partial", lambda ep: (
            ep / "worlds" / T.world_id(ep, "b") / "gather_summaries" / "l-001.md").unlink()),
    ):
        row = _malform(name, mutate)
        assert row.get("ungradable") is True, f"{name}: the malformed world still graded"
        assert row.get("malformed") is True, (
            f"{name}: the row does not say the input was malformed")
        assert row.get("ungradable_reason"), f"{name}: the exclusion carries no reason"
        assert "b" in row["ungradable_reason"], f"{name}: the reason does not name the world"

    short = J.accepted_episode(tmp_path / "named", ledgers={"b": [J.oracle_row("b")], "c": []})
    (short / "worlds" / T.world_id(short, "b") / "gather_summaries" / "l-001.md").unlink()
    said = _rows(short)["b"]["ungradable_reason"]
    assert "gather_summaries" in said, (
        "a world left short by a mid-copy fault was excluded without naming the input that was "
        "short")


def test_921_two_world_entries_under_one_label_are_refused_at_manifest_load(tmp_path):
    import yaml

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    doc = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert _rows(ep), "the control failed: the manifest did not load"

    doc["worlds"].append(dict(doc["worlds"][-1], world_id="b"))
    (ep / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(J.refusals()) as raised:
        _grade(ep)
    assert "b" in str(raised.value)


def test_921_a_world_label_equal_to_a_real_run_id_grades(tmp_path):
    # A label is a world token (lower-case), so the collision is with a run of that name.
    colliding = "fresh_case_n59"
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", colliding),
        dispositions={"a": "benign", "b": "malicious", colliding: "malicious"},
        ledgers={"b": [J.oracle_row("b")], colliding: []})

    assert sorted(_rows(ep)) == sorted(["b", colliding]), (
        "control: a label spelled like a run id did not load while no such run existed")

    # The real run appears under the tenant's runs base — `runs_base` writes an ORDINARY
    # finished run there — and the label still grades.
    _base, source_run_dir = location_path(J.runs_base)(tmp_path, source_run_id=colliding)
    assert source_run_dir.name == colliding
    assert sorted(_rows(ep)) == sorted(["b", colliding]), (
        "a label spelled like a natural run id of the tenant did not grade")


def test_921_the_family_pass_reader_takes_the_first_row_and_counts_a_torn_line(tmp_path):
    from defender._io import bind

    first = J.oracle_row("b")
    second = dict(first, source="passthrough")
    torn = json.dumps(J.ledger_row(source="passthrough", world_label="b"))[:40]
    ep = J.accepted_episode(tmp_path, ledgers={"c": []})
    J.write_ledger(ep, "b", [], raw="".join([
        json.dumps(first) + "\n",
        json.dumps(second) + "\n",
        torn + "\n",
        json.dumps(dict(first, source="teleported")) + "\n",
    ]))

    with bind(ep) as bound:
        kept, malformed, _read = _family().read_world_ledger(
            bound, T.world_id(ep, "b"))
    assert [row["source"] for row in kept] == ["oracle", "passthrough"], (
        "a row of a repeated pair-key was dropped; each row is its own call")
    assert malformed == 2, (
        "the torn line and the out-of-vocabulary `source` were dropped without a count")

    rows = _rows(ep)
    assert rows["b"]["malformed"] is True, "a partly-read ledger was graded"
    assert J.fixture_world_id("b") in rows["b"]["ungradable_reason"], (
        "the refusal does not name the ledger file it refused")
    assert rows["c"].get("ungradable") is not True, "world b's torn ledger took world c's grade"
