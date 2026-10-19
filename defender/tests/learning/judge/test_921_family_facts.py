"""#921 — a world's row: the facts read off X's own archived record (`family.read_world`)."""
from __future__ import annotations

import json

import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


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

    assert sorted(rows) == ["b", "c"], "a graded non-control world has no row in the record"
    for label, row in rows.items():
        missing = [fact for fact in J.PER_WORLD_FACTS if fact not in row]
        assert not missing, f"world {label} is missing per-world facts: {missing}"
        assert "bucket" in row, f"world {label} carries no bucket"
        assert row["declared"] in ("benign", "malicious"), (
            "the ground truth known by construction is not on the row")


def test_921_served_nothing_reads_x_own_rows_off_the_composed_token(tmp_path):
    ep = J.accepted_episode(tmp_path, ledgers={
        # b: one family-tier base row and nothing of its own — J2's whole case.
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

    (ep / "served" / f"{J.world_token('c')}.jsonl").unlink()
    absent = _rows(ep)["c"]
    assert absent.get("ungradable") is not True, (
        "an ABSENT ledger set the world aside; S8 makes it a world no call reached")
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
    (ep / "worlds" / "c" / "investigation.md").write_text(
        J.investigation_document("c", moved=False), encoding="utf-8")
    unmoved = _rows(ep)["c"]
    assert unmoved["resolution_moved"] is False
    assert unmoved.get("ungradable") is not True


def test_921_verdict_is_read_off_the_archived_report_against_the_manifest(tmp_path):
    ep = J.accepted_episode(tmp_path,
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    rows = _rows(ep)

    assert rows["b"]["verdict"] == "benign"
    assert rows["b"]["declared"] == "malicious"
    assert rows["c"]["verdict"] == rows["c"]["declared"] == "malicious"

    # The vocabulary is read through the shipped normalizer, and that normalizer coerces
    # nothing: a zero-width-laced headline renders as `malicious` to a human and is NOT one.
    (ep / "worlds" / "c" / "report.md").write_text(
        J.report_text("mali​cious"), encoding="utf-8")
    laced = _rows(ep)
    assert laced["c"].get("malformed") is True, (
        "a laced headline graded as a clean one; the normalizer is exact by decision and the "
        "judge is the reader that must not be fooled by a value that renders as `malicious`")
    assert laced["b"].get("ungradable") is not True, (
        "world c's laced headline cost world b its grade")

    # Positive control on the same drive: the same world with a CLEAN headline grades, so the
    # exclusion above cannot pass on a reader that excludes everything.
    (ep / "worlds" / "c" / "report.md").write_text(
        J.report_text("malicious"), encoding="utf-8")
    assert _rows(ep)["c"]["verdict"] == "malicious"


def test_921_a_world_missing_an_input_is_ungradable_named_and_excluded_from_the_verdict_word(
        tmp_path):
    import yaml

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    (ep / "worlds" / "b" / "report.md").unlink()
    grade = _grade(ep)
    row = J.rows(grade)["b"]
    assert row["ungradable"] is True
    assert "report.md" in json.dumps(row), "the missing input is not named on the record"
    assert "b" not in grade.graded_worlds

    fresh = J.accepted_episode(tmp_path / "gone-investigation",
                               ledgers={"b": [J.oracle_row("b")], "c": []})
    (fresh / "worlds" / "c" / "investigation.md").unlink()
    gone = J.rows(_grade(fresh))["c"]
    assert gone["ungradable"] is True
    assert "investigation" in json.dumps(gone)

    both = J.accepted_episode(tmp_path / "no-declared")
    doc = yaml.safe_load((both / "family.yaml").read_text(encoding="utf-8"))
    for world in doc["worlds"]:
        if world["world_id"] != "a":
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
            f"{name}: world b's malformed archive cost world c its grade — one world's bad "
            "artifact is not a reason to throw away a sibling that graded cleanly")
        return rows["b"]

    for name, mutate in (
        ("vocab", lambda ep: (ep / "worlds" / "b" / "report.md").write_text(
            J.report_text("probably-bad"), encoding="utf-8")),
        ("unreadable", lambda ep: (ep / "worlds" / "b" / "report.md").write_bytes(
            b"\xff\xfe\x00not utf-8")),
        ("truncated", lambda ep: (ep / "worlds" / "b" / "investigation.md").write_text(
            "# investigation b\n\n```invlang\n:T resolutions\n"
            "h-001  open → held    [l-001 r1 severe ⟂ e-001 :: cut off here\n",
            encoding="utf-8")),
        # F-7 — the partially archived world.
        ("partial", lambda ep: (
            ep / "worlds" / "b" / "gather_summaries" / "l-001.md").unlink()),
    ):
        row = _malform(name, mutate)
        assert row.get("ungradable") is True, f"{name}: the malformed world still graded"
        assert row.get("malformed") is True, (
            f"{name}: the row does not say the input was MALFORMED — absent and malformed are "
            "different answers and a reader keying on `ungradable` alone cannot tell them apart")
        assert row.get("ungradable_reason"), f"{name}: the exclusion carries no reason"
        assert "b" in row["ungradable_reason"], f"{name}: the reason does not name the world"

    short = J.accepted_episode(tmp_path / "named", ledgers={"b": [J.oracle_row("b")], "c": []})
    (short / "worlds" / "b" / "gather_summaries" / "l-001.md").unlink()
    said = _rows(short)["b"]["ungradable_reason"]
    assert "gather_summaries" in said, (
        "a world left short by a mid-copy fault was excluded without naming the input that was "
        "short")

    # An ABSENT input is tier 1 and is NOT marked malformed — the two tiers stay separable.
    absent = J.accepted_episode(tmp_path / "absent", ledgers={"b": [J.oracle_row("b")], "c": []})
    (absent / "worlds" / "b" / "report.md").unlink()
    gone = _rows(absent)["b"]
    assert gone.get("ungradable") is True, "an absent report.md still graded"
    assert gone.get("malformed") is not True, (
        "an absent input was recorded as a malformed one; tier 1 skips, tier 2 refuses, and "
        "the record is where the difference has to survive")


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
    # #1224: a label is a world token (lower-case), so the collision is with a run of that name.
    colliding = "fresh_case_n59"
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", colliding),
        dispositions={"a": "benign", "b": "malicious", colliding: "malicious"},
        ledgers={"b": [J.oracle_row("b")], colliding: []})

    assert sorted(_rows(ep)) == sorted(["b", colliding]), (
        "the control failed: a label spelled like a run id did not load while no such run "
        "existed, so the refusal below would not be about the collision")

    # The real run appears under the tenant's runs base — `runs_base` writes an ORDINARY
    # finished run there — and the label still grades.
    _base, source_run_dir = J.runs_base(tmp_path, source_run_id=colliding)
    assert source_run_dir.name == colliding
    assert sorted(_rows(ep)) == sorted(["b", colliding]), (
        "a label spelled like a natural run id of the tenant no longer grades — the judge read "
        "the tenant's runs, which it no longer does (J3)")


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
            bound, "b", episode_token=J.EPISODE_TOKEN)
    assert [row["source"] for row in kept] == ["oracle", "passthrough"], (
        "a row of a repeated pair-key was dropped; each row is its own call (A2)")
    assert malformed == 2, (
        "the torn line and the out-of-vocabulary `source` were dropped without a count")

    rows = _rows(ep)
    assert rows["b"]["malformed"] is True, "a partly-read ledger was graded (A3)"
    assert J.world_token("b") in rows["b"]["ungradable_reason"], (
        "the refusal does not name the ledger file it refused")
    assert rows["c"].get("ungradable") is not True, "world b's torn ledger took world c's grade"
