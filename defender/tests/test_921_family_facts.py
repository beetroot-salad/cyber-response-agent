"""#921 — a world's row: the facts read off X's own archived record (`family.read_world`).

#1224 retired the mechanical half's bucket table: `holding_queried`, `scope_discriminated` and
"a doctored answer was served" were keyed on the manifest's holding system and the staged/
patched ledger words, all three gone with cluster staging, and the judge MODEL now decides each
world's bucket (O11). What survives is the row the model is shown beside the archive — every
fact read off X's OWN ledger, X's OWN archived document and report, and the manifest, never
another world and never the comparator — and the tier rule that sets a world aside:

* **J2** — the row population is filtered on the world's COMPOSED token; a family-tier `base`
  row in X's file is not X's own (`served_nothing` reads X's own rows alone).
* **J3** — the reader inherits `_absorb`'s first-row-wins, re-validates `source` against the
  ledger's words on read, and SKIPS a malformed line while recording the count on the row.
* **J4** — `resolution_moved` reads ANY qualifying row past `fences_at`.
* **J5** — an ABSENT archived document makes the world `ungradable`, named with its missing
  input; a MALFORMED input does too, marked `malformed`; a DUPLICATE label, or one colliding
  with a real run, is refused at manifest load. (#1224, S8: an absent served ledger is a world
  no call reached, not a missing input — whether a world ran is its own record's to say.)
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _state1135


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    # The learning STATE root too, so the shared findings queue this pass appends to is
    # this test's own and not the checkout's real `learning/_pending/`. Isolation belongs
    # here rather than in the appender: a production path that picks a different queue when
    # an env var is unset is a pass whose rows can land where no drain reads.
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _family():
    return J.mod("learning.judge.family")


def _grade(ep, runs_base=None):
    """Grade `ep` afresh: a final `judge.yaml` short-circuits a second pass, so a scenario that
    changes the archive and grades again removes it first."""
    (ep / "judge.yaml").unlink(missing_ok=True)
    return J.grade(ep, runs_base=runs_base if runs_base is not None
                   else ep.parent / "defender-runs")


def _rows(ep, runs_base=None):
    return J.rows(_grade(ep, runs_base))


# ---------------------------------------------------------------------------------------
# the record's own shape
# ---------------------------------------------------------------------------------------


def test_921_family_record_carries_a_row_per_graded_world(tmp_path):
    """`episodes/<id>/judge.yaml` carries one row per graded non-control world, each with every
    per-world fact and its bucket.

    A graded world with no row is O3's stated failing mode. The facts are `verdict` against
    `declared`, `resolution_moved`, `malformed_rows` and `served_nothing` — all read off X's own
    archived record plus the manifest; the bucket is the judge model's (O11).
    """
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


# ---------------------------------------------------------------------------------------
# served_nothing — X's own rows, off the composed token
# ---------------------------------------------------------------------------------------


def test_921_served_nothing_reads_x_own_rows_off_the_composed_token(tmp_path):
    """`served_nothing` is computed from rows in X's OWN ledger file —
    `episodes/<id>/served/<world_token>.jsonl`, joined to `worlds/<label>/` through
    `world_token_for(episode_token_for(episode_id), label)` — and from the world's OWN decision
    rows within it.

    THE WORLD IS NAMED TWICE AND THE TWO NAMES ARE DIFFERENT KEYS (G5): the archive is keyed on
    the short manifest label, the ledger on the composed token, so a reader that opens
    `served/<label>.jsonl` reads the wrong file.

    J2, settled: the file INTERLEAVES two populations — X's own decision rows (`world_id == X`)
    and family-tier `base` rows spelled `world_id: null`. Filter on the composed token first: a
    `base` row is evidence of a FAMILY-TIER read and is not the world's own.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        # b: one family-tier base row and nothing of its own — J2's whole case.
        "b": [J.ledger_row(source="base", world_label=None)],
        # c: the same call, this time as the world's own decision row.
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    rows = _rows(ep)
    assert rows["b"]["served_nothing"] is True, (
        "a family-tier `base` row was counted as the world's own served call")
    assert rows["c"]["served_nothing"] is False

    # And the file the reader must open is the COMPOSED token's, not the label's.
    J.write_ledger(ep, "c", [])
    stray = ep / "served" / "c.jsonl"
    stray.write_text(json.dumps(J.ledger_row(source="oracle", world_label="c")) + "\n",
                     encoding="utf-8")
    assert _rows(ep)["c"]["served_nothing"] is True, (
        "a file named by the short archive label was read as the world's ledger")


def test_921_an_empty_or_absent_ledger_is_a_world_that_served_nothing(tmp_path):
    """An EMPTY ledger file has zero rows, so the world served nothing — and it stays gradable.

    #1224 (S8) moved the ABSENT case: whether a world ran is its own record's to say
    (`world_records/`), so an archived world with no ledger file is one whose investigator made
    no call that reached it — `served_nothing`, gradable — not a missing input. Both are driven
    against the same world so the reading is visible rather than asserted.
    """
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
    """The row reads only what is in the file.

    A served call whose ledger write failed upstream — reported to stderr and dropped (G2) —
    leaves no row at all, so the world served nothing; the pass invents nothing to cover it and
    raises nothing about it. Positive control on the same world: adding the row the failed
    write would have made flips the fact, so the negative cannot pass on a reader that always
    answers the same.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": []})
    quiet = _rows(ep)["b"]
    assert quiet["served_nothing"] is True
    assert quiet.get("errors") in (None, [], ()), (
        "the pass raised or recorded an error about a call it simply cannot see")

    J.write_ledger(ep, "b", [J.ledger_row(source="passthrough", world_label="b")])
    assert _rows(ep)["b"]["served_nothing"] is False


# ---------------------------------------------------------------------------------------
# resolution_moved, verdict vs declared
# ---------------------------------------------------------------------------------------


def test_921_resolution_moved_needs_a_row_past_fences_at_with_before_ne_after(tmp_path):
    """`resolution_moved` is a `:T resolutions` row past the manifest's `fences_at` with
    `before != after`, read out of X's ARCHIVED `investigation.md`.

    J4, settled: read ANY qualifying row — the intent is "was the hand-off revisited", not "did
    the net state move". P7 shows `iter_resolutions` yields every resolution of a lead in
    document order, with no dedup, so a lead that oscillates back to where it started is
    structurally reachable and still counts.
    """
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
    """The verdict is X's archived `report.md` disposition, normalized through
    `_vocab.normalized_disposition`, beside `disposition_declared` from the manifest — the
    ground truth known by construction.

    That normalizer is EXACT by decision (#923 removed the zero-width strip from it): a world
    that laced its own headline would otherwise read as AGREEING with its declared disposition.
    So a laced headline is refused, exactly as a headline outside the vocabulary is.
    """
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


# ---------------------------------------------------------------------------------------
# J5 / J3 — the postures the human settled
# ---------------------------------------------------------------------------------------


def test_921_a_world_missing_an_input_is_ungradable_named_and_excluded_from_the_verdict_word(
        tmp_path):
    """J5 tier 1, settled with the human: a world whose input is ABSENT is `ungradable`, carried
    on the family record WITH THE NAME of the missing input, and EXCLUDED from the graded set
    the family's word is taken over.

    Silent exclusion is authoring-active in both directions, which is why the exclusion must be
    on the record: quietly dropping a world flips the family's word with no trace that a world
    was skipped.

    Three absences are driven, each by deleting the real artifact: the archived report (a state
    `verify_family` deliberately produces — `verdicts` SKIPS such a world, A8 executed), the
    archived `investigation.md`, and `disposition_declared` on the manifest entry. (#1224 made
    the served ledger and `alert.json` optional — S8.)
    """
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

    # `disposition_declared` absent from the manifest entry: #1224 moved this case to the
    # manifest load — the runtime loader the judge reads through refuses the manifest, naming
    # the field, before any world is read.
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
    """J5 tier 2, settled: a MALFORMED input sets its own world aside loudly — `ungradable`,
    `malformed: true`, with a reason naming the world — and grades the rest.

    FOUR malformations, each written as real bytes: a disposition outside the vocabulary, a
    report that cannot be read at all, a document truncated inside an open invlang fence, and
    — F-7, settled at the phase-F seam — A PARTIALLY ARCHIVED WORLD (every required input
    present, the supporting directory short of a lead the world's own document names: the state
    a mid-copy fault in `archive.py` leaves, P10).

    THE MESSAGE IS PART OF THE DEMAND: a partial archive is otherwise indistinguishable from a
    genuine malformation, so the refusal must NAME THE INPUT THAT WAS SHORT.
    """
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
    """J5 tier 3, settled: a DUPLICATE or ambiguous key — two world entries under one label — is
    refused at manifest load.

    A duplicate label makes "X's own archived record" ambiguous at the one join every per-world
    fact goes through (`worlds/<label>/` on one side, `served/<world_token>.jsonl` on the
    other), and picking either entry silently is a grade computed from a world nobody named.
    Positive control: the same manifest with distinct labels loads and grades.
    """
    import yaml

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    doc = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert _rows(ep), "the control failed: the manifest did not load"

    doc["worlds"].append(dict(doc["worlds"][-1], world_id="b"))
    (ep / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(J.refusals()) as raised:
        _grade(ep)
    assert "b" in str(raised.value)


def test_921_a_world_label_colliding_with_a_real_run_id_is_refused_at_manifest_load(tmp_path):
    """F-3, settled at the phase-F seam: a world label that COLLIDES WITH A REAL RUN ID under
    the runs base is refused at manifest load, alongside J5 tier 3's duplicate-label refusal.

    A family row carries `source_run_dir: episodes/<id>/worlds/<label>`, and its consumer
    honours ONLY THE LAST PATH SEGMENT under the runs dir (`runs_dir / Path(source_run_dir).name`).
    A label spelled like a real run id therefore resolves to WRONG BUT REAL content instead of
    failing loudly. Refusing at LOAD is the same tier J5 gives the duplicate label.

    Positive control FIRST, on the same manifest: with no such run on disk the episode loads and
    grades, so the refusal below is on the COLLISION and not on how the label is spelled.
    """
    # #1224: a label is a world token (lower-case), so the collision is with a run of that name.
    colliding = "fresh_case_n59"
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", colliding),
        dispositions={"a": "benign", "b": "malicious", colliding: "malicious"},
        ledgers={"b": [J.oracle_row("b")], colliding: []})

    assert sorted(_rows(ep)) == sorted(["b", colliding]), (
        "the control failed: a label spelled like a run id did not load while no such run "
        "existed, so the refusal below would not be about the collision")

    # The real run appears under the operator's runs base — `runs_base` writes an ORDINARY
    # finished run. #1078: the collision check is keyed on the explicit `runs_base=` the caller
    # threads in.
    base, _source_run_dir = J.runs_base(tmp_path, source_run_id=colliding)
    with pytest.raises(J.refusals()) as raised:
        _grade(ep, runs_base=base)
    assert colliding in str(raised.value), (
        "the manifest was refused without naming the label that collided; the operator has to "
        "rename one of the two and the message is the only thing that says which")


def test_921_the_family_pass_reader_takes_the_first_row_and_counts_a_torn_line(tmp_path):
    """J3, settled: the ledger reader inherits `_absorb`'s FIRST-ROW-WINS on a duplicate
    pair-key, RE-VALIDATES `source` against the ledger's words on read, and SKIPS a malformed
    line WHILE RECORDING THE COUNT on the world's row.

    G15's own words are the reason: "two readers resolving a duplicate key in opposite
    directions is how one file gets read as two different recordings". Losing a row is less bad
    than losing a grade here, because the count itself is evidence; a torn line that fails the
    world would throw away every other fact the file carries.
    """
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
    assert [row["source"] for row in kept] == ["oracle"], (
        "the LATER row won a duplicate pair-key; `_absorb` takes the first and the two readers "
        "must not disagree about the same bytes")
    assert malformed == 2

    row = _rows(ep)["b"]
    assert row["malformed_rows"] == 2, (
        "the torn line and the out-of-vocabulary `source` were dropped without a count; the "
        "count is the evidence that the measurement was partial")
    assert row["served_nothing"] is False
    assert row.get("ungradable") is not True, "a torn line took the whole world's grade with it"
