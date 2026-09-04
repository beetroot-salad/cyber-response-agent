"""#921 — the amended mechanical half: five per-world facts, read off X's own archived record.

THE AMENDMENT REPLACED THE BUCKET TABLE AND N8. `delta_o`, the mutation/undeclared membership
test, the offline comparator lane and every "post-branch key" predicate leave this issue's path
entirely; the five facts below all read X's OWN ledger, X's OWN archived document and report,
and the manifest — no comparison with any other world, no comparator call.

The mechanism is the ledger's `source` column, EXECUTED (A1, A2, A4, G2): every served answer
carries a word saying what the world did to it, written by `WorldRegistry._served` on every
successful serve, memo hit and live call alike, with the two failure handlers writing their own
rows. `applier.py:236-237` names #921 as that column's reader in the code's own words.

FOUR §7 RESOLUTIONS ARE APPLIED HERE AS SETTLED, not as readings this file picked:
* **J1** — `H` is validated at manifest load against the seven served-system names
  (`STAGERS | PATCHABLE_SYSTEMS`) after strip+casefold, and the manifest is refused otherwise.
* **J2** — the row population is filtered on the world's COMPOSED token first, then `source`; a
  `base`-sourced H row is a family-tier read and contributes to neither `holding_queried` nor
  "the difference reached the defender".
* **J3** — the new reader inherits `_absorb`'s first-row-wins and its `artifact_file`-before-open,
  re-validates `source` against `SOURCES` on read, and SKIPS a malformed line while recording
  the count on the family record; a `staged` row on a patch-only system is REPORTED as a
  data-integrity note, never silently reclassified.
* **J4** — `scope_discriminated` reads `asked_params` when present and `params` otherwise, over
  three named keys, and treats a mapping missing one as NOT DISCRIMINATING rather than as a
  refusal; `resolution_moved` reads ANY qualifying row past `fences_at`.
* **J5** — one rule, three tiers: an ABSENT input makes the world `ungradable`, named with its
  missing input and excluded from `verdict_word`; a MALFORMED input refuses the pass loudly; a
  DUPLICATE/ambiguous label is refused at manifest load. A FAULTED call is `ungradable` too —
  not a defender failure.

RED against `d1b8b06a`: `learning/judge/family.py` does not exist, and no reader of the ledger
outside the serving path reads `source` at all.
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _judge_921 as J


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _family():
    return J.mod("learning.judge.family")


#: The four buckets that name a DEFECT. `none` and `agreed-without-evidence` are outcomes, not
#: defects, and F-1's exclusion is from these four — `lead-set` most of all, because it is the
#: never-asked bucket and the one that authors a lesson.
FAILURE_BUCKETS = ("lead-set", "lead-quality", "analyze-discipline", "decision-discipline")


# ---------------------------------------------------------------------------------------
# the record's own shape
# ---------------------------------------------------------------------------------------


def test_921_family_record_carries_a_row_per_graded_world(tmp_path):
    """`episodes/<id>/judge.yaml` carries one row per graded non-control world, each with all
    five facts and its bucket.

    A graded world with no row is O3's stated failing mode; so is a bucket that prose assigned
    where the ledger could. The five facts are `holding_queried`, `scope_discriminated`,
    "a doctored answer was served", `resolution_moved` and `verdict` against `declared` — all
    read off X's own archived record plus the manifest.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [J.staged_row("b")],
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    grade = _family().grade_family(ep)
    rows = J.rows(grade)

    assert sorted(rows) == ["b", "c"], "a graded non-control world has no row in the record"
    for label, row in rows.items():
        missing = [fact for fact in J.PER_WORLD_FACTS if fact not in row]
        assert not missing, f"world {label} is missing per-world facts: {missing}"
        assert "bucket" in row, f"world {label} carries no bucket"
        assert row["declared"] in ("benign", "malicious"), (
            "the ground truth known by construction is not on the row")


# ---------------------------------------------------------------------------------------
# fact 1 — holding_queried
# ---------------------------------------------------------------------------------------


def test_921_holding_queried_reads_x_own_rows_on_H(tmp_path):
    """`holding_queried` is computed from rows in X's OWN ledger file —
    `episodes/<id>/served/<world_token>.jsonl`, joined to `worlds/<label>/` through
    `world_token_for(episode_token_for(episode_id), label)` — and from the world's OWN decision
    rows within it.

    THE WORLD IS NAMED TWICE AND THE TWO NAMES ARE DIFFERENT KEYS (G5): the archive is keyed on
    the short manifest label, the ledger on the composed token, so a reader that opens
    `served/<label>.jsonl` finds nothing and reads it as a world that served nothing.

    J2, settled: the file INTERLEAVES two populations — X's own decision rows (`world_id == X`)
    and family-tier `base` rows spelled `world_id: null`, written into X's own file for keys the
    capture never held, and one live call to H writes BOTH (A2, executed). Filter on the
    composed token first, then read `source`: a `base`-sourced H row is evidence of a
    FAMILY-TIER read and contributes to neither `holding_queried` nor "a doctored answer was
    served". Unfiltered, a doctored run's numerous base rows pad the world's own count with the
    family's live reads.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        # b: one family-tier base row on H and nothing of its own — J2's whole case.
        "b": [J.ledger_row(source="base", world_label=None)],
        # c: the same call, this time as the world's own decision row.
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    rows = J.rows(_family().grade_family(ep))

    assert rows["b"]["holding_queried"] is False, (
        "a family-tier `base` row was counted as the world's own read of H")
    assert rows["c"]["holding_queried"] is True

    # And the file the reader must open is the COMPOSED token's, not the label's.
    stray = ep / "served" / "c.jsonl"
    stray.write_text(json.dumps(J.ledger_row(source="staged", world_label="c")) + "\n",
                     encoding="utf-8")
    assert J.rows(_family().grade_family(ep))["c"]["doctored_answer_served"] is False, (
        "a file named by the short archive label was read as the world's ledger")


def test_921_an_empty_ledger_file_is_lead_set_like_a_world_that_never_queried_H(tmp_path):
    """An EMPTY ledger file has zero rows on H, so `holding_queried` is false and the bucket is
    `lead-set` — the same observable as "never queried H".

    The empty case is DECIDED; the ABSENT case is J5's and is a different answer (`ungradable`),
    so the two must never be collapsed in the fixture. Both are exercised here against the same
    world so the difference is visible rather than asserted.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [], "c": []})
    rows = J.rows(_family().grade_family(ep))
    assert rows["b"]["holding_queried"] is False
    assert rows["b"]["bucket"] == "lead-set"
    assert rows["b"].get("ungradable") is not True, (
        "an EMPTY ledger was treated as an ABSENT one; J5 gives those two different answers")

    (ep / "served" / f"{J.world_token('c')}.jsonl").unlink()
    absent = J.rows(_family().grade_family(ep))["c"]
    assert absent["ungradable"] is True, "an ABSENT ledger file was read as an empty one"


def test_921_a_row_whose_system_is_empty_or_absent_is_inert_to_every_per_world_fact(tmp_path):
    """A ledger row whose `system` is empty or absent satisfies `system == H` under no reading
    of J2 and contributes to none of the five facts. It is inert — not a match and not an error.

    Both spellings are exercised, because "empty" and "absent" are two different rows on disk
    and a reader keying on `row.get("system") == H` answers the same for both only by accident.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [
        dict(J.ledger_row(source="staged", world_label="b"), system=""),
        {k: v for k, v in J.ledger_row(source="staged", world_label="b").items()
         if k != "system"},
    ]})
    row = J.rows(_family().grade_family(ep))["b"]

    assert row["holding_queried"] is False
    assert row["doctored_answer_served"] is False
    assert row["bucket"] == "lead-set"
    assert row.get("ungradable") is not True, "an inert row was reported as a missing input"


def test_921_a_served_call_with_no_row_is_invisible_to_the_mechanical_half(tmp_path):
    """The mechanical half reads only what is in the file.

    A served call whose ledger write failed upstream — reported to stderr and dropped (G2) —
    leaves no row at all, so `holding_queried` is false; the family pass invents nothing to
    cover it and raises nothing about it. Positive control on the same world: adding the row the
    failed write would have made flips the fact, so the negative cannot pass on a reader that
    always answers false.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": []})
    quiet = J.rows(_family().grade_family(ep))["b"]
    assert quiet["holding_queried"] is False
    assert quiet.get("errors") in (None, [], ()), (
        "the pass raised or recorded an error about a call it simply cannot see")

    J.write_ledger(ep, "b", [J.ledger_row(source="passthrough", world_label="b")])
    assert J.rows(_family().grade_family(ep))["b"]["holding_queried"] is True


# ---------------------------------------------------------------------------------------
# fact 2 — scope_discriminated
# ---------------------------------------------------------------------------------------


def test_921_scope_discriminated_reads_index_window_and_scope_key_off_the_right_form(tmp_path):
    """`scope_discriminated` reads index, window and scope key off the row's params — and
    `params` MEANS THREE DIFFERENT THINGS across the source classes (G6, executed as A4).

    On a `staged` row `params` is the PREPARED form, whose index is the world's retargeted view
    name (`wv-<episode_token>.<label>-…`), with the form ASKED alongside in `asked_params`; on a
    pre-prepare `refused`/`fault` row it is the form ASKED; on a post-prepare `fault` row it is
    the form RUN with `asked_params` beside it. Read naively, EVERY `staged` row scores as a
    scope failure — the one row the amended M8 fixture exists to carry.

    J4, settled: read `asked_params` when present and `params` otherwise, over the three named
    keys (index, window, scope key), and treat a mapping MISSING one of them as NOT
    DISCRIMINATING rather than as a refusal.

    ALL THREE FORMS ARE DRIVEN, not two. F-1's second half: the body used to drive `staged` and
    `passthrough` only, so the reading J4 gives the two NON-DECISION source classes — the ones
    A1's red flags 2 executed and F-1 settled as still having queried — was named in this
    docstring and asserted nowhere. Against a pre-prepare `refused` row `params` IS the form
    ASKED and there is no `asked_params` beside it, so a reader that always prefers `params`
    reads the ASKED form as the form that RAN; against a post-prepare `fault` row `params` is
    the form that RAN, with the asked form beside it, and the same reader scores the world on
    bytes the analyst never chose. J4's rule ("`asked_params` when present, `params`
    otherwise") answers both, and both are exercised below.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [J.staged_row("b", scope_ok=True)],
        "c": [J.ledger_row(source="passthrough", world_label="c",
                           params={"index": J.EVENTS_PATTERN, "window": "24h",
                                   "scope_key": "host.name"})],
    })
    rows = J.rows(_family().grade_family(ep))
    assert rows["b"]["scope_discriminated"] is True, (
        "the staged row's PREPARED index was read as the scope the analyst asked about; "
        "`asked_params` is where that question lives")
    assert rows["c"]["scope_discriminated"] is True

    # Form 2 — a PRE-PREPARE `refused` row: `params` is the form ASKED and nothing else is
    # there. The world still asked the discriminating question with all three keys (F-1), so
    # the fact is TRUE; a reader that treats a missing `asked_params` as a missing question
    # scores it false.
    J.write_ledger(ep, "c", [J.ledger_row(
        source="refused", world_label="c",
        params={"index": J.EVENTS_PATTERN, "window": "24h", "scope_key": "host.name"},
        payload="this ES|QL query's FROM clause addresses several corpora")])
    asked_form = J.rows(_family().grade_family(ep))["c"]
    assert asked_form["scope_discriminated"] is True, (
        "on a pre-prepare `refused` row `params` IS the form the analyst asked, and it carried "
        "all three keys; the fact was read off a form this row does not have")
    assert asked_form["holding_queried"] is True, (
        "the refused row's own params were read while the world was still scored as never "
        "having asked H")

    # Form 3 — a POST-PREPARE `fault` row: `params` is the form that RAN (the retargeted view,
    # scope key dropped by the prepare) and `asked_params` carries the question. Reading
    # `params` here scores a scope failure against bytes the analyst never chose.
    ran = {"index": f"wv-{J.world_token('c')}-logs-"}
    J.write_ledger(ep, "c", [J.ledger_row(
        source="fault", world_label="c", params=ran,
        asked_params={"index": J.EVENTS_PATTERN, "window": "24h", "scope_key": "host.name"},
        payload="the adapter raised after prepare")])
    ran_form = J.rows(_family().grade_family(ep))["c"]
    assert ran_form["scope_discriminated"] is True, (
        "a post-prepare `fault` row was scored on the form that RAN; `asked_params` is present "
        "and J4 makes it the form every one of the three keys is read off")

    # A params mapping missing one of the three keys is NOT DISCRIMINATING, and not a refusal.
    J.write_ledger(ep, "c", [J.ledger_row(source="passthrough", world_label="c",
                                          params={"index": J.EVENTS_PATTERN})])
    partial = J.rows(_family().grade_family(ep))["c"]
    assert partial["scope_discriminated"] is False
    assert partial.get("ungradable") is not True, (
        "a params mapping missing a key was escalated to a refusal; J4 makes it not "
        "discriminating")


# ---------------------------------------------------------------------------------------
# fact 3 — a doctored answer was served
# ---------------------------------------------------------------------------------------


def test_921_staged_and_patched_rows_say_the_difference_reached_the_defender(tmp_path):
    """"A doctored answer was served on H" is `source in {staged, patched}`.

    `passthrough` is the world changing nothing on that call, and it is its own class precisely
    so that "the world changed this" stays distinguishable from "the applier never ran" — the
    applier's own docstring calls the alternative "silent scenario deletion wearing an honest
    label". On a STATE system H the fact rests on `patched` alone, because `staged` is reachable
    only for `elastic`, the sole stager (G7); that asymmetry is exercised rather than assumed.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [J.staged_row("b")],
        "c": [J.ledger_row(source="passthrough", world_label="c")],
    })
    rows = J.rows(_family().grade_family(ep))
    assert rows["b"]["doctored_answer_served"] is True
    assert rows["c"]["doctored_answer_served"] is False

    # A state-system family: `patched` is the only way the difference can reach the defender.
    state = J.accepted_episode(tmp_path / "state", holding_system="cmdb", ledgers={
        "b": [J.ledger_row(source="patched", world_label="b", system="cmdb", verb="get-host")],
        "c": [J.ledger_row(source="passthrough", world_label="c", system="cmdb",
                           verb="get-host")],
    })
    state_rows = J.rows(_family().grade_family(state))
    assert state_rows["b"]["doctored_answer_served"] is True
    assert state_rows["c"]["doctored_answer_served"] is False


def test_921_world_whose_H_call_was_refused_is_not_graded_a_defender_failure(tmp_path):
    """`refused` and `fault` are the seam's own two words, and they do NOT partition the way
    this demand's first draft assumed. A5 was EXECUTED (`47-probe-a5.py`) and REFUTED, and the
    corrected mechanism is what this test pins:

    * **`refused` is the CAPABILITY class, full stop.** The pre-`prepared` handler files it iff
      `failure.exit_code == USAGE_EXIT_CODE` (64) — a world whose corpus this query cannot be
      pointed at. A world whose discriminating call was refused was never given the chance to
      fail on it, so grading it a defender failure would be wrong: the row is not "a doctored
      answer served", and it does not by itself put the world in `analyze-discipline` or
      `decision-discipline`. One qualified survivor, also executed: a deployment's own default
      index naming two corpora raises `StagingError(64)` and files `refused` too, so a `refused`
      row can be the DEPLOYMENT's fault rather than the world's — still a capability answer.
    * **`fault` is NOT a second spelling of that.** A missing `config.env` or a blank required
      key at prepare time raises `ConfigFault(exit_code=2)` and is filed `fault`, never
      `refused` — the sentence this demand was seeded on ("a `refused` row can be an environment
      fault at prepare time") is false. And `fault` demonstrably covers two different events: an
      ENVIRONMENT condition at prepare time, and an IN-FLIGHT ADAPTER CRASH after prepare (a
      raising adapter call writes one `fault` row with no `base` row beside it, because
      `_base_payload` raises before recording).
    * **So a faulted call makes the world `ungradable`** — J5's tier rule, settled with the
      human — named with the faulted call and excluded from `verdict_word`, rather than being
      folded in beside `refused` as "never given the chance to fail". The defender is not
      graded on a call the estate could not answer, and the exclusion is on the record instead
      of being silent.
    * **F-1, settled at the phase-F seam: A REFUSED CALL COUNTS AS HAVING QUERIED.**
      `47-runtime-probes.md` red flags 2, executed: a call the defender actually MADE that was
      `refused` or `fault`ed writes exactly one world-owned row whose `source` sits OUTSIDE
      `APPLIER_DECISIONS`, so a predicate computed over the applier decisions alone reads
      "world X never asked H" for a world that asked H and was refused. The human's rationale
      is what settles it: the grade exists to produce learnings for the DEFENDER runtime, so a
      refused call is evidence the defender asked correctly and the estate did not answer.
      `holding_queried` is therefore TRUE on a `refused` or `fault`ed H row, and both worlds
      are EXCLUDED FROM THE FAILURE BUCKETS rather than defaulted into `lead-set` — the
      never-asked bucket, and the one that authors a lesson.

    NOTHING HERE ASSERTS A `refused` ROW FOR A MISSING CONFIG. That is the refuted behaviour,
    and pinning it would harden a wrong prior into the contract.
    """
    ep = J.accepted_episode(tmp_path, ledgers={
        "b": [J.ledger_row(source="refused", world_label="b",
                           payload="this ES|QL query's FROM clause addresses several corpora")],
        "c": [J.ledger_row(source="fault", world_label="c",
                           payload="missing required config keys: ELASTIC_EVENTS_INDEX")],
    })
    rows = J.rows(_family().grade_family(ep))

    refused = rows["b"]
    assert refused["doctored_answer_served"] is False, (
        "a refused call was read as a doctored answer reaching the defender")
    assert refused["holding_queried"] is True, (
        "a call the defender MADE and the estate REFUSED read as a world that never asked H; "
        "F-1 settles it the other way — the grade exists to produce learnings for the defender "
        "runtime, and a refusal is evidence the defender asked correctly")
    assert refused["bucket"] not in FAILURE_BUCKETS, (
        f"a world refused on H landed in {refused['bucket']!r}; a refused world is excluded "
        "from the failure buckets, and `lead-set` — the never-asked bucket — is the one that "
        "authors a lesson off a question the defender did ask")
    assert refused.get("ungradable") is not True, (
        "`refused` is a real capability outcome, not a missing input")

    faulted = rows["c"]
    assert faulted["ungradable"] is True, (
        "a faulted call left the world gradable; J5's tier rule makes it ungradable")
    assert "fault" in json.dumps(faulted).lower(), (
        "the world is ungradable and the record does not name the faulted call that made it so")
    assert faulted["holding_queried"] is True, (
        "a faulted call was read as a world that never asked H; the defender asked and the "
        "estate could not answer, which is the same reading `refused` gets (F-1)")
    assert faulted["bucket"] not in FAILURE_BUCKETS, (
        f"an estate fault landed the world in {faulted['bucket']!r}; a faulted world is "
        "excluded from the failure buckets, never defaulted into `lead-set`")
    assert "c" not in _family().grade_family(ep).graded_worlds, (
        "an ungradable world was still counted into the family's verdict word")


# ---------------------------------------------------------------------------------------
# facts 4 and 5 — resolution_moved, verdict vs declared
# ---------------------------------------------------------------------------------------


def test_921_resolution_moved_needs_a_row_past_fences_at_with_before_ne_after(tmp_path):
    """`resolution_moved` is a `:T resolutions` row past the manifest's `fences_at` with
    `before != after`, read out of X's ARCHIVED `investigation.md`.

    The existing path is `scan_fences(text).bodies[fences_at:]` -> the invlang companion ->
    `iter_resolutions`; `read_frontier` takes the PREFIX and the family pass wants the
    COMPLEMENT, which no symbol spells today (G8). `before`/`after` are required fields, so the
    comparison is total over well-formed rows, and a document with no qualifying row is false by
    construction rather than an error.

    J4, settled: read ANY qualifying row past `fences_at` — the intent is "was the hand-off
    revisited", not "did the net state move". P7 shows `iter_resolutions` yields every
    resolution of a lead in document order, with no dedup and no fence-awareness at all, so a
    lead that oscillates back to where it started is structurally reachable and still counts.
    """
    ep = J.accepted_episode(tmp_path, fences_at=1)
    # `b` oscillates: row 1 moves the lead, row 2 moves it back. ANY qualifying row counts.
    rows = J.rows(_family().grade_family(ep))
    assert rows["b"]["resolution_moved"] is True, (
        "an oscillating lead's first qualifying row was discarded in favour of the net state")

    # A document whose only resolutions sit INSIDE the fenced prefix, and one whose row does
    # not move: both false by construction, neither an error.
    (ep / "worlds" / "c" / "investigation.md").write_text(
        J.investigation_document("c", moved=False), encoding="utf-8")
    unmoved = J.rows(_family().grade_family(ep))["c"]
    assert unmoved["resolution_moved"] is False
    assert unmoved.get("ungradable") is not True


def test_921_verdict_is_read_off_the_archived_report_against_the_manifest(tmp_path):
    """The verdict is X's archived `report.md` disposition, normalized through
    `_vocab.normalized_disposition`, compared against `disposition_declared` from the manifest —
    the ground truth known by construction.

    `normalized_disposition` and not a locally written `in DISPOSITION_ENUM`: it owns the
    zero-width strip a local membership test silently drops, and a report laced with one would
    otherwise render as `malicious` to a human and refuse for a reader.
    """
    ep = J.accepted_episode(tmp_path,
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / "b" / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    rows = J.rows(_family().grade_family(ep))

    assert rows["b"]["verdict"] == "benign"
    assert rows["b"]["declared"] == "malicious"
    assert rows["c"]["verdict"] == rows["c"]["declared"] == "malicious"

    # The vocabulary is read through the shipped normalizer: a zero-width-laced headline is the
    # value that separates it from a local membership test.
    (ep / "worlds" / "c" / "report.md").write_text(
        "disposition: mali​cious\n", encoding="utf-8")
    assert J.rows(_family().grade_family(ep))["c"]["verdict"] == "malicious"


# ---------------------------------------------------------------------------------------
# J1 / J5 / J3 — the postures the human settled
# ---------------------------------------------------------------------------------------


def test_921_the_holding_system_is_validated_against_the_served_roster_at_manifest_load(
        tmp_path):
    """`H` — `discriminator["holding_system"]` — is VALIDATED at manifest load: present,
    non-empty, and a member of the seven served-system names (`STAGERS | PATCHABLE_SYSTEMS`)
    compared after `strip()` and casefold. Anything else refuses the manifest (J1, settled).

    Why the refusal has to be at load and has to be loud: `H` is unvalidated model text with
    zero production readers at base — two occurrences in the whole tree, the questioner prompt
    that asks for it and one fixture — and all five per-world facts are keyed on `system == H`.
    A bogus or absent `H` therefore sends EVERY non-control world to `lead-set`, which makes
    every verdict-mismatch a `survived` family, and `survived` is the word `_gate_family` routes
    to AUTHOR a lesson. Not validating fails silently and authoring-actively; validating fails
    loudly at a step a human already reviews.

    Positive control in the same arm: a near-miss that differs only by case and surrounding
    whitespace is ACCEPTED, so the check is a roster membership test and not a string equality
    that happens to refuse everything unusual.
    """
    family_mod = _family()
    for bogus in (None, "", "   ", "elastic-search", "Elasticsearch", "splunk"):
        ep = J.accepted_episode(tmp_path / f"h-{bogus!r}", holding_system=bogus)
        with pytest.raises(J.refusals()) as raised:
            family_mod.grade_family(ep)
        assert "holding_system" in str(raised.value) or "holding" in str(raised.value)

    ok = J.accepted_episode(tmp_path / "near-miss", holding_system="  ELASTIC ",
                            ledgers={"b": [J.staged_row("b")], "c": []})
    assert J.rows(family_mod.grade_family(ok))["b"]["doctored_answer_served"] is True, (
        "a served-roster member differing only in case and whitespace was refused")


def test_921_a_world_missing_an_input_is_ungradable_named_and_excluded_from_the_verdict_word(
        tmp_path):
    """J5 tier 1, settled with the human: a world whose input is ABSENT is `ungradable`, carried
    on the family record WITH THE NAME of the missing input, EXCLUDED from `verdict_word` — and
    if no non-control world remains gradable the family is `undecidable`.

    Silent exclusion is authoring-active in both directions, which is why the exclusion must be
    on the record: `verdict_word` is `caught` when every graded world's verdict equals its
    declared disposition, so quietly dropping the one world that disagrees flips `survived` ->
    `caught` and SUPPRESSES a lesson, while quietly dropping the one that agrees flips `caught`
    -> `survived` and AUTHORS one. Either way the family record would show a grade with no trace
    that a world was skipped.

    Four absences are driven, each by deleting the real artifact: the archived report (a state
    `verify_family` deliberately produces — `verdicts` SKIPS such a world, A8 executed), the
    world's ledger file, `disposition_declared` on the manifest entry, and `alert.json`.
    """
    import yaml

    family_mod = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    (ep / "worlds" / "b" / "report.md").unlink()
    row = J.rows(family_mod.grade_family(ep))["b"]
    assert row["ungradable"] is True
    assert "report.md" in json.dumps(row), "the missing input is not named on the record"
    assert "b" not in family_mod.grade_family(ep).graded_worlds

    for label, victim in (("b", "served"), ("c", "alert.json")):
        fresh = J.accepted_episode(tmp_path / f"gone-{victim}",
                                   ledgers={"b": [J.staged_row("b")], "c": []})
        if victim == "served":
            (fresh / "served" / f"{J.world_token(label)}.jsonl").unlink()
        else:
            (fresh / "worlds" / label / victim).unlink()
        gone = J.rows(family_mod.grade_family(fresh))[label]
        assert gone["ungradable"] is True
        assert victim.split(".")[0] in json.dumps(gone)

    # `disposition_declared` absent from the manifest entry — and, with every non-control world
    # ungradable, the family word is `undecidable`.
    both = J.accepted_episode(tmp_path / "no-declared")
    doc = yaml.safe_load((both / "family.yaml").read_text(encoding="utf-8"))
    for world in doc["worlds"]:
        if world["world_id"] != "a":
            world.pop("disposition_declared", None)
    (both / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    grade = family_mod.grade_family(both)
    assert all(row["ungradable"] is True for row in J.rows(grade).values())
    assert J.word_of(grade) == "undecidable", (
        "no non-control world remained gradable and the family still produced a verdict")


def test_921_a_malformed_input_refuses_the_judge_pass_loudly(tmp_path):
    """J5 tier 2, settled: a MALFORMED input refuses the episode's judge pass loudly.

    A malformed artifact is a bug in the writer, not a fact about the defender, and this is
    `verdicts`' own posture on exactly this shape (A8, executed): it SKIPS a world archived
    without a report and REFUSES one whose report exists and cannot be read or declares a
    disposition outside the vocabulary. The tier rule preserves that split instead of
    contradicting it — tier 1 skips the absent, tier 2 refuses the malformed.

    FOUR malformations, each written as real bytes: a disposition outside the vocabulary, a
    report that cannot be read at all, a document truncated inside an open invlang fence, and
    — F-7, settled at the phase-F seam — A PARTIALLY ARCHIVED WORLD.

    P10 named the tenth state and the human's three tiers did not: `archive.py`'s per-file
    `shutil.copy2` loop and its `write_guarded` pointer write carry NO cleanup handler, so the
    docstring guarantee ("archives NOTHING rather than a half-world") covers only the
    SCREEN-detected refusal path, and a genuine mid-copy I/O fault leaves a world with all five
    required inputs present and a supporting directory SHORT. Left alone that world grades
    normally and silently on a thinner view than it appears to have. F-7 puts it in tier 2:
    a partial archive is MALFORMED and refuses the pass.

    THE MESSAGE IS PART OF THE DEMAND, NOT DECORATION. A partial archive is otherwise
    indistinguishable from a genuine malformation — the operator sees "malformed" and goes
    looking for a writer bug in the world's own artifacts — so the refusal must NAME THE INPUT
    THAT WAS SHORT. The state driven here is the one the fault leaves: the world's own archived
    `investigation.md` names lead `l-001` and `gather_summaries/` has no `l-001.md` beside it.
    The fault is not simulated inside `copy2`; the STATE a mid-copy fault leaves is written to
    disk directly, because P10's executed half establishes the state is reachable and inventing
    an I/O fault to reach it would be a fault no probe observed.
    """
    family_mod = _family()

    outside = J.accepted_episode(tmp_path / "vocab")
    (outside / "worlds" / "b" / "report.md").write_text(
        "disposition: probably-bad\n", encoding="utf-8")
    with pytest.raises(J.refusals()):
        family_mod.grade_family(outside)

    unreadable = J.accepted_episode(tmp_path / "unreadable")
    (unreadable / "worlds" / "b" / "report.md").write_bytes(b"\xff\xfe\x00not utf-8")
    with pytest.raises(J.refusals()):
        family_mod.grade_family(unreadable)

    truncated = J.accepted_episode(tmp_path / "truncated")
    (truncated / "worlds" / "b" / "investigation.md").write_text(
        "# investigation b\n\n```invlang\n:T resolutions\n  - lead: l-001\n    before: open\n",
        encoding="utf-8")
    with pytest.raises(J.refusals()):
        family_mod.grade_family(truncated)

    # F-7 — the partially archived world. Control first: the same episode with the directory
    # intact grades, so the refusal is on the SHORT input and not on the fixture.
    partial = J.accepted_episode(tmp_path / "partial",
                                 ledgers={"b": [J.staged_row("b")], "c": []})
    assert "b" in J.rows(family_mod.grade_family(partial)), (
        "the control failed: the intact episode did not grade world b at all")
    short = partial / "worlds" / "b" / "gather_summaries" / "l-001.md"
    assert short.is_file(), "the fixture stopped archiving the summary this leg makes short"
    short.unlink()

    with pytest.raises(J.refusals()) as raised:
        family_mod.grade_family(partial)
    said = str(raised.value)
    assert "gather_summaries" in said, (
        "a world left short by a mid-copy fault was refused without naming the input that was "
        "short; the message is what separates a partial archive from a malformed artifact, and "
        "without it the operator hunts a writer bug in the world's own documents")
    assert "b" in said, "the refusal does not say which world was short"


def test_921_two_world_entries_under_one_label_are_refused_at_manifest_load(tmp_path):
    """J5 tier 3, settled: a DUPLICATE or ambiguous key — two world entries under one label — is
    refused at manifest load, with J1's validation.

    A duplicate label makes "X's own archived record" ambiguous at the one join every per-world
    fact goes through (`worlds/<label>/` on one side, `served/<world_token>.jsonl` on the
    other), and picking either entry silently is a grade computed from a world nobody named.
    Positive control: the same manifest with distinct labels loads and grades.
    """
    import yaml

    family_mod = _family()
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    doc = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert J.rows(family_mod.grade_family(ep)), "the control failed: the manifest did not load"

    doc["worlds"].append(dict(doc["worlds"][-1], world_id="b"))
    (ep / "family.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(J.refusals()) as raised:
        family_mod.grade_family(ep)
    assert "b" in str(raised.value)


def test_921_a_world_label_colliding_with_a_real_run_id_is_refused_at_manifest_load(tmp_path):
    """F-3, settled at the phase-F seam: a world label that COLLIDES WITH A REAL RUN ID under
    the runs base is refused at manifest load, alongside J5 tier 3's duplicate-label refusal.

    THE COLLISION IS THE ONE OUTCOME NOBODY WOULD CHOOSE. A family row carries
    `source_run_dir: episodes/<id>/worlds/<label>`, and its one existing consumer —
    `verify_forward/env.py::case_entities_arg -> _run_paths.resolve_run_bundle`, also reached
    from `author/curator.py:184` — honours ONLY THE LAST PATH SEGMENT under the runs dir
    (`runs_dir / Path(source_run_dir).name`). A label spelled like a real run id therefore
    resolves to WRONG BUT REAL content instead of failing loudly, which the judge's own
    promotion called "strictly worse than the missing-bundle case". J12's forward-check
    exemption closes the other two promoted breaks and does NOT reach this one: the resolver has
    a second caller outside the exemption.

    Refusing at LOAD is the same tier J5 gives the duplicate label, and for the same reason —
    the ambiguity is in the manifest, so the manifest is where it is refusable. Its accepted
    cost is stated rather than hidden: the pass now needs the runs base at manifest load, which
    couples two things that are independent today.

    Positive control FIRST, on the same manifest: with no such run on disk the episode loads and
    grades, so the refusal below is on the COLLISION and not on how the label is spelled.
    """
    family_mod = _family()
    colliding = J.SOURCE_RUN_ID
    ep = J.accepted_episode(
        tmp_path, labels=("a", "b", colliding),
        dispositions={"a": "benign", "b": "malicious", colliding: "malicious"},
        ledgers={"b": [J.staged_row("b")], colliding: []})

    assert sorted(J.rows(family_mod.grade_family(ep))) == sorted(["b", colliding]), (
        "the control failed: a label spelled like a run id did not load while no such run "
        "existed, so the refusal below would not be about the collision")

    # The real run appears under the operator's runs base — `runs_base` writes an ORDINARY
    # finished run (its provenance stamp, its capture, its close), not a directory hand-placed
    # at a name no production path makes.
    J.runs_base(tmp_path)
    with pytest.raises(J.refusals()) as raised:
        family_mod.grade_family(ep)
    assert colliding in str(raised.value), (
        "the manifest was refused without naming the label that collided; the operator has to "
        "rename one of the two and the message is the only thing that says which")


def test_921_the_family_pass_reader_takes_the_first_row_and_counts_a_torn_line(tmp_path):
    """J3, settled: the new ledger reader is coined against `ledger.py`'s own names
    (`ServedCall`, `source`, `world_id`), inherits `_absorb`'s FIRST-ROW-WINS on a duplicate
    pair-key and its `artifact_file`-before-open, RE-VALIDATES `source` against `SOURCES` on
    read, and SKIPS a malformed line WHILE RECORDING THE COUNT on the family record.

    G15's own words are the reason: "two readers resolving a duplicate key in opposite
    directions is how one file gets read as two different recordings" — and this reader and
    `_absorb` read the same bytes. Losing a row is less bad than losing a grade here, because
    the count itself is evidence; a torn line that fails the world would throw away every other
    fact the file carries.

    A `staged` row on a patch-only system is REPORTED as a data-integrity note, never silently
    reclassified: G7 makes that a shape the live estate cannot produce, and quietly rewriting it
    would hide a hand-edited or corrupted recording.
    """
    family_mod = _family()
    first = J.staged_row("b")
    second = dict(first, source="passthrough")
    torn = json.dumps(J.ledger_row(source="passthrough", world_label="b"))[:40]
    ep = J.accepted_episode(tmp_path, ledgers={"c": []})
    J.write_ledger(ep, "b", [], raw="".join([
        json.dumps(first) + "\n",
        json.dumps(second) + "\n",
        torn + "\n",
        json.dumps(dict(first, source="teleported")) + "\n",
    ]))

    grade = family_mod.grade_family(ep)
    row = J.rows(grade)["b"]
    assert row["doctored_answer_served"] is True, (
        "the LATER row won a duplicate pair-key; `_absorb` takes the first and the two readers "
        "must not disagree about the same bytes")
    assert row["malformed_rows"] == 2, (
        "the torn line and the out-of-vocabulary `source` were dropped without a count; the "
        "count is the evidence that the measurement was partial")
    assert row.get("ungradable") is not True, "a torn line took the whole world's grade with it"

    # `staged` on a patch-only system: reported, never reclassified.
    state = J.accepted_episode(tmp_path / "state", holding_system="cmdb", ledgers={
        "b": [J.ledger_row(source="staged", world_label="b", system="cmdb", verb="get-host")],
        "c": [],
    })
    note = J.rows(family_mod.grade_family(state))["b"]
    assert note["doctored_answer_served"] is True, (
        "the row's own `source` was overruled instead of reported")
    assert any("cmdb" in str(n) for n in note["integrity_notes"]), (
        "a `staged` row on a system the estate cannot stage was accepted without a note")
