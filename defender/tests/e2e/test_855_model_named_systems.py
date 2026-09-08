"""#855 F-06 end to end — a `system` the MODEL named must not steer a corpus write.

THE DEFECT. Two writers sit ABOVE the grant check and record the model's raw arguments:
`QueryCapture.wrap_tool_validate` (the pydantic argument schema turned the call back, so there
are no validated arguments to key on) and `_grant_check`'s unresolvable branch. Their rows are
exit-64 `agent-fixable`, which is exactly the pitfalls channel's input, and
`_build_pitfalls_handoffs` spends a record's `system` VERBATIM as
`defender/skills/<system>/execution.md` and points the curator at it. Nothing between the two
ever re-checked the string — so an injected gather subagent could name the corpus path it
wanted a curator sent to, needing no grant for the system it named, only a schema it could fail
on purpose (any extra or mistyped argument does it).

WHAT IS ASSERTED HERE, and why live rather than over a hand-built row: the fix is a WRITER
fix, so the demand is on what the queries table contains after a real run — every row's
`system` is one the run's own dispatch named, checked against the DISPATCH ARGUMENTS rather
than against the table the claim is about. A test that recovered `dispatched` from the same
rows it checks cannot fail.

Everything between the two replay models is production code: the dispatch, the query tool, the
capture path, the two guards, the two tables. The offline half of this issue — the handoff
filter and the commit gate that refuse a phantom system directory — is unit-level and lives in
`tests/test_pitfalls_curator.py`; the seam half (#855 F-12, the lead claim) is in
`tests/test_gather_engine_seam.py` and `tests/test_record_lead.py`.

#871 — THE IDENTITY THE COARSENING TOOK WITH IT
-----------------------------------------------
Keeping the model's string off the row cost the companion rejection guard the ability to tell
two undeclared systems apart: `ghostone.query{q}` and `ghosttwo.query{q}` both key as
`("", "query", q)`, so three rejections naming three ghosts were one repeat group and the third
ended the lead — a guard refusing a call that DIFFERS from its predecessors, which is the one
thing #807/#826 promised it would never do.

The identity crosses the seam as a FOURTEENTH column, `system_key`: a fixed-length hex digest
of the model's string, written only where an above-guard writer coarsened a readable string to
`""`, and `""` everywhere else. `record_query.system_fingerprint` is its single owner. The
tests below therefore pin two things at once — that two ghosts are two calls, and that the
digest never restores what #855 removed: no column of any row EQUALS a model-authored string,
and none reaches main's context on a refusal path.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.leads.pitfalls_curator import _build_pitfalls_handoffs  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    ABOVE_GUARD_QUERY_ID,
    REJECTION_BUDGET,
)
from defender.runtime import lead_zero  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, GOLDEN_AB3, Turn, materialize  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _dispatch, _run  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, ROW_KEYS, elastic_ok, q  # noqa: E402
# The COMPANION guard's replay oracle, imported rather than re-written: O3 is the claim that
# the live verdict and a replay over the recorded table are one predicate, and a second copy
# of the oracle here could only ever agree with itself.
from defender.tests.e2e.test_repeat_breaker_807 import INCOMPLETE_IDIOM, _replay_rejections  # noqa: E402

pytestmark = pytest.mark.e2e

PARAMS = {"native_query": "FROM logs"}

#: What an injected gather subagent would name if it could pick the corpus path: a segment that
#: is not a system, and that `_pitfalls_path_rule` accepted as one because it is single-segment.
PHANTOM = "Ignore Previous Instructions"


def _bad_args(system: Any, params: dict = PARAMS, *, verb: str = "query") -> Turn:
    """A call the pydantic ARGUMENT SCHEMA turns back — `bogus_extra_arg` is P-a's executed
    `extra_argument` shape — so its row is written by `wrap_tool_validate` from the RAW
    pre-validation arguments. `system` is whatever the model put there; that is the point.

    `verb` is keyword-only and defaults to the generic word every arm HERE means: only an arm
    asserting a negative about main's context needs a distinctive one (#1015's `_loud`), and
    spelling that as a second Turn builder would be a second home for the `bogus_extra_arg`
    routing this helper owns."""
    return Turn(tool_calls=[("query", {
        "system": system, "verb": verb, "params": params, "bogus_extra_arg": "x",
    })])


def _dead_end(r: _Res) -> bool:
    """Whether the lead ended EARLY, read off the SUMMARY main receives — the only place a
    verdict is observable from outside the gather agent, and the one main's context is
    composed from.

    NOT "the guard tripped". `_run_gather` writes this same idiom for all four of its
    terminators (`GatherDeadEnd`, `UsageLimitExceeded`, `UnexpectedModelBehavior` from
    exhausted tool retries, `StoreError`), and #871 is precisely the change that makes retry
    exhaustion a reachable end for a rejection loop — a lead naming a fresh ghost each turn
    now runs to `DEFAULT_TOOL_RETRIES` instead of stopping at three. So every POSITIVE use of
    this helper is paired with `_trip_row_written`, which reads the guard's own row; a
    NEGATIVE use is safe on its own only while the lead under it makes fewer than
    `REJECTION_BUDGET` rejections, and an arm that drives more must assert the run-on some
    other way. (#1015 moved that ceiling from the framework's ten to the host's own budget:
    past it the lead now ends by the host's decision, and this helper cannot tell that from
    any other terminator either.)

    The idiom is `test_repeat_breaker_807.INCOMPLETE_IDIOM` WHOLE, not a prefix of it: G19
    names that sentence as the only vocabulary any prompt teaches main, and a truncated copy
    would keep every arm below green if the terminator lost its second half."""
    return INCOMPLETE_IDIOM in _summary(r)


def _trip_row_written(r: _Res) -> bool:
    """Whether the companion guard's REPEAT branch is what ended the lead, read off the table
    rather than the summary: `rejection_trip_detail` leads the last rejection row's digest, and
    no other terminator writes it.

    THE REPEAT BRANCH ONLY, since #1015. The companion placement now carries a second guard —
    the per-lead rejection budget — whose trip row leads with its own phrase, so this helper
    reads False for a lead the companion placement demonstrably ended. A positive use still
    means "the repeat branch stopped this lead"; a NEGATIVE one means only that, and an arm
    that wants "no host guard stopped this lead" must read the terminator
    (`test_1015_rejection_budget._terminator`) instead."""
    rows = _above_guard(r)
    return bool(rows) and "turned back at seq" in rows[-1]["payload_digest"]


def _summary(r: _Res) -> str:
    return (r.run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")


def _above_guard(r: _Res) -> list[dict]:
    return [row for row in r.own_rows if row["query_id"] == ABOVE_GUARD_QUERY_ID]


def _queued(rows: list[dict]) -> list[dict]:
    """The pitfalls queue's row shape, built from the queries-table rows THIS RUN WROTE.

    Bound at the writer's output and handed straight to `_build_pitfalls_handoffs`, rather than
    routed through `lead_repository.joined` / `extract_from_joined`: what this finding turns on
    is the value the row CARRIES and the path the handoff builder then mints from it. The join
    in between is a different seam with its own suite (#823, #841), and a test of THIS one
    should not go red when that one is mid-refactor."""
    return [
        {
            "schema_version": 1, "pitfall_id": f"r:{row['lead_id']}:{row['seq']}",
            "source_run": "r", "system": row["system"], "query_id": row["query_id"],
            "goal": "g", "executed_query": row["raw_command"],
            "stderr_digest": row["payload_digest"], "error_class": row["error_class"],
        }
        for row in rows
    ]


#: The most above-guard rejections any arm in this FILE drives — `test_only_a_coarsened_row_...`
#: at four. `_dead_end`'s negative uses read the summary alone, and past `REJECTION_BUDGET`
#: rejections the host now ends the lead itself, so every `assert not _dead_end(...)` below
#: silently changes meaning once the headroom is gone. Bound executably rather than left in
#: prose: the arms cannot notice, so the constant must.
_MOST_REJECTIONS_ANY_ARM_DRIVES = 4


def test_this_files_negative_dead_end_arms_still_have_budget_headroom():
    """The precondition `_dead_end`'s docstring states, asserted rather than described (#1015).

    Lower `REJECTION_BUDGET` to `_MOST_REJECTIONS_ANY_ARM_DRIVES` or below and three arms here
    flip from "the guard correctly let calls that DIFFER run on" to "the budget ended the
    lead" — while staying green, because they read only the summary."""
    assert _MOST_REJECTIONS_ANY_ARM_DRIVES < REJECTION_BUDGET, \
        "an arm here drives as many above-guard rejections as the budget allows, so its " \
        "`assert not _dead_end(...)` no longer says what it claims"


def test_a_schema_rejected_call_cannot_name_a_system_of_record(tmp_path):
    """The row is still WRITTEN — the rejection happened and the table records it — but it
    carries no system, because the registry declares none by that name. `""` is the honest
    answer and it needs no new branch downstream: `collect_general_failures` already skips a
    systemless row, the same guard `system_for_payload_operands` returning `""` spends for the
    bash shim's writer."""
    r = _run(tmp_path, run_id="d855-phantom", turns=[_bad_args(PHANTOM), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the schema rejection stopped leaving its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == "", \
        "a model-named system reached the queries table as a system of record"
    assert _build_pitfalls_handoffs(_queued(rows), systems=frozenset({"elastic"})) == [], \
        "the model's string became a handoff path the curator is pointed at"


def test_a_schema_rejected_call_on_a_real_system_still_records_it(tmp_path):
    """The positive control, and the channel's whole purpose: a rejection against a system the
    registry DOES declare keeps its system and still reaches the pitfalls curator. A writer
    that coarsened every above-guard row to `""` would pass the negative above and silently
    close the channel #823 opened."""
    r = _run(tmp_path, run_id="d855-real", turns=[_bad_args("elastic"), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1
    assert rows[0]["system"] == "elastic", "a real system's rejection lost its attribution"

    handoffs = _build_pitfalls_handoffs(_queued(rows), systems=frozenset({"elastic"}))
    assert [h["path"] for h in handoffs] == [
        "defender/skills/elastic/execution.md"
    ], "the rejection no longer reaches the pitfalls curator at all"


def test_an_unresolvable_call_cannot_name_a_system_of_record(tmp_path):
    """The SECOND above-guard writer, on the same defect: `_grant_check`'s non-GRANTED branch
    records its own exit-64 row before raising `ModelRetry`. An unresolvable call is
    unresolvable precisely because the grant reached no system by that name, so the string it
    names is the one least entitled to become a `skills/<system>/` path."""
    r = _run(tmp_path, run_id="d855-unresolvable",
             turns=[q(PHANTOM, "query", PARAMS), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the unresolvable branch stopped recording its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == ""


def test_no_row_names_a_system_the_dispatch_never_named(tmp_path):
    """The negative universal, over the whole table — and `dispatched` comes from the GATHER
    DISPATCH's own arguments, not from the rows being checked. #823 pinned this shape for the
    bash shim and derived `dispatched` from the table itself, which cannot fail for a row whose
    `system` the model wrote: the row is its own evidence. Read off the dispatch, the claim is
    about the run, and every above-guard writer is inside it."""
    dispatch = _dispatch()
    dispatched = {dispatch[1]["system"]}
    # Distinct `params` per turn, carried from the base where every undeclared system keyed
    # the same and identical params would have ended the lead at the third call, leaving this
    # universal quantified over two rows and a dead end. Since #871 `system_key` separates the
    # three anyway; keeping the params distinct costs nothing and stops this universal
    # depending on that fix to reach all three writers.
    turns = [
        _bad_args(PHANTOM, {"native_query": "FROM one"}),
        q("ghost", "query", {"native_query": "FROM two"}),
        _bad_args("a b", {"native_query": "FROM three"}),
        DONE,
    ]
    r = _run(tmp_path, run_id="d855-universal", turns=turns, main_turns=[
        Turn(tool_calls=[dispatch]), Turn(text="Investigation complete."),
    ])

    assert dispatch[0] == "gather", "the shared helper stopped building a gather dispatch"
    assert dispatched == {"elastic"}
    assert len(_above_guard(r)) == 3, \
        "the three above-guard writers did not all leave a row — the universal is vacuous"
    for row in r.rows:
        assert row["system"] in dispatched | {""}, \
            f"a row names a system no dispatch did: {row['system']!r}"


def test_the_companion_repeat_guard_still_bounds_a_phantom_rejection_loop(tmp_path):
    """The coarsening is spent on the guard's IDENTITY as well as on the row, and it has to be:
    the companion guard recovers its count from the rows it wrote, so a live identity keyed on
    the model's raw string over a table holding `""` would match nothing and this repeat class
    would stop being bounded at all — the silent terminator #826 item 4 closed, reopened by the
    fix for #855. Three identical rejections still end the lead."""
    r = _run(tmp_path, run_id="d855-loop",
             turns=[_bad_args(PHANTOM), _bad_args(PHANTOM), _bad_args(PHANTOM), DONE])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert "turned back at seq" in rows[-1]["payload_digest"], "no trip row was written"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" in summary
    assert PHANTOM not in summary, \
        "the model's own string crossed back into main's context on a refusal path"


# #871 — the identity the coarsening took with it. Everything above is #855's, and stays: the
# arms below add a fourteenth column and must not cost a single one of those negatives.


def test_three_different_undeclared_systems_are_three_calls_not_one_repeat(tmp_path):
    """#871 — the companion guard's ONE property is that it never ends a lead for a call that
    differs from its predecessors (#807 F-A, #826 item 4). Three rejections naming three
    DIFFERENT undeclared systems under one verb and params are three different calls, and on
    #855's coarsening they were one: the `system` column carried `""` for all three, the guard
    keys off the row, and the third took the lead down.

    `system_key` is what makes them three again — the digest the coarsened row carries in place
    of a string it may not carry. The demand is on the LEAD, not on the column: the fourth turn
    is a corrected, granted `elastic` call and it has to reach the backend. A fix that merely
    stopped COUNTING undeclared rows satisfies every "no dead end" assertion below while
    unbinding the loop `..._still_bounds_a_phantom_rejection_loop` measures, which is why that
    test is kept unchanged beside this one.

    What the digest may NOT do is undo #855. Asserted as an equality over EVERY column, not
    over `system` alone: the digest would pass `is_system_name` if it ever landed in `system`,
    so "the string is not on the table" has to be quantified over the whole row."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-distinct", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), q("ghosttwo", "query", PARAMS), _bad_args("ghostthree"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}, "a phantom name reached the table"
    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 64, 0], \
        "the third distinct ghost ended the lead — they are still one repeat group"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert not _dead_end(r), "the lead was refused for three calls that differ"

    summary = _summary(r)
    values = [value for row in r.rows for value in row.values()]
    assert "elastic" in values, \
        "no column holds the dispatched system either — the inequalities below are vacuous"
    for phantom in ("ghostone", "ghosttwo", "ghostthree"):
        assert phantom not in summary, \
            "a model-authored system name crossed into main's context on a refusal path"
        assert phantom not in values, \
            "a model-authored system string became the value of a queries-table column"


def test_the_grant_checks_writer_mints_its_own_identity_too(tmp_path):
    """The fix has TWO writers and the arms above reach the threshold through only one of
    them. `_bad_args` fails the pydantic argument schema, so its rows come from
    `wrap_tool_validate`; a well-formed call naming a system the registry does not declare
    gets past the schema and is turned back by the GRANT CHECK's unresolvable branch instead,
    which records its own row from its own argument surface. A `system_key` computed at the
    first placement and left `""` at the second fixes #871 for half the surface and leaves
    the other half exactly as it was — and every other test in this file stays green, because
    one grant-path rejection among two schema-path ones can never reach the count.

    So: three DISTINCT undeclared systems, all three driven through the grant check, and a
    corrected call that must execute. The trip control is the test below, which reaches the
    threshold through the schema placement — between them the two placements are both bound
    in both directions.

    `_above_guard` cannot tell the two writers apart (both rows carry the same sentinel
    `query_id`), so the discriminator is the TURN SHAPE: `q(...)` is schema-valid by
    construction, which is what routes it past `wrap_tool_validate`."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-grantpath", verbs=elastic_ok(rec), turns=[
        q("ghostone", "query", PARAMS), q("ghosttwo", "query", PARAMS),
        q("ghostthree", "query", PARAMS), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three grant-path rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}, "a phantom name reached the table"
    keys = {row["system_key"] for row in rows}
    assert len(keys) == 3, \
        f"the grant check's writer minted no distinct identities: {keys}"
    assert "" not in keys, \
        "a grant-path rejection was recorded unfingerprinted, so it keys as every other one"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert not _dead_end(r), \
        "three distinct ghosts ended the lead through the grant check — #871 is unfixed there"


def test_one_ghost_keys_the_same_through_both_above_guard_writers(tmp_path):
    """`system_fingerprint`'s sole-ownership claim, bound ACROSS the two placements rather than
    within each. Every other arm here drives one ghost through one writer, or three ghosts
    through two — so a placement that normalised before hashing (`.strip()`, `.lower()`,
    `str(...)`) would mint two identities for ONE ghost and every one of them would still pass:
    the fixtures are whitespace-free lowercase ASCII, on which those normalisations are the
    identity function.

    The realistic loop is exactly this shape — a typo'd extra argument on `ghostone` (schema
    placement), the same name spelled cleanly (grant placement), the typo again — and if the
    two writers disagree it is unbounded. Asserted on the ROWS, so the identity is read where
    the guard reads it, and on the LEAD, so the count they share is the one that terminates."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-both-writers", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), q("ghostone", "query", PARAMS), _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert {row["system_key"] for row in rows} == {
        record_query.system_fingerprint("ghostone", "")}, \
        "the two above-guard writers minted different identities for one ghost, so a loop " \
        "alternating between them can never reach the threshold"
    assert _dead_end(r), "one ghost through both placements stopped bounding the lead"
    assert _trip_row_written(r), \
        "the lead ended on something other than the guard, so the bound above is not the guard's"
    assert rec.calls == [], "the lead ran on past its dead end"


def test_the_grant_checks_writer_is_still_bounded_on_a_repeat(tmp_path):
    """The control for the test above, at the same placement: the grant check's writer must
    not buy O1 by minting a FRESH identity per call. The same undeclared name three times
    through the grant check still ends the lead, and the fourth turn must not execute."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-grantpath-repeat", verbs=elastic_ok(rec), turns=[
        q("ghostone", "query", PARAMS), q("ghostone", "query", PARAMS),
        q("ghostone", "query", PARAMS), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert {row["system_key"] for row in rows} == {
        record_query.system_fingerprint("ghostone", "")}, \
        "one name was recorded under more than one identity, so no repeat can ever be seen"
    assert _dead_end(r), "one ghost named three times no longer bounds the lead"
    assert _trip_row_written(r), \
        "the lead ended, but not on the guard — the summary idiom is shared with the request " \
        "limit and with exhausted tool retries, so it alone certifies nothing"
    assert rec.calls == [], "the lead ran on past its dead end"
    assert "an undeclared system" in _summary(r), \
        "the GRANT placement's dead end named a system, or said the arguments were " \
        "unreadable — neither is true, and the schema placement's twin is the only other " \
        "arm asserting this sentence at all"
    assert "ghostone" not in _summary(r), \
        "the model's own string crossed into main's context on a refusal path"


def test_the_same_undeclared_system_named_three_times_still_ends_the_lead(tmp_path):
    """The control that stops the test above being satisfied by "stop counting undeclared
    rows", stated at the same address as its own claim rather than only at
    `..._still_bounds_a_phantom_rejection_loop`'s: the SAME ghost repeated keys the same
    `system_key`, so the count survives the split and the third rejection is still the third.

    The fourth turn is the same corrected `elastic` call the run-on test grants, and here it
    must NOT reach the backend — the lead is over before it is issued. Without that arm a guard
    that counted correctly but had stopped terminating would pass on the summary text alone."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-same", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghostone"), _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert _trip_row_written(r), "no trip row was written"
    assert rec.calls == [], "the lead ran on past its dead end and executed a later call"
    assert _dead_end(r)
    assert "an undeclared system" in _summary(r), \
        "the dead end named a system, or said the arguments were unreadable — neither is true"
    assert "ghostone" not in _summary(r)
    assert record_query.system_fingerprint("ghostone", "") not in _summary(r), \
        "the digest itself crossed into main's context — it is name-shaped, so a reader " \
        "downstream can spend it exactly as it would spend a system"


def test_only_a_coarsened_row_carries_a_system_key_and_it_is_a_digest(tmp_path):
    """The ROW contract the guard's identity rests on, read off a live table: `system_key` is
    `""` on every row whose `system` column carries the dispatched name — every below-guard
    row, the bash lane, and an above-guard rejection against a system the registry DOES declare
    — and a fixed-length hex digest exactly where a readable model string was coarsened away.

    Both halves are load-bearing in opposite directions. A blanket `""` puts the ghosts back in
    one group; a fingerprint written on declared rows too would give `elastic`'s rejections an
    identity its below-guard rows do not share, splitting one system's count in half.

    The digest is bound to `record_query.system_fingerprint` rather than restated, because the
    design gives that function sole ownership: two above-guard writers reach the row and a
    second derivation at either of them is a silent split of the same ghost's count."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-column", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghosttwo"), _bad_args("ghostone"),
        _bad_args("elastic"), q("elastic", "query", PARAMS), DONE,
    ])

    keys = [row["system_key"] for row in r.own_rows]
    assert len(keys) == 5, "the five calls did not all leave their rows"
    assert all(re.fullmatch(r"[0-9a-f]{64}", k) for k in keys[:3]), \
        f"a coarsened row carries no fixed-length hex digest: {keys[:3]}"
    assert keys[0] == keys[2], "one ghost named twice produced two identities"
    assert keys[0] != keys[1], "two different ghosts produced one identity"
    assert keys[3] == keys[4] == "", \
        "a row that kept its dispatched system was fingerprinted anyway"

    assert keys[0] == record_query.system_fingerprint("ghostone", ""), \
        "the writer derives the digest itself instead of spending the owning function"
    assert record_query.system_fingerprint("elastic", "elastic") == "", \
        "a declared system fingerprints itself, which splits its own count"

    for row in r.rows:
        assert isinstance(row["system_key"], str), \
            "a row's identity is not a string, so `str(...)` at the guard is doing the work"
        if row["system"]:
            assert row["system_key"] == "", \
                f"{row['system']!r} kept its system AND took a fingerprint"
    values = [value for row in r.rows for value in row.values()]
    assert "elastic" in values, "the negative below is quantified over nothing"
    assert "ghostone" not in values, \
        "the fourteenth column put the model's string back on the table"
    assert "ghosttwo" not in values, \
        "the fourteenth column put the model's string back on the table"

    digests = {k for k in keys if k}
    assert digests, "no digest was minted, so the negative below is quantified over nothing"
    assert not any(row["system"] in digests for row in r.rows), \
        "a digest reached the `system` column, which `_build_pitfalls_handoffs` spends "\
        "verbatim as `defender/skills/<system>/execution.md` — and it is name-shaped enough "\
        "to pass `is_system_name` on the way"


def test_the_tables_second_writer_grows_the_column_too(tmp_path):
    """The fourteenth column is a ROW contract, not a `QueryCapture` one, and the queries table
    has a writer that does not go through `append_query_row` at all: `lead_zero`'s item-1
    capture spells the keys INLINE (`runtime/lead_zero/_capture.py:_record_manual_row`), which
    is why #877 had to reach in there for `payload_sha256` when it added that column.

    A row missing the key is not a guard bug — `_trip` coerces it to `""` and lead-0's rows are
    outside the gather lead's count anyway. It is a CONTRACT break: `set(row) == ROW_KEYS` is
    asserted against this writer's output in #808 and #872, and every reader written against
    the frozen set reads both writers' rows out of one file. `""` is the honest value here:
    item 1 dispatches a system of record, so nothing was coarsened away.

    Driven through the production function on a real run dir rather than over a hand-built row,
    because "the second writer agrees with the first" is exactly the claim a fixture restating
    the keys cannot make."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    lead_zero._record_manual_row(
        lead_zero._CaptureDeps(
            run_dir=run_dir, defender_dir=DEFENDER, run_id="d871-second-writer",
            lead_id="l-000",
        ),
        "search", {"index": "logs"}, {"rows": [{"a": 1}]}, exit_code=0,
    )

    rows = record_query.lead_rows(run_dir, "l-000")
    assert len(rows) == 1, "the second writer left no row, so the contract below is vacuous"
    assert set(rows[0]) == ROW_KEYS, \
        "the two writers disagree about the row's keys — one file, two shapes"
    assert rows[0]["system"], "item 1's row names no system, so the claim below is vacuous"
    assert rows[0]["system_key"] == "", \
        "item 1 dispatches a system of record; nothing was coarsened, so nothing is keyed"


def test_the_replay_of_the_recorded_table_agrees_with_the_live_run(tmp_path):
    """O3 — the guard recovers its identity from the ROW ALONE, so #807's replay oracle over
    the table a run left must reach the run's own verdict. The identity that separates two
    ghosts is stored, not derived from the other columns (the string it fingerprints is by
    design absent), so a column the oracle does not read is a column the offline replay is
    blind to — and the replay is how a recorded run's dead ends are audited at all.

    Driven over BOTH tables in one test on purpose. An oracle that had simply stopped counting
    above-guard rows agrees with the live run on the distinct-ghost table and disagrees with it
    on the repeated-ghost one, so the "no trip" arm alone certifies nothing."""
    rec = VerbRecorder()
    distinct = _run(tmp_path / "distinct", run_id="d871-replay-run-on", verbs=elastic_ok(rec),
                    turns=[
                        _bad_args("ghostone"), _bad_args("ghosttwo"), _bad_args("ghostthree"),
                        q("elastic", "query", PARAMS), DONE,
                    ])
    same = _run(tmp_path / "same", run_id="d871-replay-trip", turns=[
        _bad_args("ghostone"), _bad_args("ghostone"), _bad_args("ghostone"), DONE,
    ])

    assert len(rec.calls) == 1, \
        "the corrected call never executed, so the parity below is over the wrong table"
    assert not _dead_end(distinct), \
        "the live run did not run on, so the parity below is over the wrong table"
    assert _replay_rejections(distinct.rows) == [], \
        "the replay refuses a lead the live run let run on"

    assert _dead_end(same), "the live run did not trip, so the parity below is over the wrong table"
    assert _trip_row_written(same), \
        "the live run ended on something other than the guard, so the parity below is over " \
        "the wrong table"
    assert _replay_rejections(same.rows) == [(LEAD, 2, "repeat")], \
        "the replay misses the trip the live run took, on the table that run wrote"


def test_calls_with_no_readable_system_at_all_are_still_one_group(tmp_path):
    """N5 — the fingerprint is of a READABLE string, and a `system` argument that is not a
    string has none. `_text.as_str` coarsens it to `""` at the schema placement, the same value a
    row already stores, and no fingerprint is minted: "no readable system at all" is ONE
    mistake however many shapes the argument takes, so three of them still end the lead.

    Fingerprinting `str(raw)` instead would separate `12345` from `True` from `{}` and hand a
    model an unbounded supply of distinct identities — the guard would count to three only if
    the model repeated itself exactly, which is the property #826 item 4 exists to deny.

    The readable-ghost run is the same assertion under the complementary condition, at the same
    two addresses (the incomplete idiom and the column), so "the lead ended" cannot be read as
    "this suite's dead end always fires"."""
    blank = _run(tmp_path / "blank", run_id="d871-n5", turns=[
        _bad_args(12345), _bad_args(True), _bad_args({"n": 1}), DONE,
    ])
    readable = _run(tmp_path / "readable", run_id="d871-n5-control", turns=[
        _bad_args("ghostone"), _bad_args("ghosttwo"), _bad_args("ghostthree"), DONE,
    ])

    rows = _above_guard(blank)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}
    assert {row["system_key"] for row in rows} == {""}, \
        "an unreadable system argument was fingerprinted, so each shape is its own group"
    assert _dead_end(blank), "three unreadable calls are one mistake and no longer bounded"
    assert _trip_row_written(blank), \
        "the lead ended on something other than the guard, so the bound above is not the " \
        "guard's"

    control = {row["system_key"] for row in _above_guard(readable)}
    assert len(control) == 3, \
        f"the control minted no distinct digests either, so `blank`'s says nothing: {control}"
    assert "" not in control, \
        f"a readable ghost went unfingerprinted, so `blank`'s says nothing: {control}"
    assert not _dead_end(readable)


def test_an_invisible_system_string_is_folded_and_never_called_an_undeclared_system(tmp_path):
    """The MESSAGE half of `names_something_readable`, at the seam — the fold half is pinned at
    `test_826_deferred_defects` and nothing drove the two together.

    `_undeclared_target` decided this with `raw.strip()` before #871, and `.strip()` answers
    True for every zero-width and format codepoint. Both halves of that are observable here on
    ONE run: three invisible strings must be ONE repeat group (so the third ends the lead — the
    `system_fingerprint` half), and the sentence MAIN receives must not call them "an undeclared
    system" (the `_undeclared_target` half), because they named nothing a reader can see. Under
    `.strip()` the first still holds and the second silently flips, which is why the fold arms
    elsewhere in this file cannot stand in for this one.

    The complementary control is `..._named_three_times_still_ends_the_lead`, which asserts the
    sentence IS present for a readable ghost on the same placement — so this is not satisfied by
    a dead end that stopped saying anything."""
    r = _run(tmp_path, run_id="d871-invisible", turns=[
        _bad_args("\u200b"), _bad_args("\ufeff"), _bad_args("\u200b\u200b"), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system_key"] for row in rows} == {""}, \
        "an invisible system string was fingerprinted, so each is its own group and the loop " \
        "they make is bounded by nothing"
    assert _dead_end(r), "three indistinguishable invisible strings stopped being one mistake"
    assert _trip_row_written(r), \
        "the lead ended on something other than the guard, so the bound above is not the guard's"
    assert "an undeclared system" not in _summary(r), \
        "the dead end told MAIN a system was named when the argument held nothing readable — " \
        "the message and the fold answered the readability question differently"


def test_a_declared_system_is_never_folded_into_that_group(tmp_path):
    """The control for the test above, and the property that keeps the coarsening honest: two
    rejections against UNDECLARED systems do not top up the count for a REAL one. `elastic`
    keys as itself, so its first rejection is its first — the lead runs on and the corrected
    call executes."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d855-notfolded", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghosttwo"),
        _bad_args("elastic"), q("elastic", "query", PARAMS), DONE,
    ])

    rows = r.own_rows
    assert [row["exit_code"] for row in rows] == [64, 64, 64, 0], \
        "the real system's call was refused by a count only the phantoms earned"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" not in summary


def test_the_dispatch_argument_is_the_only_system_the_run_can_name(tmp_path):
    """Belt to the universal's braces: the same phantom, driven through BOTH above-guard
    writers in one run, leaves no `defender/skills/<phantom>/execution.md` anywhere in the
    handoff the curator would receive — the artifact the whole finding is about."""
    r = _run(tmp_path, run_id="d855-handoff",
             turns=[_bad_args(PHANTOM), q(PHANTOM, "query", PARAMS), DONE])

    handoffs = _build_pitfalls_handoffs(_queued(r.own_rows), systems=frozenset({"elastic"}))
    paths = [h["path"] for h in handoffs]
    assert not any(PHANTOM in p for p in paths), f"the curator is pointed at {paths}"
    assert all(Path(p).parts[:2] == ("defender", "skills") for p in paths)


def test_the_gather_dispatch_is_unchanged_by_all_of_this(tmp_path):
    """A control the three negatives need: the run this suite drives is an ordinary one, and
    an ordinary granted call still records its system, executes, and is attributed. Without it
    every assertion above is satisfiable by a query tool that records nothing."""
    r = _run(tmp_path, run_id="d855-control", turns=[q("elastic", "query", PARAMS), DONE])
    executed = [row for row in r.own_rows if row["exit_code"] == 0]
    assert executed, "no call executed — the negatives above are vacuous"
    assert {row["system"] for row in executed} == {"elastic"}
    assert _dispatch()[1]["system"] == "elastic", \
        "the shared dispatch changed system; this suite's `dispatched` set is stale"
