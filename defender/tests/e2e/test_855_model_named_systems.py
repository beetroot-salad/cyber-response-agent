"""#855 F-06 end to end — a `system` the MODEL named must not steer a corpus write. Two above-guard writers (schema rejection, unresolvable grant) record the model argument; the queries table must hold only systems the dispatch named, no host-authored column may echo model text (#1016 O1), and undeclared systems stay distinct to the repeat guard via a digest `system_key` (#871)."""
from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.leads.pitfalls_curator import _build_pitfalls_handoffs  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _dispatch, _run  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
# O3's replay parity (live verdict == the companion guard's oracle over the recorded table) is
# `test_1017_query_row_surface.py::test_the_replay_through_the_surface_agrees_with_the_live_run`'s,
# which checks it through the typed surface and over the raw rows alike.
from defender.tests.e2e.test_repeat_breaker_807 import INCOMPLETE_IDIOM  # noqa: E402

pytestmark = pytest.mark.e2e

PARAMS = {"native_query": "FROM logs"}

#: What an injected gather subagent would name if it could pick the corpus path: a segment that
#: is not a system, and that `_pitfalls_path_rule` accepted as one because it is single-segment.
PHANTOM = "Ignore Previous Instructions"

#: A `system` argument holding one zero-width space: readable to `str`, invisible to a reader,
#: and `names_something_readable`-false — so it reaches the GRANT placement (it is a `str`, so
#: `as_str` does not coarsen it) and is recorded with NO fingerprint (N5). #1016 keeps it in the
#: O1 sweep because it is model-authored text like any other, and the one shape a serialising
#: oracle would silently fail to look for (`_host_authored` searches raw values for that
#: reason).
ZERO_WIDTH = "\u200b"

#: A model-authored `system` value too long for pydantic to print whole: its error text renders
#: `input_value=` through a repr that TRUNCATES with an ellipsis around 50 characters. That makes
#: this the shape a SCRUB cannot clean — `str(e).replace(what_the_model_sent, "<withheld>")` never
#: matches a string pydantic already shortened, so the leading characters survive verbatim in a
#: host-authored column while every fixture with a short ASCII ghost name looks spotless. #1016
#: N5 rules the scrub out in prose ("a substring scrub over repr-escaped text leaves fragments");
#: this constant is what makes that ruling FAIL A TEST instead of only reading well. The marker is
#: at the FRONT because the front is the half that survives.
LONG_GHOST_VALUE = "ghostlongvalue" + "x" * 300

#: The three columns carrying the call's own arguments, which #1016 N1 keeps verbatim: they are
#: what makes the row an audit record of what was attempted, and `system_fingerprint`'s docstring
#: already concedes they store unbounded model text. O1 is quantified over the COMPLEMENT.
#:
#: `raw_command` IS NOT WHOLLY MODEL-AUTHORED: `_record` builds it as
#: `_raw_command(system, verb, params)` from the ALREADY-COARSENED system, so a coarsened row
#: reads `'' ghostverb 'native_query=…'` and its FIRST shlex field is host material. Exempting
#: the whole column would put that field outside every O1 negative here — in exactly the place
#: #855's leak lived, and on the value `_queued()` hands the curator as `executed_query`.
#: `_raw_command_system` below is what keeps it inside.
MODEL_AUTHORED_COLUMNS = frozenset({"verb", "params", "raw_command"})


def _bad_args(system: Any, params: dict = PARAMS, *,
              verb: str = "query", extra_key: str = "bogus_extra_arg") -> Turn:
    """A call the pydantic ARGUMENT SCHEMA turns back — `bogus_extra_arg` is P-a's executed
    `extra_argument` shape — so its row is written by `wrap_tool_validate` from the RAW pre-
    validation arguments."""
    assert extra_key not in ("system", "verb", "params", "query_id"), \
        f"extra_key={extra_key!r} is one of the tool's own arguments — it would overwrite that " \
        "argument, or (for `query_id`) make the call valid, instead of adding an extra one"
    return Turn(tool_calls=[("query", {
        "system": system, "verb": verb, "params": params, extra_key: "x",
    })])


def _host_authored(row: dict) -> str:
    """Every column of `row` the HOST wrote, as one searchable string — #1016 O1's oracle."""
    return "\x00".join(
        str(v) for k, v in row.items() if k not in MODEL_AUTHORED_COLUMNS
    )


def _model_authored(row: dict) -> str:
    """The complement — the three columns O1 exempts (#1016 N1), joined the same way and for the
    same reason."""
    return "\x00".join(
        str(v) for k, v in row.items() if k in MODEL_AUTHORED_COLUMNS
    )


def _raw_command_system(row: dict) -> str:
    """The system field of `raw_command` — the ONE part of an exempt column the host wrote."""
    return next(iter(shlex.split(row["raw_command"])), "")


def _detail(row: dict) -> str:
    """The DETAIL half of a failure row's digest — `_record` composes `f"exit={code};
    {redact_model_visible(detail).strip()[:160]}"`."""
    return row["payload_digest"].split(";", 1)[-1].strip()


def _dead_end(r: _Res) -> bool:
    """Whether the lead ended EARLY, read off the SUMMARY main receives — the only place a
    verdict is observable from outside the gather agent, and the one main's context is
    composed from."""
    return INCOMPLETE_IDIOM in _summary(r)


def _trip_row_written(r: _Res) -> bool:
    """Whether the companion guard's REPEAT branch is what ended the lead, read off the table
    rather than the summary: `rejection_trip_detail` leads the last rejection row's digest,
    and no other terminator writes it."""
    rows = _above_guard(r)
    return bool(rows) and "turned back at seq" in rows[-1]["payload_digest"]


def _summary(r: _Res) -> str:
    return (r.run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")


def _above_guard(r: _Res) -> list[dict]:
    """The rows the above-guard placements' two guards COUNT — spent from
    `record_query.in_rejection_domain`, the predicate #1015 made public for exactly this."""
    return [row for row in r.own_rows if record_query.in_rejection_domain(row)]


def _queued(rows: list[dict]) -> list[dict]:
    """The pitfalls queue's row shape, built from the queries-table rows THIS RUN WROTE."""
    return [
        {
            "schema_version": 1, "pitfall_id": f"r:{row['lead_id']}:{row['seq']}",
            "source_run": "r", "system": row["system"], "query_id": row["query_id"],
            "goal": "g", "executed_query": row["raw_command"],
            "stderr_digest": row["payload_digest"], "error_class": row["error_class"],
        }
        for row in rows
    ]


#: The most above-guard rejections any arm in this FILE drives on ONE lead —
#: `test_only_a_coarsened_row_...` at four. `_dead_end`'s negative uses read the summary alone,
#: and past `REJECTION_BUDGET` rejections the host now ends the lead itself, so every
#: `assert not _dead_end(...)` below silently changes meaning once the headroom is gone.
#:
#: A HAND-MAINTAINED CENSUS, and that is its limit: the assertion below relates two CONSTANTS,
#: so it catches a budget that moved down and NOT an arm that started driving more. The
#: durable oracle is `test_1015_rejection_budget._terminator` — a negative arm that read the
#: lead's terminator instead of the summary would need no census at all. Until the four
#: `assert not _dead_end(...)` sites are converted, re-count this when adding an arm.
_MOST_REJECTIONS_ANY_ARM_DRIVES = 4


def test_a_schema_rejected_call_cannot_name_a_system_of_record(tmp_path):
    """The row is still WRITTEN — the rejection happened and the table records it — but it
    carries no system, because the registry declares none by that name."""
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
    DISPATCH's own arguments, not from the rows being checked."""
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
    would stop being bounded at ..."""
    ghost = _bad_args(PHANTOM, verb="ghostverb", extra_key="ghostkeyname")
    r = _run(tmp_path, run_id="d855-loop", turns=[ghost, ghost, ghost, DONE])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert "turned back at seq" in rows[-1]["payload_digest"], "no trip row was written"
    assert rows[-1]["payload_digest"].startswith(
        "exit=64; refused: repeat of request already turned back at seq"), \
        "the trip phrase no longer LEADS the digest — it is 160 characters from being cut, " \
        "and two helpers in this file detect a trip by nothing else"
    assert "ghostverb" in _model_authored(rows[-1]), \
        "the trip row lost the call's own arguments, so the negative below is quantified " \
        "over a row that never carried the model's text at all"
    # The TAIL, demanded as well as bounded. O4 says the trip row's tail must OBEY O1, not that
    # it may satisfy O1 by not existing — and `rejection_trip_detail`'s own docstring says why
    # the distinction matters: "replacing the detail outright would make the append-only table
    # permanently forget why the last call was malformed". This row is both the trip record and
    # the third rejection's own record, and it is the only place the latter is written down.
    # Without these two lines the negatives below are satisfied by passing an empty tail.
    assert "; rejected: " in rows[-1]["payload_digest"], \
        "the trip row dropped its rejection tail — the table now records THAT the guard fired " \
        "and no longer why this call was turned back, which no other row carries"
    assert "Extra inputs are not permitted" in rows[-1]["payload_digest"], \
        "the trip row's tail no longer names the error type, so an operator reading the one " \
        "row that ended the lead cannot tell what the model kept getting wrong"
    trip_host = _host_authored(rows[-1])
    for text in (PHANTOM, "ghostverb", "ghostkeyname"):
        assert text not in trip_host, \
            f"the trip row's tail put {text!r} in a host-authored column of a coarsened row"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" in summary
    assert PHANTOM not in summary, \
        "the model's own string crossed back into main's context on a refusal path"


# #871 — the identity the coarsening took with it. Everything above is #855's, and stays: the
# arms below add a fourteenth column and must not cost a single one of those negatives.


def test_three_different_undeclared_systems_are_three_calls_not_one_repeat(tmp_path):
    """#871 — the companion guard's ONE property is that it never ends a lead for a call that
    differs from its predecessors (#807 F-A, #826 item 4)."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-distinct", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "ghostverb", PARAMS),
        _bad_args("ghostthree", verb="ghostverb"), q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 3, "the three rejections did not all leave their rows"
    assert {row["system"] for row in rows} == {""}, "a phantom name reached the table"
    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 64, 0], \
        "the third distinct ghost ended the lead — they are still one repeat group"
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert not _dead_end(r), "the lead was refused for three calls that differ"

    summary = _summary(r)
    for phantom in ("ghostone", "ghosttwo", "ghostthree"):
        assert phantom not in summary, \
            "a model-authored system name crossed into main's context on a refusal path"

    # #1016 O1, in place of `phantom not in values`. The paired positives are on the SAME rows:
    # the model's verb IS in the columns O1 exempts, and the detail the host owes an operator is
    # still there — so neither negative can be satisfied by a row that carried nothing.
    assert any("unresolvable: ghosttwo.ghostverb" in seen for seen in r.gather.seen), \
        "the model never read its own ghost back, so the negatives below are quantified over " \
        "a string this run never produced"
    for row in rows:
        assert _detail(row), \
            "a coarsened row recorded no reason at all — O1 is a claim about what the host " \
            "may say, not a licence to say nothing"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negatives below are vacuous"
        host = _host_authored(row)
        # `bogus_extra_arg` is in the sweep because two of these three rows are SCHEMA
        # rejections, whose `system` and `verb` are valid strings pydantic never mentions:
        # the only model text their digest can carry is the argument NAME. Without it the
        # schema half of this arm cannot fail, and one grant row is doing all the work.
        for text in ("ghostone", "ghosttwo", "ghostthree", "ghostverb", "bogus_extra_arg"):
            assert text not in host, \
                f"{text!r} — model-authored text — is in a host-authored column of a row " \
                "whose `system` the host deliberately withheld"


def test_the_grant_checks_writer_mints_its_own_identity_too(tmp_path):
    """The fix has TWO writers and the arms above reach the threshold through only one of them."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-grantpath", verbs=elastic_ok(rec), turns=[
        q("ghostone", "ghostverb", PARAMS), q("ghosttwo", "ghostverb", PARAMS),
        q("ghostthree", "ghostverb", PARAMS), q("elastic", "query", PARAMS), DONE,
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

    # #1016 O2 and O1, at the placement where they are hardest to hold together. O2 first,
    # because it is O1's positive control AND a demand in its own right: the string the row may
    # not carry is one the MODEL must still read back, or a subagent that mistyped a system name
    # can never correct it. The negative under it is over the same run, the same call and the
    # same string, so a fix that bought O1 by never producing the refusal fails here loudly
    # instead of passing quietly.
    assert any("unresolvable: ghosttwo.ghostverb" in seen for seen in r.gather.seen), \
        "the refusal the MODEL reads stopped naming the system it asked for — a mistyped " \
        "system name is now uncorrectable, and every O1 negative in this file is vacuous"
    for row in rows:
        assert _detail(row), \
            "a coarsened grant-path row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negative below is vacuous"
        host = _host_authored(row)
        for text in ("ghostone", "ghosttwo", "ghostthree", "ghostverb"):
            assert text not in host, \
                f"the grant check put {text!r} — model-authored text — in a host-authored " \
                "column of a row whose `system` it had just withheld"


def test_one_ghost_keys_the_same_through_both_above_guard_writers(tmp_path):
    """`system_fingerprint`'s sole-ownership claim, bound ACROSS the two placements rather than
    within each."""
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


def test_only_a_coarsened_row_carries_a_system_key_and_it_is_a_digest(tmp_path):
    """The ROW contract the guard's identity rests on, read off a live table: `system_key` is
    `""` on every row whose `system` column carries the dispatched name — every below-guard
    row, the bash lane, and an above-guard rejection against a system the registry DOES
    declare — and a fixed-length hex digest ..."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d871-column", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), _bad_args("ghosttwo", verb="ghostverb"),
        _bad_args("ghostone", verb="ghostverb"),
        _bad_args("elastic", verb="ghostverb"), q("elastic", "query", PARAMS), DONE,
    ])

    # `r.own_rows` re-reads and re-parses `executed_queries.jsonl` on every access, so it is
    # bound once: the table is immutable by now, and five reads of it in one test read as a
    # claim that it might not be.
    own = r.own_rows
    keys = [row["system_key"] for row in own]
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
    # #1016 O1, in place of the two `not in values` arms this test shipped with. The fourth turn
    # is the positive control and it is exact rather than analogous: the SAME `_bad_args` shape,
    # the same `bogus_extra_arg` key, the same run and the same writer — differing only in the
    # condition O1 is scoped by. Its system was DECLARED, so nothing was coarsened, so N3 says
    # its digest keeps pydantic's text verbatim and the model's argument name with it. If that
    # row's digest is clean too, the writer has stopped recording rather than started scrubbing.
    declared = own[3]
    assert declared["system"] == "elastic", \
        "the control row lost its declared system, so it is not the complementary condition"
    assert declared["system_key"] == "", \
        "the control row was coarsened after all, so it is not the complementary condition"
    assert "bogus_extra_arg" in _host_authored(declared), \
        "a row that KEPT its system stopped recording the model's own argument name — the " \
        "negatives below are then satisfied by a writer that records nothing (#1016 N3)"
    for row in own[:3]:
        assert _detail(row), "a coarsened row recorded no reason at all"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negatives below are vacuous"
        host = _host_authored(row)
        for text in ("ghostone", "ghosttwo", "ghostverb", "bogus_extra_arg"):
            assert text not in host, \
                f"the fourteenth column's row put {text!r} — model-authored text — in a " \
                "host-authored column of a coarsened row"

    digests = {k for k in keys if k}
    assert digests, "no digest was minted, so the negative below is quantified over nothing"
    assert not any(row["system"] in digests for row in r.rows), \
        "a digest reached the `system` column, which `_build_pitfalls_handoffs` spends "\
        "verbatim as `defender/skills/<system>/execution.md` — and it is name-shaped enough "\
        "to pass `is_system_name` on the way"


def test_calls_with_no_readable_system_at_all_are_still_one_group(tmp_path):
    """N5 — the fingerprint is of a READABLE string, and a `system` argument that is not a string
    has none."""
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
    `test_826_deferred_defects` and nothing drove the two together."""
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


# #1016 — the host's own columns. #871 claimed no column of a coarsened row carries the model's
# string and shipped an EQUALITY arm; `payload_digest` embeds it. The two arms below are the
# whole of the fix's discrimination: the five coarsened shapes, and the row that was NOT
# coarsened and must therefore be untouched.


def test_no_host_authored_column_of_a_coarsened_row_carries_model_text(tmp_path):
    """#1016 O1 — on a row whose `system` the host withheld, no column the HOST wrote echoes
    anything the model wrote."""
    # TWO LEADS OF THREE SHAPES AND A CONTROL, not one lead of seven — and the split is #1015's,
    # not a preference. That issue bounds a lead at `REJECTION_BUDGET` above-guard rejections
    # over its LIFETIME, so a seventh row cannot exist on one lead: the host ends the lead at
    # the sixth and the control never runs. Every claim below is preserved by the split because
    # none of them is about a lead. The six coarsened rows are ACCUMULATED across both runs for
    # the report at the end, each negative is still paired with a control written by the same
    # writer in the same run, and `ghostkeyname` is still spelled on exactly one call of its
    # own lead. What a single lead bought — and what #1015 takes away — is nothing this test
    # asserts.
    rec = VerbRecorder()
    first = _run(tmp_path / "a", run_id="d1016-shapes-a", verbs=elastic_ok(rec), turns=[
        q("ghosttwo", "ghostverb", {"native_query": "FROM one"}),
        q(ZERO_WIDTH, "ghostverb", {"native_query": "FROM two"}),
        _bad_args("ghostone", {"native_query": "FROM three"}, verb="ghostverb"),
        _bad_args("elastic", {"native_query": "FROM control a"}, verb="ghostverb",
                  extra_key="elastickeyname"),
        DONE,
    ])
    # `r` is the run holding the ghost-key shape, so the O2 read of `r.gather.seen` below is a
    # statement about THAT call: `ghostkeyname` is spelled here and nowhere else in this lead.
    r = _run(tmp_path / "b", run_id="d1016-shapes-b", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", {"native_query": "FROM four"}, verb="ghostverb",
                  extra_key="ghostkeyname"),
        _bad_args([PHANTOM], {"native_query": "FROM five"}, verb="ghostverb"),
        _bad_args([LONG_GHOST_VALUE], {"native_query": "FROM six"}, verb="ghostverb"),
        _bad_args("elastic", {"native_query": "FROM control b"}, verb="ghostverb",
                  extra_key="elastickeyname"),
        DONE,
    ])

    first_rows, rows = _above_guard(first), _above_guard(r)
    assert len(first_rows) == 4, \
        "the first lead's four shapes did not all leave their rows — its negatives are vacuous"
    assert len(rows) == 4, \
        "the second lead's four shapes did not all leave their rows — its negatives are vacuous"
    # Bind each row to the turn that wrote it, so a per-row negative names a KNOWN call. Read
    # off `params`, a column O1 exempts, which is why it is still readable here at all.
    assert [row["params"]["native_query"] for row in first_rows] == [
        "FROM one", "FROM two", "FROM three", "FROM control a",
    ], "the rows are not the first lead's calls in order — the claims below are misaddressed"
    assert [row["params"]["native_query"] for row in rows] == [
        "FROM four", "FROM five", "FROM six", "FROM control b",
    ], "the rows are not the second lead's calls in order — the claims below are misaddressed"
    for ended in (first, r):
        assert not _dead_end(ended), \
            "a lead ended early: either the shapes tripped one of the companion placement's " \
            "guards (so one of these rows is a trip row and they are not distinct calls) or " \
            "the lead outran `DEFAULT_TOOL_RETRIES` — `_trip_row_written` tells the repeat " \
            "branch from the rest. At the FOUR rejections each lead here drives, neither is " \
            "reachable: `REJECTION_BUDGET` is the tighter of the two ceilings and the " \
            "headroom census below tracks it"

    coarsened = [*first_rows[:3], *rows[:3]]
    control = first_rows[3]
    assert {row["system"] for row in coarsened} == {""}, \
        "a shape was not coarsened at all, so O1 does not even apply to it"
    ghost_key = record_query.system_fingerprint("ghostone", "")
    assert [row["system_key"] for row in coarsened] == [
        record_query.system_fingerprint("ghosttwo", ""), "", ghost_key, ghost_key, "", "",
    ], "N5's fold or the two placements' fingerprints changed under #1016 — the identity is " \
       "#871's and this issue does not touch it"

    # BOTH controls, one per lead: each run's negatives are paired with a row its OWN writer
    # produced under the complementary condition, which is what the single-lead form bought
    # before #1015 split the shapes.
    for kept in (control, rows[3]):
        assert kept["system"] == "elastic", \
            "a control lost its declared system, so it is not the complementary condition"
        assert kept["system_key"] == "", \
            "a control was coarsened after all, so it is not the complementary condition"
        assert "elastickeyname" in _host_authored(kept), \
            "a row that KEPT its system stopped recording the model's own argument name " \
            "(#1016 N3) — so the negatives below are satisfied by a writer that records nothing"

    # #1016 O2 at the SCHEMA placement, which had nothing pinning it (the grant half is two
    # tests up). The whole of M2 is that the ROW stops carrying pydantic's text while the MODEL
    # keeps reading it, so an implementation that re-raised the host's coarse rendering to the
    # model greens every other arm here — and a subagent that cannot see WHICH argument was
    # refused cannot drop it, and retries until the lead runs out.
    #
    # It is also the ghost-key negative's positive control, and it is a statement about the
    # COARSENED call only because `ghostkeyname` is spelled there and nowhere else in the lead:
    # the control one turn later uses `elastickeyname`. Sharing the key would make this true of
    # the control's own retry text and blind to the call it is about.
    assert any("ghostkeyname" in seen for seen in r.gather.seen), \
        "on a COARSENED call the model stopped reading back the argument name it got wrong, " \
        "so it can never drop it (#1016 O2) — and the `ghostkeyname` negative below is then " \
        "quantified over a string this run never produced"

    for row in coarsened:
        assert _detail(row), \
            "a coarsened row recorded no reason at all — O1 bounds what the host may say " \
            "about the call, it does not licence saying nothing"
        assert "ghostverb" in _model_authored(row), \
            "the row lost the call's own arguments, so the negative below is vacuous"
        # THE ONE HOST-AUTHORED FIELD OF AN EXEMPT COLUMN. `raw_command`'s verb and params
        # halves are model text by design (N1) and the sweep below skips the column for them —
        # but its first field is `_raw_command`'s `system` argument, which this writer coarsened
        # one line earlier. Without this arm the oracle is blind exactly there: handing
        # `_raw_command` the raw system again — the ghost back in the value `_queued()` gives
        # the pitfalls curator as `executed_query`, the field #855's leak lived in — passes
        # every other assertion in this file.
        assert _raw_command_system(row) == row["system"] == "", \
            "`raw_command`'s system field is not the system OF RECORD: the audit string " \
            f"carries {_raw_command_system(row)!r} where the row carries {row['system']!r}, " \
            "and O1's oracle exempts that column"

    # WHAT the host says, not merely THAT it said something. A blacklist plus a truthiness
    # check is satisfied by any detail the model's text cannot be read out of — a single
    # constant for every shape, or an ENCODING of the very text being hunted (base64 of
    # pydantic's message holds none of the eight tokens and all of their content). Both leave
    # `payload_digest` useless to the operator it exists for. So each placement owes a positive:
    #
    # * the GRANT placement names the CLASS of failure it withheld the specifics of (N8 picks
    #   "an undeclared system", the vocabulary `_undeclared_target` already speaks to main).
    #   Asserted on the word, not the sentence, so the wording stays the fix's to choose.
    # * the SCHEMA placement carries pydantic's message TEMPLATE for the error type, UNDER THE
    #   FIELD NAME the renderer chose. The templates are host material (C21: they quote no
    #   input) and the only part of pydantic's text that survives #1016.
    #
    #   The field half is `DECLARED_ARGS`' only positive control. The ghost-key negatives pin
    #   only that a model-chosen `loc[0]` becomes the placeholder, so a renderer emitting
    #   `argument:` for EVERY error satisfies them all while the digest silently stops saying
    #   which of the tool's OWN arguments was wrong. Shapes five and six fail on `system`, a
    #   declared name, so the pair below pins both halves: declared field printed as itself,
    #   invented one withheld.
    for row in coarsened[:2]:
        assert "undeclared" in _detail(row), \
            "a coarsened grant-path row no longer says what KIND of failure it withheld the " \
            "specifics of, so its digest tells an operator nothing"
    for row, template in zip(coarsened[2:], (
        # FROM three — the model's extra argument, under the default ghost key
        "argument: Extra inputs are not permitted",
        # FROM four  — same, under a name the model chose
        "argument: Extra inputs are not permitted",
        # FROM five  — `system` was a list: a DECLARED field, so it is printed as itself
        "system: Input should be a valid string",
        # FROM six   — same, a list pydantic cannot print whole
        "system: Input should be a valid string",
    ), strict=True):
        assert template in _detail(row), \
            f"a coarsened schema-path row no longer reads {template!r}, so it has either " \
            "dropped pydantic's own message (leaving a detail that cannot be read back, and is " \
            "indistinguishable from one that encodes the model's text instead) or stopped " \
            "naming the tool's own argument the way `DECLARED_ARGS` says it must"

    # ACCUMULATED rather than asserted per row, and that is the point of driving six shapes in
    # one lead: a per-row `assert` stops at the first leak, and the first leak is the coarse one
    # every candidate fix closes. The failure has to name EVERY shape still leaking, or a fix
    # that repairs the grant placement and leaves pydantic's `loc` standing reads as progress.
    hosts = [_host_authored(row) for row in coarsened]
    leaks = [
        (row["params"]["native_query"], text)
        for row, host in zip(coarsened, hosts, strict=True)
        for text in ("ghostone", "ghosttwo", ZERO_WIDTH, PHANTOM, "ghostlongvalue",
                     "ghostverb", "ghostkeyname", "bogus_extra_arg")
        if text in host
    ]
    assert leaks == [], (
        "model-authored text is in a host-authored column of a row whose `system` the host "
        f"withheld — (call, leaked text): {leaks}"
    )


def test_an_empty_system_argument_is_coarsened_like_every_other(tmp_path):
    """The SIXTH shape, and the one a predicate written as "did the recorded value differ from
    what the model SENT?" answers wrongly: a literal `system=""`."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1016-empty", verbs=elastic_ok(rec), turns=[
        _bad_args("", {"native_query": "FROM one"}, verb="ghostverb",
                  extra_key="ghostkeyname"),
        q("", "ghostverb", {"native_query": "FROM two"}),
        DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 2, "the two empty-system rejections did not both leave their rows"
    assert [row["system"] for row in rows] == ["", ""], \
        "an empty system argument stopped being recorded as `''`, so this is no longer the " \
        "row shape O1 is quantified over"
    assert [row["system_key"] for row in rows] == ["", ""], \
        "an empty system argument was fingerprinted, so the row is no longer indistinguishable " \
        "from a coarsened one and the claim below is about a different population"

    assert any("ghostkeyname" in seen for seen in r.gather.seen), \
        "the model stopped reading back the argument name it got wrong, so it can never drop " \
        "it (#1016 O2) — and the negative below is quantified over a string this run never made"
    assert all("ghostverb" in _model_authored(row) for row in rows), \
        "the rows lost the call's own arguments, so the negative below is vacuous"

    hosts = [_host_authored(row) for row in rows]
    leaks = [
        (row["params"]["native_query"], text)
        for row, host in zip(rows, hosts, strict=True)
        for text in ("ghostverb", "ghostkeyname")
        if text in host
    ]
    assert leaks == [], (
        "an empty `system` argument bought the model its own text in a host-authored column of "
        f"a row whose identity columns say the host withheld a name: {leaks}"
    )

    # And the row still SAYS something. O1 bounds what the host may put in that tail; it is not
    # a licence to empty it — the same positive each of the five shapes above owes.
    schema, grant = rows
    assert "Extra inputs are not permitted" in _detail(schema), \
        "the schema placement stopped naming the error type, so its digest tells an operator " \
        "nothing about why the call was turned back"
    assert "undeclared" in _detail(grant), \
        "the grant placement stopped saying what KIND of failure it withheld the specifics of"


def test_a_row_that_kept_its_system_records_the_rejection_verbatim(tmp_path):
    """#1016 O3 — the limit the fix may not overshoot, and the arm no existing test provides."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1016-declared", verbs=elastic_ok(rec), turns=[
        _bad_args("elastic", {"native_query": "FROM one"}),
        q("elastic", "nosuchverb", {"native_query": "FROM two"}),
        DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 2, "the two declared-system rejections did not both leave their rows"
    schema, grant = rows
    assert [row["system"] for row in rows] == ["elastic", "elastic"], \
        "a rejection against a DECLARED system lost its attribution — #855's coarsening " \
        "widened, and O3 is quantified over rows that no longer exist"
    assert [row["system_key"] for row in rows] == ["", ""], \
        "a declared system was fingerprinted, so these rows were treated as coarsened and " \
        "the positives below say nothing about the non-coarsened path"

    assert "Extra inputs are not permitted" in schema["payload_digest"], \
        "the schema placement stopped recording pydantic's own text for a DECLARED system — " \
        "the coarse rendering escaped the coarsened rows it is scoped to (#1016 N3)"
    assert "bogus_extra_arg" in schema["payload_digest"], \
        "pydantic's text survived but the offending argument NAME did not — a curator reading " \
        "this row can no longer tell which argument the model got wrong"
    # VERBATIM, not merely informative. The two arms above are satisfied by a partial
    # coarsening — `e.errors(include_input=False)` rendered as `loc: msg` keeps both the
    # template and the key — so on their own they do not hold the fix to N3 at all: swapping
    # the non-coarsened branch's `str(e)` for that rendering leaves this whole file green while
    # every declared-system rejection silently loses the failing VALUE, which is the half of
    # the digest the pitfalls curator reads to say what the model actually sent. The two
    # fragments below are the parts of pydantic's text that only `str(e)` produces, and both
    # land inside `_record`'s 160-character window for this shape.
    assert "[type=extra_forbidden" in schema["payload_digest"], \
        "pydantic's error TYPE bracket is gone — the digest is a re-rendering, so the coarse " \
        "path has widened onto rows that kept their system (#1016 N3/O3)"
    assert "input_value=" in schema["payload_digest"], \
        "the failing VALUE is gone from a DECLARED system's digest — that is the half the " \
        "pitfalls channel #823 opened exists to carry, and O3 says it stays byte for byte"
    assert "unresolvable: elastic.nosuchverb" in grant["payload_digest"], \
        "the grant placement stopped recording `decision.refusal` for a DECLARED system, so " \
        "the row no longer says which verb was unresolvable"


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


