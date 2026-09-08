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

#1016 — THE COLUMN THE EQUALITY ARMS COULD NOT SEE
---------------------------------------------------
#871's design comment claimed the table "does not carry the model's raw system string in any
column, bounded or not". The arms it shipped tested a WEAKER property: they flattened the rows
to `values = [v for row in rows for v in row.values()]` and asserted `phantom not in values` —
list MEMBERSHIP, so a column merely CONTAINING the string passed. `payload_digest` contains it
at both above-guard placements, and it is not only the system string that lands there: the
grant check records `decision.refusal`, which names the system AND the verb, and the schema
placement records `str(e)`, whose pydantic text names the model's own chosen argument KEY (the
error's `loc`) on every extra-argument failure and the system VALUE whenever it was not a
string.

O1 is the honest version of that claim, and it is stated over the HOST-AUTHORED columns only:
every key `append_query_row` writes except `verb`, `params` and `raw_command`, which hold the
call's own arguments verbatim by design and always will (#1016 N1 — scrubbing them would
destroy the row's audit value, and `system_fingerprint`'s docstring already concedes the
channel). On a row whose `system` was coarsened to `""` — a row where the host DECIDED to
withhold the name — no host-authored column may echo anything the model wrote. The oracle is a
SUBSTRING search over `_host_authored(row)`, and it REPLACES the equality arms rather than
sitting beside them: an arm that both checks cannot go red for the reason #1016 exists.

The verb is spelled `ghostverb` wherever the check runs, because `query` is the tool's OWN name
and pydantic prints it in the header of every message this schema produces (`1 validation error
for query`) — a digest carrying `query` says nothing about whether the model's verb reached it.
The scope is deliberately narrow and #1016 N3 says so out loud: a row that KEPT its system
records `str(e)` and `decision.refusal` byte-for-byte as before, model text and all, and
`test_a_row_that_kept_its_system_records_the_rejection_verbatim` is the arm that holds the fix
to that line.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.leads.pitfalls_curator import _build_pitfalls_handoffs  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.scripts.gather_tools.record_query import ABOVE_GUARD_QUERY_ID  # noqa: E402
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

#: The three columns `append_query_row` fills with the call's OWN arguments, verbatim and by
#: design. #1016 N1 keeps them that way: they are what makes the row an audit record of what was
#: attempted, and `record_query.system_fingerprint`'s docstring already concedes that they store
#: unbounded model text. O1 is therefore quantified over the COMPLEMENT — the host's own columns.
MODEL_AUTHORED_COLUMNS = frozenset({"verb", "params", "raw_command"})


def _bad_args(system: Any, params: dict = PARAMS, *,
              verb: str = "query", extra_key: str = "bogus_extra_arg") -> Turn:
    """A call the pydantic ARGUMENT SCHEMA turns back — `bogus_extra_arg` is P-a's executed
    `extra_argument` shape — so its row is written by `wrap_tool_validate` from the RAW
    pre-validation arguments. `system` is whatever the model put there; that is the point.

    `verb` and `extra_key` are KEYWORD-ONLY and default to the spelling every pre-#1016 arm
    drove, so none of them changes shape here. #1016 needs both spelled ghost-side at the arms
    that check the row's host-authored columns:

    * `verb="ghostverb"` — `query` is the TOOL's own name, and pydantic leads every message this
      schema produces with it (`1 validation error for query`). A digest containing `query`
      therefore says nothing about whether the MODEL's verb reached the row, so the default
      spelling makes the O1 oracle unable to fail for the reason it exists.
    * `extra_key="ghostkeyname"` — the model CHOOSES this name, and pydantic reports it as the
      error's `loc`. It lands in every extra-argument digest whether the system string was
      readable or not, which makes it the one arm that tells a renderer filtering `loc` down to
      the tool's declared parameter names apart from a plain `e.errors(include_input=False)`:
      dropping the input alone still leaves the key standing."""
    return Turn(tool_calls=[("query", {
        "system": system, "verb": verb, "params": params, extra_key: "x",
    })])


def _host_authored(row: dict) -> str:
    """Every column of `row` the HOST wrote, as one searchable string — #1016 O1's oracle.

    A SUBSTRING search, and that is the whole point: #871's arms flattened the row to a list of
    values and asked `phantom not in values`, which is column-value EQUALITY, and every leak
    #1016 closes is a model string EMBEDDED in a host-composed sentence.

    The haystack is the raw column VALUES joined on NUL, never a `json.dumps` of them, and the
    difference is the whole strength of the oracle. A serialized row ESCAPES precisely the
    characters a model is freest to spell: `json.dumps` renders a ghost holding `"` as `\\"`, a
    backslash as `\\\\`, a newline as `\\n` — and, left on its `ensure_ascii` default, a
    zero-width system as the six ASCII characters `\\u200b`. Each of those makes a search for
    the string the model actually sent find nothing while the column carries it verbatim, which
    is the same escaping blind spot #1016 N5 cites to rule OUT a substring scrub of `str(e)`:
    an oracle inheriting it is WEAKER than the column-value equality arms it replaced, not
    stronger. Joined raw, every codepoint the model wrote is searchable as written, and
    `test_the_o1_oracle_sees_what_a_serialised_row_would_hide` is what holds it there.

    NUL is the separator because no column can hold one, so no needle can straddle two columns
    and no false positive can be manufactured by the join itself."""
    return "\x00".join(
        str(v) for k, v in row.items() if k not in MODEL_AUTHORED_COLUMNS
    )


def _model_authored(row: dict) -> str:
    """The complement — the three columns O1 exempts (#1016 N1), joined the same way and for
    the same reason.

    Every O1 negative in this file is paired with a POSITIVE over this string on the SAME row:
    the model's verb is present here and absent there, one run, one writer, one call. Without
    it `ghost not in _host_authored(row)` is satisfied by a row that never saw the ghost at all
    — which is precisely how #871's equality arms stayed green for two issues."""
    return "\x00".join(
        str(v) for k, v in row.items() if k in MODEL_AUTHORED_COLUMNS
    )


def _detail(row: dict) -> str:
    """The DETAIL half of a failure row's digest — `_record` composes
    `f"exit={code}; {redact_model_visible(detail).strip()[:160]}"`.

    Every O1 arm asserts this is non-empty beside its negatives, because O1 is a claim about
    what the host may put in that tail and NOT a licence to empty it: a writer that recorded no
    reason at all would satisfy every substring negative in this file, keep the whole suite
    green, and destroy the only column that tells an operator why the call was turned back."""
    return row["payload_digest"].split(";", 1)[-1].strip()


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
    NEGATIVE use is safe on its own only while the lead under it makes fewer than ten
    rejections, and an arm that drives more must assert the run-on some other way.

    The idiom is `test_repeat_breaker_807.INCOMPLETE_IDIOM` WHOLE, not a prefix of it: G19
    names that sentence as the only vocabulary any prompt teaches main, and a truncated copy
    would keep every arm below green if the terminator lost its second half."""
    return INCOMPLETE_IDIOM in _summary(r)


def _trip_row_written(r: _Res) -> bool:
    """Whether the COMPANION GUARD is what ended the lead, read off the table rather than the
    summary: `rejection_trip_detail` leads the last rejection row's digest, and no other
    terminator writes it."""
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
    fix for #855. Three identical rejections still end the lead.

    #1016 O4 rides on the same run, because the trip row is the one row on this path where the
    host composes a digest of its OWN and then appends the model's: `rejection_trip_detail`
    leads with "turned back at seq …" and carries `str(e)` as a tail. Both halves are demanded
    here and they pull in opposite directions — the phrase must still LEAD (it survives
    `_record`'s 160-character truncation only because it does, and `_trip_row_written` plus the
    assertion below are the two helpers that detect a trip by it), and the tail must obey O1
    like every other coarsened row's. A fix that scrubbed the whole detail satisfies O1 and
    breaks every trip detector in this file; a fix that special-cased the trip row and left the
    tail raw satisfies the detectors and leaks. The ghost key is spelled `ghostkeyname` because
    that tail is pydantic's text and the argument NAME is what it names."""
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

    What the digest may NOT do is undo #855. Since #1016 that is asserted as a SUBSTRING sweep
    over every HOST-AUTHORED column rather than as the equality over every column it used to be:
    the digest would pass `is_system_name` if it ever landed in `system`, so "the string is not
    on the table" has to be quantified over the whole row — and #871 shipped it as
    `phantom not in [v for row in rows for v in row.values()]`, which is list membership and
    therefore column-value EQUALITY, so `payload_digest` was free to embed all three ghosts
    inside a sentence and did. The equality arm is REPLACED, not kept beside this one: an arm
    that asserts both cannot go red for the reason #1016 exists.

    The verb is `ghostverb` on the three rejections so the sweep can look for it. `query` is the
    tool's own name and pydantic prints it in every message this schema produces, so under the
    old spelling the verb half of the negative was unfailable."""
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
    assert _replay_rejections(same.rows) == [(LEAD, 2)], \
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


# #1016 — the host's own columns. #871 claimed no column of a coarsened row carries the model's
# string and shipped an EQUALITY arm; `payload_digest` embeds it. The two arms below are the
# whole of the fix's discrimination: the five coarsened shapes, and the row that was NOT
# coarsened and must therefore be untouched.


def test_the_o1_oracle_sees_what_a_serialised_row_would_hide():
    """`_host_authored` itself, because every O1 negative in this file is only as strong as it
    is — and the shapes that defeat a SERIALISING oracle are ones no fixture here spells.

    A row rendered through `json.dumps` escapes exactly the characters a model is freest to put
    in a `system` value or an invented argument name: `"` becomes `\\"`, a backslash doubles, a
    newline becomes `\\n`, and on `ensure_ascii`'s default a zero-width codepoint becomes six
    ASCII ones. A substring search for what the model actually sent then finds nothing while
    the column carries it verbatim — the same escaping blind spot #1016 N5 cites to rule OUT a
    substring scrub of `str(e)`, and inheriting it would make the replacement oracle WEAKER
    than the column-value equality arms it retired rather than stronger.

    Hand-built rows, deliberately: driving these ghosts through a live lead would put them
    through `system_fingerprint`, `shlex.join` and the summary arms too, and this is a claim
    about the ORACLE, not about the writers. The last fixture is the plain ASCII ghost every
    other arm in this file uses, so a helper that stopped searching altogether fails here."""
    for ghost in ('gh"ost', "C:\\ghost", "ghost\nname", ZERO_WIDTH, "ghostplain"):
        row = dict.fromkeys(MODEL_AUTHORED_COLUMNS, "-") | {
            "system": "", "system_key": "",
            "payload_digest": f"exit=64; unresolvable: {ghost}.someverb",
        }
        assert ghost in _host_authored(row), \
            f"the O1 oracle cannot see {ghost!r} in a host-authored column — every negative " \
            "quantified over it is unfailable for a ghost holding that character"
        assert ghost not in _model_authored(row), \
            "the complement is answering about the wrong columns"


def test_no_host_authored_column_of_a_coarsened_row_carries_model_text(tmp_path):
    """#1016 O1 — on a row whose `system` the host withheld, no column the HOST wrote echoes
    anything the model wrote. Five coarsened shapes and one control, all in ONE lead, because
    the property is about the writers and not about any one call.

    THE FIVE SHAPES, and why it takes all five. They differ in which of the two above-guard
    placements records them and in what pydantic (or the grant check) then says, and each one
    kills a different wrong implementation:

    1. GRANT / readable ghost — `decision.refusal` names the system AND the verb
       (`unresolvable: ghosttwo.ghostverb (unknown, …)`). This is the coarsest leak and the one
       #871's own probe would have found; it dies to any fix at all.
    2. GRANT / nothing readable — a zero-width `system` is a `str`, so `as_str` does not coarsen
       it and it reaches the grant check intact; `system_key` stays `""` because N5 folds it,
       and the refusal carries it anyway. It is the shape that leaks INVISIBLY, and the one an
       oracle left on `json.dumps`'s `ensure_ascii` default cannot see (`_host_authored`).
    3. SCHEMA / readable ghost on an extra argument — pydantic names the offending KEY and its
       value, never the `system` value, so this row leaks `bogus_extra_arg` and no system name
       at all. It is the shape #871's arms drove, and the reason they concluded the schema
       placement was clean.
    4. SCHEMA / the model choosing the argument NAME — the ONLY arm that separates a renderer
       filtering pydantic's `loc` down to the tool's own declared parameter names from a plain
       `e.errors(include_input=False)`. Dropping the input still leaves `loc` standing, and
       `loc` here is `("ghostkeyname",)`: a string the model picked, in a host column, on a row
       the host coarsened. An implementation that only stopped printing input values passes
       every other arm in this test and fails this one.
    5. SCHEMA / a non-string `system` — the ONLY arm that separates a predicate asked of the
       PRE-COERCION argument from one asked of `raw_system`, which `wrap_tool_validate` already
       binds to `as_str(raw.get("system"))`. Coerced, a list reads as `""`, which equals the
       value the row records, which reads as NOT coarsened — so the leak stays wide open on the
       one shape that puts the model's chosen text in pydantic's `input_value=`. `system_key`
       stays `""` here too (N5): the row's own identity gives no hint that anything was hidden.

    THE CONTROL is the sixth turn and it is exact rather than analogous: the same `_bad_args`
    shape and the same `ghostkeyname` argument, against `elastic`, which the registry DECLARES.
    Nothing was coarsened, so #1016 N3 leaves its digest exactly as it is — the model's argument
    name included. Every negative below is therefore paired, on the same column, in the same
    run, by the same writer, under the complementary condition: if the control row is clean too
    then the writer stopped RECORDING rather than started withholding, and none of this test's
    negatives mean anything.

    The remaining vacuity guards are inline: each row is bound to the turn that wrote it by its
    own `params`, the model's verb must still be in the columns O1 exempts, and the detail half
    of every digest must be non-empty."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1016-shapes", verbs=elastic_ok(rec), turns=[
        q("ghosttwo", "ghostverb", {"native_query": "FROM one"}),
        q(ZERO_WIDTH, "ghostverb", {"native_query": "FROM two"}),
        _bad_args("ghostone", {"native_query": "FROM three"}, verb="ghostverb"),
        _bad_args("ghostone", {"native_query": "FROM four"}, verb="ghostverb",
                  extra_key="ghostkeyname"),
        _bad_args([PHANTOM], {"native_query": "FROM five"}, verb="ghostverb"),
        _bad_args([LONG_GHOST_VALUE], {"native_query": "FROM six"}, verb="ghostverb"),
        _bad_args("elastic", {"native_query": "FROM seven"}, verb="ghostverb",
                  extra_key="elastickeyname"),
        DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == 7, \
        "the seven shapes did not all leave their rows — every negative below is vacuous"
    # Bind each row to the turn that wrote it, so a per-row negative names a KNOWN call. Read
    # off `params`, a column O1 exempts, which is why it is still readable here at all.
    assert [row["params"]["native_query"] for row in rows] == [
        "FROM one", "FROM two", "FROM three", "FROM four", "FROM five", "FROM six",
        "FROM seven",
    ], "the rows are not the seven calls in order, so the per-shape claims below are misaddressed"
    assert not _dead_end(r), \
        "the lead ended early: either the shapes tripped the companion guard (so one of " \
        "these rows is a trip row and they are not distinct calls) or this lead now makes " \
        "more rejections than `DEFAULT_TOOL_RETRIES` allows — `_trip_row_written` tells the " \
        "two apart, and a sixth coarsened shape is what would cross the second"

    coarsened, control = rows[:6], rows[6]
    assert {row["system"] for row in coarsened} == {""}, \
        "a shape was not coarsened at all, so O1 does not even apply to it"
    ghost_key = record_query.system_fingerprint("ghostone", "")
    assert [row["system_key"] for row in coarsened] == [
        record_query.system_fingerprint("ghosttwo", ""), "", ghost_key, ghost_key, "", "",
    ], "N5's fold or the two placements' fingerprints changed under #1016 — the identity is " \
       "#871's and this issue does not touch it"

    assert control["system"] == "elastic", \
        "the control lost its declared system, so it is not the complementary condition"
    assert control["system_key"] == "", \
        "the control was coarsened after all, so it is not the complementary condition"
    assert "elastickeyname" in _host_authored(control), \
        "a row that KEPT its system stopped recording the model's own argument name (#1016 " \
        "N3) — so the negatives below are satisfied by a writer that records nothing"

    # #1016 O2 at the SCHEMA placement — "at the schema placement it still sees pydantic's full
    # text". The grant half of O2 is pinned two tests up; this half had nothing, and the gap is
    # not cosmetic: the whole of M2 is that the ROW stops carrying pydantic's text while the
    # MODEL keeps reading it, and an implementation that re-raised the host's coarse rendering
    # to the model instead of the original error greens every other arm in this file. What the
    # model loses then is exactly what O2 protects — a subagent that cannot see WHICH argument
    # was refused cannot drop it, and retries until the lead runs out.
    #
    # This is also the ghost-key negative's missing positive control: without it,
    # "`ghostkeyname` is not in a host-authored column" is satisfied by a run in which the
    # string never appeared anywhere at all.
    # `ghostkeyname` is spelled on the COARSENED call and nowhere else in this lead — the
    # control one turn later uses `elastickeyname` for exactly this reason. Sharing the key
    # would make this assertion true of the control's own retry text and blind to the
    # coarsened call it is about, which is the shape of vacuity this whole file guards against.
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

    # WHAT the host says, not merely THAT it said something. A blacklist of literals plus a
    # truthiness check is satisfiable by any detail the model's text cannot be read out of —
    # including a single constant for every shape, and including an ENCODING of the very text
    # the blacklist is hunting (base64 of pydantic's message contains none of the seven tokens
    # and is a complete copy of all of them). Both leave `payload_digest` useless to the
    # operator it exists for, which is the column's whole job (`record_query.payload_digest`:
    # on a failure "it is the discriminating half"). So each placement owes a positive:
    #
    # * the GRANT placement names the CLASS of failure it withheld the specifics of — #1016 N8
    #   picks "an undeclared system" and `_undeclared_target` already speaks that vocabulary to
    #   main. Asserted on the word, not the sentence, so the wording stays the fix's to choose.
    # * the SCHEMA placement carries pydantic's own message TEMPLATE for the error type. Those
    #   templates are host material — C21 pins that they quote no input — and they are the only
    #   part of pydantic's text that survives #1016 at all. A row that names the error type is
    #   one an operator can act on without ever seeing what the model wrote.
    for row in coarsened[:2]:
        assert "undeclared" in _detail(row), \
            "a coarsened grant-path row no longer says what KIND of failure it withheld the " \
            "specifics of, so its digest tells an operator nothing"
    for row, template in zip(coarsened[2:], (
        "Extra inputs are not permitted",   # FROM three — the model's extra argument
        "Extra inputs are not permitted",   # FROM four  — same, under a name the model chose
        "Input should be a valid string",   # FROM five  — `system` was a list
        "Input should be a valid string",   # FROM six   — a list pydantic cannot print whole
    ), strict=True):
        assert template in _detail(row), \
            f"a coarsened schema-path row dropped pydantic's own message ({template!r}), so " \
            "the digest no longer names the error type — and a detail that cannot be read " \
            "back is indistinguishable from one that encodes the model's text instead"

    # ACCUMULATED rather than asserted per row, and that is the point of driving five shapes in
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
    what the model SENT?" answers wrongly: a literal `system=""`.

    `_system_of_record("")` is `""` because no registry declares it, and `system_fingerprint`
    mints no digest for it (`names_something_readable("")` is false). So the ROW is `system=""`,
    `system_key=""` — byte-identical in both identity columns to shapes 2, 5 and 6 above and
    indistinguishable from them to every reader of the table — while `given == recorded` reads
    "nothing was withheld" and hands the detail back to `str(e)` at the schema placement and
    `decision.refusal` at the grant placement. What those carry is not the system string (there
    was none to withhold) but the model's own chosen argument KEY and its VERB: the two shapes
    O1 exists for, in a host-authored column of a row that says the host withheld a name.

    One character of model output is the whole of the bypass, which is why this is driven
    rather than argued — both placements, in one lead, under the sweep the five shapes get."""
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

    leaks = [
        (row["params"]["native_query"], text)
        for row in rows
        for text in ("ghostverb", "ghostkeyname")
        if text in _host_authored(row)
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
    """#1016 O3 — the limit the fix may not overshoot, and the arm no existing test provides.

    O1 is scoped to rows the host COARSENED, for a reason stated as N3: a rejection against a
    system the registry declares is the pitfalls channel's whole input, and its digest is the
    only place an operator or the curator ever reads what actually went wrong. Those digests
    carry model text today — pydantic's `input_value=`, the model's own extra argument name,
    the verb inside `unresolvable: elastic.nosuchverb` — and they must keep carrying it byte for
    byte. The obvious wrong fix is the tempting one: render the coarse detail everywhere and
    the O1 arms all pass, quietly emptying the channel #823 opened.

    Both above-guard placements are driven, because the fix touches both and the predicate that
    decides "was this coarsened?" is spelled once at each:

    * the SCHEMA placement, whose detail is `str(e)` — pydantic's own text, wording, key names
      and input values intact;
    * the GRANT placement, whose detail is `decision.refusal` — a declared system with an
      unknown verb, where the verb the model spelled is the one thing that makes the message
      actionable.

    `system` and `system_key` are asserted on both rows for the same reason the control in the
    O1 arm asserts them: "not coarsened" is the CONDITION this test is quantified over, and a
    row that was coarsened after all would make these positives claims about the wrong thing."""
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
