"""#1015 end to end — a gather lead that SPENDS its rejections is stopped by the HOST.

THE CODE DOES NOT EXIST YET. The import block below names the surface the design doc (issue
#1015, "Discussion outcome — intent + design") specifies; this suite is RED by construction
until it is built. The predicate-and-strings half is
`tests/test_1015_rejection_budget_predicate.py`.

THE DEFECT, reproduced by execution on main (the issue's C3/C4)
--------------------------------------------------------------
The companion guard (#826 item 4, #871) bounds a repeat loop above the guard by IDENTITY.
Nothing bounds a lead whose rejections all DIFFER, and there is an unbounded supply of ways to
differ: fresh ghost names, whitespace and case drift (each spelling mints its own
`system_fingerprint`), and assigned-but-blank codepoints — U+3164 HANGUL FILLER, U+2800 BRAILLE
PATTERN BLANK, U+115F/U+1160, a lone variation selector — which `names_something_readable`
answers True for ON PURPOSE ("renders blank" is a property of the font, not of the string; its
docstring names this issue as the containment).

Driven on this base, 30 distinct ghosts end at `UnexpectedModelBehavior` after 11 rejections
and main is handed pydantic-ai's own text including its documentation URL. Worse, the
framework's counter RESETS: `ToolManager.for_run_step` rebuilds `retries` from `failed_tools`
alone, so `query`'s count is dropped on every step where `query` did not FAIL — a successful
call is sufficient but not necessary, and a bash reduce or a `list_verbs` turn does it too.
One good call every few turns un-bounds the loop entirely — 36 rejections against 4 real
queries, ending on the request limit.

THE ORACLE, and why nothing shorter will do
-------------------------------------------
`INCOMPLETE_IDIOM` alone certifies NOTHING: `_run_gather` writes it for all four of its
terminators (`test_855::_dead_end` says so in its own docstring). Every POSITIVE arm here
therefore reads all three of

  1. the gather session's `truncated_by` — `dead-end`, not `retry-exhausted`, not
     `request-limit` — read out of the real session store the run wrote;
  2. the last above-guard row's `payload_digest`, LEADING with the budget phrase and never
     with "turned back at seq" (O2);
  3. the summary main receives, carrying the budget reason and the budget escape.

Everything between the two replay models is production code: the dispatch, the query tool, both
above-guard placements, both guards, the queries table and the session store. Fakes enter only
through the harness's declared injection seams (`verbs=`, `box=`); there is no
`monkeypatch.setattr` in this file.

OBLIGATIONS (verbatim ids from the design doc)
----------------------------------------------
O1 bounded host-decided stop regardless of identity or interleaved success · O2 the repeat
guard's promise stands · O3 replay parity including the stop's KIND · O4 no model-authored byte
in the summary · O5 leads below the budget untouched.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import session_store  # noqa: E402
from defender.runtime.agent_role import GATHER_AGENT_ID_PREFIX  # noqa: E402
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS  # noqa: E402
from defender.runtime.driver import DEFAULT_TOOL_RETRIES  # noqa: E402
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
# `wrap_fresh`'s frame grammar and the real store's read channel, both spent from their one
# home rather than re-spelled here — `_frames680` carries no optional dependency of its own.
from defender.tests._frames680 import FRAME_RE  # noqa: E402
from defender.tests._session_store_705 import sql  # noqa: E402
from defender.tests.e2e._replay_harness import Turn, VerbRecorder  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    PARAMS,
    _above_guard,
    _bad_args,
    _dead_end,
    _summary,
)
# The COMPANION guard's replay oracle and main's one idiom, imported rather than re-written:
# O3 is the claim that the live verdict and a replay over the recorded table are ONE predicate,
# and a second copy of the oracle here could only ever agree with itself.
from defender.tests.e2e.test_repeat_breaker_807 import (  # noqa: E402
    INCOMPLETE_IDIOM,
    _replay_rejections,
)

# THE SURFACE UNDER TEST — none of it exists on this base (RED by construction)
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    REJECTION_BUDGET,
    REJECTION_BUDGET_ESCAPE,
    RejectionBudgetTrip,
    rejection_budget_dead_end_reason,
)

pytestmark = pytest.mark.e2e

B = REJECTION_BUDGET

#: The whitespace and case drift of ONE name. Every spelling is `names_something_readable` and
#: hashes to its own `system_key`, so the repeat guard sees B different calls — which is the
#: input class the issue calls the sharpest.
DRIFT = ("ghostone", " ghostone", "ghostone ", "GHOSTONE", "GhostOne", "ghost one")

#: Assigned characters in visible categories that render blank in most fonts. C6 measured
#: `names_something_readable` True for every one of them, so each mints its own identity and
#: the family is unbounded. This is the class option 2 (a coarser fold key) cannot close.
FONT_BLANK = ("ㅤ", "⠀", "ᅟ", "ᅠ", "️", "ㅤ⠀")

#: A ghost family, a verb and a params fragment that could not be mistaken for prose if any of
#: them crossed into main's context. Used where the claim is a NEGATIVE about the summary, so
#: none of the three may be a word the host's own sentences could plausibly contain.
LOUD_SYSTEM = "Zq7-Wintermute-Phantom"
LOUD_VERB = "Zq7-Sunspot-Verb"
LOUD_PARAM = "Zq7-CANARY-PARAM"


def _loud(i: int) -> Turn:
    """`_bad_args` with every model-authored field replaced by a distinctive string: a ghost
    system, a ghost verb and a ghost params value, under the extra argument the pydantic schema
    refuses (so the row comes from `wrap_tool_validate`, from the RAW arguments).

    SPENT from `_bad_args` rather than re-spelled. `bogus_extra_arg` is the one thing routing
    these turns to the schema placement instead of the grant check, so a second copy of the Turn
    shape is a copy whose routing stays put when the schema moves — and because the sibling
    grant-placement arm asserts the same negatives, the arm below would stay green while no
    longer reaching the placement it exists for. The only thing `_bad_args` lacked is a verb,
    which a negative about main's context cannot discriminate on while it is the generic word
    `query`; that is a keyword on the owner, not a reason for a second builder."""
    return _bad_args(
        f"{LOUD_SYSTEM}-{i}",
        {"native_query": f"FROM {LOUD_PARAM}-{i}"},
        verb=f"{LOUD_VERB}-{i}",
    )


def _terminator(r: _Res) -> str | None:
    """How this lead's gather session ENDED, read out of the real session store the run wrote
    — the one place the four terminators are distinguishable at all.

    `_run_gather` sets exactly one of `session_store.TRUNCATED_BY_*` per arm and stamps it in a
    `finally`; the summary main receives ends with the same idiom whichever arm ran, so the
    summary cannot answer this question and the queries table does not carry it.

    The read goes through `_session_store_705.sql` — "the observation channel that does not go
    through the reader under test" — the same helper `test_808_correlation_lead` and
    `test_826_gather_deferred` ask this column with, so the four readers move together."""
    store = session_store.open_store_for_read(session_store.resolve_store_path(r.run_dir))
    try:
        rows = sql(
            store, "SELECT truncated_by FROM session WHERE agent_id = ?",
            (f"{GATHER_AGENT_ID_PREFIX}{LEAD}",),
        )
    finally:
        store.close()
    assert rows, "this lead opened no gather session — the run never dispatched"
    return rows[0][0]


def _budget_phrase(occurrence: int = B) -> str:
    """The leading phrase `rejection_detail` gives a budget trip's row — spent from the
    PRODUCER, not re-spelled. With no rejection tail that call returns exactly the phrase, so a
    rewording moves the row and this oracle together; a copy here would drift from the shipped
    sentence and keep every arm below green against a table that no longer says it. The wording
    itself is pinned once, in `test_1015_rejection_budget_predicate`, where it is the subject
    under test."""
    return rq.rejection_detail(RejectionBudgetTrip(occurrence=occurrence, budget=B))


def _summary_body(r: _Res) -> str:
    """The summary main receives with its untrusted frame removed. `wrap_fresh` is
    `f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"` and preserves the body verbatim.

    The grammar is SPENT from `_frames680.FRAME_RE`, the repo's one spelling of #875's frame,
    rather than re-compiled here: nine suites already read frames through it, and a local copy
    would keep this file green against a frame shape the shared regex had moved off (the tag
    charset, the salt run, where the newlines sit). `_toon872.framed_content` is the copy this
    file must NOT reach for — that module `importorskip`s the optional `toons` wheel — but
    `_frames680` carries no such dependency.

    The two tag lines are tied by the SALT rather than checked independently: a body that
    happened to open or close with a tag-shaped line would otherwise be mistaken for the frame,
    and this helper's whole job is to make the O4 claim an equality over what is left. The tag
    is asserted too, because the shared regex admits any tag and only `untrusted` is the
    boundary O4 is about.

    Recovered so the assertion below can be an EQUALITY. A substring check on the reason is
    satisfied by a summary that ALSO carries something else — which is exactly the shape O4
    forbids, and the only thing standing between a model-authored fragment and main's context
    is that nothing but the host's own two sentences is in this file."""
    summary = _summary(r)
    m = FRAME_RE.fullmatch(summary)
    assert m is not None, \
        f"the summary is not one whole frame: {summary[:120]!r}"
    assert m.group("tag") == "untrusted", \
        f"the summary's one frame is not the untrusted one: {m.group('tag')!r}"
    return m.group("body")


def _assert_budget_stop(r: _Res, *, occurrence: int = B) -> None:
    """THE THREE-PART ORACLE. Every one of the three is load-bearing:

    - the TERMINATOR, because `INCOMPLETE_IDIOM` is written by all four of `_run_gather`'s arms
      and a lead that merely exhausted the framework's tool retries writes it too;
    - the DIGEST, because it is the only record on the queries table of WHICH guard stopped the
      lead, and O2 demands a budget stop never claim the call repeated one already turned back;
    - the SUMMARY, because that is main's context, and it is what O1 says must carry the host's
      own sentence rather than pydantic-ai's.
    """
    assert _terminator(r) == session_store.TRUNCATED_BY_DEAD_END, \
        f"the lead ended as {_terminator(r)!r}, not by the host's own decision"

    rows = _above_guard(r)
    assert rows, "no above-guard rejection was recorded, so the assertions below are vacuous"
    digest = rows[-1]["payload_digest"]
    assert digest.startswith(f"exit=64; {_budget_phrase(occurrence)}"), \
        f"the trip row does not lead with the budget phrase: {digest!r}"
    assert "turned back at seq" not in digest, \
        "a budget stop's row says the call repeated one already turned back — O2"

    reason = rejection_budget_dead_end_reason(
        RejectionBudgetTrip(occurrence=occurrence, budget=B))
    summary = _summary(r)
    assert "the lead's whole allowance" in summary, \
        "main was not told the lead spent its allowance — the reason below may be empty"
    assert REJECTION_BUDGET_ESCAPE in summary, "main was handed no escape for a budget stop"
    assert INCOMPLETE_IDIOM in summary, "the fixed idiom stopped following the escape"
    assert rq.REPEAT_ESCAPE not in summary, \
        "a budget stop handed main the repeat guard's escape"

    # EQUALITY, not `reason in summary`. S1 discharges O4 with TWO facts, and the second is
    # that `_run_gather`'s dead-end arm composes this file from `reason` and `escape` ALONE,
    # discarding the lead's own output. A substring check tests only the first: it stays green
    # while a placement appends (or prepends) a model-authored fragment of its own around the
    # dispatcher's sentences — a truncated ghost name, a params key, a hash prefix — none of
    # which is a substring of any canary a negative could name. Stated whole, there is nowhere
    # in this file for a byte the model authored to be.
    assert _summary_body(r) == (
        f"gather for {LEAD} hit a dead end: {reason} {REJECTION_BUDGET_ESCAPE} "
        f"{INCOMPLETE_IDIOM}"
    ), "main's context carries something besides the host's own two sentences — O4"


# ── O1: the bound holds however the calls differ ───────────────────────────────────────────


def test_a_budget_of_distinct_ghosts_ends_the_lead_at_the_schema_placement(tmp_path):
    """O1 through `wrap_tool_validate` — the argument schema turns the call back, so the row is
    written from the RAW pre-validation arguments and the guard is asked there.

    B rejections naming B DIFFERENT undeclared systems are B different calls: the repeat guard
    is silent by construction (asserted on the rows — B distinct `system_key`s), and before this
    issue nothing else counted them. The corrected `elastic` call must not run: the lead is over
    before it is issued, which is what makes this a STOP rather than a message."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-schema", verbs=elastic_ok(rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B + 3)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the lead wrote {len(rows)} above-guard rejections against a budget of {B}"
    assert len({row["system_key"] for row in rows}) == B, \
        "the ghosts did not key distinctly, so the REPEAT guard could have taken this stop"
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end and executed a later call"


def test_a_budget_of_distinct_ghosts_ends_the_lead_at_the_grant_placement(tmp_path):
    """O1 through the SECOND above-guard placement. `_grant_check`'s unresolvable branch reads a
    different argument surface (validated arguments, not raw ones) and records its own row
    before raising; a budget wired at one placement and not the other fixes half the surface
    and leaves the other half exactly as it was — the shape #871 had to repair.

    `q(...)` is schema-valid by construction, which is what routes it past
    `wrap_tool_validate`; `_above_guard` cannot tell the two writers apart, so the turn shape is
    the discriminator."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-grant", verbs=elastic_ok(rec), turns=[
        *[q(f"ghost{i}", "query", PARAMS) for i in range(B + 3)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the grant placement wrote {len(rows)} rejections against a budget of {B}"
    assert len({row["system_key"] for row in rows}) == B
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end"


def test_whitespace_and_case_drift_of_one_name_is_still_bounded(tmp_path):
    """O1 over the input class the issue calls the sharpest. `system_fingerprint` hashes the
    model's string EXACTLY as it was written — no `.strip()`, no `.lower()`, deliberately
    (#871's `test_one_ghost_keys_the_same_through_both_above_guard_writers` pins that the two
    placements agree, not that the hash normalises) — so six spellings of one name are six
    identities and the repeat guard cannot see a repeat.

    The distinct keys are asserted, not assumed: if the fingerprint DID normalise, the repeat
    guard would take this stop at its own threshold and the digest would say "turned back at
    seq", which is a different claim than the one this arm makes."""
    rec = VerbRecorder()
    assert len(DRIFT) == B, "the drift family no longer spans exactly one budget"
    r = _run(tmp_path, run_id="d1015-drift", verbs=elastic_ok(rec), turns=[
        *[_bad_args(name) for name in DRIFT], q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B
    assert {row["system_key"] for row in rows} == {
        rq.system_fingerprint(name, "") for name in DRIFT}, \
        "the drifted spellings did not each mint their own identity"
    assert len({row["system_key"] for row in rows}) == B, \
        "two spellings folded together, so the REPEAT guard could have taken this stop"
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end"


def test_names_that_print_as_nothing_are_bounded_by_the_budget_and_by_nothing_else(tmp_path):
    """O1 over the family option 2 cannot close. Each of these is an ASSIGNED character in a
    visible category that renders blank in most fonts, so `names_something_readable` answers
    True (C6) and each mints its own `system_key` — an unbounded supply of names that print as
    nothing and each get their own repeat group. `names_something_readable`'s docstring says
    this is deliberate and points at this issue for the containment.

    The predicate is asserted here at the seam, because it is the REASON this arm is not
    already covered by #871's N5 fold: a fold that caught these would take the stop with the
    repeat guard's sentence instead."""
    rec = VerbRecorder()
    assert len(FONT_BLANK) == B, "the font-blank family no longer spans exactly one budget"
    for name in FONT_BLANK:
        assert rq.names_something_readable(name), \
            f"{name!r} folded into the N5 group — this arm no longer measures the budget"

    r = _run(tmp_path, run_id="d1015-blank", verbs=elastic_ok(rec), turns=[
        *[_bad_args(name) for name in FONT_BLANK], q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B
    assert len({row["system_key"] for row in rows}) == B, \
        "the blank names folded together, so the REPEAT guard could have taken this stop"
    assert {row["system"] for row in rows} == {""}, "a model-named system reached the table"
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end"


def test_a_successful_query_between_rejections_does_not_refill_the_budget(tmp_path):
    """O1's "regardless of successful calls in between" — the C3/C4 heart of this issue, and
    the explicit non-obligation "no reset on success".

    pydantic-ai drops a tool's retry count when that tool SUCCEEDED in the step
    (`tool_manager.py:117-127`), which is exactly why the framework ceiling does not bound this
    loop: one good call every few turns buys ten more rejections, indefinitely, until the
    lead's whole request budget is gone. The host's budget is over the lead's LIFETIME rows, so
    a lead that recovered and then thrashes again still ends at B lifetime above-guard
    rejections.

    Two successful `elastic` calls DO reach the backend before the stop — asserted, so this is
    not a lead that simply never recovered — and the third never issues."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-interleaved", verbs=elastic_ok(rec), turns=[
        _bad_args("g1"), _bad_args("g2"), q("elastic", "query", {"native_query": "FROM a"}),
        _bad_args("g3"), _bad_args("g4"), q("elastic", "query", {"native_query": "FROM b"}),
        _bad_args("g5"), _bad_args("g6"), q("elastic", "query", {"native_query": "FROM c"}),
        _bad_args("g7"), DONE,
    ])

    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 0, 64, 64, 0, 64, 64], \
        "the lead did not run the interleaved shape through to its sixth rejection"
    # The PREMISE, stated as the weakest thing that establishes it: some successful call
    # reached the backend, so the framework's per-tool counter did drop at least once. The
    # exact count is the run-on CONTROL below, and the two must not be the same expression —
    # `rec.calls` is frozen once `_run` returns, so a closing assertion identical to this one
    # can never fail on its own and the arm would carry no run-on evidence at all.
    assert rec.calls, \
        "no successful call reached the backend, so no reset was ever available"
    assert len(_above_guard(r)) == B
    _assert_budget_stop(r)
    assert len(rec.calls) == 2, "the lead ran on past its dead end and executed a third query"


def test_a_lead_whose_only_refusals_are_above_the_guard_never_reaches_the_frameworks_arm(
        tmp_path):
    """C11, EXECUTED — the claim the design deferred to this suite. On this base a lead driving
    a fresh ghost per turn ends at `UnexpectedModelBehavior` after eleven rejections, and main's
    context receives, verbatim: "Tool 'query' exceeded max retries count of 10. Consider raising
    the retry limit, or see the docs … https://ai.pydantic.dev/…". That is framework internals
    crossing into main on a refusal path.

    `REJECTION_BUDGET < DEFAULT_TOOL_RETRIES` is what forecloses it: rejections >= failed steps
    for a lead whose only `query` failures are above-guard rows, so the host's bound is reached
    first. A MIXED lead (below-guard parameter refusals among the ghosts) is explicitly NOT
    covered by this claim and is not asserted here.

    The summary carrying the host's own reason is the positive control on the same address: the
    two negatives below are about what main did NOT receive, and an empty summary would satisfy
    them for the wrong reason."""
    r = _run(tmp_path, run_id="d1015-c11", turns=[
        *[_bad_args(f"ghost{i}") for i in range(DEFAULT_TOOL_RETRIES + 4)], DONE,
    ])

    assert len(_above_guard(r)) == B < DEFAULT_TOOL_RETRIES, \
        "the lead wrote enough failed steps to reach the framework's own ceiling"
    _assert_budget_stop(r)
    assert _terminator(r) != session_store.TRUNCATED_BY_RETRY_EXHAUSTED
    assert _terminator(r) != session_store.TRUNCATED_BY_REQUEST_LIMIT
    summary = _summary(r)
    assert "exceeded max retries" not in summary, \
        "pydantic-ai's own text crossed into main's context on a refusal path"
    assert "ai.pydantic.dev" not in summary, \
        "a framework documentation URL crossed into main's context on a refusal path"


# ── O5: below the budget, nothing changed ──────────────────────────────────────────────────


def test_a_lead_one_rejection_short_of_the_budget_is_untouched(tmp_path):
    """O5 — the liveness half. B-1 above-guard rejections leave the lead exactly as it is
    today: every row written, no terminator stamped, no dead end in the summary, and the
    corrected call still reaches the backend.

    Its positive control is the SAME shape one turn longer, asserted at the SAME four addresses
    under the complementary condition — so "the run was untouched" cannot be satisfied by a
    guard that never fires at all, and "the guard fires" cannot be satisfied by one that ends
    every lead."""
    below_rec = VerbRecorder()
    below = _run(tmp_path / "below", run_id="d1015-below", verbs=elastic_ok(below_rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B - 1)],
        q("elastic", "query", PARAMS), DONE,
    ])
    at_rec = VerbRecorder()
    at = _run(tmp_path / "at", run_id="d1015-at", verbs=elastic_ok(at_rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B)],
        q("elastic", "query", PARAMS), DONE,
    ])

    assert len(_above_guard(below)) == B - 1, "the rejections below the budget lost their rows"
    assert _terminator(below) is None, \
        f"a lead below the budget was stamped {_terminator(below)!r}"
    assert not _dead_end(below), "a lead below the budget was told it hit a dead end"
    assert len(below_rec.calls) == 1, "the corrected call never reached the backend"

    assert len(_above_guard(at)) == B
    assert _terminator(at) == session_store.TRUNCATED_BY_DEAD_END, \
        "one more rejection changed nothing, so the negatives above say nothing"
    assert _dead_end(at)
    assert at_rec.calls == [], "the lead at its budget still executed the corrected call"


# ── O2: the repeat guard's promise, and its precedence ─────────────────────────────────────


def test_the_same_ghost_three_times_is_still_the_repeat_guards_stop(tmp_path):
    """O2 — #871's owner's promise, at the lead. The repeat guard is asked FIRST because its
    sentence names the specific repeated request; a call that is both the 3rd repeat and the
    B-th rejection gets the more specific one. Here the repeat comes first in time as well, and
    the stop must be the repeat guard's ENTIRELY: its row detail, its reason, its escape.

    Both runs are driven in one arm so the two sentences are asserted against each other rather
    than in two suites that could drift into agreeing. The complementary control is the same
    four addresses on a lead that spent the budget instead."""
    repeat_rec = VerbRecorder()
    repeat = _run(tmp_path / "repeat", run_id="d1015-repeat", verbs=elastic_ok(repeat_rec),
                  turns=[*[_bad_args("ghostone")] * (rq.REPEAT_THRESHOLD + 1),
                         q("elastic", "query", PARAMS), DONE])
    budget_rec = VerbRecorder()
    budget = _run(tmp_path / "budget", run_id="d1015-precedence",
                  verbs=elastic_ok(budget_rec),
                  turns=[*[_bad_args(f"ghost{i}") for i in range(B)],
                         q("elastic", "query", PARAMS), DONE])

    rows = _above_guard(repeat)
    assert len(rows) == rq.REPEAT_THRESHOLD, \
        "the repeat guard stopped taking its own stop once the budget existed"
    assert _terminator(repeat) == session_store.TRUNCATED_BY_DEAD_END
    assert "turned back at seq" in rows[-1]["payload_digest"], \
        "the repeat guard's own trip row lost its sentence to the budget's"
    assert "before anything ran in this lead" not in rows[-1]["payload_digest"], \
        "the repeat guard's trip row was written with the budget's phrase"
    assert repeat_rec.calls == [], "the lead ran on past its dead end"

    repeat_summary = _summary(repeat)
    assert rq.rejection_dead_end_reason(
        "an undeclared system", "query",
        rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)) in repeat_summary, \
        "a lead stopped for REPEATING was given the budget's reason — O2"
    assert rq.REPEAT_ESCAPE in repeat_summary
    assert REJECTION_BUDGET_ESCAPE not in repeat_summary
    assert "the lead's whole allowance" not in repeat_summary, \
        "main was told this lead spent its allowance when it repeated one request three times"

    # The complementary condition at the same four addresses.
    _assert_budget_stop(budget)
    assert "turned back at seq" not in _summary(budget), \
        "a lead stopped for SPENDING was told it repeated a request already turned back — O2"


# ── O3: the recorded table replays to the same stop, of the same kind ──────────────────────


def test_the_replay_of_each_table_agrees_with_the_live_run_on_the_kind_of_stop(tmp_path):
    """O3 — an operator auditing a recorded run has only `executed_queries.jsonl`, and the stop
    must be recoverable from it: the same lead, the same seq, and the same GUARD. The trip row
    is an ordinary `ABOVE_GUARD_QUERY_ID` / `agent-fixable` row by design (it must keep
    counting), so the kind is not a column — it is what the two predicates, asked in the live
    order at the guarded rows, answer.

    Three tables in one arm on purpose. An oracle that had merely gained a second ask agrees
    with the live run on the budget table and disagrees on the repeat one; an oracle that asked
    the budget FIRST reports "budget" for a stop the live run took as a repeat; and an oracle
    that counted a row it should not agrees on neither seq. The run-on table is the fourth
    corner: no trip at all.

    The seqs are the LIVE ones, read off the same tables — the interleaved table's stop is at
    seq 7 with only six rejections on it, which a replay counting rows rather than asking the
    predicate cannot reach."""
    rec = VerbRecorder()
    budget = _run(tmp_path / "budget", run_id="d1015-replay-budget", verbs=elastic_ok(rec),
                  turns=[*[_bad_args(f"ghost{i}") for i in range(B)], DONE])
    repeat = _run(tmp_path / "repeat", run_id="d1015-replay-repeat", turns=[
        *[_bad_args("ghostone")] * 3, DONE])
    inter_rec = VerbRecorder()
    inter = _run(tmp_path / "inter", run_id="d1015-replay-inter", verbs=elastic_ok(inter_rec),
                 turns=[
                     _bad_args("g1"), _bad_args("g2"),
                     q("elastic", "query", {"native_query": "FROM a"}),
                     _bad_args("g3"), _bad_args("g4"),
                     q("elastic", "query", {"native_query": "FROM b"}),
                     _bad_args("g5"), _bad_args("g6"), DONE,
                 ])
    run_on = _run(tmp_path / "runon", run_id="d1015-replay-runon", turns=[
        *[_bad_args(f"ghost{i}") for i in range(B - 1)], DONE])

    # The live verdicts first: a parity claim over a table nobody stopped on is vacuous.
    _assert_budget_stop(budget)
    _assert_budget_stop(inter)
    assert _terminator(repeat) == session_store.TRUNCATED_BY_DEAD_END
    assert "turned back at seq" in _above_guard(repeat)[-1]["payload_digest"]
    assert _terminator(run_on) is None
    assert not _dead_end(run_on)

    assert _replay_rejections(budget.rows) == [(LEAD, B - 1, "budget")], \
        "the replay disagrees with the live budget stop, on the table that run wrote"
    assert _replay_rejections(repeat.rows) == [(LEAD, rq.REPEAT_THRESHOLD - 1, "repeat")], \
        "the replay reports the wrong guard for a stop the live run took as a repeat"
    assert _replay_rejections(inter.rows) == [(LEAD, 7, "budget")], \
        "the replay lost the stop's seq once successful rows sat between the rejections"
    assert _replay_rejections(run_on.rows) == [], \
        "the replay refuses a lead the live run let run on"


# ── O4: nothing the model wrote crosses into main ──────────────────────────────────────────


def test_no_byte_the_model_authored_reaches_main_through_a_budget_stop(tmp_path):
    """O4 / S1 — the asset is main's context on the refusal path, the #855 leak channel. The
    budget stop must carry NO model-authored byte: not the system string, not its digest, not
    the verb, not a params fragment.

    Discharged in the design by two facts together — the trip type and the budget reason take
    integers only, AND `_run_gather`'s dead-end arm composes the summary from `reason` and
    `escape` alone, discarding the lead's own output — and this is the arm over both.

    Every negative here has its positive control. The ghost names and the params canary are
    DISTINCTIVE strings, and the run is shown to have actually carried them: the canary and the
    digests are read back off the queries table, which is where they legitimately live (the
    gather agent reads that table; main does not). The summary is shown to be non-empty and to
    carry the host's own reason, so "not in the summary" is not true of an empty file."""
    r = _run(tmp_path, run_id="d1015-leak",
             turns=[*[_loud(i) for i in range(B)], DONE])

    _assert_budget_stop(r)
    summary = _summary(r)

    values = [str(value) for row in r.rows for value in row.values()]
    assert any(LOUD_PARAM in value for value in values), \
        "the model's params never reached the table, so the negative below is vacuous"
    digests = {row["system_key"] for row in _above_guard(r)}
    assert len(digests) == B, \
        "no fingerprint was minted, so the digest negative below is vacuous"
    assert "" not in digests, \
        "a rejection went unfingerprinted, so the digest negative below is vacuous"
    assert len(summary) > len(INCOMPLETE_IDIOM), \
        "the summary is barely longer than the idiom — the negatives below are vacuous"

    assert LOUD_PARAM not in summary, \
        "a model-authored params fragment crossed into main's context on a refusal path"
    assert LOUD_SYSTEM not in summary, \
        "a model-authored system name crossed into main's context on a refusal path"
    assert LOUD_VERB not in summary, \
        "a model-authored verb crossed into main's context on a refusal path"
    for digest in digests:
        assert digest not in summary, \
            "the fingerprint crossed into main's context — it is name-shaped, so a reader " \
            "downstream can spend it exactly as it would spend a system"


# ── the arms the adversary's pass added ────────────────────────────────────────────────────


def test_the_repeat_guard_takes_a_stop_that_is_both_a_repeat_and_the_budgets(tmp_path):
    """PRECEDENCE, on the only table where it is observable — and it is a claim about what
    MAIN is told, not an ordering preference.

    The design fixes it: the guards are asked "repeat FIRST, then the budget", because "a call
    that is both the 3rd repeat and the B-th rejection gets the more specific one". Every other
    arm in this file reaches one guard or the other, so the order is free in all of them: a
    lead of B distinct ghosts never repeats, and a lead repeating one ghost trips at 3 and
    never reaches B. The two only collide on a table built to make them collide.

    Two spellings of `ghostone`, three fresh ghosts, then `ghostone` again: at the sixth call
    the repeat guard sees its 3rd occurrence AND the budget sees its 6th rejection. The repeat
    sentence names the earlier request the lead is repeating, which the lead can act on; the
    budget's can only say the allowance is gone. Asked the other way round main loses the
    specific explanation it had before this issue — and, worse, `_replay_rejections` asks
    repeat first over the recorded table and would report `repeat` for a stop the live run took
    as `budget`, which is O3's own failing-by.

    The replay is asserted here for that reason, not as a duplicate of the O3 arm below."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-both", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghostone"),
        *[_bad_args(f"g{i}") for i in range(3)],
        _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the lead wrote {len(rows)} rejections — the two guards did not collide on the last"
    assert rq.rejection_budget_trip(rows[:-1], LEAD) is not None, \
        "the budget would not have tripped here either, so this arm pins no precedence"

    digest = rows[-1]["payload_digest"]
    assert "turned back at seq" in digest, \
        "the budget took a stop the repeat guard owns — main lost the specific sentence"
    assert _budget_phrase() not in digest, "the budget's phrase reached a repeat guard's row"

    body = _summary_body(r)
    assert rq.REPEAT_ESCAPE in body, "main was handed the wrong escape for a repeat stop"
    assert REJECTION_BUDGET_ESCAPE not in body
    assert "the lead's whole allowance" not in body, \
        "main was told it spent its allowance for a stop taken on a repeat"

    assert _replay_rejections(r.rows) == [(LEAD, rows[-1]["seq"], "repeat")], \
        "the replay names a different guard than the one the live run stopped on — O3"
    assert rec.calls == [], "the lead ran on past its dead end"


def test_no_byte_the_model_authored_reaches_main_through_the_grant_placements_stop(tmp_path):
    """O4 at the SECOND placement. The leak-check arm below drives `wrap_tool_validate` only
    (its turns carry `bogus_extra_arg`, which is what routes them to the schema), so the grant
    check's own budget branch — which holds the model's string in a differently-named local,
    `system` rather than `raw_system`, and reaches the dispatcher one function further on — is
    checked by no negative anywhere.

    That asymmetry is #855's own lesson, in its words: the fix has TWO writers and arms that
    reach the stop through only one of them leave the other exactly as it was. Here the cost is
    the #855 leak channel itself — an unbounded model-authored system name in main's context on
    a refusal path.

    Schema-valid turns by construction (`q`), so every row here is the grant check's."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-grant-leak", verbs=elastic_ok(rec), turns=[
        *[q(f"{LOUD_SYSTEM}-{i}", f"{LOUD_VERB}-{i}",
            {"native_query": f"FROM {LOUD_PARAM}-{i}"}) for i in range(B)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, "the grant placement did not take this stop"
    _assert_budget_stop(r)

    body = _summary_body(r)
    for canary in (LOUD_SYSTEM, LOUD_VERB, LOUD_PARAM):
        assert canary in str(r.rows), \
            f"{canary} never reached the table, so its absence from main's context says nothing"
        assert canary not in body, \
            f"the model's own {canary!r} crossed into main's context through the grant stop"
    for row in rows:
        assert row["system_key"] not in body, \
            "a ghost's fingerprint — a stable identifier of the model's string — reached main"

    # The truncation escape the whole-string canaries above cannot see: no run of six
    # characters from any dispatched value is in main's context either.
    for value in (LOUD_SYSTEM, LOUD_VERB, LOUD_PARAM):
        for i in range(len(value) - 5):
            assert value[i:i + 6] not in body, \
                f"a {value[i:i + 6]!r} fragment of the model's own argument reached main"


def test_a_lead_iterating_on_a_declared_systems_parameters_is_not_the_budgets(tmp_path):
    """C13, LIVE — the design's loudest non-obligation, and the one the predicate's unit arms
    cannot carry alone. They pin `rejection_budget_trip` over hand-built tables; nothing pins
    what the live guard hands it. A placement that counted its own rows instead — every
    `agent-fixable` row of the lead, say — passes every unit arm (the predicate is untouched)
    and every other live arm (none of them mixes the two domains), while ending a healthy lead
    at its FIRST above-guard refusal.

    That population is not hypothetical: below-guard parameter refusals against a DECLARED
    system run 4+ per lead in 30 of the 320 archived leads, with tails of 30, 71 and 98. They
    are the model iterating on a real system's parameters under specific coaching, which is a
    lead working, and a bound of 6 over them would end it. Five of them, then one ghost, then
    the corrected call: the lead must finish, and the corrected query must RUN.

    The replay is asserted because the same wrong domain also makes the recorded table replay
    to a verdict the live run did not take — a flat O3 disagreement."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-below", verbs=elastic_ok(rec), turns=[
        *[q("elastic", "query", {"native_query": f"FROM t{i}", "nope": i}) for i in range(5)],
        _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    # The domain's OWN predicate, negated — not a hand-spelled complement of it. C13's
    # population is "agent-fixable, and NOT what the guard counts", and `in_rejection_domain` is
    # the one home of the second half (its docstring: a fourth copy "would split the guards in
    # silence while every fixture stayed green"). Written out here, widening the domain would
    # leave this arm — the only live guarantee that a healthy lead is not the budget's — green
    # over a population that had moved inside it.
    #
    # `own_rows`, not `rows`: #808's reserved lead-0 resolves against `GOLDEN_AB3` before MAIN's
    # first turn and writes its own rows into this table (an above-guard agent-fixable one, on
    # this fixture). `_above_guard` already excludes them, and a census that did not would be
    # counting another lead's refusals into this one's five.
    below = [row for row in r.own_rows
             if not rq.in_rejection_domain(row)
             and row.get("error_class") == AGENT_FIXABLE_ERROR_CLASS]
    assert len(below) == 5, \
        f"the lead wrote {len(below)} below-guard refusals — this arm drives the wrong shape"
    assert len(_above_guard(r)) == 1, "the ghost did not land above the guard"

    assert _terminator(r) is None, \
        f"a healthy lead was ended as {_terminator(r)!r} — the budget counted C13's population"
    assert not _dead_end(r), "the lead was stopped after one above-guard rejection"
    assert rec.calls, "the corrected query never ran — the lead was killed before it"
    assert _replay_rejections(r.rows) == [], \
        "the replay reports a stop the live run did not take — O3"
