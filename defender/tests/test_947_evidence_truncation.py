"""#947 Part C — a sibling inherits the evidence its prefix names, and nothing past it.

#920 gave a sibling the source run's whole `executed_queries.jsonl`, `gather_raw/` and
`gather_summaries/`, because the inherited message prefix is full of absolute paths into the
run dir that produced it and `permission.decide_read` roots the sibling at its own. That was
right about the paths and wrong about the SET: the source ran ON past the fork, and its later
leads carry the answers this pair exists to not share. A sibling handed them starts holding
evidence its own history never mentions — a model reading its own transcript finds payload
files for leads it never dispatched, and the branch measures agreement with the source's
conclusion rather than a difference from it.

So the cut is by LEAD. `branch.leads_at` answers which gather leads existed at the branch point,
and everything keyed on a later one is left behind.

WHAT MAKES A LEAD COUNT is its RETURN, not its call: `hydrate(role="send")` truncates a trailing
response whose tool call is unresolved, so a lead counts exactly when the prefix carries the
dispatch that finished it. A REFUSED dispatch claims nothing at all — its call never became
evidence, and leaving the claim pending lets the next return pop somebody else's.

AND THE LEADS NO DISPATCH ACCOUNTS FOR ARE KEPT, always. Lead-0's reserved ids are written by
`lead_zero` before the model's first turn, so nothing in MAIN's session dispatched them — and
the sibling must keep them, because `claim_lead` raises on id reuse and the inherited claim is
itself what stops a resumed run redoing turn-0 work (`e2e/test_920_branch_resume.py` pins that).
Derived as a SET DIFFERENCE rather than by naming the ids, so the day lead-0 mints a different
one nothing silently drops it.

THE COPY ITSELF IS A SAFETY BOUNDARY. The run dir is the box's rw bind, so a link planted at an
artifact's name is something the model wrote — and `copy2` of one writes the TARGET's bytes into
the sibling under that name, where every later reader takes them for an in-run artifact. The
`artifact_file`/`artifact_dir` helpers exist for exactly that, and a refusal has to be LOUD: a
silently skipped artifact is a sibling running without the evidence its prefix names.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    ToolCallPart,
    ToolReturnPart,
)

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    ALERT_DOC,
    GOLDEN_INVESTIGATION,
    branch_mod,
    legal_source,
    spec_at,
)
from defender.tests._session_store_705 import store_mod  # noqa: E402

#: The tool a lead is dispatched through. The design calls it `gather_dispatch`; the runtime
#: registers it as `gather` (`tools_gather.register_gather_tool`, and `driver.py`'s own comment
#: — "gated on the literal tool name 'gather'"). Spelled here so an implementation written
#: against the design's prose name fails loudly rather than accounting for no dispatch at all
#: and keeping every lead as unattributed.
GATHER_TOOL = "gather"

#: A lead nothing in MAIN's session dispatched — the shape lead-0's reserved ids have. NOT
#: `l-000`: the rule is a set difference, and an id chosen so that a hardcoded reserved-id list
#: cannot satisfy this file is what proves it.
UNDISPATCHED = "l-zzz"


def dispatch(store, session_id, lead, *, call_id=None, spelling="dict"):
    """One `gather` call/return pair in MAIN's session. Returns the RETURN's row id.

    `spelling="json"` puts the args on the wire as an unparsed JSON STRING, which is what a
    provider hands back when it does not parse arguments — both shapes reach the store, and a
    reader that knew only the first scores every one of the other's dispatches as claiming
    nothing.
    """
    ss = store_mod()
    tool_call_id = call_id if call_id is not None else f"gd-{lead}"
    args = {"lead_id": lead, "system": "elastic", "goal": f"measure {lead}",
            "what_to_summarize": ["what the window holds"]}
    store.append(session_id, [ModelResponse(parts=[ToolCallPart(
        tool_name=GATHER_TOOL, args=json.dumps(args) if spelling == "json" else args,
        tool_call_id=tool_call_id)])], agent_id="main")
    store.append(session_id, [ModelRequest(parts=[ToolReturnPart(
        tool_name=GATHER_TOOL, content=f"summary for {lead}",
        tool_call_id=tool_call_id)])], agent_id="main")
    return ss.path_row_ids(store, session_id)[-1]


def refused_dispatch(store, session_id, lead, *, call_id):
    """A `gather` call the tool REFUSED — `ModelRetry`, which the framework records as a
    `RetryPromptPart`. Returns the refusal's row id."""
    ss = store_mod()
    store.append(session_id, [ModelResponse(parts=[ToolCallPart(
        tool_name=GATHER_TOOL, args={"lead_id": lead, "system": "elastic", "goal": "x",
                                     "what_to_summarize": []},
        tool_call_id=call_id)])], agent_id="main")
    store.append(session_id, [ModelRequest(parts=[RetryPromptPart(
        content=f"lead id {lead} is already claimed", tool_name=GATHER_TOOL,
        tool_call_id=call_id)])], agent_id="main")
    return ss.path_row_ids(store, session_id)[-1]


def dispatch_call_only(store, session_id, lead, *, call_id=None):
    """A `gather` call with NO return — the run killed mid-gather, or a lead still in flight at
    the tip. Returns the CALL's row id."""
    ss = store_mod()
    store.append(session_id, [ModelResponse(parts=[ToolCallPart(
        tool_name=GATHER_TOOL,
        args={"lead_id": lead, "system": "elastic", "goal": f"measure {lead}",
              "what_to_summarize": []},
        tool_call_id=call_id if call_id is not None else f"gd-{lead}")])], agent_id="main")
    return ss.path_row_ids(store, session_id)[-1]


def bare_return(store, session_id, *, call_id):
    """A `gather` RETURN with no call of its own — the shape a provider produces when it
    re-answers an id it has already been refused on. Returns the return's row id."""
    ss = store_mod()
    store.append(session_id, [ModelRequest(parts=[ToolReturnPart(
        tool_name=GATHER_TOOL, content="summary for a lead nobody re-dispatched",
        tool_call_id=call_id)])], agent_id="main")
    return ss.path_row_ids(store, session_id)[-1]


def evidence(run_dir: Path, rows: list[tuple[str, int]]) -> None:
    """Write the source run's captured evidence: one table row, sidecar, claim and summary per
    `(lead, seq)`, in the order given — interleaved across leads, the way a real run's table is.
    """
    paths = RunPaths(run_dir)
    paths.gather_raw.mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_summaries").mkdir(parents=True, exist_ok=True)
    lines = []
    for lead, seq in rows:
        lines.append(json.dumps({
            "lead_id": lead, "seq": seq, "system": "elastic", "verb": "esql",
            "query_id": "elastic.sshd-failed-by-srcip", "params": {"lead": lead, "seq": seq},
            "payload_path": f"gather_raw/{lead}/{seq}.json",
            "exit_code": 0, "payload_status": "ok",
        }))
        (paths.gather_raw / lead).mkdir(parents=True, exist_ok=True)
        (paths.gather_raw / lead / f"{seq}.json").write_text(
            json.dumps({"lead": lead, "seq": seq}), encoding="utf-8")
        (paths.gather_raw / f"{lead}.lead.json").write_text(
            json.dumps({"lead_id": lead}), encoding="utf-8")
        (run_dir / "gather_summaries" / f"{lead}.md").write_text(
            f"# {lead}\nwhat this lead measured\n", encoding="utf-8")
    paths.executed_queries.write_text("\n".join(lines) + "\n", encoding="utf-8")


def gathering_source(tmp_path, *, spelling: str = "dict"):
    """A finished run that dispatched three leads and carries a fourth nobody dispatched.

    Returns `(store, run_dir, session_id, returns)` where `returns[i]` is the row id of lead
    `l-00{i+1}`'s tool RETURN.
    """
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    returns = [dispatch(store, session_id, lead, spelling=spelling)
               for lead in ("l-001", "l-002", "l-003")]
    evidence(run_dir, [(UNDISPATCHED, 0), ("l-001", 0), ("l-002", 0), ("l-001", 1),
                       ("l-003", 0), ("l-002", 1)])
    return store, run_dir, session_id, returns


def sibling_dir(tmp_path, name: str = "run-sibling") -> Path:
    target = tmp_path / "defender-runs" / name
    (target / "gather_raw").mkdir(parents=True, exist_ok=True)
    return target


def resume(store, run_dir, message_id, target: Path):
    """Open the sibling the way the driver does, at `message_id`."""
    branch = branch_mod()
    return branch.open_main_session(store, spec_at(store, run_dir, message_id), target)


# ==========================================================================
# 1. which leads existed at the branch point
# ==========================================================================

@pytest.mark.parametrize(("landed", "expected"), [
    (0, {UNDISPATCHED, "l-001"}),
    (1, {UNDISPATCHED, "l-001", "l-002"}),
    (2, {UNDISPATCHED, "l-001", "l-002", "l-003"}),
])
def test_a_lead_counts_from_the_turn_its_dispatch_returned(tmp_path, landed, expected):
    """    `leads_at` answers the leads whose gather RETURN landed at or before the branch point.

    Three branch points over ONE run, so an implementation that reads the finished run dir —
    which knows every lead — fails two of the three rather than passing all of them. The return
    is the boundary because that is where the prefix's own truncation falls: `fork` seeds the
    child's render length through `_complete_prefix_len`, so a dispatch whose return has not
    landed is not in the history the sibling is handed."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)

    assert branch_mod().leads_at(store, session_id, returns[landed], run_dir) == expected


def test_a_dispatch_still_in_flight_at_the_branch_claims_nothing(tmp_path):
    """    Branching at a gather CALL, one row before its return, does not count that lead.

    The pair rule seen from the other side, and the reason the return is what is scored: a call
    with no result is a turn the resumed model can neither answer nor withdraw, so `validate`
    refuses that branch point outright — and the lead behind it produced no summary the prefix
    could refer to."""
    ss = store_mod()
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    path = ss.path_row_ids(store, session_id)
    call_row = path[path.index(returns[1]) - 1]

    assert branch_mod().leads_at(store, session_id, call_row, run_dir) == {
        UNDISPATCHED, "l-001"}


def test_a_lead_dispatched_but_never_answered_is_never_inherited(tmp_path):
    """    A lead whose dispatch CALL landed and whose return never did is out at every branch
    point — including the tip, where its call is the last row of the run.

    THE arm that separates the two ways of computing the lead-0 fallback. The kept set is
    `tabled - dispatched-after-the-branch`, and the leads nothing dispatched at all are lead-0's
    reserved ids. Build the subtrahend from RETURNS and a lead that was dispatched but never
    answered — a run killed mid-gather, or a dispatch in flight at the tip — is absent from it,
    falls through the subtraction as though `lead_zero` had written it, and its evidence is
    inherited at EVERY branch point. Every other row of this probe passes under both readings;
    only the last one tells them apart.

    Recorded on the CALL and landed on the RETURN is the split that makes both true at once: a
    lead in flight claims its id (so it is not lead-0's) without counting as evidence the prefix
    holds."""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    first = dispatch(store, session_id, "l-001")
    second = dispatch(store, session_id, "l-002")
    unanswered = dispatch_call_only(store, session_id, "l-003")
    evidence(run_dir, [(UNDISPATCHED, 0), ("l-001", 0), ("l-002", 0), ("l-003", 0)])
    leads_at = branch_mod().leads_at

    assert leads_at(store, session_id, first, run_dir) == {UNDISPATCHED, "l-001"}
    assert leads_at(store, session_id, second, run_dir) == {UNDISPATCHED, "l-001", "l-002"}
    assert leads_at(store, session_id, unanswered, run_dir) == {UNDISPATCHED, "l-001", "l-002"}, (
        "the never-answered lead was inherited — its dispatch left no trace in the subtrahend, "
        "so it read as evidence lead-0 had written before the model's first turn")


def test_a_lead_no_dispatch_accounts_for_survives_every_branch_point(tmp_path):
    """    A lead in the table that MAIN's session never dispatched is kept at every branch point.

    Lead-0's reserved ids are exactly this shape — `lead_zero` writes them before the model's
    first turn, so no `gather` call in MAIN's session names them — and dropping them breaks the
    resume in a way that reads as a fresh run: `claim_lead` raises on id reuse, so the inherited
    claim is what stops a resumed run redoing turn-0 work, and without it the sibling
    re-resolves the alert's ancestors over evidence its prefix already holds.

    The id here is deliberately NOT `l-000`: the rule is "the leads no dispatch accounts for",
    derived as a set difference, and an implementation that hardcodes the reserved ids passes
    every arm written with them and silently drops the next one lead-0 mints."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir) for at in returns]

    assert all(UNDISPATCHED in leads for leads in everywhere), (
        f"the undispatched lead was dropped at some branch point: {everywhere}")


def test_a_lead_named_only_by_a_table_row_still_crosses(tmp_path):
    """    A lead whose only trace is a row in `executed_queries.jsonl` survives truncation too.

    The third leg of the census, and the shape it has on a real run is a lead whose payload was
    LOST: `persist_payload` answers `None` when the sidecar cannot be written (a full disk, a
    `guarded_mkdir` refusal) and `record_query` writes the row anyway with no `payload_path`
    behind it, deliberately — the row is the evidence that the call happened at all. Nothing
    else in the run dir then names that lead.

    Dropped from the census, its row is cut out of the sibling's inherited table, and the
    sibling's own account of what its prefix did loses a call the prefix genuinely made — while
    `repeat_note` and `_next_seq`, which read the table, stop seeing a question this defender
    has already asked.

    Same before/after as its two siblings: read once without the row and once with it, over one
    run dir, so a census that never reads the table returns the same set twice and fails here."""
    tabled = "l-tableonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)

    assert tabled not in branch_mod().leads_at(store, session_id, returns[0], run_dir), (
        "the fixture's lead is already known through an artifact, so this arm would pass "
        "against a census that never reads the queries table")
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "lead_id": tabled, "seq": 0, "system": "elastic", "verb": "esql",
            "query_id": "elastic.sshd-failed-by-srcip", "params": {"lead": tabled},
            "payload_path": None, "exit_code": 0, "payload_status": "ok",
        }) + "\n")

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir) for at in returns]
    assert all(tabled in leads for leads in everywhere), (
        f"a lead named only by its table row is invisible to the lead census ({everywhere}) — "
        "the sibling's inherited table loses a call its own prefix made")

    resume(store, run_dir, returns[1], target)

    assert tabled in {r["lead_id"] for r in read_jsonl_rows(RunPaths(target).executed_queries)}


def test_a_lead_claimed_without_a_captured_row_still_crosses(tmp_path):
    """    A lead the source run CLAIMED but recorded no query for is still inherited.

    Lead-0's correlation lead is exactly this shape on a real run: `lead_zero` writes
    `gather_raw/l-00c.lead.json` and, when item 1 resolves its ancestors without capturing
    anything under that id, leaves no table row and no payload directory behind it. A lead
    universe read from `executed_queries.jsonl` alone cannot see it, so it is dropped from the
    kept set and its claim never crosses — after which the resumed run is free to dispatch that
    id again, which is precisely the turn-0 work a branch point is past by construction.

    `claim_lead` raises on id reuse, so the inherited claim IS the mechanism that stops the
    re-dispatch; `e2e/test_920_branch_resume.py` pins the byte-identity one layer up. The id
    here is a neutral one, because the rule is "a lead this run claimed", not a list of lead-0's
    reserved names."""
    claimed = "l-claimonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    (RunPaths(run_dir).gather_raw / f"{claimed}.lead.json").write_text(
        json.dumps({"lead_id": claimed}), encoding="utf-8")
    target = sibling_dir(tmp_path)

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir) for at in returns]
    assert all(claimed in leads for leads in everywhere), (
        f"a lead with a claim and no captured row is invisible to the lead universe ({everywhere})"
        " — the sibling inherits no claim for it and may re-dispatch an id its own prefix spent")

    resume(store, run_dir, returns[1], target)

    assert (RunPaths(target).gather_raw / f"{claimed}.lead.json").is_file()


def test_a_lead_known_only_by_its_summary_still_crosses(tmp_path):
    """    A lead named by nothing but `gather_summaries/{lead}.md` survives truncation too.

    The third source of the lead census, and the one with NO backstop. The claim-only lead
    beside it is protected twice over — `claim_lead` writes `{lead}.lead.json` as an exclusive
    create, so a sibling that re-used that id would at least be REFUSED. A summary-only lead has
    no claim sidecar, so the reuse gate never fires: the sibling mints the id again, writes a
    second `gather_summaries/{lead}.md` over a lead of its own, and the two runs' summaries
    occupy one filename with nothing anywhere reporting a collision. Dropping this lead is
    therefore quieter than dropping either of the others, which is why it is pinned rather than
    left to the union's shape.

    `{lead}.md` maps back through the same first-dot split the payload sidecars use
    (`l-x.md` -> `l-x`), so the summaries directory names leads in exactly the sense the other
    two sources do.

    THE BEFORE/AFTER IS THE DISCRIMINATOR. The set is read once with the summary absent and once
    with it present, over one run dir, so the only thing that differs between the two answers is
    that file: a census built from the table and `gather_raw/` alone returns the same set twice
    and fails here. The first read doubles as the fixture's own integrity check — if this lead
    were reachable some other way, the arm would be measuring that other way."""
    summarized = "l-summonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    summary = run_dir / "gather_summaries" / f"{summarized}.md"
    target = sibling_dir(tmp_path)

    assert summarized not in branch_mod().leads_at(store, session_id, returns[0], run_dir), (
        "the fixture's lead is already known through the table or `gather_raw/`, so this arm "
        "would pass against a census that never reads the summaries")
    summary.write_text(f"# {summarized}\nwhat this lead measured\n", encoding="utf-8")

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir) for at in returns]
    assert all(summarized in leads for leads in everywhere), (
        f"a lead named only by its summary is invisible to the lead census ({everywhere}) — its "
        "summary is left behind, and with no claim sidecar nothing stops the sibling re-using "
        "the id and writing a second run's summary over that filename")

    resume(store, run_dir, returns[1], target)

    assert (target / "gather_summaries" / f"{summarized}.md").is_file()


def test_a_refusal_clears_the_claim_before_any_later_return_can_pop_it(tmp_path):
    """    A `RetryPromptPart` CLEARS the pending claim, so a later return under that id lands
    nothing at all.

    The arm beside this one re-dispatches under the reused id, which overwrites the pending
    entry on the way past — so the clearing branch never has to do anything and deleting it
    changes no answer. Here the return arrives with NO intervening call, which is the only
    shape under which the refusal's own bookkeeping is what decides: cleared, nothing pops and
    the refused lead stays out; left pending, the return pops the REFUSED claim and credits
    `l-004` as landed at a turn where nothing ran.

    Credited, that lead's evidence is inherited on the strength of a dispatch the tool refused
    — which is evidence the sibling's own prefix does not name, carried across because a
    refusal was mistaken for work."""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused_dispatch(store, session_id, "l-004", call_id="reused-1")
    orphan = bare_return(store, session_id, call_id="reused-1")
    # No l-004 artifact here: this arm isolates whether the stale pending entry can make the
    # orphan return LAND it. Pre-existing evidence under a refused id is the separate arm below
    # and must be inherited.
    evidence(run_dir, [(UNDISPATCHED, 0)])

    assert branch_mod().leads_at(store, session_id, orphan, run_dir) == {UNDISPATCHED}, (
        "a return under a REFUSED call id landed the refused lead — the sibling inherits "
        "evidence on the strength of a dispatch that never ran")


def test_a_refused_retry_does_not_remove_an_inherited_undispatched_lead(tmp_path):
    """A retry-refused call is absent from the dispatch census, not merely from ``pending``.

    Lead-0 can leave a pre-existing claim and evidence that MAIN never dispatched. If MAIN later
    tries that same id, the claim gate returns ``RetryPromptPart`` and performs no work. Counting
    the refused call as a dispatch subtracts the pre-existing lead from the lead-0 fallback, so
    the sibling silently loses evidence and is then free to reuse the inherited id.
    """
    inherited = "l-004"
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused = refused_dispatch(store, session_id, inherited, call_id="already-claimed")
    evidence(run_dir, [(UNDISPATCHED, 0), (inherited, 0)])

    assert branch_mod().leads_at(store, session_id, refused, run_dir) == {
        UNDISPATCHED, inherited,
    }, "the retry-refused gather erased a pre-existing inherited lead from the census"


def test_a_refused_dispatch_does_not_land_for_whoever_reuses_its_call_id(tmp_path):
    """    A refused call lands nothing; the next return credits the lead THAT call named.

    The join is by `tool_call_id`, because the CALL carries the lead id and the RETURN carries
    only the id — so a refusal that stayed pending is popped by the next return, and the two
    leads swap places: the refused one is credited at a row it never ran on, and the lead that
    actually landed there is left looking un-landed. The refused id's PRE-EXISTING evidence is
    inherited independently through the undispatched fallback; that is not this return landing
    it, and keeping the two paths separate is the review regression beside this test.

    `_tool_gather`'s refusals arrive as `ModelRetry`, which the framework records as a
    `RetryPromptPart` — the same shape `fence_count_at` already drops without counting. The
    fixture reuses the id deliberately: a provider that re-mints one after a refusal is what
    makes the stale entry reachable at all."""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused = refused_dispatch(store, session_id, "l-004", call_id="reused-1")
    landed = dispatch(store, session_id, "l-005", call_id="reused-1")
    evidence(run_dir, [(UNDISPATCHED, 0), ("l-004", 0), ("l-005", 0)])
    leads_at = branch_mod().leads_at

    assert leads_at(store, session_id, refused, run_dir) == {UNDISPATCHED, "l-004"}, (
        "the refused call removed a pre-existing undispatched lead from inherited evidence")
    assert leads_at(store, session_id, landed, run_dir) == {
        UNDISPATCHED, "l-004", "l-005",
    }, (
        "the return under the reused id credited the REFUSED lead — so the sibling inherits "
        "evidence its prefix never names and drops the lead that actually landed there")


@pytest.mark.parametrize("spelling", ["dict", "json"])
def test_a_dispatch_counts_however_the_provider_spelled_its_arguments(tmp_path, spelling):
    """    `ToolCallPart.args` is a dict on the ordinary path and a JSON STRING when the provider
    hands back unparsed arguments; both name the same lead.

    Both shapes reach the store — `_appended_text` reads the same two for `append_block` and
    documents why — and a reader that knew only the dict would score every one of the other's
    dispatches as accounting for no lead. Which fails SAFE for the lead set (unaccounted leads
    are kept) and therefore silently: the sibling inherits the source's later leads, conclusions
    included, and nothing anywhere is red."""
    store, run_dir, session_id, returns = gathering_source(tmp_path, spelling=spelling)

    assert branch_mod().leads_at(store, session_id, returns[0], run_dir) == {
        UNDISPATCHED, "l-001"}


# ==========================================================================
# 2. what the sibling's run dir ends up holding
# ==========================================================================

def test_the_sibling_inherits_the_leads_the_branch_point_held_and_no_later_one(tmp_path):
    """    The sibling's table, payload tree and summaries carry the branch point's leads only.

    All three artifacts together, because they are keyed on the same set and a truncation
    applied to one of them is worse than none: a table row whose sidecar is missing reads to
    every offline reader as a payload this episode LOST (`lead_extraction` skips a row whose
    `raw_ref` is not a file), and a payload tree with no row behind it is evidence no reader
    joins at all.

    The dropped lead is the source's own later work — the conclusions the pair exists to not
    share — so this is the whole point of the cut, not a tidiness rule."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)

    resume(store, run_dir, returns[1], target)

    rows = read_jsonl_rows(RunPaths(target).executed_queries)
    assert {r["lead_id"] for r in rows} == {UNDISPATCHED, "l-001", "l-002"}
    assert sorted(p.name for p in RunPaths(target).gather_raw.iterdir()) == sorted([
        UNDISPATCHED, f"{UNDISPATCHED}.lead.json", "l-001", "l-001.lead.json",
        "l-002", "l-002.lead.json"])
    assert sorted(p.name for p in (target / "gather_summaries").iterdir()) == sorted(
        [f"{UNDISPATCHED}.md", "l-001.md", "l-002.md"])


def test_the_inherited_table_keeps_the_order_the_source_wrote_it_in(tmp_path):
    """    The surviving rows appear in the SOURCE's order, interleaved leads and all.

    `executed_queries.jsonl` is append-only and `(lead_id, seq)`-keyed, and the sibling appends
    to it: a truncation that grouped by lead would put the sibling's own new rows after a
    re-sorted history, so `_next_seq` and `repeat_note` — which read the table in file order —
    would be reasoning over a sequence the run never had."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)

    resume(store, run_dir, returns[1], target)

    kept = [(r["lead_id"], r["seq"]) for r in read_jsonl_rows(RunPaths(target).executed_queries)]
    assert kept == [(UNDISPATCHED, 0), ("l-001", 0), ("l-002", 0), ("l-001", 1), ("l-002", 1)]


def test_the_source_runs_own_evidence_is_left_whole(tmp_path):
    """    Truncation happens in the SIBLING's copy: the source keeps every row it ever wrote.

    COPIED, never moved or shared. The source run is the base of the comparison the branch
    exists to produce, and an episode that edited it would make the pair's own control depend on
    how many siblings had been run against it."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)

    resume(store, run_dir, returns[1], sibling_dir(tmp_path))

    rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    assert {r["lead_id"] for r in rows} == {UNDISPATCHED, "l-001", "l-002", "l-003"}
    assert (RunPaths(run_dir).gather_raw / "l-003" / "0.json").is_file()


def test_the_alert_is_inherited_verbatim(tmp_path):
    """    `alert.json` crosses to the sibling byte for byte.

    It is the case INPUT, not the source run's work: both siblings investigate the same alert,
    and a run dir without one has no `read_file` target for the very first turn of any resumed
    history. Byte-identical rather than merely present, because a re-rendered alert is a
    different input and the pair would be comparing two cases."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)

    resume(store, run_dir, returns[1], target)

    assert RunPaths(target).alert.read_text(encoding="utf-8") == ALERT_DOC


def test_a_sibling_that_already_has_its_alert_is_not_refused_as_seeded(tmp_path):
    """    An `alert.json` already in the sibling's run dir is not "evidence a fresh sibling must
    not carry" — the resume proceeds.

    The constraint the arm above has to live inside, and the reason `alert.json` cannot simply
    join the list `refuse_seeded_run_dir` reads: `materialize_run_dir` writes the alert into
    EVERY run dir before anything else happens, so a refusal that counted it would refuse every
    branch taken through the ordinary entry point — the same trap `_holds_content`'s own
    docstring records for an empty `gather_raw/`."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)
    RunPaths(target).alert.write_text(ALERT_DOC, encoding="utf-8")

    resume(store, run_dir, returns[1], target)

    assert RunPaths(target).alert.read_text(encoding="utf-8") == ALERT_DOC


@pytest.mark.parametrize("artifact", [
    "report.md",
    "tool_trace.jsonl",
    "budget.json",
    "circuit_breaker.json",
    "policy_denials.jsonl",
    "lessons_loaded.jsonl",
    "review_record.1.json",
    "wire_logs/llm_requests.jsonl",
])
def test_the_sibling_does_not_inherit_the_source_runs_own_account_of_itself(tmp_path, artifact):
    """    Nothing that records how the SOURCE run went crosses to the sibling.

    Three different reasons, one rule. `report.md` is the source's disposition — inheriting it
    hands the sibling the answer the pair exists to not share, and `run.py` parses that
    frontmatter as the run's headline. The counters (`budget.json`, `circuit_breaker.json`) are
    this run's spend and this run's per-system fault tallies: inherited, a sibling starts
    pre-tripped or pre-spent for faults it never took. And the wire log is MAIN's whole
    transcript plus every gather payload verbatim — `_run_paths.WIRE_LOG_DIR` exists precisely
    so it is unreadable to the agents of its own run, and copying it into a fresh run dir
    re-opens that at the one moment the run dir is being assembled.

    `tool_trace.jsonl` is the projection the visualizer reads, and a sibling carrying the
    source's would render one run's trace under another run's id."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    planted = run_dir / artifact
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("the source run's own account\n", encoding="utf-8")
    target = sibling_dir(tmp_path)

    resume(store, run_dir, returns[1], target)

    assert not (target / artifact).exists(), (
        f"the sibling inherited {artifact} — its own record of its own run now opens with "
        "another run's")


# ==========================================================================
# 3. the copy is a boundary
# ==========================================================================

@pytest.mark.parametrize("name", ["executed_queries.jsonl", "gather_raw", "gather_summaries"])
def test_a_symlink_wearing_an_artifacts_name_is_refused_rather_than_followed(tmp_path, name):
    """    An inherited artifact that is a LINK is refused, loudly, and its target's bytes never
    reach the sibling under that name.

    A real hazard, not a hypothetical: the run dir is the box's rw bind, so a link at an
    artifact's name is something the model wrote. `is_file()` and `copytree`'s `symlinks=True`
    both answer about the TARGET or about what is inside the tree — neither about the root they
    were handed — so a plain copy writes the target's bytes into the sibling under an artifact's
    name, where the resumed model, the offline readers and every later gate take them for
    in-run evidence. `artifact_file`/`artifact_dir` are the lstat-based answer and they fail
    closed.

    REFUSED, NOT SKIPPED. A sibling silently missing the evidence its own prefix names reads as
    a run that gathered nothing and then reasoned about it — which is the same shape as the
    branch working, and is exactly what the loud refusal is for."""
    branch = branch_mod()
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "0.json").write_text('{"owner": "not this run"}', encoding="utf-8")
    secret_file = tmp_path / "secret.jsonl"
    secret_file.write_text('{"lead_id": "l-999", "seq": 0}\n', encoding="utf-8")
    planted = run_dir / name
    if planted.is_dir():
        shutil.rmtree(planted)
    else:
        planted.unlink()
    planted.symlink_to(secret if name != "executed_queries.jsonl" else secret_file)
    target = sibling_dir(tmp_path)

    with pytest.raises(branch.BranchError, match=name.split("/")[-1]):
        resume(store, run_dir, returns[1], target)

    assert "not this run" not in "".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in target.rglob("*") if p.is_file()), (
        "the link's target crossed into the sibling wearing an artifact's name")
