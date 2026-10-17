"""#947 Part C — a sibling inherits the evidence its prefix names, and nothing past it."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

from defender.tests._spec1077 import fixture_run

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
from defender.run_repository import RunPaths  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    ALERT_DOC,
    GOLDEN_INVESTIGATION,
    branch_mod,
    legal_source,
    spec_at,
)
from defender.tests._session_store_705 import store_mod  # noqa: E402
from defender.tests._alert_plant import plant_alert

#: The tool a lead is dispatched through. The design calls it `gather_dispatch`; the runtime
GATHER_TOOL = "gather"

#: A lead nothing in MAIN's session dispatched — the shape lead-0's reserved ids have. NOT
#: `l-000`: the rule is a set difference, and an id chosen so that a hardcoded reserved-id list
#: cannot satisfy this file is what proves it.
UNDISPATCHED = "l-zzz"


def dispatch(store, session_id, lead, *, call_id=None, spelling="dict"):
    """One `gather` call/return pair in MAIN's session."""
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
    """A finished run that dispatched three leads and carries a fourth nobody dispatched."""
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
    """Open the sibling the way the driver does, at `message_id`, on a fresh run state for
    `target` (#1235 round 2: seeding takes the sibling's `RunState`, not its run dir)."""
    from defender.runtime.run_state import RunState

    branch = branch_mod()
    return branch.open_main_session(store, spec_at(store, run_dir, message_id),
                                    RunState(target, target.name), run=fixture_run(target), source_run=fixture_run(run_dir))


# 1. which leads existed at the branch point

@pytest.mark.parametrize(("landed", "expected"), [
    (0, {UNDISPATCHED, "l-001"}),
    (1, {UNDISPATCHED, "l-001", "l-002"}),
    (2, {UNDISPATCHED, "l-001", "l-002", "l-003"}),
])
def test_a_lead_counts_from_the_turn_its_dispatch_returned(tmp_path, landed, expected):
    """`leads_at` answers the leads whose gather RETURN landed at or before the branch point."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)

    assert branch_mod().leads_at(store, session_id, returns[landed], run_dir, source_run=_run_handle_1165(run_dir)) == expected


def test_a_dispatch_still_in_flight_at_the_branch_claims_nothing(tmp_path):
    """Branching at a gather CALL, one row before its return, does not count that lead."""
    ss = store_mod()
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    path = ss.path_row_ids(store, session_id)
    call_row = path[path.index(returns[1]) - 1]

    assert branch_mod().leads_at(store, session_id, call_row, run_dir, source_run=_run_handle_1165(run_dir)) == {
        UNDISPATCHED, "l-001"}


def test_a_lead_dispatched_but_never_answered_is_never_inherited(tmp_path):
    """A lead whose dispatch CALL landed and whose return never did is out at every branch point — including the tip, where its call is the last row of..."""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    first = dispatch(store, session_id, "l-001")
    second = dispatch(store, session_id, "l-002")
    unanswered = dispatch_call_only(store, session_id, "l-003")
    evidence(run_dir, [(UNDISPATCHED, 0), ("l-001", 0), ("l-002", 0), ("l-003", 0)])
    leads_at = branch_mod().leads_at

    assert leads_at(store, session_id, first, run_dir, source_run=_run_handle_1165(run_dir)) == {UNDISPATCHED, "l-001"}
    assert leads_at(store, session_id, second, run_dir, source_run=_run_handle_1165(run_dir)) == {UNDISPATCHED, "l-001", "l-002"}
    assert leads_at(store, session_id, unanswered, run_dir, source_run=_run_handle_1165(run_dir)) == {UNDISPATCHED, "l-001", "l-002"}, (
        "the never-answered lead was inherited — its dispatch left no trace in the subtrahend, "
        "so it read as evidence lead-0 had written before the model's first turn")


def test_a_lead_no_dispatch_accounts_for_survives_every_branch_point(tmp_path):
    """A lead in the table that MAIN's session never dispatched is kept at every branch point."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir, source_run=_run_handle_1165(run_dir)) for at in returns]

    assert all(UNDISPATCHED in leads for leads in everywhere), (
        f"the undispatched lead was dropped at some branch point: {everywhere}")


def test_a_lead_named_only_by_a_table_row_still_crosses(tmp_path):
    """A lead whose only trace is a row in `executed_queries.jsonl` survives truncation too."""
    tabled = "l-tableonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)

    assert tabled not in branch_mod().leads_at(store, session_id, returns[0], run_dir, source_run=_run_handle_1165(run_dir)), (
        "the fixture's lead is already known through an artifact, so this arm would pass "
        "against a census that never reads the queries table")
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "lead_id": tabled, "seq": 0, "system": "elastic", "verb": "esql",
            "query_id": "elastic.sshd-failed-by-srcip", "params": {"lead": tabled},
            "payload_path": None, "exit_code": 0, "payload_status": "ok",
        }) + "\n")

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir, source_run=_run_handle_1165(run_dir)) for at in returns]
    assert all(tabled in leads for leads in everywhere), (
        f"a lead named only by its table row is invisible to the lead census ({everywhere}) — "
        "the sibling's inherited table loses a call its own prefix made")

    resume(store, run_dir, returns[1], target)

    assert tabled in {r["lead_id"] for r in read_jsonl_rows(RunPaths(target).executed_queries)}


def test_a_lead_claimed_without_a_captured_row_still_crosses(tmp_path):
    """A lead the source run CLAIMED but recorded no query for is still inherited."""
    claimed = "l-claimonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    (RunPaths(run_dir).gather_raw / f"{claimed}.lead.json").write_text(
        json.dumps({"lead_id": claimed}), encoding="utf-8")
    target = sibling_dir(tmp_path)

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir, source_run=_run_handle_1165(run_dir)) for at in returns]
    assert all(claimed in leads for leads in everywhere), (
        f"a lead with a claim and no captured row is invisible to the lead universe ({everywhere})"
        " — the sibling inherits no claim for it and may re-dispatch an id its own prefix spent")

    resume(store, run_dir, returns[1], target)

    assert (RunPaths(target).gather_raw / f"{claimed}.lead.json").is_file()


def test_a_lead_known_only_by_its_summary_still_crosses(tmp_path):
    """A lead named by nothing but `gather_summaries/{lead}.md` survives truncation too."""
    summarized = "l-summonly"
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    summary = run_dir / "gather_summaries" / f"{summarized}.md"
    target = sibling_dir(tmp_path)

    assert summarized not in branch_mod().leads_at(store, session_id, returns[0], run_dir, source_run=_run_handle_1165(run_dir)), (
        "the fixture's lead is already known through the table or `gather_raw/`, so this arm "
        "would pass against a census that never reads the summaries")
    summary.write_text(f"# {summarized}\nwhat this lead measured\n", encoding="utf-8")

    everywhere = [branch_mod().leads_at(store, session_id, at, run_dir, source_run=_run_handle_1165(run_dir)) for at in returns]
    assert all(summarized in leads for leads in everywhere), (
        f"a lead named only by its summary is invisible to the lead census ({everywhere}) — its "
        "summary is left behind, and with no claim sidecar nothing stops the sibling re-using "
        "the id and writing a second run's summary over that filename")

    resume(store, run_dir, returns[1], target)

    assert (target / "gather_summaries" / f"{summarized}.md").is_file()


def test_a_refusal_clears_the_claim_before_any_later_return_can_pop_it(tmp_path):
    """A `RetryPromptPart` CLEARS the pending claim, so a later return under that id lands nothing at all."""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused_dispatch(store, session_id, "l-004", call_id="reused-1")
    orphan = bare_return(store, session_id, call_id="reused-1")
    # No l-004 artifact here: this arm isolates whether the stale pending entry can make the
    # orphan return LAND it. Pre-existing evidence under a refused id is the separate arm below
    # and must be inherited.
    evidence(run_dir, [(UNDISPATCHED, 0)])

    assert branch_mod().leads_at(store, session_id, orphan, run_dir, source_run=_run_handle_1165(run_dir)) == {UNDISPATCHED}, (
        "a return under a REFUSED call id landed the refused lead — the sibling inherits "
        "evidence on the strength of a dispatch that never ran")


def test_a_refused_retry_does_not_remove_an_inherited_undispatched_lead(tmp_path):
    """A retry-refused call is absent from the dispatch census, not merely from ``pending``."""
    inherited = "l-004"
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused = refused_dispatch(store, session_id, inherited, call_id="already-claimed")
    evidence(run_dir, [(UNDISPATCHED, 0), (inherited, 0)])

    assert branch_mod().leads_at(store, session_id, refused, run_dir, source_run=_run_handle_1165(run_dir)) == {
        UNDISPATCHED, inherited,
    }, "the retry-refused gather erased a pre-existing inherited lead from the census"


def test_a_refused_dispatch_does_not_land_for_whoever_reuses_its_call_id(tmp_path):
    """A refused call lands nothing"""
    store, run_dir, session_id, _path_ids = legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    refused = refused_dispatch(store, session_id, "l-004", call_id="reused-1")
    landed = dispatch(store, session_id, "l-005", call_id="reused-1")
    evidence(run_dir, [(UNDISPATCHED, 0), ("l-004", 0), ("l-005", 0)])
    leads_at = branch_mod().leads_at

    assert leads_at(store, session_id, refused, run_dir, source_run=_run_handle_1165(run_dir)) == {UNDISPATCHED, "l-004"}, (
        "the refused call removed a pre-existing undispatched lead from inherited evidence")
    assert leads_at(store, session_id, landed, run_dir, source_run=_run_handle_1165(run_dir)) == {
        UNDISPATCHED, "l-004", "l-005",
    }, (
        "the return under the reused id credited the REFUSED lead — so the sibling inherits "
        "evidence its prefix never names and drops the lead that actually landed there")


@pytest.mark.parametrize("spelling", ["dict", "json"])
def test_a_dispatch_counts_however_the_provider_spelled_its_arguments(tmp_path, spelling):
    """`ToolCallPart.args` is a dict on the ordinary path and a JSON STRING when the provider hands back unparsed arguments"""
    store, run_dir, session_id, returns = gathering_source(tmp_path, spelling=spelling)

    assert branch_mod().leads_at(store, session_id, returns[0], run_dir, source_run=_run_handle_1165(run_dir)) == {
        UNDISPATCHED, "l-001"}


# 2. what the sibling's run dir ends up holding

def test_the_sibling_inherits_the_leads_the_branch_point_held_and_no_later_one(tmp_path):
    """The sibling's table, payload tree and summaries carry the branch point's leads only."""
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


def test_a_sibling_that_already_has_its_alert_is_not_refused_as_seeded(tmp_path):
    """An `alert.json` already in the sibling's run dir is not "evidence a fresh sibling must not carry" — the resume proceeds."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    target = sibling_dir(tmp_path)
    plant_alert(target, ALERT_DOC.encode("utf-8"))

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
    """Nothing that records how the SOURCE run went crosses to the sibling."""
    store, run_dir, session_id, returns = gathering_source(tmp_path)
    planted = run_dir / artifact
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("the source run's own account\n", encoding="utf-8")
    target = sibling_dir(tmp_path)

    resume(store, run_dir, returns[1], target)

    assert not (target / artifact).exists(), (
        f"the sibling inherited {artifact} — its own record of its own run now opens with "
        "another run's")


# 3. the copy is a boundary

@pytest.mark.parametrize("name", ["executed_queries.jsonl", "gather_raw", "gather_summaries"])
def test_a_symlink_wearing_an_artifacts_name_is_refused_rather_than_followed(tmp_path, name):
    """An inherited artifact that is a LINK is refused, loudly, and its target's bytes never reach the sibling under that name."""
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
