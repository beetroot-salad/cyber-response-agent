"""#632 part 2 — the denial at the runtime site: what the model gets, what moves, what wins.

One test per demand of `spec_graph_632-verb-authorization.yaml`, named by its
`discharged_by`. RED against `d01001e6` by construction.

The ordering §7 settled — R3/R23 as REVERSED at phase F — and which every test below reads
from:

    unknown system → unknown verb → THE GRANT CHECK → the query_id traversal screen
      → param validation → the availability short-circuit → execute

**The grant check runs first.** It beats the malformedness checks, it beats the
caller-supplied id's traversal screen, and it beats the availability short-circuit. The
earlier split (malformed first, then the screen, then the grant) is overturned: its
intersection with the other two paths let a model suppress EVERY policy-denial record for
the life of a run by appending one unrecognised parameter — or one `../` — to any call it
expected to be refused. Three cheap silences beside the one R3's second half was chosen to
close is not a cost anyone accepted; it is the hole itself.

What that ordering buys, and what every test here asserts in its own words:

* A denied call ALWAYS produces its denial audit record. There is no path on which
  authorization is skipped and the refusal goes unrecorded.
* A denied call leaves NO evidence row — full stop, not "when well-formed". The narrowing
  the earlier ordering forced onto every no-evidence-row obligation is WITHDRAWN.
  AMENDED BY #860: "evidence row" means a row a call that REACHED a system wrote. A denied
  call now leaves exactly one `∅.denied` SENTINEL row (`record_query.DENIED_QUERY_ID`) —
  writer-only, split onto `JoinedLead.sentinels` and never `.queries`, partitioned out of
  every learning-loop router by its `∅.` prefix like the repeat trip and the shim failure
  before it — so the offline judge can see that the lead tried and was refused. It consumes
  a seq and an empty sidecar the way every sentinel does; it charges no breaker, counts
  toward no guard, and its `error_class` is `denied`, not `agent-fixable`. `_Run.own_evidence`
  is the "no evidence row" reading; `_Run.own_denied_rows` the sentinel's.
* A call that is both malformed and denied takes the DENIAL path: the model sees the
  denial, not the malformedness.
* The traversal screen no longer precedes authorization. What keeps a hostile
  model-authored `query_id` out of the durable record is now §7 R12's bounded, NORMALIZED
  projection (d66) rather than an ordering — the projection is the sanitizer that column
  was missing, and this file asserts it on the denial path directly.
* The screen SURVIVES the reordering, and is pinned where it still runs. Behind the grant
  check, no denied call reaches it, so nothing about the reversal keeps it alive; the
  granted path is where it is now the first refusal that can fire, and d53 drives it there.
  Without that half the whole screen could be deleted with this suite green.

§7 R11, read literally, is the other rule every label below reads from: a system a role's
grant reaches NOWHERE is UNRESOLVABLE (today's row-written, retry-coached treatment), and
DENIED is the label only for a verb withheld on a system the grant otherwise reaches.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.circuit_breaker import DENIED_ERROR_CLASS  # noqa: E402
from defender.runtime.driver import GATHER_DEF  # noqa: E402
from defender.scripts.gather_tools.record_query import DENIED_QUERY_ID  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DENIED,
    DONE,
    GRANTED,
    LEAD,
    UNDECLARED,
    ScopedFakeVerbs,
    grant_of,
    q,
    recording_table,
    run_gather,
    ticket_envelope,
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402

pytestmark = pytest.mark.e2e

GRANTED_PAIR = ("elastic", "query")
DENIED_PAIR = ("elastic", "esql")
DECLARED = ("query", "esql", "alerts", "health-check")


def _registry(rec: VerbRecorder, *, granted=(GRANTED_PAIR,), declared=DECLARED,
              systems=("elastic",), raises: BaseException | None = None) -> ScopedFakeVerbs:
    """One system declaring `declared`, a grant naming only `granted` — so `elastic.esql` is
    DECLARED AND WITHHELD (a denial) while `elastic.nosuch` is undeclared (today's path)."""
    table = recording_table(rec, {s: declared for s in systems}, raises=raises)
    return ScopedFakeVerbs(table, grant_of("gather", granted))




def test_a_denied_verb_returns_a_legible_refusal_and_the_run_continues(tmp_path: Path):
    """A verb the role's verb_grant does not name returns a plain legible refusal as the
    tool's ORDINARY result — nothing raised for the driver to catch, no evidence row (one
    `∅.denied` sentinel, #860), no circuit-breaker contribution — and the agent's next turn
    still runs.

    §7 R2 settles this as the pinned reading, no longer provisional: the refusal is a
    business outcome, and only a missing audit record is an infrastructure fault. The shape
    is the one zero-state refusal the codebase already has — the breaker's early return
    (n6) — never a `ModelRetry`, which the design forbids because a denial is either a
    policy bug or an injection attempt and neither is fixable by retrying."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE], run_id="d0")

    assert rec.calls == [], "the denied verb body ran"
    assert r.gather.calls >= 2, "the refusal did not come back as a result the loop continued past"
    assert r.own_evidence == [], "a denied call wrote an evidence row"
    assert len(r.own_denied_rows) == 1, "the denial left no `∅.denied` sentinel row (#860)"
    assert r.breaker.get("total_failures", 0) == 0
    assert "esql" in r.gather_saw


def test_a_denial_reaches_the_model_even_when_its_row_cannot_be_written(tmp_path: Path):
    """§7 R2, held at the row: a denial is a BUSINESS outcome the model must see and continue
    past, and the `∅.denied` row (#860) is written after the audit record and before the
    refusal is returned — so a row write that faults (the table replaced by a directory here;
    a planted link or a full disk in the box) must not turn "not granted" into an `OSError`
    that escapes the capability and ends the lead. Reported to stderr and dropped, the way
    the estate seam drops a failed `refused` row: the refusal is what propagates.

    The table is broken from INSIDE the gather leg's first model turn, so lead-0's own rows
    and the dispatch have already landed and only the denied call's write meets the fault.

    Observed failing by: the gather loop stopping at one call (the exception ended the lead),
    or the refusal text absent from what the model saw."""
    from defender._run_paths import RunPaths
    from defender.tests._verb_authorization_632 import _Run
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, ReplayFn, Turn, drive, materialize

    class BreakingReplay(ReplayFn):
        def __init__(self, turns, run_dir):
            super().__init__(turns)
            self.run_dir = run_dir

        def __call__(self, messages, info):  # noqa: ANN001 — the framework's callable protocol
            if self.calls == 0:
                table = RunPaths(self.run_dir).executed_queries
                table.unlink()
                table.mkdir()
            return super().__call__(messages, info)

    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = BreakingReplay([q(*DENIED_PAIR), DONE], run_dir)
    drive(run_dir, run_id="d0-broken-table", main=main, gather=gather, verbs=_registry(rec))
    r = _Run(run_dir, main, gather)

    assert rec.calls == [], "the denied verb body ran"
    assert r.gather.calls >= 2, \
        "the row-write fault ended the lead: the refusal never came back as a result"
    assert "not granted" in r.gather_saw, "the model did not see the refusal"
    assert "esql" in r.gather_saw, "the refusal the model saw does not name the verb"
    assert len(r.own_denials) == 1, "the audit record — written FIRST — is missing"


def test_a_denied_verb_is_not_the_unknown_verb_path(tmp_path: Path):
    """A denied verb is refused WITHOUT the evidence row, the `agent-fixable` class or the
    retry coaching that an undeclared verb still gets. Absence shapes the catalog; a
    distinguishable error shapes the call — and building the per-role view by narrowing the
    same verb map the unknown-verb branch reads is the shape that collapses them (§7 R2)."""
    rec = VerbRecorder()
    denied = run_gather(tmp_path / "a", verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE],
                        run_id="d2-denied")
    unknown = run_gather(tmp_path / "b", verbs=_registry(rec),
                         turns=[q("elastic", "nosuch-verb"), DONE], run_id="d2-unknown")

    assert denied.own_evidence == []
    assert [row["error_class"] for row in denied.own_denied_rows] == [DENIED_ERROR_CLASS], \
        "the denial's sentinel row reads as something a retry could fix"
    assert len(unknown.own_rows) == 1, "an undeclared verb stopped writing its row"
    assert unknown.own_rows[0]["error_class"] == "agent-fixable"
    assert denied.own_denials, "the denial left no audit record at all"
    assert unknown.own_denials == [], "an undeclared verb was audited as a policy denial"


def test_an_undeclared_verb_keeps_todays_unknown_verb_treatment(tmp_path: Path):
    """A verb no adapter declares still gets today's unknown-verb treatment — the queries
    row, the `agent-fixable` class and the retry coaching. The complementary positive
    control for the denial's negative: the two never-executed calls stay two treatments,
    because the model mis-forming a call is something gather can learn from and being denied
    is not."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q("elastic", "nosuch-verb"), DONE],
                   run_id="d37")

    assert rec.calls == []
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["exit_code"] != 0
    assert r.own_rows[0]["error_class"] == "agent-fixable"
    assert r.own_rows[0]["verb"] == "nosuch-verb"
    assert r.gather.calls >= 2, "the unknown verb did not bounce the agent back into its loop"


def test_a_denial_names_the_system_and_verb_it_refused(tmp_path: Path):
    """The refusal a denied call returns names the system and the verb it refused, rather
    than a generic invalid-input message. Surface hiding is not an objective; denial
    messages stay legible."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE], run_id="d24")

    seen = r.gather_saw
    assert "elastic" in seen
    assert "esql" in seen
    assert rec.calls == []


def test_a_refusal_lists_only_the_roles_granted_subset(tmp_path: Path):
    """A refusal enumerates only the verbs the role's verb_grant reaches for that system,
    never the full adapter set, and a system the grant reaches NOWHERE reads as unresolvable
    — it lists nothing (§7 R11). The design's reason for not hardening this message was that
    the catalog is handed to the model in full; R-A2 narrowed exactly that catalog, so the
    reject path's listing would otherwise be the wider channel.

    Checked on the DENIAL'S OWN DELTA, not the whole ambient prompt. The dispatch
    catalog/template index is a ROLE-LEVEL surface scoped to GATHER_DEF's real committed
    grant (matching what the generated roster and its audit are scored against, not
    whatever narrower ad-hoc registry a particular test injects for query execution) — so
    gather's REAL grant, which really does hold `elastic.alerts`, legitimately advertises it
    ambiently regardless of this test's own registry. What this demand pins is that the
    REFUSAL ITSELF adds nothing wider than what it refused, which `gather_delta` (the text
    this exact tool call contributed, past the ambient dispatch prompt) isolates.

    Recorded and NOT built (RS4): cumulative probing across every pair still reconstructs
    the grant, accepted under the design's stated non-objective on surface hiding.

    Recorded and NOT built (RS14): because a wholly ungranted system is UNRESOLVABLE rather
    than denied, a call into one produces no policy-denial record — the probe that maps a
    role's systems leaves its trace in the queries table, not in the denial stream. That is
    R11's own consequence, not a widening of it, and the only silence the grant-first
    ordering does not close."""
    rec = VerbRecorder()
    reg = _registry(rec, granted=(GRANTED_PAIR,), systems=("elastic", "ticket"))

    partial_ = run_gather(tmp_path / "a", verbs=reg, turns=[q(*DENIED_PAIR), DONE],
                          run_id="d65-partial")
    assert "esql" in partial_.gather_delta, "the refusal did not name the verb it refused"
    assert "alerts" not in partial_.gather_delta, \
        "the refusal itself listed a verb the grant withholds"

    whole = run_gather(tmp_path / "b", verbs=reg, system="ticket",
                       turns=[q("ticket", "query"), DONE], run_id="d65-whole")
    assert reg.decide("ticket", "query").outcome == UNDECLARED, \
        "a wholly ungranted system read as denied rather than unresolvable"
    assert len(whole.own_rows) == 1, "a wholly ungranted system wrote no unresolvable row"
    assert whole.own_denials == [], "a wholly ungranted system was audited as a policy denial"




def test_a_denied_gather_verb_leaves_only_its_sentinel_row_and_an_empty_sidecar(tmp_path: Path):
    """A denied gather verb CONSERVES the run's evidence surface and allocates only what its
    `∅.denied` sentinel is: everything the run had written before the denied call is
    byte-identical afterwards (the queries table appended to, never rewritten), and what a
    QUERY call allocates — a query row, a payload — is absent. Since #860 the denial takes a
    sequence number and an EMPTY sidecar, exactly as the repeat trip and the shim failure do,
    because the sidecar must exist for the row to survive `extract_from_joined`.

    CONSERVATION IS THE LOAD-BEARING HALF, and absence alone is not enough. "Leaves nothing
    behind" read as an empty tree is satisfiable by DESTROYING evidence, and an implementer
    attacking exactly this assertion did that: after a denial it deleted the lead's dispatch
    sidecar and its queries row, which is strictly worse than the state it was hiding. A
    snapshot taken before the call and required to match afterwards catches that; a scoped
    absence check cannot, because the deleted file is absent either way.

    The two kinds of state are DISJOINT BY PATH, which is what makes both halves assertable
    at once. Dispatch writes one flat sidecar at the root of the payload tree, consumes no
    sequence number and does not create the lead-scoped subdirectory; a query call writes only
    inside that subdirectory. A recursive glob of the whole tree conflates them and demands an
    empty tree no correct implementation can produce — which is why the scoped
    `payload_files` and the conservation snapshot replace it rather than joining it.

    Also carries the whole-lead consensus: a lead every query of which was denied leaves
    ZERO query rows on the evidence surface. What keeps the denial out of the learning
    loop's input is no longer absence but the `∅.` partition every router already applies
    (`draft_synthesis`, `_handoff`, `capture`, the branch precondition) — pinned in
    `test_a_denials_sentinel_row_is_a_sentinel_to_every_reader` below.

    NO NARROWING. Under the grant-first ordering this holds for every denied call, whatever
    else is wrong with it: a malformed-and-denied call and a traversal-shaped-id denied call
    both take the denial path and both leave no row, pinned separately. The earlier
    "well-formed denied calls only" scoping is withdrawn — it existed only because
    authorization used to run last."""
    rec = VerbRecorder()
    r = run_gather(tmp_path / "denied", verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR), q("elastic", "alerts"), DONE], run_id="d3",
                   watch=True)

    assert rec.calls == [], "a denied verb body ran"
    assert r.own_evidence == [], \
        "a lead whose every query was denied still put query rows on the evidence surface"
    assert [row["query_id"] for row in r.own_rows] == [DENIED_QUERY_ID, DENIED_QUERY_ID], \
        "the two denials are not the lead's two `∅.denied` rows and nothing else"
    assert [f.read_bytes() for f in r.payload_files] == [b"", b""], \
        "a denial's sidecar carries bytes — a denied call has no payload to persist"
    assert len(r.own_denials) == 2, "the two denials are not both in the audit stream"

    # Conservation. The snapshots straddle the two denied calls; the first is the state the
    # dispatch left, and it must survive them byte for byte — the queries table APPENDED TO
    # (its prior bytes a prefix of its later ones), nothing else touched, and the only
    # additions the two sentinels' own empty sidecars (plus the table itself, when lead-0
    # wrote no row before the dispatch).
    assert len(r.snapshots) >= 3, "the drive did not straddle both denied calls"
    before, after = r.snapshots[0], r.snapshots[-1]
    assert before, "the pre-call snapshot is empty — conservation would hold vacuously"
    table = "executed_queries.jsonl"
    assert sorted(set(before) - set(after)) == [], "a denial removed evidence the run had allocated"
    assert sorted(k for k in set(before) & set(after) if before[k] != after[k] and k != table) == [], \
        "a denial rewrote evidence the run had allocated"
    if table in before:
        assert after[table].startswith(before[table]), "the queries table was rewritten, not appended to"
    sidecars = {f"gather_raw/{LEAD}/{row['seq']}.json" for row in r.own_denied_rows}
    assert set(after) - set(before) <= sidecars | {table}, (
        "a denial added something beyond its sentinel's own sidecar: "
        f"{sorted(set(after) - set(before) - sidecars - {table})}"
    )
    assert (r.run_dir / "gather_raw" / f"{LEAD}.lead.json").is_file(), \
        "the lead's own dispatch sidecar was destroyed to make the tree look untouched"

    # The sequence counter, observed where it is observable: the sentinel takes a number
    # like every sentinel (#860), so the FIRST granted call after two denials takes seq 2,
    # and the two numbers before it are the denials' own — neither skipped nor shared.
    kept = VerbRecorder()
    later = run_gather(tmp_path / "then-granted", verbs=_registry(kept),
                       turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*GRANTED_PAIR), DONE],
                       run_id="d3-seq")
    assert [c.verb for c in kept.calls] == ["query"]
    assert [(row["seq"], row["query_id"]) for row in later.own_rows] \
        == [(0, DENIED_QUERY_ID), (1, DENIED_QUERY_ID), (2, "elastic.query")], \
        "the denials' sentinel rows and the granted row do not take consecutive seqs in order"


def test_a_granted_gather_verb_still_writes_its_row_and_its_payload(tmp_path: Path):
    """A granted gather verb still writes its queries row and its
    `gather_raw/{lead_id}/{seq}.json` payload, unchanged. The positive control the negative
    above needs: proof the evidence surface is observable at all, so `no row` is a
    difference the channel can see rather than an empty run."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*GRANTED_PAIR), DONE], run_id="d31")

    assert [c.verb for c in rec.calls] == ["query"]
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["exit_code"] == 0
    assert r.own_rows[0]["seq"] == 0
    assert (r.run_dir / "gather_raw" / LEAD / "0.json").is_file()
    assert r.own_denials == [], "a granted call was audited as a policy denial"


def test_a_denial_is_the_dispatched_leads_own_row_and_the_audit_record_is_the_runs(tmp_path: Path):
    """The DECISION needs no lead context — the grant is a function of role, system and verb —
    but since #860 the denial's ROW is the dispatching lead's own conduct: its `lead_id` is
    the lead the call was refused inside, which is how the offline judge finds it (the lead
    whose only activity was a withheld verb used to be invisible there). The audit record
    stays what it was — a fact about the RUN, §7 R12's bounded projection, with no lead
    column: the row carries the attribution, the record carries the policy fact, and neither
    is derived from the other."""
    rec = VerbRecorder()
    reg = _registry(rec)

    decision = reg.decide(*DENIED_PAIR)
    assert decision.outcome == DENIED
    assert decision.refusal is not None
    assert "esql" in decision.refusal

    r = run_gather(tmp_path, verbs=reg, turns=[q(*DENIED_PAIR), DONE], run_id="d44")
    assert len(r.own_denials) == 1, "the denial was not audited at all"
    assert "lead_id" not in r.own_denials[0], \
        "the audit record grew a lead column — attribution is the row's job, not the record's"
    assert [(row["lead_id"], row["system"], row["verb"]) for row in r.own_denied_rows] \
        == [(LEAD, *DENIED_PAIR)], "the denial's row does not name the lead it was refused inside"
    assert r.own_evidence == [], "the denial allocated a query row"




def test_a_lead_less_call_is_the_same_internal_error_at_every_capture_frame(tmp_path: Path):
    """The premise d44 retired: a denial is the dispatching lead's own row, so the capture has
    NO lead-less path any more — and the two frames that touch the queries table say so the
    same way. The rejection guard used to answer `None` for deps with no `lead_id` while the
    row write two lines later raised on the same deps; a denial routed through both turned a
    policy refusal into an internal error at the second frame after the first had let it
    through. Observably: the guard raises the row write's own `RuntimeError`, before reading
    the table (positive control: the same guard, with a lead, reads it and answers `None`)."""
    from defender._paths import PATHS
    from defender.runtime import tools
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.query_tool import QueryCapture

    policy = compile_policy_for(GATHER_DEF, run_dir=tmp_path, defender_dir=PATHS.defender_dir)
    ident = dict(run_dir=tmp_path, defender_dir=PATHS.defender_dir, run_id=tmp_path.name,
                 cwd_anchor=tmp_path, policy=policy)
    capture = QueryCapture(_registry(VerbRecorder()))

    with pytest.raises(RuntimeError, match="without a dispatched lead_id"):
        capture._rejection_guard(
            tools.GatherDeps(**ident), "elastic", "esql", {}, system_key="")
    assert capture._rejection_guard(
        tools.GatherDeps(**ident, lead_id=LEAD), "elastic", "esql", {}, system_key="",
    ) is None, "positive control: with a lead, an empty table trips nothing"


def test_a_malformed_call_keeps_todays_queries_row(tmp_path: Path):
    """A malformed call on a GRANTED verb — the model mis-forming a query it is entitled to
    make — still writes its queries row, because gather can learn from that; being denied is
    not something to learn from. Two kinds of never-executed call, two treatments.

    The call is granted on purpose: under the grant-first ordering the malformedness check
    is reached only once authorization has admitted the call, so this is the only situation
    in which the malformed path is the one taken."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*GRANTED_PAIR, {"nosuch_param": 1}), DONE], run_id="d5")

    assert rec.calls == []
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["error_class"] == "agent-fixable"
    assert r.own_denials == []


def test_a_malformed_and_denied_call_takes_the_denial_path(tmp_path: Path):
    """A call that is both malformed AND denied takes the DENIAL path: the grant check runs
    first, so the model sees the denial rather than the malformedness, no query row is
    written (the `∅.denied` sentinel is), and the denial IS audited.

    This is the ordering reversed at phase F, and the reason is the composition the earlier
    split created: with the malformed check first, appending one unrecognised parameter to
    every call it expected to be refused let a model produce zero denial records for the
    life of a run, with nothing in the record noticing. A refusal a caller can choose the
    flavour of is not an authorization decision."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR, {"nosuch_param": 1}), DONE], run_id="d55")

    assert rec.calls == []
    assert r.own_evidence == [], "the malformed-and-denied call still left an evidence row"
    assert len(r.own_denied_rows) == 1, "the malformed-and-denied call took the malformed path's row"
    assert len(r.own_denials) == 1, \
        "one unrecognised parameter suppressed the denial record — the malformed check ran first"
    assert r.own_denials[0]["verb"] == "esql"
    assert "esql" in r.gather_saw, "the model saw the malformedness, not the denial"


def test_a_denied_call_is_refused_before_its_query_id_meets_the_traversal_screen(tmp_path: Path):
    """A denied call carrying a path-traversal `query_id` is refused by the GRANT CHECK,
    ahead of the traversal screen: no query row (the `∅.denied` sentinel, whose id is the
    writer's and never the model's), a denial record written, and the model sees the denial
    reason rather than the traversal reason (§7 R23, reversed at phase F
    along with R3 — the screen was the third cheap silence).

    What R23's ordering used to buy — a hostile model-authored id kept out of the durable
    record — is now bought by §7 R12's bounded, NORMALIZED projection instead: the record
    identifies the call without carrying the raw string the model chose. That is asserted
    here, on the denial path, because reversing the ordering without it would re-open
    exactly the hazard R23 named.

    THE SCREEN ITSELF IS PINNED ON THE GRANTED PATH, and that half is the conservation the
    reordering owes. Moving authorization in front of the screen means no denied call reaches
    it any more, so the reversal alone leaves an implementation free to DELETE the screen and
    ship every test in this suite green — a granted call's model-authored id would then reach
    catalog-path construction unscreened, which is the hazard R23 was chosen to close. The
    complementary condition is therefore driven below: the same hostile id on a GRANTED verb,
    where the screen is now the first refusal that can fire. It keeps today's malformed
    treatment unchanged (a queries row, agent-fixable, retry coaching) and the model-authored
    id never becomes the row's catalog id."""
    hostile = "elastic.../../../../tmp/PWNED"
    rec = VerbRecorder()
    r = run_gather(tmp_path / "denied", verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR, query_id=hostile), DONE], run_id="d53")

    assert rec.calls == []
    assert r.own_evidence == [], "the traversal-and-denied call still left an evidence row"
    assert len(r.own_denials) == 1, "the traversal screen ran first and suppressed the denial record"
    assert "esql" in r.gather_saw, "the model saw the traversal reason, not the denial"

    record = r.own_denials[0]
    assert hostile not in json.dumps(record), \
        "the raw model-authored traversal id landed in the durable denial record unnormalized"
    # The same hazard on the ROW (#860): the sentinel's id is the writer's literal, and the
    # model's string reaches no column of it.
    assert [row["query_id"] for row in r.own_denied_rows] == [DENIED_QUERY_ID]
    assert hostile not in json.dumps(r.own_denied_rows), \
        "the raw model-authored traversal id landed in the denial's sentinel row"
    assert record.get("call_id"), "the record identifies no call at all — the projection is empty"

    # The screen, where it is still reachable: authorization admits the call, so the screen is
    # what must refuse it. Without this every assertion above survives the screen's deletion.
    kept = VerbRecorder()
    screened = run_gather(tmp_path / "granted", verbs=_registry(kept),
                          turns=[q(*GRANTED_PAIR, query_id=hostile), DONE], run_id="d53-screen")

    assert kept.calls == [], \
        "a granted call's traversal-shaped query_id reached the verb — the screen is gone"
    assert len(screened.own_rows) == 1, \
        "the screened call lost the malformed treatment the screen has always given it"
    assert screened.own_rows[0]["error_class"] == "agent-fixable"
    assert screened.own_rows[0]["query_id"] != hostile, \
        "the model-authored traversal id became the call's catalog id"
    assert screened.own_denials == [], \
        "a granted call refused by the traversal screen was audited as a policy denial"


def test_a_denial_is_decided_before_the_availability_short_circuit(tmp_path: Path):
    """A denial against a system this run has already given up on is still DECIDED and
    AUDITED: the grant check runs before the availability short-circuit (§7 R3). Without
    this ordering an attacker who first exhausts a system silences the audit trail for it —
    the short-circuit refuses with no record at all, so the denial would never be evaluated.

    The refusal the model sees is the denial's, not the breaker's down-message."""
    from defender.scripts.adapters.faults import TransportFault

    rec = VerbRecorder()
    assert circuit_breaker.PER_SYSTEM_FAIL_LIMIT == 2, "the trip budget moved; the script below is stale"

    r = run_gather(tmp_path, verbs=_registry(rec, raises=TransportFault("down")), turns=[
        q(*GRANTED_PAIR), q(*GRANTED_PAIR),   # two infra faults trip `elastic` for this run
        q(*DENIED_PAIR),                      # ... and the denial must still be evaluated
        DONE,
    ], run_id="d56")

    assert circuit_breaker.is_tripped(r.run_dir, "elastic"), "the system never went down"
    assert len(r.own_denials) == 1, "the availability short-circuit silenced the denial's audit record"
    assert r.own_denials[0]["verb"] == "esql"
    assert len(r.own_evidence) == 2, "the denial against a down system wrote an evidence row"
    assert len(r.own_denied_rows) == 1, "the down-message short-circuited the denial's own row"




def test_a_denial_does_not_move_the_circuit_breaker(tmp_path: Path):
    """A denial contributes nothing to the circuit breaker, matching the closed-ticket
    tool's existing rule that a business refusal is not an infra fault. Partly free by
    construction — the breaker no-ops unless the exit code is an infra one (n10) — so what
    this guards is the EXIT-CODE CHOICE: a `policy-denial` outcome must never be filed under
    an infra code.

    Ordering is load-bearing: the breaker raises the run-wide kill switch AFTER the row is
    appended, deliberately, and a denial short-circuit inserted upstream must not invert
    that."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*DENIED_PAIR), DONE], run_id="d10")

    assert r.breaker.get("total_failures", 0) == 0
    assert r.breaker.get("systems", {}) == {}
    assert r.main.calls == 2, "the run did not continue past three denials"
    # The exit-code choice, read off the row the denial writes since #860: outside the infra
    # set (so the three rows above charged nothing) and NOT the generic fault code the model
    # used to see, so a reader of the table tells a withheld verb from an outage without
    # parsing the detail.
    assert {row["exit_code"] for row in r.own_denied_rows} == {circuit_breaker.DENIED_EXIT_CODE}
    assert not circuit_breaker.is_infra_failure(circuit_breaker.DENIED_EXIT_CODE)


def test_a_denials_sentinel_row_is_a_sentinel_to_every_reader(tmp_path: Path):
    """The `∅.denied` row (#860) is a SENTINEL to every reader that partitions on the
    prefix, and outside both repeat guards' domains — which is what lets it exist at all
    where §7 R3 used to say "no row": the offline join files it under `.sentinels` and never
    `.queries` (so the learning loop's routers, which read `.queries` or ask `is_sentinel`,
    never see it), a model cannot spell its id onto a real query, and three identical denials
    are three rows and no trip on either guard — the live run never reaches a guard for a
    denied call, so a replay that counted them would report a stop the run never made."""
    from defender.learning.lead_repository import joined
    from defender.runtime.query_tool import resolve_query_id
    from defender.scripts.gather_tools.record_query import (
        in_rejection_domain,
        is_reserved_query_id,
        rejection_budget_trip,
        repeat_trip,
    )

    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*DENIED_PAIR), DONE], run_id="d86")
    assert len(r.own_denied_rows) == 3
    assert r.own_evidence == []

    lead = next(lead for lead in joined(r.run_dir) if lead.lead_id == LEAD)
    assert lead.queries == [], "a denial reached `.queries` — the learning loop's input"
    assert [row.query_id for row in lead.sentinels] == [DENIED_QUERY_ID] * 3
    assert all(row.is_sentinel for row in lead.sentinels)
    assert all(row.error_class == DENIED_ERROR_CLASS for row in lead.sentinels)

    assert is_reserved_query_id(DENIED_QUERY_ID)
    assert resolve_query_id("elastic", "query", DENIED_QUERY_ID) != DENIED_QUERY_ID, \
        "a model spelled the denial's own id onto a query"

    rows = r.rows
    params = dict(r.own_denied_rows[0]["params"])
    assert repeat_trip(rows, LEAD, system=DENIED_PAIR[0], verb=DENIED_PAIR[1], params=params) is None, \
        "three denials tripped the repeat guard — the replay reports a stop the live run never made"
    assert not any(in_rejection_domain(row) for row in rows), \
        "a denial's row entered the rejection domain — it is neither above-guard nor agent-fixable"
    assert rejection_budget_trip(rows, LEAD, budget=3) is None


def test_an_infra_fault_still_moves_the_circuit_breaker(tmp_path: Path):
    """A GRANTED call's backend outage stays an infra fault and still moves the circuit
    breaker — distinguishable from a policy denial in BOTH the audit trail and the breaker.
    The positive control the denial's breaker negative needs: proof the breaker channel can
    see a difference at all.

    The fault the fake raises is the transport fault the #611 ledger observed on the real
    adapters, not an author-imagined one."""
    from defender.scripts.adapters.faults import TransportFault

    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec, raises=TransportFault("connection refused")),
                   turns=[q(*GRANTED_PAIR), DONE], run_id="d33")

    assert len(rec.calls) == 1, "the granted verb never ran — the outage is not the fault under test"
    assert r.own_rows[0]["error_class"] == "infra"
    assert r.breaker["systems"]["elastic"]["failures"] == 1
    assert r.own_denials == [], "an infra fault was relabelled into the policy-denial stream"




def test_a_denial_is_decided_from_the_grant_without_importing_the_adapter(tmp_path: Path):
    """A denial is decided from the verb_grant ALONE: a system whose adapter cannot be
    imported at all is still refused observably, and a broken import neither produces the
    refusal nor masks it. This is what makes the deny decision independent of the
    fault-containment posture — and what the load check's totality rests on.

    THE DENIAL LEG IS DRIVEN ON THE UNLOADABLE SYSTEM, and that placement is the whole point.
    Putting only the UNRESOLVABLE verdict on the broken adapter leaves the denial leg decided
    against a module that imports cleanly, so the property "no import is needed to deny" is
    never observed — and an implementation that wraps the decision in a broad `except` and
    falls back to UNRESOLVABLE passes, silently downgrading every denial on any system whose
    adapter is momentarily unimportable into an outcome that is neither refused as policy nor
    audited. `cmdb` below therefore has a grant entry (so the grant REACHES it), a second
    declared verb the grant withholds (so that verb is a denial), and an adapter that raises
    on import (so any implementation that touches it to decide raises or downgrades).

    The two labels differ and both are decided without the import (§7 R11, read literally):
    `mystery` is a system this grant reaches nowhere, so it is UNRESOLVABLE, while
    `elastic.esql` and `cmdb.list-hosts` are verbs withheld on systems the grant does reach,
    so they are DENIED. Neither verdict needs the adapter, which is the property under test.

    The audit half is driven end to end rather than at the decision seam, because "downgraded
    to unresolvable" and "denied" differ in what lands on disk: the downgrade writes a queries
    row and no denial record, which is the observable that separates the exploit from the
    correct implementation."""
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "elastic_adapter.py").write_text(
        "def query(ctx, *, native_query: str) -> dict:\n    return {}\n"
        "VERBS = {'query': query, 'esql': query}\n", encoding="utf-8")
    (adapters / "cmdb_adapter.py").write_text(
        "raise ImportError('boom')\n"
        "VERBS = {'get-host': None, 'list-hosts': None}\n", encoding="utf-8")

    from defender.runtime.verbs import ModuleVerbRegistry

    grant = grant_of("gather", (("elastic", "query"), ("cmdb", "get-host")))
    reg = ModuleVerbRegistry(read_roster(adapters), grant)
    assert reg.decide("mystery", "get-host").outcome == UNDECLARED, \
        "a system the grant reaches nowhere resolved to something other than unresolvable"
    assert reg.decide("elastic", "esql").outcome == DENIED
    assert reg.decide("elastic", "query").outcome == GRANTED
    assert reg.decide("cmdb", "list-hosts").outcome == DENIED, (
        "a verb withheld on a system whose adapter cannot be imported was not denied — the "
        "decision reached for the module instead of the grant, or swallowed the import error "
        "and downgraded the denial to unresolvable"
    )

    r = run_gather(tmp_path / "run", verbs=reg, system="cmdb",
                   turns=[q("cmdb", "list-hosts"), DONE], run_id="d38-unloadable")
    assert [row["query_id"] for row in r.own_rows] == [DENIED_QUERY_ID], \
        "the denial on an unloadable system was recorded as an unresolvable query instead"
    assert len(r.own_denials) == 1, \
        "a denial on an unloadable system produced no audit record — it was downgraded"
    assert r.own_denials[0]["verb"] == "list-hosts"


def test_a_transient_adapter_import_failure_does_not_stick_across_a_run(tmp_path: Path):
    """A one-time adapter import failure does not stick as a permanent denial, and each call
    to a broken system pays its cost fresh: no remembered failure state changes what a later
    call experiences. Guards the fault-containment posture from being re-introduced as a
    cache — which would make a transient glitch indistinguishable from a policy decision for
    the rest of the run."""
    rec = VerbRecorder()
    calls: list[int] = []

    def flaky(ctx, *, native_query: str = "FROM logs", **rest):
        calls.append(1)
        rec.record("query", ctx, {"native_query": native_query})
        if len(calls) == 1:
            raise ImportError("transient: the adapter's dependency was not yet importable")
        return [{"ok": True}]

    reg = ScopedFakeVerbs({"elastic": {"query": flaky}}, grant_of("gather", (GRANTED_PAIR,)))
    r = run_gather(tmp_path, verbs=reg, turns=[q(*GRANTED_PAIR), q(*GRANTED_PAIR), DONE],
                   run_id="d39")

    assert len(calls) == 2, "the second call was answered from a remembered failure"
    assert len(r.own_rows) == 2
    assert r.own_rows[1]["exit_code"] == 0, "the retry inherited the first call's failure"
    assert r.own_denials == [], "an import failure was recorded as a policy denial"


def test_repeated_identical_denials_each_audit_and_never_move_run_state(tmp_path: Path):
    """Every denied call appends its OWN audit record — no dedup key, no per-run cache — and
    the hundredth identical denial has still moved no run state, so the first and the
    hundredth are indistinguishable in everything except the audit stream.

    Recorded and NOT built (RS6): that indistinguishability is exactly why a denial loop has
    no exit. The design refuses to coach a retry and nothing else ends the loop, so a model
    re-issuing a denied call spins until the run-level budget stops it. Neither obvious home
    for a counter is legal — the circuit breaker is for infrastructure faults, and the
    `∅.denied` rows (#860) sit outside both repeat guards' domains by construction, so
    n identical denials are n rows and never a trip."""
    rec = VerbRecorder()
    n = 5
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[*(q(*DENIED_PAIR) for _ in range(n)), DONE],
                   run_id="d42")

    assert len(r.own_denials) == n, "denials were deduplicated or cached"
    assert r.own_evidence == []
    assert len(r.own_denied_rows) == n, "the nth identical denial was counted, tripped or deduplicated"
    assert r.breaker.get("total_failures", 0) == 0
    assert rec.calls == []


@pytest.mark.parametrize(("system", "verb"), [
    ("Elastic", "query"), (" elastic", "query"), ("elastic ", "query"),
    ("elastic", "QUERY"), ("elastic", " query"), ("elastic", "query "),
])
def test_a_case_or_whitespace_variant_of_a_granted_name_never_executes(
    tmp_path: Path, system: str, verb: str,
):
    """A case or whitespace variant of a granted system name or a granted verb name is never
    treated as granted and never executes: no normalization equates it to the real name.

    §7 R11 fixes the LABEL the three answering copies left open: a near-miss resolves to
    nothing in the registry, so it reads as UNRESOLVABLE — today's row-written,
    retry-coached treatment — not as a denial. The two differ in written state, which is why
    the label had to be decided rather than inferred."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(system, verb), DONE],
                   run_id=f"d48-{abs(hash((system, verb)))}")

    assert rec.calls == [], f"the near-miss {system}.{verb} reached a verb body"
    assert r.own_denials == [], "a near-miss was audited as a policy denial rather than unresolvable"
    assert len(r.own_rows) == 1, "a near-miss wrote no unresolvable row"
    assert r.own_rows[0]["exit_code"] != 0




def test_gather_is_denied_ticket_get_ticket(tmp_path: Path):
    """Gather is denied `ticket.get-ticket`, which only the judge uses. The verb_grant
    subsumes a hand-written rule: reducing gather to `list-tickets` makes the self-case
    exclusion's GET branch unreachable. A class-shaped grant could not have expressed this —
    both are reads on a system gather legitimately holds."""
    rec = VerbRecorder()
    reg = ScopedFakeVerbs(
        recording_table(rec, {"ticket": ("list-tickets", "get-ticket")}),
        GATHER_DEF.verb_grant,
    )
    r = run_gather(tmp_path, verbs=reg, system="ticket",
                   turns=[q("ticket", "get-ticket", {"key": "SOC-1"}), DONE], run_id="d22")

    assert rec.calls == [], "gather reached get-ticket"
    assert r.own_evidence == []
    assert len(r.own_denials) == 1
    assert r.own_denials[0]["verb"] == "get-ticket"


def test_gather_list_tickets_still_reaches_the_store(tmp_path: Path):
    """Gather's `ticket.list-tickets` still reaches the ticket store, unchanged. The
    positive control for the denial above: the same system, through the same registry
    lookup, on the verb the verb_grant does name.

    THE FAKE ANSWERS IN THE STORE'S REAL ENVELOPE SHAPE, and that is a correction rather than
    a detail. The list endpoint answers `{"total", "tickets"}` and gather's ticket screen
    enforces that shape as a contract — a bare array is filed as malformed. A fake handing
    back a bare array while this test demanded `exit_code == 0` made the two demands
    contradict at the edges: the only implementation satisfying both is one whose screen skips
    non-object payloads, which is exactly the bypass that lets the self-case exclusion be
    dodged by changing the response's shape."""
    rec = VerbRecorder()

    def list_tickets(ctx, **params):
        rec.record("list-tickets", ctx, params)
        return ticket_envelope("SOC-777")

    table = recording_table(rec, {"ticket": ("get-ticket",)})
    table["ticket"]["list-tickets"] = list_tickets
    reg = ScopedFakeVerbs(table, GATHER_DEF.verb_grant)
    r = run_gather(tmp_path, verbs=reg, system="ticket",
                   turns=[q("ticket", "list-tickets", {}), DONE], run_id="d34")

    assert [c.verb for c in rec.calls] == ["list-tickets"]
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["exit_code"] == 0
    assert "SOC-777" in r.gather_delta, "the granted read's own content never reached the model"
    assert r.own_denials == []


def test_the_self_case_list_filter_still_excludes_the_current_ticket(tmp_path: Path):
    """The list-path identity filter still EXCLUDES the current investigation's own ticket
    from what gather sees, unchanged by the verb_grant. The guard is KEPT rather than retired
    with its tests (§7 R17): narrowing gather to `list-tickets` makes its hand-written GET
    branch unreachable, and one dead branch is cheap — deleting it would make any future
    widening of the grant silently re-open the self-read.

    THE SELF KEY IS THE RUN'S OWN ID, and the exclusion is asserted on the model-visible
    result rather than on the call count. A fixture returning two tickets neither of which
    IS the current case exercises nothing: the filter runs, removes nothing, and every
    assertion about call counts and exit codes passes over a screen that was never asked to
    screen. The store below returns the run's own key beside a foreign one, so the surviving
    difference between "the screen ran" and "the screen was deleted" is visible in the text
    the model got back.

    The second drive is the shape half. A screen that only inspects an object envelope is
    bypassed by answering with a bare array — and gather's ticket screen deliberately files
    that shape as MALFORMED rather than passing it through, because reading a bare array as
    the ticket list would invent a shape the store does not document, on the one path where
    inventing one hands the model its own answer key. Withheld, not silently forwarded."""
    run_id = "d23-self-case"
    rec = VerbRecorder()

    def list_tickets(ctx, *, status=None, label=None, q=None, require_closed=False):
        rec.record("list-tickets", ctx, {"status": status, "label": label, "q": q})
        return ticket_envelope(run_id, "SOC-777")

    reg = ScopedFakeVerbs({"ticket": {"list-tickets": list_tickets}}, GATHER_DEF.verb_grant)
    r = run_gather(tmp_path / "envelope", verbs=reg, system="ticket",
                   turns=[q("ticket", "list-tickets", {}), DONE], run_id=run_id)

    assert len(rec.calls) == 1, "the filter was applied by refusing the call instead of filtering it"
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["exit_code"] == 0
    assert "SOC-777" in r.gather_delta, \
        "the screen dropped the whole listing — the exclusion below would hold vacuously"
    assert run_id not in r.gather_delta, \
        "the current investigation's own ticket survived gather's self-case exclusion"
    payload = (r.run_dir / "gather_raw" / LEAD / "0.json").read_text(encoding="utf-8")
    assert run_id not in payload, \
        "the unscreened listing was captured to the payload tree, where the loop rereads it"

    shaped = VerbRecorder()

    def bare_list(ctx, **params):
        shaped.record("list-tickets", ctx, params)
        return [{"key": run_id, "status": "open"}, {"key": "SOC-777", "status": "closed"}]

    bare = ScopedFakeVerbs({"ticket": {"list-tickets": bare_list}}, GATHER_DEF.verb_grant)
    b = run_gather(tmp_path / "bare", verbs=bare, system="ticket",
                   turns=[q("ticket", "list-tickets", {}), DONE], run_id="d23b")

    assert len(shaped.calls) == 1
    assert len(b.own_rows) == 1
    assert b.own_rows[0]["exit_code"] != 0, \
        "a non-object listing bypassed the screen instead of being filed as malformed"
    assert "d23b" not in b.gather_delta, \
        "a bare array bypassed the self-case exclusion — the screen keys on the payload's shape"


def test_an_impersonated_query_id_does_not_change_the_grant_decision(tmp_path: Path):
    """A `query_id` impersonating a committed template id belonging to another system or
    verb changes neither what the verb_grant enforces nor what SYSTEM/VERB the call is
    recorded as having been: the grant decision is a function of role, system and verb, and
    of nothing else. The role grant expresses no per-params, per-template or per-`query_id`
    constraint.

    The `query_id` itself is a DIFFERENT story since #869 (M3/FK-7): `resolve_query_id`
    refuses a prefix that disagrees with the call's own dispatched system — the fix for the
    exact impersonation this test builds — so the forged, foreign-prefixed id never reaches
    the row at all; it falls back to the untagged `{system}.{verb}` value, which is what is
    asserted below instead of the forged string."""
    rec = VerbRecorder()
    forged = "ticket.get-ticket-by-key"

    denied = run_gather(tmp_path / "a", verbs=_registry(rec),
                        turns=[q(*DENIED_PAIR, query_id=forged), DONE], run_id="d69-denied")
    assert rec.calls == [], "an impersonated id bought execution of a withheld verb"
    assert denied.own_evidence == []
    assert [row["query_id"] for row in denied.own_rows] == [DENIED_QUERY_ID], \
        "the forged id reached the denial's row, or the denial wrote something other than its sentinel"

    allowed = run_gather(tmp_path / "b", verbs=_registry(rec),
                         turns=[q(*GRANTED_PAIR, query_id=forged), DONE], run_id="d69-allowed")
    assert [c.verb for c in rec.calls] == ["query"]
    assert allowed.own_rows[0]["query_id"] == "elastic.query"
    assert "ticket" not in allowed.own_rows[0]["query_id"]
    assert allowed.own_rows[0]["system"] == "elastic"
    assert allowed.own_rows[0]["verb"] == "query"
