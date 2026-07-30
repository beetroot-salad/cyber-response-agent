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
from defender.runtime.driver import GATHER_DEF  # noqa: E402
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
    tool's ORDINARY result — nothing raised for the driver to catch, no sequence number, no
    evidence row, no circuit-breaker contribution — and the agent's next turn still runs.

    §7 R2 settles this as the pinned reading, no longer provisional: the refusal is a
    business outcome, and only a missing audit record is an infrastructure fault. The shape
    is the one zero-state refusal the codebase already has — the breaker's early return
    (n6) — never a `ModelRetry`, which the design forbids because a denial is either a
    policy bug or an injection attempt and neither is fixable by retrying."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE], run_id="d0")

    assert rec.calls == [], "the denied verb body ran"
    assert r.gather.calls >= 2, "the refusal did not come back as a result the loop continued past"
    assert r.rows == [], "a denied call wrote an evidence row"
    assert r.breaker.get("total_failures", 0) == 0
    assert "esql" in r.gather_saw


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

    assert denied.rows == []
    assert len(unknown.rows) == 1, "an undeclared verb stopped writing its row"
    assert unknown.rows[0]["error_class"] == "agent-fixable"
    assert denied.denials, "the denial left no audit record at all"
    assert unknown.denials == [], "an undeclared verb was audited as a policy denial"


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
    assert len(r.rows) == 1
    assert r.rows[0]["exit_code"] != 0
    assert r.rows[0]["error_class"] == "agent-fixable"
    assert r.rows[0]["verb"] == "nosuch-verb"
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
    assert len(whole.rows) == 1, "a wholly ungranted system wrote no unresolvable row"
    assert whole.denials == [], "a wholly ungranted system was audited as a policy denial"




def test_a_denied_gather_verb_leaves_no_queries_row_and_no_payload_file(tmp_path: Path):
    """A denied gather verb CONSERVES the run's evidence surface and allocates nothing of its
    own: everything the run had written before the denied call is byte-identical afterwards,
    and the three things a query call allocates — the lead-scoped payload directory, a
    queries row, a sequence number — are all absent.

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
    ZERO rows on the evidence surface, which is what keeps a denial out of the learning
    loop's input. Currently violated — the reject branch records before refusing (c4/g5).

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
    assert r.rows == [], "a lead whose every query was denied still put rows on the evidence surface"
    assert r.payload_files == [], "a denied call left a payload file behind"
    assert not (r.run_dir / "gather_raw" / LEAD).exists(), \
        "the lead-scoped payload directory was allocated for a denial"
    assert len(r.denials) == 2, "the two denials are not both in the audit stream"

    # Conservation. The snapshots straddle the two denied calls; the first is the state the
    # dispatch left, and it must survive them byte for byte.
    assert len(r.snapshots) >= 3, "the drive did not straddle both denied calls"
    before, after = r.snapshots[0], r.snapshots[-1]
    assert before, "the pre-call snapshot is empty — conservation would hold vacuously"
    assert after == before, (
        "a denial changed the evidence surface the run had already allocated: "
        f"removed={sorted(set(before) - set(after))} added={sorted(set(after) - set(before))} "
        f"rewritten={sorted(k for k in set(before) & set(after) if before[k] != after[k])}"
    )
    assert (r.run_dir / "gather_raw" / f"{LEAD}.lead.json").is_file(), \
        "the lead's own dispatch sidecar was destroyed to make the tree look untouched"

    # The sequence counter, observed where it is observable: the FIRST granted call after two
    # denials still takes seq 0. A denial that quietly consumed a number shows up here and
    # nowhere else, because the counter has no other reader.
    kept = VerbRecorder()
    later = run_gather(tmp_path / "then-granted", verbs=_registry(kept),
                       turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*GRANTED_PAIR), DONE],
                       run_id="d3-seq")
    assert [c.verb for c in kept.calls] == ["query"]
    assert [row["seq"] for row in later.rows] == [0], \
        "a denial consumed a sequence number the granted call then skipped"


def test_a_granted_gather_verb_still_writes_its_row_and_its_payload(tmp_path: Path):
    """A granted gather verb still writes its queries row and its
    `gather_raw/{lead_id}/{seq}.json` payload, unchanged. The positive control the negative
    above needs: proof the evidence surface is observable at all, so `no row` is a
    difference the channel can see rather than an empty run."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*GRANTED_PAIR), DONE], run_id="d31")

    assert [c.verb for c in rec.calls] == ["query"]
    assert len(r.rows) == 1
    assert r.rows[0]["exit_code"] == 0
    assert r.rows[0]["seq"] == 0
    assert (r.run_dir / "gather_raw" / LEAD / "0.json").is_file()
    assert r.denials == [], "a granted call was audited as a policy denial"


def test_a_denial_outside_a_dispatched_lead_runs_no_lead_scoped_allocation(tmp_path: Path):
    """A denial needs no lead context: the allocation machinery a denial must not touch is
    LEAD-SCOPED, and the decision plus its audit record are both reachable without it. This
    pins that the early return is genuinely EARLY rather than merely conditional — today
    the capture path raises outright when a query reaches it with no dispatched lead, so a
    denial routed through it would turn a policy refusal into an internal error."""
    rec = VerbRecorder()
    reg = _registry(rec)

    decision = reg.decide(*DENIED_PAIR)
    assert decision.outcome == DENIED
    assert decision.refusal is not None
    assert "esql" in decision.refusal

    r = run_gather(tmp_path, verbs=reg, turns=[q(*DENIED_PAIR), DONE], run_id="d44")
    assert not (r.run_dir / "gather_raw" / LEAD).exists()
    assert len(r.denials) == 1, "the denial was not audited at all"
    assert "lead_id" not in r.denials[0], \
        "the denial record carries lead-scoped state a denial must never allocate"




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
    assert len(r.rows) == 1
    assert r.rows[0]["error_class"] == "agent-fixable"
    assert r.denials == []


def test_a_malformed_and_denied_call_takes_the_denial_path(tmp_path: Path):
    """A call that is both malformed AND denied takes the DENIAL path: the grant check runs
    first, so the model sees the denial rather than the malformedness, no queries row is
    written, and the denial IS audited.

    This is the ordering reversed at phase F, and the reason is the composition the earlier
    split created: with the malformed check first, appending one unrecognised parameter to
    every call it expected to be refused let a model produce zero denial records for the
    life of a run, with nothing in the record noticing. A refusal a caller can choose the
    flavour of is not an authorization decision."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR, {"nosuch_param": 1}), DONE], run_id="d55")

    assert rec.calls == []
    assert r.rows == [], "the malformed-and-denied call still left an evidence row"
    assert len(r.denials) == 1, \
        "one unrecognised parameter suppressed the denial record — the malformed check ran first"
    assert r.denials[0]["verb"] == "esql"
    assert "esql" in r.gather_saw, "the model saw the malformedness, not the denial"


def test_a_denied_call_is_refused_before_its_query_id_meets_the_traversal_screen(tmp_path: Path):
    """A denied call carrying a path-traversal `query_id` is refused by the GRANT CHECK,
    ahead of the traversal screen: no queries row, a denial record written, and the model
    sees the denial reason rather than the traversal reason (§7 R23, reversed at phase F
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
    assert r.rows == [], "the traversal-and-denied call still left an evidence row"
    assert len(r.denials) == 1, "the traversal screen ran first and suppressed the denial record"
    assert "esql" in r.gather_saw, "the model saw the traversal reason, not the denial"

    record = r.denials[0]
    assert hostile not in json.dumps(record), \
        "the raw model-authored traversal id landed in the durable denial record unnormalized"
    assert record.get("call_id"), "the record identifies no call at all — the projection is empty"

    # The screen, where it is still reachable: authorization admits the call, so the screen is
    # what must refuse it. Without this every assertion above survives the screen's deletion.
    kept = VerbRecorder()
    screened = run_gather(tmp_path / "granted", verbs=_registry(kept),
                          turns=[q(*GRANTED_PAIR, query_id=hostile), DONE], run_id="d53-screen")

    assert kept.calls == [], \
        "a granted call's traversal-shaped query_id reached the verb — the screen is gone"
    assert len(screened.rows) == 1, \
        "the screened call lost the malformed treatment the screen has always given it"
    assert screened.rows[0]["error_class"] == "agent-fixable"
    assert screened.rows[0]["query_id"] != hostile, \
        "the model-authored traversal id became the call's catalog id"
    assert screened.denials == [], \
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
    assert len(r.denials) == 1, "the availability short-circuit silenced the denial's audit record"
    assert r.denials[0]["verb"] == "esql"
    assert len(r.rows) == 2, "the denial against a down system wrote an evidence row"




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
    assert r.rows[0]["error_class"] == "infra"
    assert r.breaker["systems"]["elastic"]["failures"] == 1
    assert r.denials == [], "an infra fault was relabelled into the policy-denial stream"




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
    reg = ModuleVerbRegistry(adapters, grant)
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
    assert r.rows == [], \
        "the denial on an unloadable system was recorded as an unresolvable query instead"
    assert len(r.denials) == 1, \
        "a denial on an unloadable system produced no audit record — it was downgraded"
    assert r.denials[0]["verb"] == "list-hosts"


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
    assert len(r.rows) == 2
    assert r.rows[1]["exit_code"] == 0, "the retry inherited the first call's failure"
    assert r.denials == [], "an import failure was recorded as a policy denial"


def test_repeated_identical_denials_each_audit_and_never_move_run_state(tmp_path: Path):
    """Every denied call appends its OWN audit record — no dedup key, no per-run cache — and
    the hundredth identical denial has still moved no run state, so the first and the
    hundredth are indistinguishable in everything except the audit stream.

    Recorded and NOT built (RS6): that indistinguishability is exactly why a denial loop has
    no exit. The design refuses to coach a retry and nothing else ends the loop, so a model
    re-issuing a denied call spins until the run-level budget stops it. Neither obvious home
    for a counter is legal — the evidence table is the surface a denial must stay out of,
    and the circuit breaker is for infrastructure faults."""
    rec = VerbRecorder()
    n = 5
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[*(q(*DENIED_PAIR) for _ in range(n)), DONE],
                   run_id="d42")

    assert len(r.denials) == n, "denials were deduplicated or cached"
    assert r.rows == []
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
    assert r.denials == [], "a near-miss was audited as a policy denial rather than unresolvable"
    assert len(r.rows) == 1, "a near-miss wrote no unresolvable row"
    assert r.rows[0]["exit_code"] != 0




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
    assert r.rows == []
    assert len(r.denials) == 1
    assert r.denials[0]["verb"] == "get-ticket"


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
    assert len(r.rows) == 1
    assert r.rows[0]["exit_code"] == 0
    assert "SOC-777" in r.gather_delta, "the granted read's own content never reached the model"
    assert r.denials == []


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
    assert len(r.rows) == 1
    assert r.rows[0]["exit_code"] == 0
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
    assert len(b.rows) == 1
    assert b.rows[0]["exit_code"] != 0, \
        "a non-object listing bypassed the screen instead of being filed as malformed"
    assert "d23b" not in b.gather_delta, \
        "a bare array bypassed the self-case exclusion — the screen keys on the payload's shape"


def test_an_impersonated_query_id_does_not_change_the_grant_decision(tmp_path: Path):
    """A `query_id` impersonating a committed template id belonging to another system or
    verb changes neither what the verb_grant enforces nor what the call is recorded as
    having been: the grant decision is a function of role, system and verb, and of nothing
    else. The role grant expresses no per-params, per-template or per-`query_id` constraint.

    Recorded and NOT built (RS8): whether a DOWNSTREAM consumer attributes a call to a
    template by that forgeable id matters only if the unused-grant flag ships, which §7 R18
    leaves to the design's own open question."""
    rec = VerbRecorder()
    forged = "ticket.get-ticket-by-key"

    denied = run_gather(tmp_path / "a", verbs=_registry(rec),
                        turns=[q(*DENIED_PAIR, query_id=forged), DONE], run_id="d69-denied")
    assert rec.calls == [], "an impersonated id bought execution of a withheld verb"
    assert denied.rows == []

    allowed = run_gather(tmp_path / "b", verbs=_registry(rec),
                         turns=[q(*GRANTED_PAIR, query_id=forged), DONE], run_id="d69-allowed")
    assert [c.verb for c in rec.calls] == ["query"]
    assert allowed.rows[0]["query_id"] == forged
    assert allowed.rows[0]["system"] == "elastic"
    assert allowed.rows[0]["verb"] == "query"
