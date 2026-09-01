"""#983 e2e — the outcome-level demands, driven through the real lookup and the real close.

Unit tests can show that a vocabulary member exists and that a check refuses a row. What they
cannot show is the thing #983 is actually for: that a container-root alert with an authored
registry entry behind it reaches `disposition: benign` through `close_investigation`, and that
the ways of faking that entry do not. Those are close-level outcomes — the entry price is
collected at the close as well as at the write gate, and `report.md` is written from the close's
own argument — so each scenario is driven end to end through `driver.run_investigation` on the
shared replay harness.

THE LOOKUP IS DISPATCHED HERE, and that is this suite's hardening pass. Written without it,
every scenario was a hand-authored `:R authz` row round-tripping into a close: the registry was
a fiction the document asserted, the adapter was never called, and a `lookup` that returned an
unconditional hit — or no `lookup` at all — passed the whole file. So the O1/O2 scenarios now
run a REAL `tacit-knowledge.lookup` through the real query tool against a real fixture registry
(`_registry_verbs`), and the assertions close the loop between the two artifacts: the id the
adapter actually returned in `gather_raw/l-001/0.json` and the `anchor_id` the committed
`investigation.md` cites have to be the same string.

WHAT THE FIXTURE REGISTRY MOVES AND WHAT IT DOES NOT. The adapter under test is the REAL one;
what the scenario supplies is the tree it reads and the moment it judges expiry against, both
of which `VerbContext` already carries as values (`defender_dir`, `as_of`) precisely so a test
does not have to patch a module attribute (`lint-monkeypatch`). Scope matching, expiry, the
load-time entry rules and the payload shape are all production code inside `lookup`.

WHAT AN E2E CAN AND CANNOT CATCH HERE, stated because the boundary is the design's:
`validate_companion` is handed TEXT and never a run dir, so the anchor-receipt check
cross-checks the document against itself (see `tests/test_tacit_authz_983.py`'s docstring). A
model that fabricated BOTH rows — a `:R consultations` hit it never got and the `:R authz` row
citing it — writes a document that is internally consistent, and only `executed_queries.jsonl`
disagrees. These scenarios pin the half that IS mechanical: the run's own tables record what
the registry actually said, so the fabrication is discoverable by a reader and by any later
check that joins the two. Widening the validator to read the run dir is a different design
than the one this issue settled.

The document is the SHARED container-root scene (`tests/_tacit983.py`); each scenario moves one
cell.

`drive` defaults its review-stage bundle to a hermetic composer that finds `holds`, so a benign
close — a CONFIDENT disposition, and therefore a reviewed one — runs the whole gate without a
provider. That matters here beyond hermeticity: `benign` takes the POST-REVIEW `_CloseFields`
construction site, which is the one the `ceiling_test` carrier never reaches (claim c11), so a
mechanism-A field populated only on the no-review branch would pass every unit test and fail
`test_runtime_evidence_lands_in_a_benign_report_body` alone.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from defender.skills.invlang.frontier import frontier_from_text
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion
from defender.tests import _tacit983 as scene
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

SYSTEM = "tacit-knowledge"
LOOKUP = "lookup"

#: The bound params a lead sends the lookup: the alerted actor, host and action, read off the
#: same scene the document is written against.
LOOKUP_PARAMS = {"actor": scene.ACTOR, "host": scene.HOST, "pattern": scene.PATTERN}

#: The moment every driven lookup is served AS OF — the alerted instant, so a scenario's
#: expiry outcome is a property of its fixture entry and not of the day the suite runs.
AS_OF = dt.datetime(2026, 5, 5, 3, 42, 11, tzinfo=dt.UTC)


def _run(tmp_path: Path, doc: str, disposition: str, *, run_id: str):
    """Land `doc` as the run's `investigation.md` through MAIN's own writer, then close.

    `append_block` rather than a seeded file: the write gate — invlang validation included —
    is half of what these scenarios are about, and a document staged around it would let a
    refusal the gate WOULD have made read as a close that succeeded."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": doc})]),
        Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return run_dir, replay


def _registry_verbs(root: Path, rec: VerbRecorder) -> FakeVerbs:
    """A gather registry whose `tacit-knowledge.lookup` IS the shipped adapter's, repointed at
    the fixture tree under `root` and at `AS_OF`.

    The wrapper exists to move two values `VerbContext` already carries and to record what the
    query tool bound — it decides nothing. Its param surface is asserted equal to the real
    verb's through `declared_params`, the query tool's OWN reader of a verb signature, so the
    shim cannot drift into validating a contract the production verb does not have."""
    from defender.runtime.verbs import VerbContext, declared_params
    from defender.scripts.adapters import tacit_knowledge_adapter

    def lookup(ctx: VerbContext, *, actor: str, host: str, pattern: str) -> dict:
        rec.record(LOOKUP, ctx, {"actor": actor, "host": host, "pattern": pattern})
        return tacit_knowledge_adapter.lookup(
            replace(ctx, defender_dir=root, as_of=AS_OF),
            actor=actor, host=host, pattern=pattern,
        )

    assert declared_params(lookup) == declared_params(tacit_knowledge_adapter.lookup), (
        "the harness shim's params are not the shipped verb's — the scenario would be "
        "validating a call shape no lead can actually make"
    )
    return FakeVerbs({SYSTEM: {LOOKUP: lookup}})


def _run_with_lookup(
    tmp_path: Path, *, entries, doc: str, disposition: str, run_id: str,
):
    """One run that DISPATCHES the registry lookup and then writes `doc`.

    Four MAIN turns — dispatch the lead, commit the document, close, stop — with the gather
    subagent replaying one `query` call in between. Everything between the two replay models
    is production: the gather dispatch, the query tool's param validation, the real adapter,
    the capture capability that persists the payload and the two tables, and the write gate
    and close the document then meets."""
    root = tmp_path / "estate"
    scene.write_registry(root, *entries)
    run_dir = materialize(tmp_path, GOLDEN)
    rec = VerbRecorder()

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": scene.LEAD, "system": SYSTEM,
            "goal": (
                "does an authored tacit-knowledge entry sanction container UID 0 rewriting "
                "the CA bundle on build-runner-07.prod"
            ),
            "what_to_summarize": ["the matching entry id, its scope, and its review_by"],
        })]),
        Turn(tool_calls=[("append_block", {"text": doc})]),
        Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("query", {
            "system": SYSTEM, "verb": LOOKUP, "params": LOOKUP_PARAMS,
        })]),
        Turn(text="Summary: reported what the tacit-knowledge registry answered."),
    ])
    drive(
        run_dir, run_id=run_id, main=main, gather=gather,
        verbs=_registry_verbs(root, rec),
    )
    return run_dir, main, gather, rec


def _payload(run_dir: Path, seq: int = 0) -> dict:
    """What the REAL adapter handed back, off the run's own by-ref payload file.

    The scenario's ground truth: the document's citation is asserted against this rather than
    against the fixture's literals, so the assertion is "the row cites what the registry
    returned" and not "the row cites what the test author typed twice"."""
    path = run_dir / "gather_raw" / scene.LEAD / f"{seq}.json"
    assert path.is_file(), (
        f"the lookup persisted no payload at {path} — the lead never reached the adapter"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def _investigation(run_dir: Path, replay: ReplayFn) -> str:
    """The committed `investigation.md`, or a failure naming what the write gate said.

    Read through a helper rather than inline, because the interesting failure here is the gate
    REFUSING the document and the bare `FileNotFoundError` a direct read raises says nothing
    about which rule refused it."""
    path = run_dir / "investigation.md"
    assert path.is_file(), (
        f"nothing was committed — the write gate refused the document. Feedback the model "
        f"received:\n{_feedback(replay)[-2000:]}"
    )
    return path.read_text(encoding="utf-8")


def _committed_disposition(run_dir: Path) -> str | None:
    report = run_dir / "report.md"
    if not report.is_file():
        return None
    m = re.search(r"^disposition:\s*(\S+)", report.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def _feedback(replay: ReplayFn) -> str:
    """Everything the model was told across the run — where a gate's refusal lands."""
    return "\n".join(replay.seen)


def _authz_rows(text: str) -> list[dict]:
    from defender.skills.invlang import _walkers

    companion, _ = parse_dense_companion(text)
    return list(_walkers.iter_authz_resolutions(companion))


def _authz_verdicts(text: str) -> list[str]:
    return [row.get("verdict", "") for row in _authz_rows(text)]


# ---------------------------------------------------------------- O1: benign becomes reachable


def test_registry_hit_lets_a_container_root_case_close_benign(tmp_path):
    """A lead DISPATCHES `tacit-knowledge.lookup`, the real adapter answers with an unexpired
    scope-matching entry, the `:R authz` row cites THAT entry, and the run closes `benign`
    (demand `benign_reachable_on_registry_hit`).

    THE issue's case: 50 identical events a day for 30 days from container UID 0, closed
    `inconclusive` every time because no identity system in this deployment holds a record for
    that actor (claim c7, accepted as given). The registry entry is what changes, and nothing
    else about the run does: the same document, the same gates, the same review.

    The loop between the two artifacts is what makes this an e2e rather than a longer unit
    test. The id in the committed row is asserted EQUAL to the id in the payload the adapter
    persisted — not equal to a constant this file spells — so a lookup that answered with
    something else, or answered without being asked, is visible here and nowhere else.

    Deliberately NOT routing the contract to whatever identity became root so a real identity
    check becomes possible — that is a hypothesis/lead-design question and is out of scope
    here (non-obligation 1)."""
    doc = scene.benign_document(rows=scene.authorized_rows(baseline=True))
    run_dir, main, gather, rec = _run_with_lookup(
        tmp_path, entries=[scene.registry_entry()], doc=doc, disposition="benign",
        run_id="tacit-benign",
    )

    assert rec.verbs == [LOOKUP], (
        f"the registry lookup was not dispatched exactly once: {rec.verbs}"
    )
    assert rec.only().params == LOOKUP_PARAMS, (
        "the query tool bound something other than the alerted actor, host and pattern"
    )

    matched = _payload(run_dir)["matched"]
    assert matched is not None, (
        "the real adapter came back with no entry for an actor, host and pattern its own "
        "fixture entry covers — the rest of this scenario would be asserting over a fiction"
    )

    assert main.calls == 4, (
        f"the run stopped early ({main.calls}/4) — a gate denied something:\n{_feedback(main)}"
    )
    produced = _investigation(run_dir, main)
    assert validate_companion(produced, None) == []
    assert [r.get("anchor_id") for r in _authz_rows(produced)] == [matched["id"]], (
        "the committed `:R authz` row cites an entry other than the one the lookup returned"
    )
    assert _committed_disposition(run_dir) == "benign", (
        "a container-root case with an authored registry entry behind it still could not "
        f"close benign — O1's failure, unchanged:\n{_feedback(main)[-2000:]}"
    )

    assert frontier_from_text(produced).contracts == (), (
        "the discharged contract is still on the retrieval frontier, so the run would be "
        "pushed back to re-ask a question an authored registry entry already answered"
    )


def test_a_citation_the_lookup_never_returned_does_not_close_benign(tmp_path):
    """The same run, with the lookup MISSING and the model citing an entry id anyway: the close
    does not reach `benign` (demand `authz_anchor_id_is_receipted`, O2).

    The fake this whole mechanism exists to refuse, driven end to end. The registry the run
    actually reads holds one entry, scoped to a host this alert is not about, so the real
    adapter returns no match — and the document then claims an `authorized` verdict citing an
    entry id, exactly as a model that decided the answer before asking would. Everything else
    about the document is the one that WORKS in the test above; the `anchor_id` cell is the
    only difference, so a refusal here cannot be some other rule firing.

    The lead's own honest record of the miss rides in the document (a `:R consultations` row
    with no entry to name), which is what the citation is checked against. See this module's
    docstring for the fabrication this cannot catch and why that boundary is where it is."""
    doc = scene.benign_document(
        rows=scene.consult_block(scene.lookup_miss_row(), scene.consultation_row())
        + scene.authz_block(scene.authz_row(anchor_id=scene.FABRICATED_ENTRY_ID)),
    )
    run_dir, main, gather, rec = _run_with_lookup(
        tmp_path,
        entries=[scene.registry_entry(id="tk-other-fleet", host_scope="web-frontend-*.prod")],
        doc=doc, disposition="benign", run_id="tacit-fabricated",
    )

    assert _payload(run_dir)["matched"] is None, (
        "fixture control: the entry in this run's registry is scoped to another fleet, so the "
        "lookup has to come back empty"
    )
    assert _committed_disposition(run_dir) != "benign", (
        "a `:R authz` row citing an entry no lookup ever returned bought a benign close — "
        "authorization by convention became authorization by assertion"
    )
    feedback = _feedback(main)
    assert scene.FABRICATED_ENTRY_ID in feedback or "ac1" in feedback, (
        "the run was blocked without telling the model which citation or which contract was "
        "the problem — nothing here is repairable"
    )


def test_runtime_evidence_lands_in_a_benign_report_body(tmp_path):
    """A benign close's `report.md` BODY carries one line per qualifying `:R consultations` row,
    so a human reading the closed case can see whether the alerted pattern is recognized as
    recurring in this estate (demand `consultation_reaches_report_body`, fork F4 / RF1).

    Driven through the REVIEWED close on purpose. `benign` is a confident disposition, so it
    takes the post-challenge-gate `_CloseFields(...)` — the construction site that omits
    `ceiling_test` entirely and takes the `= ()` default. A baseline field populated the way
    `ceiling_test` is would be empty here, which is exactly the gap RF1 found in the design's
    "not a new architecture" claim, and exactly the disposition O3 needs it on.

    No lookup dispatch: this scenario is about the CARRIER, and the registry hit it rides
    beside is pinned by the test above. What it does assert is that the `tacit-knowledge`
    consultation sitting in the same bucket does NOT ride out with the baseline — the report's
    recurrence paragraph is O3's, and a registry citation is not a recurrence claim."""
    doc = scene.benign_document(rows=scene.authorized_rows(baseline=True))
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-benign-body")

    _investigation(run_dir, replay)
    assert (run_dir / "report.md").is_file(), f"the close was refused:\n{_feedback(replay)[-2000:]}"
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    head, _, body = report.partition("---\n")[2].partition("---\n")
    assert "runtime-evidence" in body, (
        "the baseline consultation did not reach the committed report's body — O3's gap "
        "(the density the agent already computes never reaching report.md) is unchanged"
    )
    assert scene.WINDOW_BEFORE_ALERT in body, "the window did not travel with it"
    assert "1500 occurrences over 30d" in body, "the occurrence count did not travel with it"
    assert "runtime-evidence" not in head, (
        "the baseline reached the FRONTMATTER, which is capped at 512 bytes and gates things"
    )
    assert body.count("tk-baseline-30d") == 1
    assert scene.ENTRY_ID not in body, (
        "the lead's `tacit-knowledge` lookup record rode out with the baseline — the report's "
        "recurrence paragraph now carries an authorization citation, which is a different "
        "claim about a different anchor kind"
    )


def test_runtime_evidence_lands_in_an_inconclusive_report_body(tmp_path):
    """...and on the OTHER `_CloseFields` construction site too.

    `inconclusive` skips the review and commits from the `NO_REVIEW_DISPOSITIONS` branch. Both
    sites, because mechanism A's whole point is visibility on every close and a field wired at
    one site is a field that reports the baseline for half the corpus."""
    doc = scene.inconclusive_document(rows=scene.consult_block(scene.consultation_row()))
    run_dir, replay = _run(tmp_path, doc, "inconclusive", run_id="tacit-inconclusive-body")

    _investigation(run_dir, replay)
    assert (run_dir / "report.md").is_file(), f"the close was refused:\n{_feedback(replay)[-2000:]}"
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    body = report.partition("---\n")[2].partition("---\n")[2]
    assert "runtime-evidence" in body
    assert "ceiling_test" in body, (
        "the existing ceiling_test note lane stopped working — the new field displaced it "
        "rather than sitting beside it"
    )


# ---------------------------------------------------------------- O2: the three fakes


def test_expired_entry_falls_through_to_indeterminate(tmp_path):
    """An entry whose `review_by` is in the past does not discharge: the REAL lookup comes back
    empty and the contract falls through to `indeterminate` exactly as on any other registry
    miss — never to `unauthorized`, and never to a stale `authorized`
    (demand `expired_entry_does_not_discharge`).

    The verdict is DERIVED from a real lookup rather than hand-written into a cell: the fixture
    registry holds the entry this case's own document was written for, well formed and inside
    the review span, and the only thing wrong with it is that its `review_by` fell before the
    alert. A hand-authored `indeterminate` row proves nothing about expiry — it is the same
    document a run with no registry at all would write. This one is the entry ALMOST answering.

    `indeterminate`, not `unauthorized`: an expired sanction says nothing about whether the
    action is permitted, only that nobody has re-attested it. Writing `unauthorized` here would
    escalate every action whose sanction simply aged out.

    The run's own attempt at `benign` is refused, and the refusal is asserted on the FEEDBACK
    the model got as well as on the absent report — a close that silently did nothing and a
    close that was refused with a reason are different runs, and only one of them is
    repairable."""
    doc = scene.document(
        rows=scene.consult_block(scene.lookup_miss_row(
            result="miss: the covering entry expired 2026-04-15 and no longer answers",
        )) + scene.authz_block(scene.authz_row(
            verdict="indeterminate", grounding="", anchor_id="", basis="retry",
            reasoning="registry entry tk-ca-bundle-build-runner expired 2026-04-15; no hit",
        )),
        settled=False,
    )
    run_dir, main, gather, rec = _run_with_lookup(
        tmp_path,
        entries=[scene.registry_entry(added_at="2026-03-01", review_by="2026-04-15")],
        doc=doc, disposition="benign", run_id="tacit-expired",
    )

    assert _payload(run_dir)["matched"] is None, (
        "an entry past its own `review_by` still answered the lookup — a stale sanction "
        "authorizes forever, which is the one thing a file entry cannot notice about itself"
    )
    assert scene.ENTRY_ID not in json.dumps(_payload(run_dir)), (
        "the expired entry's id reached the model anyway — a miss that names the entry it "
        "nearly matched is a citation waiting to be written"
    )

    produced = _investigation(run_dir, main)
    assert validate_companion(produced, None) == [], (
        "the expired-entry document is well formed — recording the miss is legal"
    )
    assert "authorized" not in _authz_verdicts(produced), (
        "a stale registry entry produced an `authorized` verdict"
    )
    assert "unauthorized" not in _authz_verdicts(produced), (
        "an expired sanction was read as a refusal rather than as no answer"
    )

    assert _committed_disposition(run_dir) != "benign", (
        "an expired registry entry bought a benign close"
    )
    assert "ac1" in _feedback(main), (
        "the close was refused without naming the contract that is still open — the model has "
        "nothing to repair"
    )


def test_recurrence_alone_never_authorizes(tmp_path):
    """A dense, long-running occurrence pattern with NO registry entry behind it produces no
    benign close, EVEN WHEN THE MODEL WRITES THE AUTHORIZATION ITSELF — a patient adversary's
    month of quiet activity cannot self-authorize (demand `no_statistical_self_authorization`,
    O2).

    THE regression guard of this whole change, and the one a corner-cutting implementation
    would most want to fake: the discarded middle design had raw telemetry recurrence grounding
    authorization directly, and it was discarded because it cannot tell established practice
    from an ongoing bad habit nobody has caught.

    The model here ATTEMPTS the authorization rather than declining to, which is the version of
    this test that discriminates: a document that simply omits the `:R authz` row is refused by
    the open-contract gate that predates this issue entirely, and proves nothing about
    recurrence. This one runs the real lookup against a registry that has nothing for this
    actor, gets a miss, and then writes `verdict=authorized` grounded on the baseline — 1500
    occurrences over 30 days, one actor, one host, nothing adverse inside the window, and the
    window closes before the alert. It still buys nothing."""
    doc = scene.benign_document(
        rows=scene.consult_block(scene.lookup_miss_row(), scene.consultation_row())
        + scene.authz_block(scene.authz_row(
            anchor_kind="runtime-evidence", grounding="telemetry-baseline",
            anchor_id="tk-baseline-30d",
            reasoning="1500 occurrences over 30d, one actor, one host, nothing adverse")),
    )
    run_dir, main, gather, rec = _run_with_lookup(
        tmp_path,
        entries=[scene.registry_entry(id="tk-other-actor", actor_scope="svc-build-agent")],
        doc=doc, disposition="benign", run_id="tacit-recurrence",
    )

    assert _payload(run_dir)["matched"] is None, (
        "fixture control: no entry in this run's registry covers the alerted actor"
    )
    assert _committed_disposition(run_dir) is None, (
        "a benign close committed on a baseline consultation promoted into a verdict — the "
        "middle design this issue's own discussion discarded, reachable by writing the "
        "density finding into the `:R authz` bucket instead of the `:R consultations` one"
    )
    feedback = _feedback(main)
    assert "telemetry-baseline" in feedback or "runtime-evidence" in feedback, (
        "the run was blocked without naming the grounding it refused, so a model cannot tell "
        "'this evidence does not authorize' from 'try again'"
    )


def test_exhausted_contract_is_not_looped_back_but_still_escalates(tmp_path):
    """An `indeterminate` contract carrying `basis=exhausted` leaves `verdict` and the forced
    escalation exactly as they are, and only stops being re-dispatched
    (demands `exhausted_is_not_redispatched` + `indeterminate_escalation_unchanged`, O4).

    Both halves in one run, because the demand is a PAIR and asserting either alone admits the
    build that gets the other backwards: a `basis` that also discharged the contract would
    satisfy "not re-dispatched" perfectly.

    Driven through a real dispatch, because `basis=exhausted` is a claim ABOUT dispatch: the
    lead really did query the tacit-knowledge system, and the receipt the row owes is checked
    against that lead's own `:L findings` row."""
    row = scene.authz_row(
        verdict="indeterminate", grounding="", anchor_id="", basis="exhausted",
        reasoning="every anchor kind applicable to this predicate was queried; none answered",
    )
    doc = scene.inconclusive_document(
        rows=scene.consult_block(scene.lookup_miss_row()) + scene.authz_block(row))
    run_dir, main, gather, rec = _run_with_lookup(
        tmp_path,
        entries=[scene.registry_entry(id="tk-other-actor", actor_scope="svc-build-agent")],
        doc=doc, disposition="inconclusive", run_id="tacit-exhausted",
    )

    assert _payload(run_dir)["matched"] is None, "fixture control: the registry had no answer"
    produced = _investigation(run_dir, main)
    assert validate_companion(produced, None) == []
    assert _committed_disposition(run_dir) == "inconclusive", (
        "`basis=exhausted` changed what the run commits — it may only change whether the run "
        f"loops back:\n{_feedback(main)[-2000:]}"
    )
    assert frontier_from_text(produced).contracts == (), (
        "a contract no registry in this deployment can ever answer is still being handed back "
        "for another retrieval loop — O4's burned loop"
    )
