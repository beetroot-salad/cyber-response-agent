"""#983 e2e — the outcome-level demands, driven through the real lookup and the real close."""
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
from defender.tests.support.shared.contracts import _tacit983 as scene
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
    """Land `doc` as the run's `investigation.md` through MAIN's own writer, then close."""
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id)
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": doc})]),
        Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return run_dir, replay


def _registry_verbs(root: Path, rec: VerbRecorder) -> FakeVerbs:
    """A gather registry whose `tacit-knowledge.lookup` IS the shipped adapter's, repointed at
    the fixture tree under `root` and at `AS_OF`."""
    from defender.runtime.verbs import VerbContext, declared_params
    from defender.integrations import tacit_knowledge_adapter

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
    """One run that DISPATCHES the registry lookup and then writes `doc`."""
    root = tmp_path / "estate"
    scene.write_registry(root, *entries)
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id)
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
    """What the REAL adapter handed back, off the run's own by-ref payload file."""
    path = run_dir / "gather_raw" / scene.LEAD / f"{seq}.json"
    assert path.is_file(), (
        f"the lookup persisted no payload at {path} — the lead never reached the adapter"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def _investigation(run_dir: Path, replay: ReplayFn) -> str:
    """The committed `investigation.md`, or a failure naming what the write gate said."""
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
    does not reach `benign` (demand `authz_anchor_id_is_receipted`, O2)."""
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


# ---------------------------------------------------------------- O2: the three fakes


def test_expired_entry_falls_through_to_indeterminate(tmp_path):
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
