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
    the fixture tree under `root` and at `AS_OF`. The registry is the run's agent knowledge, so
    `root` is handed as the run tenant's agent root, not as `defender_dir`."""
    from defender.systems.verbs import VerbContext
    from defender.kit.verbs import declared_params
    from defender.integrations import tacit_knowledge_adapter

    def lookup(ctx: VerbContext, *, actor: str, host: str, pattern: str) -> dict:
        rec.record(LOOKUP, ctx, {"actor": actor, "host": host, "pattern": pattern})
        return tacit_knowledge_adapter.lookup(
            replace(ctx, tenant=replace(ctx.tenant, agent_root=root), as_of=AS_OF),
            actor=actor, host=host, pattern=pattern,
        )

    assert declared_params(lookup) == declared_params(tacit_knowledge_adapter.lookup), (
        "the harness shim's params are not the shipped verb's"
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


# ---------------------------------------------------------------- benign becomes reachable


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
        "the real adapter found no entry for an actor, host and pattern its own fixture covers"
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
        f"a container-root case with an authored registry entry still could not close benign:\n"
        f"{_feedback(main)[-2000:]}"
    )

    assert frontier_from_text(produced).contracts == (), (
        "the discharged contract is still on the retrieval frontier"
    )


def test_a_citation_the_lookup_never_returned_does_not_close_benign(tmp_path):
    """The same run, with the lookup MISSING and the model citing an entry id anyway: the close
    does not reach `benign`."""
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
        "a `:R authz` row citing an entry no lookup returned bought a benign close"
    )
    feedback = _feedback(main)
    assert scene.FABRICATED_ENTRY_ID in feedback or "ac1" in feedback, (
        "the block did not name the offending citation or contract"
    )


def test_runtime_evidence_lands_in_a_benign_report_body(tmp_path):
    doc = scene.benign_document(rows=scene.authorized_rows(baseline=True))
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-benign-body")

    _investigation(run_dir, replay)
    assert (run_dir / "report.md").is_file(), f"the close was refused:\n{_feedback(replay)[-2000:]}"
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    head, _, body = report.partition("---\n")[2].partition("---\n")
    assert "runtime-evidence" in body, (
        "the baseline consultation did not reach the committed report's body"
    )
    assert scene.WINDOW_BEFORE_ALERT in body, "the window did not travel with it"
    assert "1500 occurrences over 30d" in body, "the occurrence count did not travel with it"
    assert "runtime-evidence" not in head, (
        "the baseline reached the FRONTMATTER, which is capped at 512 bytes and gates things"
    )
    assert body.count("tk-baseline-30d") == 1
    assert scene.ENTRY_ID not in body, (
        "the lead's `tacit-knowledge` lookup record rode out with the baseline"
    )


# ---------------------------------------------------------------- the three fakes


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
        "an entry past its own `review_by` still answered the lookup"
    )
    assert scene.ENTRY_ID not in json.dumps(_payload(run_dir)), (
        "the expired entry's id reached the model anyway"
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
        "a benign close committed on a baseline consultation promoted into a verdict"
    )
    feedback = _feedback(main)
    assert "telemetry-baseline" in feedback or "runtime-evidence" in feedback, (
        "the block did not name the grounding it refused"
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
        "a contract no registry here can answer is still handed back for another retrieval loop"
    )


# ---------------------------------------------------------------- #1390: the platform-served lookup


def _spec() -> object:
    from defender.tests.learning.oracle.live_contracts import _spec1224

    return _spec1224


def _current_entry(**overrides: str) -> dict:
    """A well-formed entry in force on the day the suite runs (a live run's clock)."""
    today = dt.datetime.now(dt.UTC).date()
    return scene.registry_entry(added_at=str(today - dt.timedelta(days=10)),
                                review_by=str(today + dt.timedelta(days=30)), **overrides)


def _gather_lookups(tmp_path: Path, est, *turns) -> tuple[Path, list[dict]]:
    """One live investigation whose gather lead on `tacit-knowledge` runs `turns`, over the
    estate's real gather registry; returns the run dir and the lead's tacit-knowledge rows."""
    S = _spec()
    run_dir, _gather = S.drive_gather(
        tmp_path / "run", verbs=S.plain_registry(est), tenant=est.place(), system=SYSTEM,
        gather_turns=[*turns, S.done_turn()])
    return run_dir, [r for r in S.lead_rows(run_dir) if r["system"] == SYSTEM]


def _payload(run_dir: Path, row: dict) -> dict:
    return json.loads((run_dir / row["payload_path"]).read_text(encoding="utf-8"))


def test_1390_a_granted_lookup_runs_through_the_query_tool_and_is_recorded(tmp_path):
    """Granted: the lookup is one queries row with the registry's answer, and `list_verbs` describes it. O4."""
    from defender.investigation.query_catalog import _tool_list_verbs

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    entry = _current_entry()
    est.write_registry(json.dumps({"entries": [entry]}))

    run_dir, rows = _gather_lookups(tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS))

    assert [(r["verb"], r["params"], r["exit_code"]) for r in rows] == [
        (LOOKUP, LOOKUP_PARAMS, 0)]
    assert _payload(run_dir, rows[0]) == {"matched": entry}
    listed = _tool_list_verbs(S.plain_registry(est), SYSTEM)
    for needle in ("the 2 verb(s) your grant admits", "lookup", "health-check",
                   "actor", "host", "pattern"):
        assert needle in listed, f"list_verbs does not describe {needle!r}:\n{listed}"


def test_1390_a_withheld_lookup_is_refused_and_recorded_as_denied(tmp_path):
    """A table row granting `lookup` to no role refuses the call through the query tool's grant check, recorded as a denial. O4."""
    from defender.systems.circuit_breaker import DENIED_EXIT_CODE

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate",
                        tacit_roles=(("lookup", ()), ("health-check", ("gather",))))
    est.write_registry(json.dumps({"entries": [_current_entry()]}))

    _run_dir, rows = _gather_lookups(tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS))

    assert [(r["verb"], r["exit_code"]) for r in rows] == [(LOOKUP, DENIED_EXIT_CODE)]


def test_1390_deleted_rows_withhold_both_verbs(tmp_path):
    """A table with no `tacit-knowledge` rows withholds the lookup: never run, and `list_verbs` offers nothing. O10."""
    from defender.investigation.query_catalog import _tool_list_verbs

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate", tacit_roles=())
    est.write_registry(json.dumps({"entries": [_current_entry()]}))

    _run_dir, rows = _gather_lookups(tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS))

    assert [r for r in rows if r["exit_code"] == 0] == [], f"a lookup with no grant row ran: {rows}"
    assert "your grant reaches no verb" in _tool_list_verbs(S.plain_registry(est), SYSTEM)


def test_1390_a_broken_registry_is_a_miss_whose_reason_is_on_the_call(tmp_path):
    """A registry with no `entries:` list answers a miss, and its whole-file refusal is on the lookup's queries row and in `health-check`. O9."""
    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    est.write_registry("sanctions:\n  - id: tk-misfiled\n")
    reason = "declares no `entries:` list"

    run_dir, rows = _gather_lookups(
        tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS),
        S.query_turn(SYSTEM, "health-check", {}))

    assert [(r["verb"], r["exit_code"]) for r in rows] == [(LOOKUP, 0), ("health-check", 0)]
    assert _payload(run_dir, rows[0]) == {"matched": None}
    assert reason in json.dumps(rows[0]), f"the lookup's queries row does not carry the refusal: {rows[0]}"
    health = _payload(run_dir, rows[1])
    assert reason in json.dumps(health), f"health-check does not report the refusal: {health}"
    assert not str(health.get("registry", "")).startswith("/"), (
        "health-check names the registry by a host path")
