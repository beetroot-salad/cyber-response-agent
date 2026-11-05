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
    """A gather registry whose `tacit-knowledge.lookup` IS the platform's (the one a real run's
    registry serves, #1390), repointed at the fixture tree under `root` and at `AS_OF`: the
    shim drops the run state so the alerted instant, not the suite's wall time, is the day. The
    registry is the run's agent knowledge, so `root` is handed as the run tenant's agent root."""
    from defender._git import REPO_ROOT
    from defender.kit.verbs import declared_params
    from defender.systems.verbs import ModuleVerbRegistry, VerbContext, read_roster
    from defender.tests.support.tenancy import _tenants1106

    shipped = ModuleVerbRegistry(
        read_roster(REPO_ROOT / "defender" / "integrations"),
        _tenants1106.fixture_grants().gather).verbs(SYSTEM)[LOOKUP]

    def lookup(ctx: VerbContext, *, actor: str, host: str, pattern: str) -> dict:
        rec.record(LOOKUP, ctx, {"actor": actor, "host": host, "pattern": pattern})
        return shipped(
            replace(ctx, tenant=replace(ctx.tenant, agent_root=root), as_of=AS_OF, run_state=None),
            actor=actor, host=host, pattern=pattern,
        )

    assert declared_params(lookup) == declared_params(shipped), (
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
    """What the REAL lookup handed back, off the run's own by-ref payload file."""
    path = run_dir / "gather_raw" / scene.LEAD / f"{seq}.json"
    assert path.is_file(), (
        f"the lookup persisted no payload at {path} — the lead never reached the lookup"
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


def _gather_lookups(tmp_path: Path, est, *turns, system: str = SYSTEM, **drive) -> tuple[Path, list[dict], object]:
    """One live investigation whose gather lead (on `system`) runs `turns`, over the estate's real
    registry; returns the run dir, the lead's `tacit-knowledge` rows and the gather replay."""
    S = _spec()
    run_dir, gather = S.drive_gather(
        tmp_path / "run", verbs=S.plain_registry(est), tenant=est.place(), system=system,
        gather_turns=[*turns, S.done_turn()], **drive)
    return run_dir, [r for r in S.lead_rows(run_dir) if r["system"] == SYSTEM], gather


def _stored_answer(run_dir: Path, row: dict) -> dict:
    return json.loads((run_dir / row["payload_path"]).read_text(encoding="utf-8"))


def test_1390_a_granted_lookup_runs_through_the_query_tool_and_is_recorded(tmp_path):
    """Granted: the lookup is one queries row with the registry's answer, and `list_verbs` describes it. O4."""
    from defender.investigation.query_catalog import _tool_list_verbs

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    entry = _current_entry()
    est.write_registry(json.dumps({"entries": [entry]}))

    run_dir, rows, _gather = _gather_lookups(tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS))

    assert [(r["verb"], r["params"], r["exit_code"]) for r in rows] == [
        (LOOKUP, LOOKUP_PARAMS, 0)]
    assert _stored_answer(run_dir, rows[0]) == {"matched": entry}
    listed = _tool_list_verbs(S.plain_registry(est), SYSTEM)
    for needle in ("the 2 verb(s) your grant admits", "lookup", "health-check",
                   "actor", "host", "pattern"):
        assert needle in listed, f"list_verbs does not describe {needle!r}:\n{listed}"


def _asks_after_a_witness(tmp_path: Path, est, *verbs: str) -> tuple[list[dict], list[dict], list[dict], str]:
    """A lead on `idp` that reads idp first (the witness that it is live and asking), then asks each of
    `verbs` on `tacit-knowledge`. Returns the idp rows, the tacit rows, the tacit denial records and
    what the investigator was told after the last call."""
    from defender.records import RunPaths
    from defender._io import read_jsonl_rows

    S = _spec()
    asked = S.query_params("user:alice")
    est.answer("idp", "query", asked, {"rows": []})
    run_dir, tacit, gather = _gather_lookups(
        tmp_path, est, S.query_turn("idp", "query", asked),
        *[S.query_turn(SYSTEM, v, LOOKUP_PARAMS if v == LOOKUP else {}) for v in verbs], system="idp")
    idp = [r for r in S.lead_rows(run_dir) if r["system"] == "idp"]
    paths = RunPaths(run_dir)
    denials = [d for d in read_jsonl_rows(paths.policy_denials)
               if d.get("system") == SYSTEM] if paths.policy_denials.is_file() else []
    return idp, tacit, denials, gather.seen[-1]


def _row(verb: str, roles: tuple[str, ...] = ("gather",)) -> tuple[str, tuple[str, ...]]:
    return (verb, roles)


@pytest.mark.parametrize(("rows", "denied", "control"), [
    pytest.param((_row(LOOKUP, ()), _row("health-check")), LOOKUP, "health-check", id="row-with-no-role"),
    pytest.param((_row(LOOKUP, ()), _row("health-check", ())), LOOKUP, None, id="both-roles-empty-lookup"),
    pytest.param((_row(LOOKUP, ()), _row("health-check", ())), "health-check", None, id="both-roles-empty-health-check"),
    pytest.param((_row("health-check"),), LOOKUP, "health-check", id="lookup-row-deleted"),
    pytest.param((_row(LOOKUP),), "health-check", LOOKUP, id="health-check-row-deleted"),
    pytest.param((), LOOKUP, None, id="rows-deleted"),
])
def test_1390_a_withheld_or_row_less_call_is_denied_and_recorded_not_undeclared(tmp_path, rows, denied, control):
    """Whether the table withholds the verb, deleted its row or deleted every row, the call is denied with a denial record and wording that does not send the model to add rows; a granted verb on the same system still works. O4, A3, O10."""
    from defender.systems.circuit_breaker import DENIED_EXIT_CODE

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate", tacit_roles=rows)
    est.write_registry(json.dumps({"entries": [_current_entry()]}))

    idp, tacit, denials, told = _asks_after_a_witness(tmp_path, est, *([control] if control else []), denied)

    assert [r["exit_code"] for r in idp] == [0], "witness: the lead really asked, and idp answered"
    assert [(r["verb"], r["exit_code"]) for r in tacit] == [
        *([(control, 0)] if control else []), (denied, DENIED_EXIT_CODE)], (
        f"the calls were not recorded as a granted answer and a denial: {tacit}")
    assert [d.get("verb") for d in denials] == [denied], (
        f"a denial leaves one policy-denial record for the withheld verb, found {denials}")
    assert "withheld" in told.lower(), f"the refusal does not say the verb is withheld:\n{told}"
    for add_rows in ("needs rows", "just connected"):
        assert add_rows not in told.lower(), (
            f"the refusal tells the model to add table rows ({add_rows!r}):\n{told}")


def test_1390_with_no_rows_list_verbs_offers_the_lead_nothing_on_the_registry(tmp_path):
    """A table with no `tacit-knowledge` rows leaves `list_verbs` offering no verb on it, and the same registry with rows offers both. O10."""
    from defender.investigation.query_catalog import _tool_list_verbs

    S = _spec()
    granted = S.TacitEstate(tmp_path / "granted")
    assert "the 2 verb(s) your grant admits" in _tool_list_verbs(S.plain_registry(granted), SYSTEM), (
        "positive control: with rows the registry's verbs are listed")
    bare = S.TacitEstate(tmp_path / "bare", tacit_roles=())

    assert "your grant reaches no verb" in _tool_list_verbs(S.plain_registry(bare), SYSTEM)


def test_1390_a_registry_refused_whole_is_a_miss_whose_reason_is_in_the_stored_answer(tmp_path):
    """A registry with no `entries:` list answers a miss; the stored answers of `lookup` and `health-check` carry the reader's refusal. O9."""
    from defender.systems import tacit_registry

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    path = est.write_registry("sanctions:\n  - id: tk-misfiled\n")
    reason = tacit_registry.read_registry(path).fatal
    assert reason and "entries:" in reason, f"premise: the reader refuses the file whole: {reason!r}"

    run_dir, rows, _g = _gather_lookups(
        tmp_path, est, _spec().query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS),
        _spec().query_turn(SYSTEM, "health-check", {}))

    assert [(r["verb"], r["exit_code"]) for r in rows] == [(LOOKUP, 0), ("health-check", 0)]
    visible = reason.replace(str(path), "skills/tacit-knowledge/registry.yaml")
    assert _stored_answer(run_dir, rows[0]) == {"matched": None, "registry_problems": [visible]}
    health = _stored_answer(run_dir, rows[1])
    assert health["registry_problems"] == [visible]
    assert not str(health["registry"]).startswith("/"), "health-check names the registry by a host path"


def test_1390_a_dropped_entry_rides_a_hit_in_the_stored_answer(tmp_path):
    """A hit from a registry that also dropped an entry is stored with `matched` unchanged and the reader's refusal beside it. O9."""
    from defender.systems import tacit_registry

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    good = _current_entry()
    path = est.write_registry(json.dumps({"entries": [
        good, {**_current_entry(id="tk-1390-blanket"), "actor_scope": "*"}]}))
    dropped = list(tacit_registry.read_registry(path).refusals)
    assert len(dropped) == 1, f"premise: the reader drops the blanket entry: {dropped}"

    run_dir, rows, _g = _gather_lookups(tmp_path, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS))

    assert _stored_answer(run_dir, rows[0]) == {"matched": good, "registry_problems": dropped}


def test_1390_the_repeat_guard_applies_to_the_registry(tmp_path):
    """The third identical lookup in one lead is stopped by the repeat guard and never reaches the registry; the first two are answered. O4."""
    from defender.investigation.record_query import REPEAT_ESCAPE

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    est.write_registry(json.dumps({"entries": [_current_entry()]}))
    ask = S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS)

    _run_dir, rows, gather = _gather_lookups(tmp_path, est, ask, ask, ask)

    codes = [r["exit_code"] for r in rows]
    assert codes[:2] == [0, 0] and len(codes) == 3 and codes[2] != 0, (
        f"the third identical lookup was not stopped: {codes}")
    assert REPEAT_ESCAPE in gather.seen[-1], f"the lead was not told to move on:\n{gather.seen[-1]}"


def test_1390_a_tripped_circuit_breaker_refuses_a_lead_on_the_registry(tmp_path):
    """With the run's breaker tripped for `tacit-knowledge` (a platform verb has no infra failure to charge, so it is charged directly), no lead on it runs a lookup; untripped, one does. O4."""
    from defender.systems import circuit_breaker

    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    est.write_registry(json.dumps({"entries": [_current_entry()]}))
    ask = S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS)
    _d, control, _g = _gather_lookups(tmp_path / "control", est, ask)
    assert [r["exit_code"] for r in control] == [0], "positive control: the untripped lead is answered"
    state = S.run_state(tmp_path / "breaker-run")
    for _ in range(circuit_breaker.PER_SYSTEM_FAIL_LIMIT):
        circuit_breaker.record_outcome(state, SYSTEM, 124)
    assert circuit_breaker.is_tripped(state, SYSTEM), "premise: the breaker is tripped"

    _d, rows, gather = _gather_lookups(tmp_path / "tripped", est, ask, run_state=state)

    assert rows == [] and gather.seen == [], f"a lead on a tripped registry ran: {rows}"


def test_1390_a_resumed_run_clock_is_the_day_a_lookup_through_the_query_tool_is_judged_against(tmp_path):
    """A run state whose clock resumed at a past reading hits an entry expired by today; a fresh run state misses it. O2."""
    S = _spec()
    est = S.TacitEstate(tmp_path / "estate")
    entry = scene.registry_entry(added_at="2026-04-01", review_by="2026-07-01")
    est.write_registry(json.dumps({"entries": [entry]}))
    assert dt.datetime.now(dt.UTC).date() > dt.date(2026, 7, 1), "premise: the entry has expired by today"
    sibling = S.run_state(tmp_path / "sibling-clock")
    sibling.resume_clock(dt.datetime(2026, 5, 1, 12, tzinfo=dt.UTC), 0.0)
    live = S.run_state(tmp_path / "live-clock")

    answers = []
    for name, state in (("sibling", sibling), ("live", live)):
        run_dir, rows, _g = _gather_lookups(
            tmp_path / name, est, S.query_turn(SYSTEM, LOOKUP, LOOKUP_PARAMS), run_state=state)
        answers.append(_stored_answer(run_dir, rows[0]))

    assert answers == [{"matched": entry}, {"matched": None}], (
        f"the query tool did not judge the lookup against the run's own clock: {answers}")
