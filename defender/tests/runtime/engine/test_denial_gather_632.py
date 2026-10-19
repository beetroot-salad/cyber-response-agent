"""Gather-site verb denial: legible refusal, no evidence row or breaker movement, decided from the grant alone before traversal/availability checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.circuit_breaker import DENIED_ERROR_CLASS  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender._query_rules import DENIED_QUERY_ID
from defender.tests.support.learning.curation._verb_authorization_632 import (  # noqa: E402
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
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402
from defender.tests.support.shared.contracts._after_start_1256 import AfterStart, Relink  # noqa: E402

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
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE], run_id="d0")

    assert rec.calls == [], "the denied verb body ran"
    assert r.gather.calls >= 2, "the refusal did not come back as a result the loop continued past"
    assert r.own_evidence == [], "a denied call wrote an evidence row"
    assert len(r.own_denied_rows) == 1, "the denial left no `∅.denied` sentinel row (#860)"
    assert r.breaker.get("total_failures", 0) == 0
    assert "esql" in r.gather_saw


def test_a_denial_reaches_the_model_even_when_its_row_cannot_be_written(tmp_path: Path):
    from defender.run_repository import RunPaths
    from defender.tests.support.learning.curation._verb_authorization_632 import _Run
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, ReplayFn, Turn, drive, materialize

    class BreakingReplay(ReplayFn):
        def __init__(self, turns, run_dir):
            super().__init__(turns)
            self.run_dir = run_dir

        def __call__(self, messages, info):  # noqa: ANN001 — the framework's callable protocol
            if self.calls == 0:
                table = RunPaths(self.run_dir).executed_queries
                table.unlink(missing_ok=True)  # the correlation lead (#1222) may have written no row
                table.mkdir()
            return super().__call__(messages, info)

    def _main() -> ReplayFn:
        return ReplayFn([
            Turn(tool_calls=[("gather", {
                "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
                "what_to_summarize": ["auth events"],
            })]),
            Turn(text="Investigation complete."),
        ])

    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='d0-broken-table')
    main = _main()
    gather = BreakingReplay([q(*DENIED_PAIR), DONE], run_dir)
    summary = drive(run_dir, run_id="d0-broken-table", main=main, gather=gather,
                    verbs=_registry(rec))
    r = _Run(run_dir, main, gather, summary)

    assert rec.calls == [], "the denied verb body ran"
    assert r.gather.calls >= 2, \
        "the row-write fault ended the lead: the refusal never came back as a result"
    assert "not granted" in r.gather_saw, "the model did not see the refusal"
    assert "esql" in r.gather_saw, "the refusal the model saw does not name the verb"
    assert len(r.own_denials) == 1, "the audit record — written FIRST — is missing"
    assert [row["query_id"] for row in summary["run_state"].lead_rows(LEAD)] == \
        [DENIED_QUERY_ID], "the denied call is not on the run's state: its view write failed"

    control_dir = materialize(tmp_path / "unbroken", GOLDEN_AB3, run_id='d0-unbroken-table')
    control = drive(control_dir, run_id="d0-unbroken-table", main=_main(),
                    gather=ReplayFn([q(*DENIED_PAIR), DONE]), verbs=_registry(VerbRecorder()))
    assert [row["query_id"] for row in control["run_state"].lead_rows(LEAD)] == \
        [DENIED_QUERY_ID], \
        "positive control: over an unbroken table the denied call's row is not on the run's state"


def test_a_denied_verb_is_not_the_unknown_verb_path(tmp_path: Path):
    """A denied verb is refused WITHOUT the evidence row, the `agent-fixable` class or the retry
    coaching that an undeclared verb still gets."""
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
    """A verb no adapter declares still gets today's unknown-verb treatment — the queries row, the
    `agent-fixable` class and the retry coaching."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q("elastic", "nosuch-verb"), DONE],
                   run_id="d37")

    assert rec.calls == []
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["exit_code"] != 0
    assert r.own_rows[0]["error_class"] == "agent-fixable"
    assert r.own_rows[0]["verb"] == "nosuch-verb"
    assert r.gather.calls >= 2, "the unknown verb did not bounce the agent back into its loop"


def test_a_refusal_lists_only_the_roles_granted_subset(tmp_path: Path):
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

    kept = VerbRecorder()
    later = run_gather(tmp_path / "then-granted", verbs=_registry(kept),
                       turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*GRANTED_PAIR), DONE],
                       run_id="d3-seq")
    assert [c.verb for c in kept.calls] == ["query"]
    assert [(row["seq"], row["query_id"]) for row in later.own_rows] \
        == [(0, DENIED_QUERY_ID), (1, DENIED_QUERY_ID), (2, "elastic.query")], \
        "the denials' sentinel rows and the granted row do not take consecutive seqs in order"


def test_a_denial_is_the_dispatched_leads_own_row_and_the_audit_record_is_the_runs(tmp_path: Path):
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


def test_a_malformed_call_keeps_todays_queries_row(tmp_path: Path):
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*GRANTED_PAIR, {"nosuch_param": 1}), DONE], run_id="d5")

    assert rec.calls == []
    assert len(r.own_rows) == 1
    assert r.own_rows[0]["error_class"] == "agent-fixable"
    assert r.own_denials == []


def test_a_malformed_and_denied_call_takes_the_denial_path(tmp_path: Path):
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
    """A denial against a system this run has already given up on is still DECIDED and AUDITED: the
    grant check runs before the availability short-circuit (§7 R3)."""
    from defender.scripts.adapters.faults import TransportFault

    rec = VerbRecorder()
    assert circuit_breaker.PER_SYSTEM_FAIL_LIMIT == 2, "the trip budget moved; the script below is stale"

    r = run_gather(tmp_path, verbs=_registry(rec, raises=TransportFault("down")), turns=[
        q(*GRANTED_PAIR), q(*GRANTED_PAIR),   # two infra faults trip `elastic` for this run
        q(*DENIED_PAIR),                      # ... and the denial must still be evaluated
        DONE,
    ], run_id="d56")

    assert circuit_breaker.is_tripped(r.summary["run_state"], "elastic"), \
        "the system never went down"
    assert len(r.own_denials) == 1, "the availability short-circuit silenced the denial's audit record"
    assert r.own_denials[0]["verb"] == "esql"
    assert len(r.own_evidence) == 2, "the denial against a down system wrote an evidence row"
    assert len(r.own_denied_rows) == 1, "the down-message short-circuited the denial's own row"


def test_a_denial_does_not_move_the_circuit_breaker(tmp_path: Path):
    """A denial contributes nothing to the circuit breaker, matching the closed-ticket tool's
    existing rule that a business refusal is not an infra fault."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec),
                   turns=[q(*DENIED_PAIR), q(*DENIED_PAIR), q(*DENIED_PAIR), DONE], run_id="d10")

    assert r.breaker.get("total_failures", 0) == 0
    assert r.breaker.get("systems", {}) == {}
    assert r.main.calls == 2, "the run did not continue past three denials"
    assert {row["exit_code"] for row in r.own_denied_rows} == {circuit_breaker.DENIED_EXIT_CODE}
    assert not circuit_breaker.is_infra_failure(circuit_breaker.DENIED_EXIT_CODE)


def test_a_denials_sentinel_row_is_a_sentinel_to_every_reader(tmp_path: Path):
    from defender.learning.lead_repository import joined
    from defender.runtime.query_tool import resolve_query_id
    from defender.scripts.gather_tools.record_query import (
        in_rejection_domain,
        rejection_budget_trip,
        repeat_trip,
    )
    from defender._query_rules import is_reserved_query_id

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


def test_a_denial_is_decided_from_the_grant_without_importing_the_adapter(tmp_path: Path):
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "elastic_adapter.py").write_text(
        "def check_settings(*_a, **_k):\n    return None\n"
        "def query(ctx, *, native_query: str) -> dict:\n    return {}\n"
        "VERBS = {'query': query, 'esql': query}\n", encoding="utf-8")
    (adapters / "cmdb_adapter.py").write_text(
        "def check_settings(*_a, **_k):\n    return None\n"
        "def get_host(ctx, *, host: str) -> dict:\n    return {}\n"
        "def list_hosts(ctx) -> dict:\n    return {}\n"
        "VERBS = {'get-host': get_host, 'list-hosts': list_hosts}\n", encoding="utf-8")
    relink = Relink(adapters / "cmdb_adapter.py",
                    "raise ImportError('boom')\n"
                    "VERBS = {'get-host': None, 'list-hosts': None}\n")

    from defender.runtime.verbs import ModuleVerbRegistry

    grant = grant_of("gather", (("elastic", "query"), ("cmdb", "get-host")))
    reg = ModuleVerbRegistry(read_roster(adapters), grant)
    relink.break_()
    assert reg.decide("mystery", "get-host").outcome == UNDECLARED, \
        "a system the grant reaches nowhere resolved to something other than unresolvable"
    assert reg.decide("elastic", "esql").outcome == DENIED
    assert reg.decide("elastic", "query").outcome == GRANTED
    assert reg.decide("cmdb", "list-hosts").outcome == DENIED, (
        "a verb withheld on a system whose adapter cannot be imported was not denied — the "
        "decision reached for the module instead of the grant, or swallowed the import error "
        "and downgraded the denial to unresolvable"
    )

    # The run starts over the importable file; the lead's call meets it broken.
    relink.restore()
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    root = tmp_path / "tenant-data"
    S.plant(root, table="""dispositions:
  elastic:
    query: {roles: [gather]}
  cmdb:
    get-host: {roles: [gather]}
""")
    r = run_gather(tmp_path / "run", verbs=reg, system="cmdb", tenant=S.tenant_folder_of(root),
                   turns=[AfterStart(q("cmdb", "list-hosts"), relink.break_), DONE],
                   run_id="d38-unloadable")
    assert relink.broken == 2, "premise: the adapter was not broken after the run's start"
    assert [row["query_id"] for row in r.own_rows] == [DENIED_QUERY_ID], \
        "the denial on an unloadable system was recorded as an unresolvable query instead"
    assert len(r.own_denials) == 1, \
        "a denial on an unloadable system produced no audit record — it was downgraded"
    assert r.own_denials[0]["verb"] == "list-hosts"


def test_a_transient_adapter_import_failure_does_not_stick_across_a_run(tmp_path: Path):
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


@pytest.mark.parametrize(("system", "verb"), [
    ("Elastic", "query"), (" elastic", "query"), ("elastic ", "query"),
    ("elastic", "QUERY"), ("elastic", " query"), ("elastic", "query "),
])
def test_a_case_or_whitespace_variant_of_a_granted_name_never_executes(
    tmp_path: Path, system: str, verb: str,
):
    """A case or whitespace variant of a granted system name or a granted verb name is never treated
    as granted and never executes: no normalization equates it to the real name."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(system, verb), DONE],
                   run_id=f"d48-{abs(hash((system, verb)))}")

    assert rec.calls == [], f"the near-miss {system}.{verb} reached a verb body"
    assert r.own_denials == [], "a near-miss was audited as a policy denial rather than unresolvable"
    assert len(r.own_rows) == 1, "a near-miss wrote no unresolvable row"
    assert r.own_rows[0]["exit_code"] != 0


def test_gather_is_denied_ticket_get_ticket(tmp_path: Path):
    """Gather is denied `ticket.get-ticket`, which only the judge used. A class-shaped grant
    could not have expressed this — both are reads on a system gather legitimately holds."""
    rec = VerbRecorder()
    reg = ScopedFakeVerbs(
        recording_table(rec, {"ticket": ("list-tickets", "get-ticket")}),
        T1106.fixture_grants().gather,
    )
    r = run_gather(tmp_path, verbs=reg, system="ticket",
                   turns=[q("ticket", "get-ticket", {"key": "SOC-1"}), DONE], run_id="d22")

    assert rec.calls == [], "gather reached get-ticket"
    assert r.own_evidence == []
    assert len(r.own_denials) == 1
    assert r.own_denials[0]["verb"] == "get-ticket"


def test_an_impersonated_query_id_does_not_change_the_grant_decision(tmp_path: Path):
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
