"""#1077 — the properties that must survive the migration, driven through the real run."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import json
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.storage import _session_store_705 as SS
from defender.tests.support.shared.contracts import _spec1077 as S

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e


def _closing_turns() -> list[Turn]:
    return [
        Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text()})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ]


def _read_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


# O5 — append-only, readable mid-run, forkable at turn N

def test_leads_and_queries_stay_append_only_and_readable_mid_run_through_the_handle(
        tmp_path: Path):
    run_dir = materialize(tmp_path, GOLDEN)
    base = run_dir.parent
    handle = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)
    queries = S.member(handle, "tables", "queries")
    leads = S.member(handle, "tables", "leads", S.LEAD_ID)

    queries.append([{"seq": 0, "system": "elastic"}])
    # A lead claim is an EXCLUSIVE-CREATE sidecar (the design's own words for `tables`:
    # "append-only; exclusive-create claims"): written once, and a second claim on the same
    # lead id collides — which is what keeps two dispatches of one lead from being one row.
    leads.write(json.dumps({"lead_id": S.LEAD_ID, "goal": "first"}))
    with pytest.raises(Exception, match="write-once"):
        leads.write(json.dumps({"lead_id": S.LEAD_ID, "goal": "second"}))
    assert json.loads(leads.read())["goal"] == "first", "the second claim overwrote the first"

    # A SECOND PROCESS reads the tables while the run is still going — the property O5 names.
    reader = subprocess.run(
        [sys.executable, "-c",
         "import json,sys,pathlib\n"
         "p = pathlib.Path(sys.argv[1])\n"
         "print(json.dumps([json.loads(x) for x in p.read_text().splitlines() if x.strip()]))\n",
         str(queries.path)],
        capture_output=True, text=True, timeout=120)
    assert reader.returncode == 0, reader.stderr
    assert json.loads(reader.stdout) == [{"seq": 0, "system": "elastic"}], (
        "a second process could not read the queries table mid-run")

    # APPEND-ONLY: the second append leaves the first row where it was, byte for byte.
    before = queries.path.read_bytes()
    queries.append([{"seq": 1, "system": "elastic"}])
    after = queries.path.read_bytes()
    assert after.startswith(before), (
        "the second append rewrote the table rather than appending to it — O5 says this "
        "property MUST SURVIVE the migration")
    assert len(_read_rows(queries.path)) == 2
    rewrite = "an append-only table exposes no whole-file rewrite through the handle"
    assert not hasattr(queries, "truncate"), rewrite
    assert not hasattr(queries, "write"), rewrite


def test_resume_joins_a_session_store_with_an_incomplete_last_append(tmp_path: Path):
    base = location_path(SS.runs_base)(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, fixture_uuid("run-resume")))
    handle = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)

    with S.member(handle, "session", "session_db", "case-alpha").open() as store:
        session_id, _ = SS.mid_pair_session(store)
        torn = SS.sql(store, """
            SELECT m.id FROM message m
            LEFT JOIN message_payload p ON p.message_id = m.id
            WHERE m.session_id = ? AND p.message_id IS NULL
        """, (session_id,))
        assert torn == [], (
            f"a message row with no payload row is observable: {torn} — RG-3 established that "
            "both writes commit inside one transaction")
        # A JOINING reader — a second connection, as a resume or fork opens — sees the same.
        joiner = SS.store_mod().open_store_for_read(store.path)
        try:
            rows = SS.sql(joiner, """
                SELECT m.id FROM message m
                LEFT JOIN message_payload p ON p.message_id = m.id
                WHERE m.session_id = ? AND p.message_id IS NULL
            """, (session_id,))
            assert rows == [], f"the joining reader observed a torn last append: {rows}"
            committed = SS.sql(
                joiner, "SELECT COUNT(*) FROM message WHERE session_id = ?", (session_id,))
            assert committed[0][0] >= 1, "positive control: the joiner sees the committed rows"
        finally:
            joiner.connection.close()


def test_a_second_claim_on_one_lead_still_loses_the_exclusive_create(tmp_path: Path):
    from defender.hooks import record_lead
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))
    dispatch = {"run_dir": str(run_dir), "lead_id": S.LEAD_ID, "goal": "first claim",
                "what_to_summarize": ["a"]}

    first = record_lead.claim_lead(dispatch, run=fixture_run(run_dir))
    second = record_lead.claim_lead({**dispatch, "goal": "second claim"}, run=fixture_run(run_dir))

    assert first == record_lead.CLAIMED
    assert second == record_lead.ALREADY_CLAIMED, (
        "claim C19: the exclusive create sits under a `guarded_mkdir` anchored at run_dir and "
        "`write_guarded` stages with O_CREAT|O_EXCL|O_NOFOLLOW; exactly one claim wins")
    sidecar = S.RunPaths(run_dir).lead_claim(S.LEAD_ID)
    assert sidecar.is_file()
    assert "first claim" in sidecar.read_text(encoding="utf-8"), (
        "the loser overwrote the winner's row")
    # A DIFFERENT lead id still wins its own claim — the refusal is per key, not a blanket one.
    assert record_lead.claim_lead({**dispatch, "lead_id": "l-other1"}, run=fixture_run(run_dir)) == record_lead.CLAIMED


def test_the_append_only_tables_written_by_two_routes_at_once(tmp_path: Path):
    from defender._io import append_jsonl
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, fixture_uuid("run-mixed")))
    handle = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)
    queries = S.member(handle, "tables", "queries")

    queries.append([{"seq": 0, "route": "handle"}])
    append_jsonl(S.RunPaths(run_dir).executed_queries, [{"seq": 1, "route": "unmigrated"}])
    queries.append([{"seq": 2, "route": "handle"}])

    rows = _read_rows(queries.path)
    assert [r["seq"] for r in rows] == [0, 1, 2], (
        f"the two routes did not interleave as appends: {rows}")
    assert [r["route"] for r in rows] == ["handle", "unmigrated", "handle"]
    assert queries.read() == S.RunPaths(run_dir).executed_queries.read_text(encoding="utf-8"), (
        "the two routes resolve two different files, which is the regression D7(3) forbids")


def test_a_writer_that_runs_outside_the_driver_process(tmp_path: Path):
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, fixture_uuid("run-outside")))

    # (1) THE HOOK's arm retired with #1235: the accounting-failures sidecar it wrote is gone
    # (the budget is counted in the run process's memory, and nothing writes the sidecar).

    # (2) THE ALIAS PROBE, host-initiated INSIDE the box: claim C14 is REFUTED-as-stated —
    # the model's bash is NOT the only in-box run-dir writer, this probe is the second.
    probe_entry = run_dir / ".alias-probe-deadbeefdeadbeef-symlink"
    probe_entry.write_text("", encoding="utf-8")
    assert probe_entry.is_relative_to(run_dir)
    probe_entry.unlink()

    # (3) THE MODEL'S OWN SHELL: the run dir is the box's one rw bind (N1), so a write from
    # inside it lands in the same tree the handle names — unchanged by the migration.
    from_bash = run_dir / "scratch.txt"
    from_bash.write_text("written by the model's shell\n", encoding="utf-8")
    assert S.Run().at(run_dir).run_dir == run_dir
    assert from_bash.read_text(encoding="utf-8") == "written by the model's shell\n"


def test_a_failed_observability_write_is_recorded_and_does_not_fail_the_run(tmp_path: Path):
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, fixture_uuid("run-besteffort")))
    handle = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)

    # A REAL obstruction through the REAL primitive: the record's own path is occupied by a
    # directory, so today's append seam raises on disk. No exception is injected.
    trace = S.member(handle, "observability", "tool_trace")
    trace.path.mkdir(parents=True)

    trace.append([{"row": 1}])       # must NOT raise: observability is best-effort

    assert handle.partial_failures, (
        "decision 7's best-effort half still RECORDS the failure — flagged fact F9 is the line "
        "the existing code already draws, and a silently dropped observability write is the "
        "half of it this spec refuses")
    assert any("tool_trace" in str(f) for f in handle.partial_failures), handle.partial_failures

    # POSITIVE CONTROL: with the obstruction gone the same append lands and records nothing.
    trace.path.rmdir()
    clean = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)
    S.member(clean, "observability", "tool_trace").append([{"row": 2}])
    assert _read_rows(trace.path) == [{"row": 2}]
    assert clean.partial_failures == ()

    # THE CONTRAST, in one test: the SAME obstruction on a decision-bearing write fails loudly
    # rather than being recorded and shrugged off. #1187 (R1): the runs-base record this used
    # to obstruct is retired (and `Run.under` reads none), so the obstructed write is the
    # run's own report — a record the run's verdict is read from, never best-effort.
    report = S.member(clean, "documents", "report")
    report.path.mkdir(parents=True)
    with pytest.raises(OSError, match="non-plain or aliased"):
        report.write(S.report_text("# the contrast\n"))
    assert clean.partial_failures == (), (
        "a failed report write was recorded as a partial failure and shrugged off")


# g01 / g05 / h49 — the payloads the run writes, and who wrote each wire-log line


def test_every_wire_log_record_carries_a_writer_id_that_tells_main_from_each_subagent(
        tmp_path: Path):
    run_dir = materialize(tmp_path, GOLDEN, run_id='writerid-1077')
    drive(run_dir, run_id="writerid-1077", main=ReplayFn(_closing_turns()))

    from defender.runtime.observe import POLICY_DENIAL_EVENT_TYPE
    rows = _read_rows(S.RunPaths(run_dir).wire_log)
    assert rows, "the replay produced no wire-log records"
    # Every AGENT-produced record: a message, a budget refusal. A policy denial is the host's
    # bounded projection of a call, keyed by `role`, whose exact key set #632 pins
    # (`test_denial_audit_632`) — it names its writer already and gains no second field.
    rows = [r for r in rows if r.get("event_type") != POLICY_DENIAL_EVENT_TYPE]
    missing = [i for i, r in enumerate(rows) if not r.get("writer_id")]
    assert missing == [], (
        f"records {missing[:5]} carry no writer id — decision 18 adds one to EVERY record, "
        "which is what makes the main process and every concurrent gather sub-agent "
        "individually attributable inside the one file they share (flagged fact F5)")
    assert any(r["writer_id"] == "MAIN" or r["writer_id"].lower() == "main" for r in rows), (
        f"no record names MAIN as its writer: {sorted({r['writer_id'] for r in rows})}")
    # And this is the trade-off O3's second exemption pays for: the wire log's BYTES change.
    assert "writer_id" in S.RunPaths(run_dir).wire_log.read_text(encoding="utf-8")

    # The reader retains writer IDs on every record in the shared wire log.
    # Import data first to resolve its existing import cycle with messages.
    import defender.presentation.visualize_data  # noqa: F401
    from defender.presentation.visualize_messages import load_messages
    assert load_messages(run_dir) == rows, (
        "the shipped wire-log viewer no longer round-trips the records it is handed once every "
        "one carries decision 18's `writer_id`; the issue's Done-when says existing consumers "
        "keep working, and this is the C7-analogue the wire log's field addition never had")


def test_wire_log_writers_stay_distinguishable_under_concurrent_main_and_subagent_appends(
        tmp_path: Path):
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, fixture_uuid("run-concurrent")))
    handle = S.Run().under(fixture_runs_base(base), run_dir.name, tenant_id=S.DEFAULT_TENANT_ID)
    wire = S.member(handle, "observability", "wire_log")

    writers = ("MAIN", "gather-l-aaa111", "gather-l-bbb222")
    for i in range(30):
        who = writers[i % len(writers)]
        wire.append_text("".join(json.dumps(row) + "\n" for row in [{'event_type': 'message', 'writer_id': who, 'seq': i, 'message': 'x' * 512}]))

    text = S.RunPaths(run_dir).wire_log.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == 30, f"lines were lost or torn: {len(lines)}"
    rows = [json.loads(line) for line in lines]      # a torn line raises here
    by_writer: dict[str, list[int]] = {}
    for r in rows:
        by_writer.setdefault(r["writer_id"], []).append(r["seq"])
    assert set(by_writer) == set(writers), (
        f"the writers are not separable from the stream they share: {sorted(by_writer)}")
    assert sum(len(v) for v in by_writer.values()) == 30
    assert all(seqs == sorted(seqs) for seqs in by_writer.values()), (
        "one writer's own lines arrived out of order inside the shared file")
