"""#1077 — the properties that must survive the migration, driven through the real run.

Carries 14 demands of `spec-flow/specs/spec_graph_1077.yaml`. O5 names three properties the
handle must not regress — leads and queries append-only and readable mid-run by another
process, the session store forkable at turn N — and the gate leaf's obligations ask two more
of the writers that share one run dir: that everything `Run` writes has every declared slot
bound (g01) and that the one `RequestLogger` MAIN and every gather sub-agent share stays a
well-formed stream whose writers are distinguishable (g05, satisfied by decision 18's writer
id, demand h49).

Scenarios are `Turn(...)` additions to `defender/tests/e2e/_replay_harness.py` — the project's
existing harness, whose fakes enter through `drive`'s own keyword seams — not fresh plumbing.

THIS FILE LIVES AT THE TOP LEVEL OF `defender/tests/` ON PURPOSE. The graph declares
`tests: defender/tests` and the checkers glob `<dir>/*.py` without recursing, so a
replay-driven test under `tests/e2e/` loses its docstring and its demand reports as a prose
orphan. Importing `defender.tests.e2e._replay_harness` from here is established practice
(`test_salt_origin_647.py`, `test_870_e2e.py`, `test_869_queries_row.py`, ~15 others).
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests import _session_store_705 as SS
from defender.tests import _spec1077 as S

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


# ---------------------------------------------------------------------------------------
# O5 — append-only, readable mid-run, forkable at turn N
# ---------------------------------------------------------------------------------------

def test_leads_and_queries_stay_append_only_and_readable_mid_run_through_the_handle(
        tmp_path: Path):
    """Leads and queries written through the handle stay append-only and are readable by a
    second process while the run is still going."""
    run_dir = materialize(tmp_path, GOLDEN)
    base = run_dir.parent
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
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


def test_the_session_store_still_forks_at_turn_n_through_the_handle(tmp_path: Path):
    """A session opened through the handle still forks at turn N and the sibling reads the
    prefix rows."""
    base = SS.runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-fork"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    session = S.member(handle, "session", "session_db", "case-alpha")

    with session.open() as store:
        session_id, n_complete = SS.mid_pair_session(store)
        rows = SS.sql(store, "SELECT id FROM message WHERE session_id = ? ORDER BY seq",
                      (session_id,))
        at = rows[n_complete - 1][0]
        forked = store.fork(session_id, at)
        prefix = SS.sql(
            store, "SELECT COUNT(*) FROM message WHERE session_id = ?", (session_id,))[0][0]
        assert prefix >= n_complete
        head = SS.sql(store, "SELECT head_message_id FROM session WHERE session_id = ?",
                      (forked,))[0][0]
    assert head == at, (
        "the fork's head is not the branch point; O5's 'forkable at turn N' is the property "
        "that must survive the migration, not a new guarantee")
    assert session.path == S.RunPaths(run_dir).session_db(base, "case-alpha")


def test_the_handles_session_access_reaches_todays_store_seam_with_no_new_guarantee(
        tmp_path: Path):
    """The handle's session access reaches today's session-store seam unchanged and claims no
    concurrency guarantee today's code does not already make — today's 30-second busy-wait
    reaches the connection, today's non-database refusal surfaces unchanged, and `fences_at`
    stays descriptive.

    Cluster M was auto-resolved as "today's behaviour, pinned BY REFERENCE" on three probe
    obligations (PO5, PO6, PO7) and one lifecycle probe (LC-P4) that nobody had answered
    (92-reconciliation.md finding 4). They are answered now, as claims RG-5..RG-8, and this test
    cites them so "by reference" names a reference:

      RG-5  `defender/runtime/session_store.py:277` — `STORE_BUSY_TIMEOUT_MS = 30_000`, applied
            from that ONE anchor at `:283` (`sqlite3.connect(timeout=…/1000)`, seconds) and at
            `:290` (`PRAGMA busy_timeout`, milliseconds).
      RG-6  a non-SQLite file at the resolved path raises `sqlite3.DatabaseError` on the first
            statement, not at `connect`.
      RG-7  (recorded, not driven) a vanished backing file under an ALREADY-OPEN connection
            raises `sqlite3.OperationalError: attempt to write a readonly database` on the next
            write — a WAL inconsistency, not a missing-file error. Not asserted here because the
            message text is brittle across sqlite builds.
      RG-8  `fences_at` has ZERO references in `runtime/session_store.py`; its one real use,
            `learning/branch/questioner/__init__.py:484-521`, slices the rendered investigation
            DOCUMENT when a continuation prompt is composed. Descriptive metadata, never a
            ceiling on what a resumed or forked sibling's connection can see.
    """
    base = SS.runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-seam"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    session = S.member(handle, "session", "session_db", "case-alpha")
    store_mod = SS.store_mod()

    assert session.open_store is store_mod.open_store, (
        "the handle wraps TODAY's seam — inventing a retry policy or enforcing `fences_at` in "
        "the store would be a behaviour change inside an issue whose Done-when says existing "
        "tests pass unchanged")
    for invented in ("retry", "retries", "with_lock", "wait_for", "fences_at"):
        assert not hasattr(session, invented), (
            f"the handle claims a concurrency guarantee today's code does not make: {invented}")

    direct = store_mod.open_store(case_id="case-alpha", runs_base=base)
    try:
        assert session.path == direct.path, "the handle resolves a different database"
    finally:
        direct.connection.close()

    # RG-5. "No new guarantee" cuts both ways: today's seam HAS a busy-wait, and the handle must
    # neither invent a retry policy nor lose this one. Pinned BY REFERENCE, never re-spelled.
    assert store_mod.STORE_BUSY_TIMEOUT_MS == 30_000, (
        "today's busy-wait is 30s at `session_store.py:277`; cluster M pins today's behaviour "
        f"by reference and this is the reference — found {store_mod.STORE_BUSY_TIMEOUT_MS}")
    with session.open() as store:
        carried = SS.sql(store, "PRAGMA busy_timeout")[0][0]
    assert carried == store_mod.STORE_BUSY_TIMEOUT_MS, (
        "the connection reached through the handle does not carry today's busy_timeout "
        f"({carried} != {store_mod.STORE_BUSY_TIMEOUT_MS}) — the wait at `:290` is what makes "
        "'wraps today's seam unchanged' true of a CONCURRENT open, which is cluster M's whole "
        "question (O5 forks a store the source run is still appending to)")

    # RG-8. The fork-point fence is descriptive metadata, not an enforced ceiling: the store
    # module has never heard of it.
    assert "fences_at" not in Path(store_mod.__file__).read_text(encoding="utf-8"), (
        "`fences_at` reached the session store — cluster M's one positive statement is that it "
        "bounds a rendered document at prompt-composition time, not which turns a resumed or "
        "forked sibling can read back out of the store")

    # Today's refusals surface unchanged through the handle, neither softened nor re-worded.
    from defender.runtime.session_store import InvalidCaseId
    with pytest.raises(InvalidCaseId):
        S.member(handle, "session", "session_db", "-not-a-case-id").open()

    # RG-6. A non-SQLite file where the lineage database belongs.
    corrupt = S.member(handle, "session", "session_db", "case-corrupt")
    corrupt.path.parent.mkdir(parents=True, exist_ok=True)
    corrupt.path.write_bytes(b"not a database, just bytes\n" * 8)
    with pytest.raises(sqlite3.DatabaseError):
        corrupt.open()


def test_resume_joins_a_session_store_with_an_incomplete_last_append(tmp_path: Path):
    """A resume or fork joining the source run's session store observes either the fully
    committed last append or its absence, never a torn message row without its payload.

    Cite `defender/runtime/session_store.py:370-401,482-504`: `append()` commits the message
    row and its payload rows inside one `BEGIN IMMEDIATE … COMMIT`, which is what makes the
    torn state unobservable rather than merely unlikely.
    """
    base = SS.runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-resume"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)

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
    """Two claims on one lead through the handle leave exactly one winner, the loser refused by
    the exclusive create."""
    from defender.hooks import record_lead
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))
    dispatch = {"run_dir": str(run_dir), "lead_id": S.LEAD_ID, "goal": "first claim",
                "what_to_summarize": ["a"]}

    first = record_lead.claim_lead(dispatch)
    second = record_lead.claim_lead({**dispatch, "goal": "second claim"})

    assert first == record_lead.CLAIMED
    assert second == record_lead.ALREADY_CLAIMED, (
        "claim C19: the exclusive create sits under a `guarded_mkdir` anchored at run_dir and "
        "`write_guarded` stages with O_CREAT|O_EXCL|O_NOFOLLOW; exactly one claim wins")
    sidecar = S.RunPaths(run_dir).lead_claim(S.LEAD_ID)
    assert sidecar.is_file()
    assert "first claim" in sidecar.read_text(encoding="utf-8"), (
        "the loser overwrote the winner's row")
    # A DIFFERENT lead id still wins its own claim — the refusal is per key, not a blanket one.
    assert record_lead.claim_lead({**dispatch, "lead_id": "l-other1"}) == record_lead.CLAIMED


def test_a_reader_process_resolving_names_in_a_live_run(tmp_path: Path):
    """A second process resolving names through the handle during a live run is an intended,
    supported situation: O5 requires leads and queries readable mid-run and the session store
    forkable at turn N."""
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-live"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    S.member(handle, "tables", "queries").append([{"seq": 0}])
    before = S.mutation_census(run_dir)

    reader = subprocess.run(
        [sys.executable, "-c",
         "import sys, pathlib\n"
         f"sys.path.insert(0, {str(S.REPO_ROOT)!r})\n"
         f"from defender.{S.HANDLE_MODULE} import Run\n"
         "run = Run.at(pathlib.Path(sys.argv[1]))\n"
         "print(run.tables.queries.path)\n"
         "print(run.observability.wire_log.path)\n"
         "print(run.record.run_id)\n",
         str(run_dir)],
        capture_output=True, text=True, timeout=180, env={**os.environ})
    assert reader.returncode == 0, reader.stderr
    said = reader.stdout.splitlines()
    assert said[0] == str(S.RunPaths(run_dir).executed_queries)
    assert said[2] == run_dir.name
    assert S.mutation_census(run_dir) == before, (
        "the reader process MUTATED the run it was reading — decision 9 makes path-asking pure "
        "for exactly this situation (claim G6: `observe.stage_trace_path` mkdirs today)")


def test_the_append_only_tables_written_by_two_routes_at_once(tmp_path: Path):
    """O5's append-only, readable-mid-run property holds even in the mixed-route intermediate
    state of D7(3), where one writer goes through the handle and another still spells the name:
    the doc requires no regression on this axis at any step."""
    from defender._io import append_jsonl
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-mixed"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
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
    """The accounting sidecar (a hook), the alias-ban probe (host-initiated inside the box) and
    the model's own shell all write outside the driver process today, and D5's 'writer methods
    wrap today's seams unchanged' keeps that true after the migration."""
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-outside"))
    owner = S.RunPaths(run_dir)

    # (1) THE HOOK, in its own process: the accounting sidecar lands beside the runs base.
    sidecar = owner.accounting_failures(base)
    assert sidecar.parent == base
    assert sidecar.name.startswith(run_dir.name)
    hook = subprocess.run(
        [sys.executable, "-c",
         "import sys, pathlib\n"
         f"sys.path.insert(0, {str(S.REPO_ROOT)!r})\n"
         "pathlib.Path(sys.argv[1]).write_text('{\"failures\": 1}\\n')\n",
         str(sidecar)], capture_output=True, text=True, timeout=120)
    assert hook.returncode == 0, hook.stderr
    assert sidecar.is_file(), "the hook's write outside the driver process did not land"

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


def test_learning_run_dir_copy_gains_a_trace_file_after_its_own_lifecycle_appeared_done(
        tmp_path: Path):
    """The forward-check verifier writing a wire trace into a learning run dir it is READING as
    evidence is existing, ongoing production behaviour that this issue explicitly leaves
    unowned, unchanged and unrestricted.

    THIS IS THE C16 REFUTATION AS A TEST: "nothing writes under `LoopPaths.runs_dir` any more"
    is FALSE, and a demand or test asserting the opposite is refused by the Resolution.
    """
    observe = S.mod("runtime.observe")
    learning_run = tmp_path / "state" / "runs" / "source-42"
    S.seed_run_tree(learning_run)
    (learning_run / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    before = S.snapshot(learning_run)

    # The verifier composes its trace name exactly as `checks.py:72` does, and `stage_trace_path`
    # creates the holding directory under the root it is handed.
    trace = observe.stage_trace_path(
        learning_run, f"{S.PREFIX}.{S.STEM}.{S.CHECK_INDEX}.trace.jsonl")
    trace.write_text('{"event_type": "message"}\n', encoding="utf-8")

    assert trace.is_relative_to(learning_run), (
        "the forward-check verifier writes into the CITED RUN's dir, in production, while "
        "reading that run as evidence (flagged fact F1, claim S7)")
    gained = set(S.snapshot(learning_run)) - set(before)
    assert gained, "the fixture did not actually write into the learning run dir"
    # The handle neither owns it nor objects to it.
    handle = S.Run().at(learning_run)
    assert handle.run_dir == learning_run
    assert handle.runs_base is None
    assert handle.record.tenant_id is None, (
        "receiver kind (5) stays out of D1-D7's scope: no accessor covers it and nothing here "
        "restricts it")


def test_a_fork_or_archive_of_a_still_running_source_is_supported(tmp_path: Path):
    """Declaring a fork from, or archiving a world of, a run that has not yet reached run-end is
    a supported operation, not a refusal."""
    from defender.tests import _triplet_947 as T
    base, source = T.runs_base(tmp_path)
    # A run that has NOT reached run-end: no sidecar beside it, no report disposition committed.
    running_sidecar = S.RunPaths(source).run_end_sidecar(base)
    if running_sidecar.exists():
        running_sidecar.unlink()
    assert not running_sidecar.exists(), "the fixture source has already ended"

    episode_dir = T.episode(tmp_path, episode_id=f"{S.EPISODE_ID}-running")
    family = S.EpisodePaths(episode_dir).family
    S.mod("runtime.branch._family").write_family(episode_dir, {
        "episode_id": f"{S.EPISODE_ID}-running", "source_run_dir": str(source),
        "source_run_id": source.name, "branch_message_id": 3, "fences_at": 3})
    assert family.is_file(), (
        "declaring a fork from a still-running source must not be a refusal — what the archive "
        "captures is whatever exists at call time, consistent with O5's 'readable mid-run'")

    sibling = T.sibling_run_dir(base, "a")
    S.mod("learning.branch.archive").archive_episode(episode_dir, {"a": sibling})
    world = S.EpisodePaths(episode_dir).world_dir("a")
    assert world.is_dir(), "archiving a world from a sibling still in progress was refused"


def test_a_failed_observability_write_is_recorded_and_does_not_fail_the_run(tmp_path: Path):
    """A failed wire-log, review-trace, sidecar or tool-trace write is recorded as a partial
    failure and does not fail the run."""
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-besteffort"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)

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
    clean = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    S.member(clean, "observability", "tool_trace").append([{"row": 2}])
    assert _read_rows(trace.path) == [{"row": 2}]
    assert clean.partial_failures == ()

    # THE CONTRAST, in one test: the SAME obstruction on an IDENTITY-BEARING write fails loudly
    # rather than being recorded and shrugged off.
    (base / S.TENANT_RECORD_NAME).mkdir()
    with pytest.raises(OSError):  # noqa: PT011 — the real primitive picks the errno, not us
        S.tenant().ensure_tenant(base)


# ---------------------------------------------------------------------------------------
# g01 / g05 / h49 — the payloads the run writes, and who wrote each wire-log line
# ---------------------------------------------------------------------------------------

def test_runs_written_records_are_all_slots_bound_and_role_disjoint(tmp_path: Path):
    """Every record `Run`'s writer methods produce under `run_dir` (queries, leads, payloads,
    review records, wire-log lines) has every declared slot bound (no unsubstituted part) and
    no two sub-collections share one source for what they each claim as their own part."""
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-payload"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)

    S.member(handle, "tables", "queries").append([{"seq": 0, "lead_id": S.LEAD_ID}])
    S.member(handle, "tables", "leads", S.LEAD_ID).write(
        json.dumps({"lead_id": S.LEAD_ID, "goal": "g"}))
    S.member(handle, "tables", "payloads", S.LEAD_ID, S.SEQ).write('{"rows": []}')
    S.member(handle, "observability", "review_record", S.TURN).write(
        json.dumps({"turn": S.TURN}))
    S.member(handle, "observability", "wire_log").append(
        [{"event_type": "message", "agent_id": "main", "seq": 0}])

    # ALL SLOTS BOUND: no resolved name carries an unsubstituted placeholder.
    written = [p for p in run_dir.rglob("*") if p.is_file()]
    assert written, "the writer methods produced nothing"
    for p in written:
        rel = p.relative_to(run_dir).as_posix()
        for placeholder in ("<", "{", "None"):
            assert placeholder not in rel, (
                f"{rel} carries an unsubstituted part — a slot the writer left unbound")

    # ROLES DISJOINT: no two sub-collections claim one file as their own.
    owners: dict[str, str] = {}
    for group, names in S.GROUP_MEMBERS.items():
        for name in names:
            if S.MEMBER_ACCESSOR[name] in S.UPWARD_ACCESSORS:
                continue
            rec = S.member(handle, group, name, *S.member_args(name))
            rel = rec.path.relative_to(run_dir).as_posix()
            assert rel not in owners or owners[rel] == f"{group}.{name}", (
                f"{rel} is claimed by both {owners[rel]} and {group}.{name}")
            owners[rel] = f"{group}.{name}"


def test_every_wire_log_record_carries_a_writer_id_that_tells_main_from_each_subagent(
        tmp_path: Path):
    """Every wire-log record carries a writer id, the main process's lines are distinguishable
    from each concurrent gather sub-agent's, and both production consumers of the wire log still
    read a record that carries the new field.

    The reader half is claim RG-9, and it is what `d16` (`old_stamp_reads_as_none`) is to claim
    C7 for the provenance stamp: `provenance.json` gains two fields WITH a demand proving an
    old/lenient reader tolerates them, and decision 18's wire-log field shipped with no
    equivalent (92-reconciliation.md finding 3, re-confirmed by 93-safety-claim-sweep.md "Held"
    item 6). `visualize_messages.load_messages` is driven here over the real replayed log;
    `compaction_dryrun._load_main_records` is driven at its own grain by `g12`'s test.
    """
    run_dir = materialize(tmp_path, GOLDEN)
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

    # RG-9 — the reader leg. `load_messages` (`defender/scripts/visualize/visualize_messages.py`
    # :27-34) reads through `defender/_io.py::read_jsonl_rows` (:643-644), the reader whose own
    # sibling's docstring says "most artifact readers are deliberately tolerant" (:650). Handed
    # a log whose every record carries the new key, it must return those records unchanged —
    # neither dropping them nor validating a key set.
    # `visualize_data` re-exports names from `visualize_messages` at its foot while the latter
    # imports `visualize_data` at its head: imported in THIS order the cycle resolves, in the
    # other it does not (a pre-existing cycle outside #1077's scope).
    import defender.scripts.visualize.visualize_data  # noqa: F401
    from defender.scripts.visualize.visualize_messages import load_messages
    assert load_messages(run_dir) == rows, (
        "the shipped wire-log viewer no longer round-trips the records it is handed once every "
        "one carries decision 18's `writer_id`; the issue's Done-when says existing consumers "
        "keep working, and this is the C7-analogue the wire log's field addition never had")


def test_wire_log_writers_stay_distinguishable_under_concurrent_main_and_subagent_appends(
        tmp_path: Path):
    """The one `RequestLogger` MAIN and every gather subagent share (flagged fact F5, concurrent
    multiplicity) stays a well-formed JSONL stream under concurrent appends through the handle —
    no torn line, and MAIN's and each subagent's lines stay distinguishable from one another by
    the writer id §7 decision 18 adds to every record."""
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base, "run-concurrent"))
    handle = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    wire = S.member(handle, "observability", "wire_log")

    writers = ("MAIN", "gather-l-aaa111", "gather-l-bbb222")
    for i in range(30):
        who = writers[i % len(writers)]
        wire.append([{"event_type": "message", "writer_id": who, "seq": i,
                      "message": "x" * 512}])

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
