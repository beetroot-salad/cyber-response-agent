"""#1344 r5 "Old history on current code": a run made by old code (d59e24acb, 2026-10-20) read by today's family.

The fixture `tests/fixtures/e2e/old-history-d59e24acb.tar.gz` is that commit's replay-harness run (append, one
`gather` l-001 reaching a stand-in elastic, append, append, close), `sessions.db` (user_version 2, with
`fork_snapshot`) and `run/` minus its wire logs; its `gather` is row 10. To regenerate: `git archive d59e24acb defender
defender/tests/fixtures/tenant-fixture` to a scratch folder, drive `_1255_snapshot.drive_source` there, `VACUUM INTO` the store,
drop `run/wire_logs`, tar sorted with mtime 0, gzip -9n. Each test unpacks it into its own tmp_path; none writes to it."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]
FIXTURE = DEFENDER / "tests" / "fixtures" / "e2e" / "old-history-d59e24acb.tar.gz"
GATHER_ROW = 10
LEAD = "l-001"


class Old:
    """The unpacked fixture planted as a finished run in a tenant's runs repository."""

    def __init__(self, tmp_path: Path, runs: Path) -> None:
        with tarfile.open(FIXTURE) as bundle:
            bundle.extractall(tmp_path / "unpacked", filter="data")
        self.unpacked = tmp_path / "unpacked" / "old-history"
        meta = json.loads((self.unpacked / "meta.json").read_text(encoding="utf-8"))
        self.name: str = meta["run_name"]
        self.case: str = meta["case_id"]
        self.gather: int = meta["gathers"][0]
        self.runs = runs
        self.run_dir = runs / self.name
        self.plant()

    def plant(self) -> None:
        from defender.records import SessionPaths, session_store
        from defender.tests.support.shared._locations_1210 import fixture_runs_base
        from defender.tests.support.shared.contracts._spec1077 import fixture_run

        self.runs.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.unpacked / "run", self.run_dir)
        store, _root = SessionPaths(fixture_runs_base(self.runs)).store(self.case)
        store.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.unpacked / "sessions.db", store)
        session_store.write_case_pointer(fixture_run(self.run_dir), case_id=self.case, store_path=store)
        self.store_path = store

    def stamp(self, tenant_id: str) -> None:
        """The `provenance.json` every run a worker makes carries; the harness-made old run has none, so it is planted."""
        from defender.tests.support.learning.branch import _triplet_947 as T

        (self.run_dir / "provenance.json").write_text(
            json.dumps(T.provenance_record(tenant_id=tenant_id)), encoding="utf-8")


def _plant(tmp_path: Path) -> tuple[Old, object]:
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(Path(os.environ["DEFENDER_DATA_ROOT"]))
    from defender.tests.support.shared._locations_1210 import location_path

    return Old(tmp_path, location_path(tenant.runs)), tenant


def test_the_fixture_is_small_and_is_a_gzip_of_one_old_run():
    """Premise: committed fixture stays well under 400 KB and holds the run, its store and nothing the flow cannot read."""
    assert FIXTURE.stat().st_size < 400_000
    with tarfile.open(FIXTURE) as bundle:
        names = bundle.getnames()
    assert "old-history/sessions.db" in names
    assert not [n for n in names if "wire_logs" in n]


def test_the_fixture_is_unpacked_per_test_and_the_committed_bytes_are_never_changed(tmp_path):
    """Obligation: Old history. Planting copies; the committed archive is read-only input."""
    before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    old, _tenant = _plant(tmp_path)
    assert old.unpacked.is_relative_to(tmp_path)
    assert old.run_dir.is_relative_to(Path(os.environ["DEFENDER_DATA_ROOT"]))
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == before


def _open(tenant, old: Old):
    from defender.investigation import branch
    from defender.records import RunId

    run = tenant.runs_repository().open(RunId.parse(old.name))
    opened = branch.source_store_if_any(run.run_dir, source_run=run)
    assert opened is not None, "the old run's session store was not found from its pointer"
    return run, opened


def test_current_admission_lets_a_world_fork_at_the_old_runs_gather(tmp_path):
    """Obligation: Old history, fork point. `branch.validate` admits the old snapshotted gather; the format is read, not refused."""
    from defender.investigation import branch
    from defender.records import session_store as ss
    from defender.tests.support.learning.branch._branch_947 import spec_at

    old, tenant = _plant(tmp_path)
    run, opened = _open(tenant, old)
    with opened as store:
        assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 2, "premise: the store is the old format"
        ids = ss.path_row_ids(store, ss.main_session_id(store))
        assert old.gather in ids, "premise: the gather response is on MAIN's path"
        assert branch.validate(store, spec_at(store, run.run_dir, old.gather), source_run=run) is None


def test_a_world_forks_and_resumes_at_the_old_gather_and_re_runs_the_lead(tmp_path):
    """Obligation: Old history, resume. The sibling forks a child session at row 10, inherits the old document and re-dispatches l-001."""
    from defender.records import RunPaths
    from defender.records import session_store as ss
    from defender.tests.e2e._lead_zero_808 import VerbRecorder, answer_hits, elastic_backend, hit
    from defender.tests.e2e._replay_harness import Turn
    from defender.tests.support.learning.branch._branch_947 import spec_at
    from defender.tests.support.runtime.state import _1255_snapshot as R
    from defender.tests.support.storage._session_head_754 import message_ids

    old, tenant = _plant(tmp_path)
    run, opened = _open(tenant, old)
    with opened as store:
        spec = spec_at(store, run.run_dir, old.gather)
        source_session = ss.main_session_id(store)
        prefix = ss.path_row_ids(store, source_session)
        prefix = prefix[: prefix.index(old.gather) + 1]
    recorder = VerbRecorder()
    query = Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                        "params": {"native_query": "user.name:dev.dana"}})])
    sibling_main = R.Recorder([R.echo("resumed"), Turn(text="Resumed and stopping.")])
    arm = R.drive_arm(tmp_path / "arm", spec, sibling_main,
                      leads={LEAD: (query, Turn(text=f"summary of {LEAD}"))},
                      verbs=elastic_backend(recorder, answer_hits([hit(ts="2026-05-25T15:20:00.000Z")])))

    assert arm.result.get("exit_reason") is None, f"the resumed run never started: {arm.result}"
    assert arm.result.get("truncated_by") is None, arm.result
    with ss.open_store(case_id=old.case, sessions=_sessions(old)) as store:
        children = [r[0] for r in store.connection.execute(
            "SELECT session_id FROM session WHERE parent_session_id = ?", (ss.main_session_id(store),))]
        assert len(children) == 1, f"the resume did not fork exactly one child session: {children}"
        assert ss.branch_point(store, children[0]) == old.gather
        child = ss.path_row_ids(store, children[0])
        assert child[: len(prefix)] == prefix, "the child does not open on the old run's inherited prefix"
        assert message_ids(store, children[0]), "the child appended nothing"
    document = RunPaths(arm.run_dir).investigation.read_text(encoding="utf-8")
    assert document.startswith((old.run_dir / "investigation.md").read_text(encoding="utf-8")[:2000]), (
        "the sibling's document does not open on the one the old run had written by the gather")
    assert LEAD in arm.gather.asked, "the sibling did not re-dispatch the gather it forked at"


def _sessions(old: Old):
    from defender.records import SessionPaths
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    return SessionPaths(fixture_runs_base(old.runs))


def _launch_over_the_old_run(tmp_path: Path, **seams):
    """The real launcher (`cli.branch`) over the planted old run at its gather: scripted questioner, oracle, verifier,
    judge; the family's siblings are recorded, not started. Returns (old, launch, estate)."""
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.learning.branch import _triplet_947 as T

    est = S.estate(tmp_path, systems=(*S.SYSTEMS, "elastic"))
    tenant = est.place()
    old = Old(tmp_path, S.location_path(tenant.runs))
    from defender._io import read_jsonl_rows

    executed = read_jsonl_rows(old.run_dir / "executed_queries.jsonl")
    assert executed, "premise: the old run recorded the queries it was answered"
    for row in executed:  # the live estate answers what the old run was answered
        est.answer(row["system"], row["verb"], row["params"],
                   json.loads((old.run_dir / row["payload_path"]).read_text(encoding="utf-8")))
    old.stamp(tenant.id)
    S.location_path(tenant.learning).mkdir(exist_ok=True)  # the host's prepare step makes the learning root
    spawn = S.FakeSpawn()
    seams.setdefault("questioner", S.questioner_for())
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    seams.setdefault("roster", est.roster())
    seams.setdefault("judge", S.FakeJudge(default="bucket: none\nsystems: []\nfindings: []\n"))
    captured = json.loads((old.run_dir / "gather_raw" / LEAD / "0.json").read_text(encoding="utf-8"))
    seams.setdefault("oracle", S.oracle(then=S.submit(captured, S.EMPTY_CLAIM)).model)
    seams.setdefault("verifier", S.passing_verifier().model)
    seams.setdefault("directory", est.launch_directory(tenant.id))
    from defender.cli.learning import branch as cli

    try:
        rc = cli.main(["--tenant", tenant.id, old.name, str(old.gather)], spawn=spawn, **seams)
    except SystemExit as stop:
        rc = stop.code
    return old, tenant, rc, spawn, est


def test_the_launcher_reads_the_old_run_primes_the_oracle_from_its_capture_and_starts_siblings(tmp_path, caplog, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """Obligation: Old history, launcher. The old capture primes the base tier and the questioner's family starts. (#1278: the
    judge pass files its findings in the learning store, so the launcher's process has a migrated database to reach.)"""
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S

    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    questioner = S.questioner_for()
    old, tenant, rc, spawn, _est = _launch_over_the_old_run(tmp_path, questioner=questioner)
    episodes = S.tenant_episodes(tenant.id)
    made = sorted(p for p in episodes.iterdir() if p.is_dir()) if episodes.is_dir() else []
    assert rc in (0, None), f"the launcher refused the old run (rc={rc}); episodes: {made}"
    (episode,) = made
    base = S.base_rows(episode)
    assert {(r["system"], r["verb"]) for r in base} == {("elastic", "alerts"), ("elastic", "query")}, base
    assert all(r["source"] == "captured" for r in base)
    assert questioner.calls >= 1, "the questioner never ran on the old run"
    assert len(spawn.worlds) == 3, f"siblings started: {spawn.worlds}"
    assert not [r for r in caplog.records if "judge pass failed" in r.getMessage()], "the judge pass failed"


def test_the_fork_candidates_of_the_old_run_are_its_one_admitted_gather(tmp_path):
    """Obligation: Old history, fork yield (r5). `fork_candidates` over the old store yields the gather row, no refusal."""
    from defender.learning.branch.fork_pick import fork_candidates

    old, tenant = _plant(tmp_path)
    run, opened = _open(tenant, old)
    with opened as store:
        found = fork_candidates(store, run)
    assert list(found.ids) == [old.gather], found


def _family_child(tmp_path: Path) -> tuple[Old, dict | None, subprocess.CompletedProcess]:
    """The real learning job entry (`_flow_entry1344.py family`: scripted questioner, oracle, verifier, judge; siblings as
    `run.main`) over the old run planted in a tenant's runs repository. Returns the end record it left, if any."""
    from defender.tests.e2e.test_1344_learning_replay import entry_in_a_code_copy
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    entry = entry_in_a_code_copy(tmp_path / "code")
    with B.run_tenant(tmp_path, root) as tenant:
        runs = root / tenant.tenant_id / "runs"
        (root / tenant.tenant_id / "learning").mkdir(exist_ok=True)
        old = Old(tmp_path, runs)
        old.stamp(tenant.tenant_id)
        job = "9f1c2d3e-0000-4000-8000-000000001344"
        marks = tmp_path / "marks"
        done = subprocess.run(
            [sys.executable, str(entry), "family", tenant.commit, str(marks / "family"), "--job", job, "--tenant",
             tenant.tenant_id, "--source", old.name, "--parent-pid", str(os.getpid())],
            env={**os.environ, "DEFENDER_DATA_ROOT": str(root), "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True, timeout=600, check=False)
        record = runs / f"{job}.learning-end.json"
        return old, (json.loads(record.read_text(encoding="utf-8")) if record.is_file() else None), done


def test_the_job_entry_over_the_old_run_ends_completed_or_typed_skipped_never_in_a_crash(tmp_path):
    """Obligation: Old history, outcome table. `completed` (forked at row 10) or `skipped` history_unreadable/no_fork_point; never entry_error/failed."""
    before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    old, end, done = _family_child(tmp_path)
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == before

    assert end is not None, f"the entry left no end record (rc={done.returncode}):\n{done.stderr[-2000:]}"
    assert end["status"] in ("completed", "skipped"), end
    if end["status"] == "skipped":
        assert end["reason"] in ("history_unreadable", "no_fork_point"), end
        assert end["message"], "a typed skip names its cause"
    else:
        assert end["reason"] is None, end
        assert end["fork_message_id"] == str(old.gather), end
        assert end["findings_count"] >= 1, end
