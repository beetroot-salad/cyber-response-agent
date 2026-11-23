"""#1108 P4 run copy: what the run's box mounts, how startup proves the bind, that `main`
advancing mid-run changes nothing the run reads, and the copy's lifetime (O-SWEEP's run-copy half).

#1618: the run's copy is filled by the fetch child (`fetch=`: `B.fetching`, the product's in-process fetch of the
tenant's served remote); there is no clone, `exports/` or `current` (K8) and no tenant lock (K1), and every fetch
starts by sweeping the tenant's dead owners (flow 8), so "the next publish" of the sweep cases is the next fetch
(`B.fetch_now`). Retired here: "the run copy shares no inode with its export" (K8: no export to share one with; the
copy is built in an owned temporary, `knowledge_1618/test_run_start_1618.py::test_a4_*`) and r_s5's middle, "a
locked-out publish sweeps nothing" (K1: no lock; `::test_a12_*` holds that a flock on the old lock path changes
nothing).

Entry: the real `run.main` (real `materialize`) and production's `_run_investigation_lifecycle`
with production `start_box` over `RecordingDocker` (it records the create argv and answers `cat`
through the captured bind table, so a planted token is read back as a daemon bind would serve
it), around a stub investigation. Assertions resolve in-box paths through the bind table, so how
`stage/` is bound is the implementation's choice. Layout:
`<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, <token>}}`; the box mounts only
`stage/`, and the owner record is the drafts' (`{"pid", "start"}`).
"""
from __future__ import annotations

import functools
import os
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

from defender.tests.e2e._box665 import RecordingDocker, _cp
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1108_p2._support import start_with
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    _dead_process,
    owner_record,
    process_start,
    write_owner,
)
from defender.tests.support.shared._locations_1210 import location_path

pytestmark = pytest.mark.e2e

WORKTREE = Path(__file__).resolve().parents[4]
REPO_ISSUER_CONFIG = WORKTREE / "playground-issuer" / "client" / "issuer.json"


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


@pytest.fixture
def boxed_only(monkeypatch):
    """No opt-out and no runtime override: a box fault cannot become the host executor."""
    from defender import box as box_mod

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


class _Investigation:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_kw: Any) -> dict:
        self.calls += 1
        return {"output": "s-b box", "requests": 0, "truncated_by": None}


def _boxed_lifecycle(docker: RecordingDocker, investigation: _Investigation):
    from defender import box as box_mod
    from defender import run as run_py

    return functools.partial(run_py._run_investigation_lifecycle, investigate=investigation,
                             start_box=start_with(docker), stop_box=box_mod.stop_box)


def _copy_root(t, out: B.Launch) -> Path:
    return B.copy_root(t, out.seen[0].run_dir)


class _StageSnapshotDocker(RecordingDocker):
    """`RecordingDocker` that, at `docker create` (the run box's create, #1343 B10) and again at the
    attached `docker start` (`.popen`), lists every run copy's root and its `stage/` — what the box
    is handed, as the daemon would see it. Anything placed in `stage/` between the two shows in the
    second. It judges nothing."""

    def __init__(self, copies: Path) -> None:
        super().__init__()
        self.copies = copies
        self.at_create: dict[str, dict[str, list[str]]] = {}
        self.at_start: dict[str, dict[str, list[str]]] = {}

    def _snapshot(self, into: dict[str, dict[str, list[str]]]) -> None:
        if self.copies.is_dir():
            for root in self.copies.iterdir():
                stage = root / "stage"
                into[root.name] = {
                    "root": sorted(os.listdir(root)) if root.is_dir() else [],
                    "stage": sorted(os.listdir(stage)) if stage.is_dir() else []}

    def __call__(self, argv, **kw):
        argv = list(argv)
        if len(argv) > 1 and argv[1] == "create":
            self._snapshot(self.at_create)
        return super().__call__(argv, **kw)

    def popen(self, argv, **kw):
        if list(argv)[1:2] == ["start"]:
            self._snapshot(self.at_start)
        return super().popen(argv, **kw)


def _exec_cats(docker: RecordingDocker) -> list[Path]:
    """Every in-box path a `docker exec ... cat <path>` read, resolved through the binds."""
    return [docker._through_binds(Path(c[-1])) for c in docker.calls
            if len(c) > 2 and c[1] == "exec" and "cat" in c]


# --- O-A: the mount set and the bind proof ----------------------------------------------------

def test_o_a_the_run_box_mounts_its_copys_agent_and_token_only_and_reads_the_token_back(
        tenant, tmp_path, boxed_only, monkeypatch):
    """The box's `/agent` resolves into the copy's `stage/agent/`; `stage/` (exactly `agent/` and
    one token at create) is the only part of the copy a mount exposes, and none exposes
    `settings/`, `owner`, the old clone's or exports' place, the private repositories or the host record. Startup
    reads the token
    back, and nothing reads an in-box `.tenant-id`."""
    from defender._model_view import MODEL_AGENT

    monkeypatch.setenv("BAO_TOKEN", "s-b-operator-bao-token-77e1")
    monkeypatch.setenv("VAULT_TOKEN", "s-b-operator-vault-token-91a4")
    docker, investigation = _StageSnapshotDocker(B.run_copies(tenant)), _Investigation()
    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert investigation.calls == 1, out.text()
    copy_root = _copy_root(tenant, out)
    stage = copy_root / "stage"

    assert docker.env().get("DEFENDER_AGENT_DIR") == str(MODEL_AGENT)
    inside = docker._through_binds(Path(MODEL_AGENT) / B.LESSON_REL)
    assert inside.resolve().is_relative_to(copy_root.resolve()), (
        f"the box's {MODEL_AGENT} is bound to {inside}, not the run copy {copy_root}")
    assert inside.relative_to(copy_root).parts[:2] == ("stage", "agent"), inside
    sources = [Path(m["source"]) for m in docker.mounts()]
    tenant_folder = Path(location_path(tenant.tenant.tenant_root))
    for forbidden in (copy_root / "settings", copy_root / "owner", tenant_folder / "knowledge",
                      tenant_folder / "exports", Path(tenant.data_root) / ".repo-scratch",
                      B.host_record_path(out.run_dir)):
        assert not T.exposes(sources, forbidden), (
            f"a box mount exposes {forbidden}: {docker.mounts()}")
    in_copy = [src for src in sources if src.resolve().is_relative_to(copy_root.resolve())]
    assert [src for src in in_copy if not src.resolve().is_relative_to(stage.resolve())] == [], (
        f"the box mounts a part of the run copy outside `stage/`: {in_copy}")
    assert T.exposes(sources, stage / "agent"), "control: the copy's stage/agent/ is mounted"

    for when, snaps in (("create", docker.at_create), ("attached start", docker.at_start)):
        listed = snaps.get(copy_root.name)
        assert listed is not None, f"premise: the copy existed at box {when}: {snaps}"
        assert listed["root"] == ["owner", "settings", "stage"], (
            f"the run copy is not {{owner, settings/, stage/}} at {when}: {listed['root']}")
        assert "agent" in listed["stage"], (when, listed)
        assert len([n for n in listed["stage"] if n != "agent"]) == 1, (
            f"the box's `stage/` holds more (or less) than agent/ and one token at {when}: {listed['stage']}")
    listed = docker.at_start[copy_root.name]
    tokens_staged = [name for name in listed["stage"] if name != "agent"]

    cats = _exec_cats(docker)
    tokens = [p for p in cats if p.resolve().is_relative_to(stage.resolve())
              and not p.resolve().is_relative_to((stage / "agent").resolve())]
    assert sorted({p.name for p in tokens}) == tokens_staged, (
        f"startup did not read back the token staged in the copy's stage/: {cats}")
    assert not [c for c in docker.calls if any(".tenant-id" in part for part in c)], (
        "the retired in-box `.tenant-id` check still runs")
    # Operator issuer variables never reach the box (control: the env is read above).
    assert B.leaks(("s-b-operator-bao-token-77e1", "s-b-operator-vault-token-91a4"),
                   create_argv=docker.create_argv) == []


class _OtherCopyDocker(RecordingDocker):
    """A daemon that bound the run copy's stage to ANOTHER folder: every read the box makes
    inside the copy but outside `stage/agent/` (the token) finds nothing there. It judges
    nothing."""

    def __init__(self, copies: Path) -> None:
        super().__init__()
        self.copies = copies

    def _exec(self, argv):
        if "cat" in argv and self.create_argv is not None:
            host = self._through_binds(Path(argv[-1]))
            under = host.resolve()
            if under.is_relative_to(self.copies.resolve()) and (
                    under.relative_to(self.copies.resolve()).parts[1:3] != ("stage", "agent")):
                return _cp(1, "", "cat: No such file or directory\n")
        return super()._exec(argv)


def test_o_a_a_box_bound_to_another_copy_refuses_before_message_zero(tenant, tmp_path,
                                                                      boxed_only):
    """The token is not where the box looks, so startup refuses before the investigation
    starts. Control: the mount-set test above (the same double, bound right, runs)."""
    docker, investigation = _OtherCopyDocker(B.run_copies(tenant)), _Investigation()
    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, f"the run never got to its box: {out.text()}"
    assert investigation.calls == 0, "a box bound to another copy got past startup"
    assert out.rc != 0, out.text()
    assert not _copy_root(tenant, out).exists(), "a refused box start left the run copy"


def _mount_sources(tenant, tmp_path) -> list[Path]:
    """The mount sources of a fresh run's box, after asserting the run reached its investigation
    and, as a control, that the product `defender/` tree is mounted."""
    docker, investigation = RecordingDocker(), _Investigation()
    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert investigation.calls == 1, out.text()
    sources = [Path(m["source"]) for m in docker.mounts()]
    assert T.exposes(sources, T.DEFENDER), "control: the product tree is mounted"
    return sources


def test_o8_the_issuer_client_config_lies_under_no_box_mount_source(tenant, tmp_path,
                                                                    boxed_only):
    """The dev issuer client config (`<repo>/playground-issuer/client/`) is under no source the
    run's box mounts. Control: the product `defender/` tree is mounted."""
    sources = _mount_sources(tenant, tmp_path)
    assert not T.exposes(sources, REPO_ISSUER_CONFIG), (
        f"a box mount exposes the issuer client config {REPO_ISSUER_CONFIG}")
    assert not T.exposes(sources, REPO_ISSUER_CONFIG.parents[1])


# --- O2: `main` advancing mid-run ---------------------------------------------------------------------------------

def test_o2_main_advanced_mid_run_changes_nothing_the_run_reads(tenant, tmp_path):
    """A merge lands on `main` and another reader fetches it while the run is live: the run's copy and stamp do not
    move. (#1618: was "`current` advanced"; the commit on the remote is what moves now.)"""
    def advance(seen: B.Seen) -> dict[str, Any]:
        merged = tenant.merge(B.MERGE_FILES)
        line = B.fetch_now(tenant, tmp_path / "other-reader")
        return {"merged": merged, "line": line, "agent": B.tree_bytes(seen.agent),
                "settings": B.tree_bytes(seen.settings), "stamp": B.read_stamp(seen.run_dir)}

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), during=advance)
    assert out.reached, out.text()
    seen = out.seen[0]
    after = seen.during
    assert after["line"] == f"ok {after['merged']}", "premise: main advanced and another reader read it"
    assert after["agent"] == seen.agent_files, "the run's knowledge changed under it"
    assert after["settings"] == seen.settings_files, "the run's settings changed under it"
    assert B.SEEDED_MARK in after["agent"][B.LESSON_REL].decode()
    assert after["stamp"] == seen.stamp


# --- O-SWEEP: owner, lifetime, sweep ----------------------------------------------------------

def test_o_sweep_the_run_copy_records_its_owner_and_is_removed_when_the_run_ends(
        tenant, tmp_path):
    """While live, the copy's `owner` record (beside `stage/`, outside the box's mounts) names
    this process's pid and start time; after the run the copy is gone."""
    def owner(seen: B.Seen) -> Any:
        root = B.copy_root(tenant, seen.run_dir)
        return owner_record(root) if (root / "owner").is_file() else None

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), during=owner)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    copy_root = _copy_root(tenant, out)
    assert out.seen[0].copies_listing == [copy_root.name], (
        f"the run copy is not `<T>/run-knowledge/<run_id>/`: {out.seen[0].copies_listing}")
    record = out.seen[0].during
    assert record is not None, "the run copy has no `owner` record beside `stage/`"
    assert record.get("pid") == os.getpid(), record
    assert str(record.get("start")) == process_start(os.getpid()), (
        f"the owner record does not name this process's start time: {record}")
    assert not copy_root.exists(), "the run copy outlived its run"


def _plant_copy(t, name: str, pid: int, start: Any) -> Path:
    """A run copy (or half-built temporary) with a planted owner."""
    root = B.run_copies(t) / name
    (root / "stage" / "agent" / "lessons").mkdir(parents=True)
    (root / "stage" / "agent" / "lessons" / "half.md").write_text("half\n", encoding="utf-8")
    write_owner(root, pid, start)
    return root


def test_o_sweep_an_owner_naming_this_pid_with_another_start_time_is_dead(tenant, tmp_path):
    """A run copy whose owner names this running pid with another start time (a reused pid) is
    swept by the next fetch; one naming the true start time survives (control)."""
    true_start = process_start(os.getpid())
    reused = _plant_copy(tenant, str(uuid.uuid4()), os.getpid(), str(int(true_start) + 1))
    kept = _plant_copy(tenant, str(uuid.uuid4()), os.getpid(), true_start)

    B.fetch_now(tenant, tmp_path)

    assert kept.is_dir(), "a live owner's run copy was swept"
    assert not reused.exists(), "a record naming a reused pid kept its copy"


def test_o_sweep_a_dead_owners_half_built_temporary_is_swept_by_the_next_fetch(tenant, tmp_path):
    """A copy is built as a dot-named temporary holding its owner, then renamed: a dead
    builder's leftover temporary is swept by the next fetch, a live one's survives (control)."""
    dead = _plant_copy(tenant, ".s-b-halfbuilt-0a1b", *_dead_process())
    live = _plant_copy(tenant, ".s-b-building-9f8e", os.getpid(), process_start(os.getpid()))

    B.fetch_now(tenant, tmp_path)

    assert live.is_dir(), "a live build's temporary was swept"
    assert not dead.exists(), "a dead owner's half-built temporary was not swept"


def test_o_sweep_the_run_copy_is_removed_when_the_run_fails(tenant, tmp_path):
    def crash(**_kw: Any) -> dict:
        raise RuntimeError("S-B: the investigation crashed")

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), lifecycle=crash)
    assert out.reached, out.text()
    assert isinstance(out.raised, RuntimeError), out.text()
    assert not _copy_root(tenant, out).exists(), "a failed run left its copy behind"


def test_o_sweep_a_fetch_never_sweeps_a_live_runs_copy(tenant, tmp_path):
    """Control for the sweeps below: a fetch sweeps only dead owners."""
    def fetch_now(seen: B.Seen) -> bool:
        B.fetch_now(tenant, tmp_path / "other-reader")
        return (B.copy_stage(tenant, seen.run_dir) / "agent").is_dir()

    out = B.launch(tenant, tmp_path, fetch=B.fetching(tenant), during=fetch_now)
    assert out.reached, out.text()
    assert out.seen[0].during is True, "a fetch swept a live run's copy"


_ORPHAN_SCRIPT = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from defender import run as run_py

    alert, tenant_id, remote, ready, data_root, origin = sys.argv[1:7]
    from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
    from defender.tests.support.tenancy._fetch_standin_1618 import in_process_fetch

    directory = tenant_directory(Path(data_root), tenant_id, origin=origin)  # #1214 Flow 4, with a sign login (#1391 D12)

    def lifecycle(**kw):
        Path(ready).write_text(str(kw["run"].run_dir), encoding="utf-8")
        time.sleep(600)

    run_py.main([alert, "--tenant", tenant_id, "--no-learn"], directory=directory, lifecycle=lifecycle,
                fetch=in_process_fetch(Path(remote)), preflight=lambda *a, **k: 0,
                visualize=lambda *a, **k: None, enqueue=lambda *a, **k: False)
""")


def test_o_sweep_a_killed_runs_copy_is_swept_by_the_next_fetch(tenant, tmp_path):
    """A run process SIGKILLed mid-run leaves its copy (its `finally` never ran); the next
    fetch sees the owner dead and removes it."""
    proc, orphan = _start_run_process(tenant, tmp_path)
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=30)
    assert orphan.is_dir(), "premise: the killed run left its copy"

    B.fetch_now(tenant, tmp_path)

    assert not orphan.exists(), "the next fetch did not sweep a dead owner's run copy"


def _start_run_process(tenant, tmp_path) -> tuple[subprocess.Popen, Path]:
    ready = tmp_path / "ready"
    script = tmp_path / "orphan_run.py"
    script.write_text(_ORPHAN_SCRIPT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
    proc = subprocess.Popen(  # noqa: S603 — a test's own child run process
        [sys.executable, str(script), str(B.plant_alert(tmp_path / "alert")), tenant.tenant_id,
         str(tenant.remote), str(ready), str(tenant.data_root), tenant.origin], env=env, cwd=str(WORKTREE),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 120
    while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not ready.exists():
        proc.kill()
        proc.wait(timeout=30)
        raise AssertionError(
            f"the child run never reached its lifecycle (rc={proc.poll()}): "
            f"{proc.stderr.read().decode(errors='replace')[-2000:]}")
    return proc, B.run_copies(tenant) / Path(ready.read_text(encoding="utf-8")).name


def test_r_s5_a_live_run_in_another_process_keeps_its_copy_and_the_next_fetch_after_its_death_sweeps_it(
        tenant, tmp_path):
    """A run live in another process keeps its copy across another reader's fetch; killed, the next fetch sweeps it.
    (#1618 K1: the middle of the retired case, "a locked-out publish sweeps nothing", goes with the lock.)"""
    proc, copy = _start_run_process(tenant, tmp_path)
    try:
        assert copy.is_dir(), "premise: the live run's copy exists"
        B.fetch_now(tenant, tmp_path / "while-live")
        assert copy.is_dir(), "a fetch swept a LIVE run's copy (another process)"
    finally:
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
    assert copy.is_dir(), "premise: the killed run left its copy"
    B.fetch_now(tenant, tmp_path / "after-death")
    assert not copy.exists(), "the next fetch did not sweep the dead owner's copy"


# --- #1170 A6/C20: a run copy made for a job is the host helper's -----------------------------

@pytest.mark.postgres
def test_a6_a_job_run_copy_is_owned_by_its_host_helper_and_a_killed_helpers_copy_is_swept(
        tmp_path, monkeypatch, migrated_database):  # noqa: F811 — the imported fixture
    """The copy a job's host helper makes names the helper's pid (not the test's), outlives nothing the helper
    left alive, and once the helper is SIGKILLed the next fetch sweeps it (the operator-run rows above are the
    control: same record, same sweep, the process that made the copy)."""
    from defender.tests.support.jobs._job_helper import ProcessHelper, helper_scene, pid_alive, until

    with helper_scene(tmp_path, monkeypatch, migrated_database) as scene:
        inv = str(uuid.uuid4())
        scene.plant(inv)
        helper = ProcessHelper(scene, scene.root, scene.argv("investigation", inv, parent=os.getpid()))
        try:
            helper.container_pid()  # the helper got as far as its container: step 4 (the copy) is behind it
            copies = until(lambda: list(B.run_copies(scene.t).glob("*/owner")), "the helper's run copy")
            record = owner_record(copies[0].parent)
            assert record.get("pid") == helper.proc.pid, record
            assert record.get("pid") != os.getpid()
            copy = copies[0].parent
        finally:
            helper.close()
        assert not pid_alive(helper.proc.pid)
        assert copy.is_dir(), "premise: the killed helper left its copy"
        B.fetch_now(scene.t, tmp_path / "next-fetch")
        assert not copy.exists(), "the next fetch did not sweep the dead helper's run copy"
