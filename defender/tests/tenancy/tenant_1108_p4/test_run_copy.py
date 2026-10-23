"""#1108 P4 slice S-B — the run copy: what the run's box mounts, how startup proves the bind,
that `current` advancing mid-run changes nothing the run reads, and the copy's lifetime.

Entry: the REAL `run.main` (real `materialize`), its lifecycle production's own
`_run_investigation_lifecycle` with `start_box` = production `start_box` over P3/P2's recording
Docker double (`RecordingDocker`: records the create argv, answers `cat` through the captured
bind table, so a planted token is read back exactly as a daemon bind would serve it), and a
stub investigation. Assertions resolve in-box paths through the captured bind table, so how
`stage/` is bound (one mount or several under it) is the implementer's choice.

Layout (U9): `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, <token>}}`; the box
mounts only `stage/`. Owner record shape is the drafts' (`_drain_support`, ASSUMED: JSON
`{"pid", "start"}`, start = `/proc/<pid>/stat` field 22).

Obligations: O-A (the box mounts the run copy's `stage/` = `agent/` + the staged token only —
not `settings/`, not `owner`, not the clone, not an export; startup reads the token back; P2's
in-box `.tenant-id` check is retired; a bind to another copy refuses before message 0), O8 (the
issuer client config path lies under no box mount source), O2 (`current` advanced mid-run
changes nothing the run reads), O-SWEEP run-copy half (owner = pid + start time; removed in
`finally`; a dead owner's copy or half-built dot-named temporary is swept by publish, a live
one's is not; a reused pid counts as dead).
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

from defender.tests.e2e._box665 import RecordingDocker, _cp
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1108_p2._support import start_with
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    owner_record,
    process_start,
    write_owner,
)
from defender.tests.tenancy.tenant_1108_p4._support import current_commit, export_dir

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
    """`RecordingDocker` that, at `docker run` (create), lists every run copy's root and its
    `stage/` — what the box is handed, as the daemon would see it. It judges nothing."""

    def __init__(self, copies: Path) -> None:
        super().__init__()
        self.copies = copies
        self.at_create: dict[str, dict[str, list[str]]] = {}

    def __call__(self, argv, **kw):
        argv = list(argv)
        if len(argv) > 1 and argv[1] == "run" and self.copies.is_dir():
            for root in self.copies.iterdir():
                stage = root / "stage"
                self.at_create[root.name] = {
                    "root": sorted(os.listdir(root)) if root.is_dir() else [],
                    "stage": sorted(os.listdir(stage)) if stage.is_dir() else []}
        return super().__call__(argv, **kw)


def _exec_cats(docker: RecordingDocker) -> list[Path]:
    """Every in-box path a `docker exec ... cat <path>` read, resolved through the binds."""
    return [docker._through_binds(Path(c[-1])) for c in docker.calls
            if len(c) > 2 and c[1] == "exec" and "cat" in c]


# --- O-A: the mount set and the bind proof ----------------------------------------------------

def test_o_a_the_run_box_mounts_its_copys_agent_and_token_only_and_reads_the_token_back(
        tenant, tmp_path, boxed_only, monkeypatch):
    """O-A/U9: in the box, `/agent` (DEFENDER_AGENT_DIR) resolves into the run copy's
    `stage/agent/` with the export's bytes; the only part of the copy any mount source exposes
    is `stage/`, which at box create holds exactly `agent/` and one token; no source exposes the
    copy's `settings/` or `owner` record, the clone, the exports or the host-held
    knowledge-source record; startup read back the token from `stage/`; nothing reads a
    `.tenant-id` in the box (P2's check retired)."""
    from defender.runtime.model_view import MODEL_AGENT

    monkeypatch.setenv("BAO_TOKEN", "s-b-operator-bao-token-77e1")
    monkeypatch.setenv("VAULT_TOKEN", "s-b-operator-vault-token-91a4")
    docker, investigation = _StageSnapshotDocker(B.run_copies(tenant)), _Investigation()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert investigation.calls == 1, out.text()
    copy_root = _copy_root(tenant, out)
    stage = copy_root / "stage"

    assert docker.env().get("DEFENDER_AGENT_DIR") == str(MODEL_AGENT)
    inside = docker._through_binds(Path(MODEL_AGENT) / B.LESSON_REL)
    assert inside.resolve().is_relative_to(copy_root.resolve()), (
        f"O-A: the box's {MODEL_AGENT} is bound to {inside}, not the run copy {copy_root}")
    assert inside.relative_to(copy_root).parts[:2] == ("stage", "agent"), inside
    sources = [Path(m["source"]) for m in docker.mounts()]
    for forbidden in (copy_root / "settings", copy_root / "owner", B.clone_dir(tenant),
                      export_dir(tenant.tenant, tenant.commit).parent,
                      B.host_record_path(out.run_dir)):
        assert not T.exposes(sources, forbidden), (
            f"O-A/U9: a box mount exposes {forbidden}: {docker.mounts()}")
    in_copy = [src for src in sources if src.resolve().is_relative_to(copy_root.resolve())]
    assert [src for src in in_copy if not src.resolve().is_relative_to(stage.resolve())] == [], (
        f"U9: the box mounts a part of the run copy outside `stage/`: {in_copy}")
    assert T.exposes(sources, stage / "agent"), "control: the copy's stage/agent/ is mounted"

    listed = docker.at_create.get(copy_root.name)
    assert listed is not None, f"premise: the copy existed at box create: {docker.at_create}"
    assert listed["root"] == ["owner", "settings", "stage"], (
        f"U9: the run copy is not {{owner, settings/, stage/}}: {listed['root']}")
    tokens_staged = [name for name in listed["stage"] if name != "agent"]
    assert "agent" in listed["stage"], listed
    assert len(tokens_staged) == 1, (
        f"U9: the box's `stage/` holds more (or less) than agent/ and one token: {listed['stage']}")

    cats = _exec_cats(docker)
    tokens = [p for p in cats if p.resolve().is_relative_to(stage.resolve())
              and not p.resolve().is_relative_to((stage / "agent").resolve())]
    assert sorted({p.name for p in tokens}) == tokens_staged, (
        f"O-A: startup did not read back the token staged in the copy's stage/: {cats}")
    assert not [c for c in docker.calls if any(".tenant-id" in part for part in c)], (
        "O-A: the retired in-box `.tenant-id` check still runs")
    # O8/P-4: operator issuer variables never reach the box (control: the env is read above).
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
    """O-A: the token is not where the box looks → startup refuses; the investigation never
    starts. Control: the mount-set test above (the same double, bound right, runs)."""
    docker, investigation = _OtherCopyDocker(B.run_copies(tenant)), _Investigation()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, f"the run never got to its box: {out.text()}"
    assert investigation.calls == 0, "O-A: a box bound to another copy got past startup"
    assert out.rc != 0, out.text()
    assert not _copy_root(tenant, out).exists(), "R-S4: a refused box start left the run copy"


def test_o8_the_issuer_client_config_lies_under_no_box_mount_source(tenant, tmp_path,
                                                                    boxed_only):
    """O8: the dev issuer client config (`<repo>/playground-issuer/client/`) is under no source
    the run's box mounts. Control: the product `defender/` tree is mounted."""
    docker, investigation = RecordingDocker(), _Investigation()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert investigation.calls == 1, out.text()
    sources = [Path(m["source"]) for m in docker.mounts()]
    assert T.exposes(sources, T.DEFENDER), "control: the product tree is mounted"
    assert not T.exposes(sources, REPO_ISSUER_CONFIG), (
        f"O8: a box mount exposes the issuer client config {REPO_ISSUER_CONFIG}")
    assert not T.exposes(sources, REPO_ISSUER_CONFIG.parents[1])


# --- O2: `current` advancing mid-run ----------------------------------------------------------

def test_o2_current_advanced_mid_run_changes_nothing_the_run_reads(tenant, tmp_path):
    """O2/O-F: a merge is published while the run is live: `current` moves, the run's copy (and
    its stamp) do not."""
    def advance(seen: B.Seen) -> dict[str, Any]:
        merged = tenant.merge(B.MERGE_FILES)
        tenant.publish()
        return {"merged": merged, "agent": B.tree_bytes(seen.agent),
                "settings": B.tree_bytes(seen.settings), "stamp": B.read_stamp(seen.run_dir)}

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=advance)
    assert out.reached, out.text()
    seen = out.seen[0]
    after = seen.during
    assert current_commit(tenant.tenant) == after["merged"], "premise: current advanced"
    assert after["agent"] == seen.agent_files, "O2: the run's knowledge changed under it"
    assert after["settings"] == seen.settings_files, "O-B: the run's settings changed under it"
    assert B.SEEDED_MARK in after["agent"][B.LESSON_REL].decode()
    assert after["stamp"] == seen.stamp


def test_f_hardlink_the_run_copy_shares_no_inode_with_its_export(tenant, tmp_path):
    """F-HARDLINK: the run copy is a copy — no file of it is the export's own inode."""
    def inodes(seen: B.Seen) -> list[str]:
        export = export_dir(tenant.tenant, tenant.commit)
        shared = []
        for half, root in (("agent", seen.agent), ("settings", seen.settings)):
            for path in Path(root).rglob("*"):
                if path.is_file():
                    twin = export / half / path.relative_to(root)
                    if twin.exists() and os.stat(twin).st_ino == os.stat(path).st_ino:
                        shared.append(f"{half}/{path.relative_to(root)}")
        return shared

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=inodes)
    assert out.reached, out.text()
    assert out.seen[0].agent_files, "premise: the copy holds files"
    assert out.seen[0].during == [], f"the run copy hard-links its export: {out.seen[0].during}"


# --- O-SWEEP: owner, lifetime, sweep ----------------------------------------------------------

def test_o_sweep_the_run_copy_records_its_owner_and_is_removed_when_the_run_ends(
        tenant, tmp_path):
    """O-SWEEP/U9: while live, `<T>/run-knowledge/<run_id>/` exists and its `owner` record (beside
    `stage/`, outside what the box mounts) names this process: its pid AND its start time. After
    the run it is gone. (Owner shape shared with the drafts: `_drain_support.owner_record`.)"""
    def owner(seen: B.Seen) -> Any:
        root = B.copy_root(tenant, seen.run_dir)
        return owner_record(root) if (root / "owner").is_file() else None

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=owner)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    copy_root = _copy_root(tenant, out)
    assert out.seen[0].copies_listing == [copy_root.name], (
        f"the run copy is not `<T>/run-knowledge/<run_id>/`: {out.seen[0].copies_listing}")
    record = out.seen[0].during
    assert record is not None, "U9: the run copy has no `owner` record beside `stage/`"
    assert record.get("pid") == os.getpid(), record
    assert str(record.get("start")) == process_start(os.getpid()), (
        f"U9: the owner record does not name this process's start time: {record}")
    assert not copy_root.exists(), "O-SWEEP: the run copy outlived its run"


def _plant_copy(t, name: str, pid: int, start: Any) -> Path:
    """A run copy (or half-built temporary) in the U9 layout with a planted owner."""
    root = B.run_copies(t) / name
    (root / "stage" / "agent" / "lessons").mkdir(parents=True)
    (root / "stage" / "agent" / "lessons" / "half.md").write_text("half\n", encoding="utf-8")
    write_owner(root, pid, start)
    return root


def _dead_process() -> tuple[int, str]:
    """`(pid, start time)` of a process that has exited (it reports its own start time)."""
    out = subprocess.run(  # noqa: S603 — a test's own short-lived process
        [sys.executable, "-c", "import os\ns=open('/proc/self/stat').read()\n"
         "print(os.getpid(), s[s.rindex(')') + 2:].split()[19])"],
        capture_output=True, text=True, check=True, timeout=60).stdout.split()
    return int(out[0]), out[1]


def test_o_sweep_an_owner_naming_this_pid_with_another_start_time_is_dead(tenant):
    """O-SWEEP/U9: an owner is pid AND start time. A run copy whose record names this RUNNING
    pid with another start time (the pid was reused) is swept by the next publish; a copy whose
    record names this pid with its true start time survives the same publish (control)."""
    true_start = process_start(os.getpid())
    reused = _plant_copy(tenant, str(uuid.uuid4()), os.getpid(), str(int(true_start) + 1))
    kept = _plant_copy(tenant, str(uuid.uuid4()), os.getpid(), true_start)

    tenant.publish()

    assert kept.is_dir(), "O-SWEEP: a live owner's run copy was swept"
    assert not reused.exists(), "O-SWEEP: a record naming a reused pid kept its copy"


def test_o_sweep_a_dead_owners_half_built_temporary_is_swept_by_the_next_publish(tenant):
    """O-SWEEP/U9: a copy is built as a dot-named temporary holding its owner, then renamed. A
    build cut off before the rename leaves the temporary; its owner is dead, so the next publish
    sweeps it. A dot-named temporary whose owner is live (this process) survives (control)."""
    dead = _plant_copy(tenant, ".s-b-halfbuilt-0a1b", *_dead_process())
    live = _plant_copy(tenant, ".s-b-building-9f8e", os.getpid(), process_start(os.getpid()))

    tenant.publish()

    assert live.is_dir(), "O-SWEEP: a live build's temporary was swept"
    assert not dead.exists(), "O-SWEEP: a dead owner's half-built temporary was not swept"


def test_o_sweep_the_run_copy_is_removed_when_the_run_fails(tenant, tmp_path):
    def crash(**_kw: Any) -> dict:
        raise RuntimeError("S-B: the investigation crashed")

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=crash)
    assert out.reached, out.text()
    assert isinstance(out.raised, RuntimeError), out.text()
    assert not _copy_root(tenant, out).exists(), "O-SWEEP: a failed run left its copy behind"


def test_o_sweep_a_publish_never_sweeps_a_live_runs_copy(tenant, tmp_path):
    """O-SWEEP (control for the sweep below): publish sweeps only dead owners."""
    def publish_now(seen: B.Seen) -> bool:
        tenant.publish()
        return (B.copy_stage(tenant, seen.run_dir) / "agent").is_dir()

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=publish_now)
    assert out.reached, out.text()
    assert out.seen[0].during is True, "O-SWEEP: a publish swept a live run's copy"


_ORPHAN_SCRIPT = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from defender import run as run_py

    alert, tenant_id, commit, ready = sys.argv[1:5]

    def lifecycle(**kw):
        Path(ready).write_text(str(kw["run"].run_dir), encoding="utf-8")
        time.sleep(600)

    run_py.main([alert, "--tenant", tenant_id, "--no-learn"], lifecycle=lifecycle,
                publish=lambda *a, **k: f"fresh {commit}", preflight=lambda *a, **k: 0,
                visualize=lambda *a, **k: None, enqueue=lambda *a, **k: False)
""")


@pytest.fixture
def issuer_config(tmp_path, tenant):
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge

    bind_forge(tenant)
    return B.write_issuer_config(tmp_path / "operator")


def test_o_sweep_a_killed_runs_copy_is_swept_by_the_next_publish(tenant, tmp_path):
    """O-SWEEP: a run process SIGKILLed mid-run leaves its copy (its `finally` never ran); the
    next publish, under the tenant lock, sees the owner dead and removes it."""
    ready = tmp_path / "ready"
    script = tmp_path / "orphan_run.py"
    script.write_text(_ORPHAN_SCRIPT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
    proc = subprocess.Popen(  # noqa: S603 — a test's own child run process
        [sys.executable, str(script), str(B.plant_alert(tmp_path / "alert")), tenant.tenant_id,
         tenant.commit, str(ready)], env=env, cwd=str(WORKTREE),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 120
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists(), (
            f"the child run never reached its lifecycle (rc={proc.poll()}): "
            f"{proc.stderr.read().decode(errors='replace')[-2000:] if proc.poll() is not None else ''}")
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
    run_id = Path(ready.read_text(encoding="utf-8")).name
    orphan = B.run_copies(tenant) / run_id
    assert orphan.is_dir(), "premise: the killed run left its copy (the run copies under <T>/run-knowledge/)"

    tenant.publish()

    assert not orphan.exists(), "O-SWEEP: publish did not sweep a dead owner's run copy"


def _start_run_process(tenant, tmp_path) -> tuple[subprocess.Popen, Path]:
    ready = tmp_path / "ready"
    script = tmp_path / "orphan_run.py"
    script.write_text(_ORPHAN_SCRIPT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
    proc = subprocess.Popen(  # noqa: S603 — a test's own child run process
        [sys.executable, str(script), str(B.plant_alert(tmp_path / "alert")), tenant.tenant_id,
         tenant.commit, str(ready)], env=env, cwd=str(WORKTREE),
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


def test_r_s5_a_live_run_in_another_process_keeps_its_copy_and_a_locked_out_publish_sweeps_nothing(
        tenant, tmp_path, issuer_config):
    """R-S5/O-SWEEP: a run LIVE in another process keeps its copy across a publish (its owner is
    alive, and is not the publisher). Killed, its copy stays while a drain holds the tenant lock
    — the child cannot sweep (it reports `stale:transient`) — and the next publish under the
    lock sweeps it."""
    from defender.learning.author.version_control import tenant_lock

    proc, copy = _start_run_process(tenant, tmp_path)
    try:
        assert copy.is_dir(), "premise: the live run's copy exists"
        tenant.publish()
        assert copy.is_dir(), "O-SWEEP: a publish swept a LIVE run's copy (another process)"
    finally:
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=30)
    tenant.merge(B.MERGE_FILES)  # origin ahead, so a locked-out child cannot be fresh (O7b)
    with tenant_lock(tenant.tenant):
        line = B.run_child(tenant, issuer_config)
        assert copy.is_dir(), "O-SWEEP: a sweep ran without the tenant lock"
    assert B.outcome_class(line) == "stale:transient", line
    tenant.publish()
    assert not copy.exists(), "O-SWEEP: publish did not sweep the dead owner's copy"
