"""#1108 P4 slice S-B — the run copy: what the run's box mounts, how startup proves the bind,
that `current` advancing mid-run changes nothing the run reads, and the copy's lifetime.

Entry: the REAL `run.main` (real `materialize`), its lifecycle production's own
`_run_investigation_lifecycle` with `start_box` = production `start_box` over P3/P2's recording
Docker double (`RecordingDocker`: records the create argv, answers `cat` through the captured
bind table, so a planted token is read back exactly as a daemon bind would serve it), and a
stub investigation. Nothing here decides geometry: assertions resolve in-box paths through the
captured bind table, so whether the copy's `agent/` is bound alone or under a root is the
implementer's choice.

Obligations: O-A (the box mounts the run copy's `agent/` + the staged token only — not
`settings/`, not the clone, not an export; startup reads the token back; P2's in-box
`.tenant-id` check is retired; a bind to another copy refuses before message 0), O8 (the issuer
client config path lies under no box mount source), O2 (`current` advanced mid-run changes
nothing the run reads), O-SWEEP run-copy half (owner record; removed in `finally`; a dead
owner's copy is swept by publish, a live one's is not).
"""
from __future__ import annotations

import functools
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from defender.tests.e2e._box665 import RecordingDocker, _cp
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1108_p2._support import start_with
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
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
    return B.run_copies(t) / out.seen[0].run_dir.name


def _exec_cats(docker: RecordingDocker) -> list[Path]:
    """Every in-box path a `docker exec ... cat <path>` read, resolved through the binds."""
    return [docker._through_binds(Path(c[-1])) for c in docker.calls
            if len(c) > 2 and c[1] == "exec" and "cat" in c]


# --- O-A: the mount set and the bind proof ----------------------------------------------------

def test_o_a_the_run_box_mounts_its_copys_agent_and_token_only_and_reads_the_token_back(
        tenant, tmp_path, boxed_only, monkeypatch):
    """O-A: in the box, `/agent` (DEFENDER_AGENT_DIR) resolves into the run copy's `agent/`
    with the export's bytes; no mount source exposes the copy's `settings/`, the clone, or the
    exports; startup read back a token planted in the copy outside `agent/`; nothing reads a
    `.tenant-id` in the box (P2's check retired)."""
    from defender.runtime.model_view import MODEL_AGENT

    monkeypatch.setenv("BAO_TOKEN", "s-b-operator-bao-token-77e1")
    monkeypatch.setenv("VAULT_TOKEN", "s-b-operator-vault-token-91a4")
    docker, investigation = RecordingDocker(), _Investigation()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert investigation.calls == 1, out.text()
    copy_root = _copy_root(tenant, out)

    assert docker.env().get("DEFENDER_AGENT_DIR") == str(MODEL_AGENT)
    inside = docker._through_binds(Path(MODEL_AGENT) / B.LESSON_REL)
    assert inside.resolve().is_relative_to(copy_root.resolve()), (
        f"O-A: the box's {MODEL_AGENT} is bound to {inside}, not the run copy {copy_root}")
    assert inside.relative_to(copy_root).parts[0] == "agent", inside
    sources = [Path(m["source"]) for m in docker.mounts()]
    for forbidden in (copy_root / "settings", B.clone_dir(tenant),
                      export_dir(tenant.tenant, tenant.commit).parent):
        assert not T.exposes(sources, forbidden), (
            f"O-A: a box mount exposes {forbidden}: {docker.mounts()}")
    assert T.exposes(sources, copy_root / "agent"), "control: the copy's agent/ is mounted"

    cats = _exec_cats(docker)
    tokens = [p for p in cats if p.resolve().is_relative_to(copy_root.resolve())
              and not p.resolve().is_relative_to((copy_root / "agent").resolve())]
    assert tokens, f"O-A: startup never read a token back from the run copy: {cats}"
    assert not [c for c in docker.calls if any(".tenant-id" in part for part in c)], (
        "O-A: the retired in-box `.tenant-id` check still runs")
    # O8/P-4: operator issuer variables never reach the box (control: the env is read above).
    assert B.leaks(("s-b-operator-bao-token-77e1", "s-b-operator-vault-token-91a4"),
                   create_argv=docker.create_argv) == []


class _OtherCopyDocker(RecordingDocker):
    """A daemon that bound the run copy's root to ANOTHER folder: every read the box makes
    inside the copy but outside `agent/` finds nothing there. It judges nothing."""

    def __init__(self, copies: Path) -> None:
        super().__init__()
        self.copies = copies

    def _exec(self, argv):
        if "cat" in argv and self.create_argv is not None:
            host = self._through_binds(Path(argv[-1]))
            under = host.resolve()
            if under.is_relative_to(self.copies.resolve()) and "agent" not in (
                    under.relative_to(self.copies.resolve()).parts[1:2]):
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
    """O-SWEEP: while live, `<T>/run-knowledge/<run_id>/` exists and records its owner (this
    process's pid, outside the model-visible `agent/`); after the run it is gone."""
    def owner(seen: B.Seen) -> list[str]:
        root = B.run_copies(tenant) / seen.run_dir.name
        return [rel for rel, data in B.tree_bytes(root).items()
                if not rel.startswith("agent/") and str(os.getpid()).encode() in data]

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=owner)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    copy_root = _copy_root(tenant, out)
    assert out.seen[0].copies_listing == [copy_root.name], (
        f"the run copy is not `<T>/run-knowledge/<run_id>/`: {out.seen[0].copies_listing}")
    assert out.seen[0].during, f"O-SWEEP: the run copy records no owner pid {os.getpid()}"
    assert not copy_root.exists(), "O-SWEEP: the run copy outlived its run"


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
        return (B.run_copies(tenant) / seen.run_dir.name / "agent").is_dir()

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
