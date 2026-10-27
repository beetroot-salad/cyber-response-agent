"""#1108 P4 round 6 — run-copy and run-start cases the earlier rounds left unpinned (each was a
wrong-but-green production variant): a second launch on a live-owned run id, a dead owner's copy
at the run id, the owner record written first, per-copy tokens, the host knowledge-source record
written before the box and a failed write stopping the run, and the dev issuer config's
location.

Real `run.main` / real `copy_for_run`; no monkeypatching. The oracles are the planted
copies' bytes and the processes that really exist.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path
from typing import Any

import pytest

from defender.tenancy import run_knowledge
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._drain_support import process_start, write_owner
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge
from defender.tests.tenancy.tenant_1108_p4.test_run_copy import (
    _boxed_lifecycle,
    _dead_process,
    _Investigation,
    boxed_only,  # noqa: F401, F811 — fixture
)

pytestmark = pytest.mark.e2e

WORKTREE = Path(__file__).resolve().parents[4]


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


def _source(t) -> run_knowledge.KnowledgeSource:
    return run_knowledge.KnowledgeSource(kind=run_knowledge.FRESH, commit=t.commit)


def _planted(t, run_id: str, pid: int, start: Any) -> Path:
    root = B.run_copies(t) / run_id
    (root / "stage" / "agent").mkdir(parents=True)
    (root / "stage" / "agent" / "marker.md").write_text("first copy\n", encoding="utf-8")
    write_owner(root, pid, start)
    return root


def _live_child():
    """A process that really exists for the length of the test (its own pid and start)."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])  # noqa: S603
    return proc


# --- D01: a second launch never steals a live-owned copy --------------------------------------

def test_r6_a_second_copy_for_a_run_id_whose_owner_lives_is_refused_and_leaves_the_first(tenant):
    child = _live_child()
    try:
        run_id = str(uuid.uuid4())
        first = _planted(tenant, run_id, child.pid, process_start(child.pid))
        with pytest.raises(run_knowledge.KnowledgeRefused):
            run_knowledge.copy_for_run(tenant.tenant, _source(tenant), run_id)
        assert (first / "stage" / "agent" / "marker.md").read_text(encoding="utf-8") == "first copy\n"
        assert (first / "owner").is_file()
        assert [p.name for p in B.run_copies(tenant).iterdir()] == [run_id], "a temporary was left"
    finally:
        child.kill()
        child.wait()


# #1279: no launch names a run id (the system mints it) and a run is never resumed, so a launch
# cannot meet a live or a dead copy at its id; `copy_for_run`'s own refusal and replacement are
# pinned directly above and below.


# --- D04: a dead owner's copy at the run id is replaced ---------------------------------------

def test_r6_a_dead_owners_copy_at_the_run_id_is_replaced_by_a_fresh_one(tenant):
    run_id = str(uuid.uuid4())
    dead_pid, dead_start = _dead_process()
    old = _planted(tenant, run_id, dead_pid, dead_start)
    copy = run_knowledge.copy_for_run(tenant.tenant, _source(tenant), run_id)
    assert copy.root.name == run_id
    assert not (old / "stage" / "agent" / "marker.md").exists(), "the dead run's files survive"
    assert (old / "stage" / "agent").is_dir()
    assert any((old / "stage" / "agent").rglob("*.md"))
    assert (old / "settings").is_dir()
    assert [p.name for p in B.run_copies(tenant).iterdir()] == [run_id]


# --- D02 / inputs-01: the owner record is written first ---------------------------------------

def test_r6_a_copy_build_cut_off_mid_write_leaves_a_temporary_that_already_names_its_owner(
        tmp_path, data_root):
    """A builder killed by the kernel in the middle of writing (here: its first file larger than
    its file-size limit, SIGXFSZ) leaves the dot-named temporary. That folder must already name
    the builder: an ownerless temporary counts dead and a concurrent publish would sweep a copy
    that is still being built."""
    big = "x" * 200_000
    with B.run_tenant(tmp_path, data_root, files={"agent/lessons/r6-big.md": big}) as t:
        run_id = str(uuid.uuid4())
        script = textwrap.dedent(f"""
            import resource, signal, sys
            from defender.tenancy import run_knowledge
            from defender.tenancy import _tenant
            tenant = _tenant.requested_tenant(_tenant.resolve_data_root(), {t.tenant_id!r})
            source = run_knowledge.KnowledgeSource(kind="fresh", commit={t.commit!r})
            signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
            resource.setrlimit(resource.RLIMIT_FSIZE, (100_000, 100_000))
            run_knowledge.copy_for_run(tenant, source, {run_id!r})
            """)
        env = {**os.environ, "PYTHONPATH": str(WORKTREE)}
        proc = subprocess.Popen([sys.executable, "-c", script], env=env, cwd=str(WORKTREE),  # noqa: S603
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _out, err = proc.communicate(timeout=120)
        assert proc.returncode < 0, f"the build was not cut off: {proc.returncode} {err!r}"
        left = [p for p in B.run_copies(t).iterdir() if p.name.startswith(".")]
        assert len(left) == 1, f"expected the builder's temporary, found {left} ({err!r})"
        owner = left[0] / "owner"
        assert owner.is_file(), "the temporary under construction names no owner"
        assert json.loads(owner.read_text(encoding="utf-8"))["pid"] == proc.pid


# --- surfaces-14: each run copy's token is its own --------------------------------------------

def test_r6_every_run_copy_stages_its_own_unpredictable_token(tenant):
    tokens = []
    for _ in range(3):
        copy = run_knowledge.copy_for_run(tenant.tenant, _source(tenant), str(uuid.uuid4()))
        tokens.append((copy.root / "stage" / run_knowledge.STAGE_TOKEN).read_text(
            encoding="utf-8").strip())
    assert len(set(tokens)) == 3, f"run copies share a token: {tokens}"
    assert all(len(t) >= 32 for t in tokens), tokens


# --- H09 / H06: the host knowledge-source record is written before the box --------------------

def test_r6_the_host_knowledge_source_record_exists_when_the_lifecycle_starts(tenant, tmp_path):
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   during=lambda seen: B.read_host_record(seen.run_dir))
    assert out.rc == 0, out.text()
    record = out.seen[0].during
    assert isinstance(record, dict), "no host record when the run's lifecycle started"
    assert record["kind"] == "fresh"
    assert record["commit"] == tenant.commit


def test_r6_a_run_that_cannot_write_its_host_knowledge_record_does_not_start(tenant, tmp_path):
    """The record is the run's only host-held knowledge source: a run that cannot write it does
    not start. The run dir is built by the real `materialize`; a wrapper then puts a directory
    where the record must go (after materialize cleared any stale sidecar)."""
    from defender import run as run_py

    def materialize_then_block(*a: Any, **k: Any):
        run = run_py._materialize_run(*a, **k)
        B.host_record_path(Path(run.run_dir)).mkdir()
        return run

    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   materialize=materialize_then_block)
    assert not out.reached, f"the run started without its knowledge record: {out.text()}"
    assert out.refusal, out.text()
    assert "knowledge record" in out.refusal, out.text()


# --- surfaces-04: the production dev-issuer-config constant lies under no box mount source ----

def test_r6_the_dev_issuer_config_location_lies_under_no_box_mount_source(tenant, tmp_path,
                                                                        boxed_only):  # noqa: F811 — fixture
    """The dev provisioning's per-tenant issuer client config (`playground-issuer/client/
    <tenant>/issuer.json`), named by the tenant's binding, is under no box mount source."""
    DEV_ISSUER_CONFIG = WORKTREE / "playground-issuer" / "client" / tenant.tenant_id / "issuer.json"
    bind_forge(tenant, issuer_config=DEV_ISSUER_CONFIG)
    docker, investigation = RecordingDocker(), _Investigation()
    out = B.launch(tenant, tmp_path, publish=lambda *a, **k: B.fresh(tenant.commit),
                   lifecycle=_boxed_lifecycle(docker, investigation))
    assert out.reached, out.text()
    assert investigation.calls == 1, out.text()
    sources = [Path(m["source"]) for m in docker.mounts()]
    assert T.exposes(sources, T.DEFENDER), "control: the product tree is mounted"
    assert not T.exposes(sources, DEV_ISSUER_CONFIG), (
        f"a box mount exposes the issuer client config {DEV_ISSUER_CONFIG}")
