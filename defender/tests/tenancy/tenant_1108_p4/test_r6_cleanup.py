"""#1108 P4 round 6 — what a failed build or command leaves behind, and a few liveness and
pinning judgements (each case was a wrong-but-green production variant): no half-built run copy
or export staging folder survives a failed write, `propose` always discards its draft, a zombie
is not a live owner, a pinned commit with no export is refused when resolved."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import httpx
import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._drain_support import draft_entries
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, export_dir

WORKTREE = Path(__file__).resolve().parents[4]


def _run_limited(code: str) -> subprocess.CompletedProcess:
    """`code` in a child process whose files may not exceed 100 kB (a write beyond it fails with
    EFBIG; Python ignores SIGXFSZ)."""
    env = {**os.environ, "PYTHONPATH": str(WORKTREE)}
    prelude = "import resource\nresource.setrlimit(resource.RLIMIT_FSIZE, (100_000, 100_000))\n"
    return subprocess.run([sys.executable, "-c", prelude + code], env=env,  # noqa: S603
                          cwd=str(WORKTREE), capture_output=True, text=True, timeout=120,
                          check=False)


BIG = {"agent/lessons/r6-big.md": "x" * 200_000}


def test_r6_a_run_copy_build_that_fails_leaves_no_half_built_folder(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root, files=BIG) as t:
        done = _run_limited(textwrap.dedent(f"""
            from defender.runtime import run_knowledge
            from defender.tenancy import _tenant
            tenant = _tenant.requested_tenant(_tenant.resolve_data_root(), {t.tenant_id!r})
            source = run_knowledge.KnowledgeSource(kind="fresh", commit={t.commit!r})
            try:
                run_knowledge.copy_for_run(tenant, source, {str(uuid.uuid4())!r})
            except OSError as e:
                print("OSError", e.errno)
            """))
        assert "OSError" in done.stdout, (done.stdout, done.stderr[-500:])
        assert list(B.run_copies(t).iterdir()) == [], "a failed build left a folder behind"


def test_r6_an_export_build_that_fails_leaves_no_staging_folder(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root, files=BIG) as t:
        exports = export_dir(t.tenant, t.commit).parent
        # `current` and the export go; the clone's objects remain, so materialise rebuilds.
        shutil.rmtree(export_dir(t.tenant, t.commit))
        done = _run_limited(textwrap.dedent(f"""
            from defender.learning.author.version_control import materialise_export
            from defender.tenancy import _tenant
            tenant = _tenant.requested_tenant(_tenant.resolve_data_root(), {t.tenant_id!r})
            try:
                materialise_export(tenant, {t.commit!r})
            except BaseException as e:
                print("failed", type(e).__name__)
            """))
        assert "failed" in done.stdout, (done.stdout, done.stderr[-500:])
        assert [p.name for p in exports.iterdir() if p.name != "current"] == [], (
            "a failed export build left its staging folder")


# --- propose always discards its draft ---------------------------------------------------------

def _staged(tmp_path) -> Path:
    staged = tmp_path / "staged" / "lessons"
    staged.mkdir(parents=True)
    (staged / "r6-proposed.md").write_text("---\nname: r6\n---\nbody\n", encoding="utf-8")
    return staged.parent


@pytest.mark.parametrize("outcome", ["proposed", "refused"])
def test_r6_propose_discards_its_draft_whether_it_succeeds_or_is_refused(p4_tenant, tmp_path,
                                                                        capsys, outcome):
    from defender.cli import tenant as cli

    t = p4_tenant
    bind_forge(t)
    if outcome == "refused":
        t.forge.fault = lambda request: (
            httpx.ConnectError("the forge is down", request=request)
            if request.method == "POST" and request.url.path.endswith("/pulls") else None)
    rc = cli.propose(t.tenant_id, _staged(tmp_path), client=t.forge.client,
                     identity=t.vault.identity())
    assert rc == (0 if outcome == "proposed" else 1), capsys.readouterr()
    assert draft_entries(t) == [], "propose left its draft behind"


# --- liveness and pinning ----------------------------------------------------------------------

def test_r6_a_zombie_is_not_a_live_owner(tmp_path):
    from defender.tenancy._owner import OWNER_FILE, owner_alive, process_start

    proc = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603 — not waited for
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{proc.pid}/stat").read_text()
            if stat[stat.rindex(")") + 2] == "Z":
                break
            time.sleep(0.02)
        else:
            pytest.fail("premise: the child never became a zombie")
        assert process_start(proc.pid) is None
        folder = tmp_path / "copy"
        folder.mkdir()
        (folder / OWNER_FILE).write_text(
            f'{{"pid": {proc.pid}, "start": "{stat[stat.rindex(")") + 2:].split()[19]}"}}',
            encoding="utf-8")
        assert not owner_alive(folder)
    finally:
        proc.wait()


def test_r6_a_pinned_commit_with_no_export_is_refused_when_it_is_resolved(tmp_path, data_root):
    from defender.runtime import run_knowledge

    with B.run_tenant(tmp_path, data_root) as t:
        absent = "fedcba9876543210" * 2 + "fedcba98"
        with pytest.raises(run_knowledge.KnowledgeRefused):
            run_knowledge.resolve_source(t.tenant, report=None, pinned=absent)
        assert run_knowledge.resolve_source(t.tenant, report=None, pinned=t.commit).commit == t.commit
