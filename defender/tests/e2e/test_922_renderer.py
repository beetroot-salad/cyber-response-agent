"""#922 — D7: the production transcript renderer survives the cut of the direction table."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

from defender import _io, _tenant, run_common
from defender.run_repository import Run
from defender.tests.e2e._replay_harness import GOLDEN, ReplayFn, Turn, drive, materialize

pytestmark = pytest.mark.e2e

MARKER = "RENDERED-BY-THE-922-GUARD"


def golden_replay(run_dir: Path) -> ReplayFn:
    """The scripted model of `driven_run`: write the golden work log and report into `run_dir`,
    then end on `MARKER` — so a page that carries `MARKER` is a page of THIS run."""
    investigation = (GOLDEN / "investigation.md").read_text(encoding="utf-8")
    report = (GOLDEN / "report.md").read_text(encoding="utf-8")
    return ReplayFn([
        Turn(tool_calls=[("write_file", {"path": model_path(run_dir / "investigation.md", run_dir=run_dir),
                                         "content": investigation})]),
        Turn(tool_calls=[("write_file", {"path": model_path(run_dir / "report.md", run_dir=run_dir),
                                         "content": report})]),
        Turn(text=MARKER),
    ])


def driven_run(tmp_path: Path):
    """One real hermetic run, driven through the replay harness — the renderer's input."""
    run_dir = materialize(tmp_path, GOLDEN, run_id='cutover-922-render')
    drive(run_dir, run_id="cutover-922-render", main=golden_replay(run_dir))
    return run_dir


def tenant_run(run_dir: Path, *, io=_io) -> Run:
    """The handle `run.py main` holds over a driven run: tenant-bound, built the way
    `run_common.materialize_run` builds it (the runs-base record naming the run's tenant,
    created once when absent, then `Run.for_tenant`). The runs base is the run dir's parent."""
    runs_base = run_dir.parent
    tenant = _tenant.ensure_runs_base_record(runs_base, _tenant.TenantId("playground"))
    return Run.for_tenant(tenant.tenant_id, run_dir.name, runs_base=runs_base, io=io)


def test_the_two_column_wrapper_never_ships_without_the_sidebar_that_fills_it(tmp_path):
    """GUARD — the sidebar and the space reserved for it are one decision, not two."""
    run_dir = driven_run(tmp_path)
    run_common.visualize(tenant_run(run_dir))

    checked = 0
    for page in ("runtime.html",):
        html = (run_dir / page).read_text(encoding="utf-8")
        if '<div class="layout">' not in html:
            continue
        checked += 1
        assert '<nav class="toc"' in html, (
            f'{page} opens the two-column shell but renders no sidebar into it — its article '
            "lands in the 240px track the sidebar was supposed to occupy")

    assert checked, (
        "positive control: neither page uses the two-column shell any more, so this guard "
        "witnesses nothing — retire it or re-point it at whatever replaced the shell")
