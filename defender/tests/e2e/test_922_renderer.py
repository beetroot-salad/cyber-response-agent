"""#922 — D7: the production transcript renderer survives the cut of the direction table.

C12 is a REFUTATION, and it is the reason `learning/core/directions.py` is marked "NOT in full"
in the deletion set. `scripts/visualize/visualize_judge.py:9-13` imports `ADVERSARIAL`,
`BENIGN`, `Direction` and `directions_for`; `visualize_primitives.py:18` imports `Direction`;
`visualize_run.py` imports nine symbols from `visualize_judge`. And `visualize_run.py` is not a
developer tool — it is run BY THE LIVE INVESTIGATION on every run (`run_common.visualize`,
reached from `run.py main`'s post-run step) and again by the learning frontend build. Deleting
`directions.py` in full breaks a production renderer AT IMPORT.

So whatever survives of `directions.py` is exactly what keeps this green, and the shipped diff
has to name that residue rather than leave the module half-alive by accident.

The drive is the production entry point, `run_common.visualize(run)` — the step `run.py main`
takes after the run, with the same `VisualizeFailed` contract. Since #1110 it renders
IN-PROCESS (no child interpreter): an import error in the renderer surfaces from that call.

C12's guards themselves are `test_1110_run_page_record_e2e.py`'s now: its O1 renders this
module's `driven_run` through that entry point and pins the saved page to the generated one,
and its O4 pins the `VisualizeFailed` channel. What stays here is the shared driven run and
handle those suites build on, and the page-shell guard.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _io, _tenant, run_common
from defender._run_handle import Run
from defender.tests.e2e._replay_harness import GOLDEN, ReplayFn, Turn, drive, materialize

pytestmark = pytest.mark.e2e

MARKER = "RENDERED-BY-THE-922-GUARD"


def golden_replay(run_dir: Path) -> ReplayFn:
    """The scripted model of `driven_run`: write the golden work log and report into `run_dir`,
    then end on `MARKER` — so a page that carries `MARKER` is a page of THIS run."""
    investigation = (GOLDEN / "investigation.md").read_text(encoding="utf-8")
    report = (GOLDEN / "report.md").read_text(encoding="utf-8")
    return ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "investigation.md"),
                                         "content": investigation})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": report})]),
        Turn(text=MARKER),
    ])


def driven_run(tmp_path: Path):
    """One real hermetic run, driven through the replay harness — the renderer's input."""
    run_dir = materialize(tmp_path, GOLDEN)
    drive(run_dir, run_id="cutover-922-render", main=golden_replay(run_dir))
    return run_dir


def tenant_run(run_dir: Path, *, io=_io) -> Run:
    """The handle `run.py main` holds over a driven run: tenant-bound, built the way
    `run_common.materialize_run` builds it (the tenant record at the runs base, created once
    when absent, then `Run.for_tenant`). The runs base is the run dir's parent, where the
    replay harness put it. `io` is the handle's own injection seam (a recorder, in #1110)."""
    runs_base = run_dir.parent
    tenant = _tenant.ensure_tenant(runs_base)
    return Run.for_tenant(tenant.tenant_id, run_dir.name, runs_base=runs_base, io=io)


def test_the_two_column_wrapper_never_ships_without_the_sidebar_that_fills_it(tmp_path):
    """GUARD — the sidebar and the space reserved for it are one decision, not two.

    The page shell reserves a fixed 240px first column for the table of contents and gives
    the article the rest. A page that opens the shell without rendering a sidebar puts its
    ARTICLE in that track: a 240px column of text on a 1600px page, everything inside it
    wrapping against a width meant for nav links.

    Neither half of the pairing shows the other, so it is asserted rather than left to a
    comment: a page may have both, or neither, never only the wrapper.
    """
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
