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
    `run_common.materialize_run` builds it (the runs-base record naming the run's tenant,
    created once when absent, then `Run.for_tenant`). The runs base is the run dir's parent,
    where the replay harness put it. `io` is the handle's own injection seam (a recorder, in
    #1110)."""
    runs_base = run_dir.parent
    tenant = _tenant.ensure_runs_base_record(runs_base, _tenant.TenantId("playground"))
    return Run.for_tenant(tenant.tenant_id, run_dir.name, runs_base=runs_base, io=io)


def test_922_the_live_investigations_renderer_still_imports_and_runs(tmp_path):
    """GUARD (green now, must stay green).

    D7/C12. `run_common.visualize` is the post-run step `run.py main` takes: it imports and
    runs `scripts/visualize/visualize_run.py`'s renderer and raises `VisualizeFailed` when the
    render fails — so an import error in the renderer (the failure a full deletion of
    `directions.py` produces) surfaces here as a raise, not as a silent skip.

    The pages are then asserted to carry the run's OWN content. That is the positive control
    that makes the no-raise meaningful: a renderer that returned having written nothing, or
    having left a page from a previous render in place, would satisfy "did not raise" and
    witness nothing about the import that C12 is about.
    """
    run_dir = driven_run(tmp_path)
    for page in ("runtime.html",):
        assert not (run_dir / page).exists(), (
            f"{page} exists before the renderer ran — the assertions below would be satisfied "
            "by a stale page rather than by this render")

    run_common.visualize(tenant_run(run_dir))

    for page in ("runtime.html",):
        rendered = (run_dir / page)
        assert rendered.is_file(), f"the renderer returned without writing {page}"
        assert MARKER in rendered.read_text(encoding="utf-8"), (
            f"{page} does not carry the run's own final turn — the renderer rendered "
            "something, but not this run")


def test_922_the_renderer_fails_loud_when_it_cannot_render(tmp_path):
    """GUARD (green now, must stay green) — the paired control for the demand above.

    The demand above rests entirely on `run_common.visualize` SURFACING a render failure. If it
    swallowed one, a `directions.py` deleted in full would render nothing and the guard would
    still pass. This drives the same production entry point over a run dir the renderer cannot
    render and asserts the contract that carries the signal: a failed render becomes
    `VisualizeFailed` naming the run dir, never a quiet return.

    The induced fault is the one the shipped code documents — an unresolvable run dir — rather
    than an imagined one; what is being pinned is the ERROR CHANNEL, and the channel is the same
    whichever way the render dies.
    """
    empty = tmp_path / "not-a-run-dir"
    empty.mkdir()

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(Run.at(empty))
    assert str(empty) in str(failed.value)


def test_922_the_renderers_own_import_surface_resolves_in_a_child_interpreter(tmp_path):
    """GUARD (green now, must stay green).

    The narrowest statement of C12, and the one a reader of the deletion set needs: every symbol
    `visualize_run.py` takes from `visualize_judge.py` must still resolve after the old-judge
    rendering is removed from that module. `visualize_run`'s import block is read off its own
    AST — nothing here carries a copy of the nine names — and each one is then looked up on the
    imported module.

    Read off the file on disk rather than the imported module object, so the AST is the
    renderer's source as shipped. (The standalone re-render still runs it as a child, via
    `python visualize_run.py <run_dir>` — #1110 O8.)
    """
    import ast
    import importlib

    source = (run_common.DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py").read_text(
        encoding="utf-8")
    wanted: dict[str, list[str]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.ImportFrom) and node.module and "visualize" in node.module:
            wanted.setdefault(node.module, []).extend(a.name for a in node.names)

    assert wanted, (
        "positive control: visualize_run.py imports nothing from the visualize package — the "
        "AST walk is not reading its import block")
    for dotted, names in sorted(wanted.items()):
        module = importlib.import_module(dotted)
        # A name imported FROM A PACKAGE may be a submodule (`from ...visualize import
        # _mirror_write`), which is an attribute of the package only once something has
        # imported it — so asking `hasattr` alone made this pass or fail on what an earlier test
        # in the same worker happened to import. A submodule resolves by its spec.
        missing = [name for name in names
                   if not hasattr(module, name) and not _is_submodule(dotted, name)]
        assert missing == [], (
            f"visualize_run.py imports {missing} from {dotted}, which no longer provides them "
            "— the live investigation's renderer breaks at import (C12/D7)")


def _is_submodule(dotted: str, name: str) -> bool:
    """Whether `dotted.name` is an importable submodule. Only a package has submodules; asking
    a plain module raises rather than answering, and that answer is no."""
    import importlib.util

    try:
        return importlib.util.find_spec(f"{dotted}.{name}") is not None
    except ModuleNotFoundError:
        return False


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
