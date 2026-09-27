"""#1110 — the run page is a run record; the local copy is a dev-only extra. End-to-end half.

Every test renders a REAL run: a run dir the replay harness drove (`test_922_renderer.
driven_run`, whose final turn is `MARKER`), or a run the real `run.py main` materialized and
drove through a replaying lifecycle. The post-run step is the real `run_common.visualize(run)`
over the run's tenant-bound handle (`test_922_renderer.tenant_run`, built the way the real
builder builds it); where the handle's backend is observed, a pass-through recorder enters
through the handle's own `io=` seam and the assertion is on the CALL it captured.

- O1: the page the post-run step renders is saved as the run's `runtime_html` record through
  the run's handle — one whole-document `write_guarded(<record>, <page>, mode="replace")`, the
  page being exactly what `render_page` generates (which itself writes nothing, M1). Also
  through `run.py main`, with the handle the real builder materialized.
- O2/S1: with `DEFENDER_DEPLOYMENT` unset or `production`, a render changes nothing outside the
  run's records — a before/after snapshot of the test's temp tree (the runs base, its
  `sessions/` sibling, the conftest's copy override), this checkout's `defender/`, and a real
  checkout's top-level copy name. Positive control: under `dev` the same snapshot shows the copy.
  Beyond that universe: a production re-render in a child whose system temp dir and home are
  fresh folders leaves both empty, and a copy root that does not exist yet is not created.
- M2: the dev copy is the in-memory page, not the record read back.
- O4: a failed copy is not a failed render; an unresolvable run, a crashing renderer (two
  observed exception classes), a renderer that cannot even be imported, or a record write the
  handle refuses IS one (`VisualizeFailed`), and then no page record exists.
- O5: a failed copy is a WARNING naming its destination, or — with none resolved — the
  resolver's reason. A copy that lands warns nothing.
- O6: an unrecognised deployment renders the record, makes no copy, and logs an error.
- O7: `run.py main` exits 0 over a run whose renderer genuinely crashes, or cannot be imported.
- O8: `python visualize_run.py <run_dir>` re-renders a finished run into its `runtime_html`
  record, and under `production` copies nothing; like the post-run step it writes through the
  handle, so a link planted at the record's name is refused, not followed (S2).

The #1084 copy mechanics under `dev` (O3/S3) are `test_1084_mirror_e2e.py`'s, migrated.

The names under test are imported inside each test, so this file collects against a tree that
does not have them yet.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender import _io, run_common
from defender._run_paths import RunPaths
from defender.tests.e2e._replay_harness import GOLDEN, drive
from defender.tests.e2e.test_922_renderer import MARKER, driven_run, golden_replay, tenant_run
from defender.tests.e2e.test_1084_mirror_e2e import (
    _assert_record_written,
    _assert_warned,
    _defender_snapshot,
    _main_checkout_by_git,
    _stray_state,
    _warnings,
)

pytestmark = pytest.mark.e2e

DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"
MIRROR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
PAGE = "runtime.html"
#: Trace rows the renderer is OBSERVED to crash on (probed against `render_runtime_page`), each
#: with the exception class it raises there and a fragment of that exception's message: real bad
#: inputs through the real renderer, not planted exceptions. TWO CLASSES on purpose — a step
#: whose catch named only the class one planted row happens to raise (`except (AttributeError,
#: OSError)`) passes a single-row suite while an other-shaped crash still escapes `run.py main`.
CRASHING_TRACE_ROWS: dict[str, tuple[dict, str, str]] = {
    # `_stats`: `(e.get("message") or {}).get(...)` on a string.
    "message-not-an-object": (
        {"type": "assistant", "message": "not-a-dict"}, "AttributeError", "has no attribute 'get'"),
    # `_stats`: iterating `message.content` when it is a number.
    "content-not-a-list": (
        {"type": "assistant", "message": {"content": 5}}, "TypeError", "not iterable"),
}
#: The renderer's module, as `run_common.visualize` imports it.
RENDERER_MODULE = "defender.scripts.visualize.visualize_run"


def _renderer():
    from defender.scripts.visualize import visualize_run

    return visualize_run


# ---------------------------------------------------------------------------------------
# The handle's backend, observed: a pass-through recorder on the handle's own `io=` seam
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IoCall:
    op: str
    args: tuple
    kwargs: dict


class ArgRecordingIo:
    """A pass-through recorder over the real `defender._io`, entering through the `Run`
    handle's `io=` injection seam (never `monkeypatch.setattr`). Every operation still really
    happens; each is recorded WITH its arguments — `_spec1077.RecordingIo` keeps only the path,
    and the page text and the write mode are the payload O1 is about. Total over `_io`, since
    `Run.for_tenant` and the handle's own mkdir also reach through it."""

    def __init__(self) -> None:
        self.calls: list[IoCall] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        real = getattr(_io, name)
        if not callable(real):
            return real

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(IoCall(name, args, dict(kwargs)))
            return real(*args, **kwargs)

        return call

    def writes_to(self, path: Path) -> list[IoCall]:
        return [c for c in self.calls if c.op == "write_guarded" and Path(c.args[0]) == path]


class _RecordReplacedAfterWriteIo(ArgRecordingIo):
    """The recorder, plus one event: right after the handle writes `record`, `other` replaces
    it — what a second render driver over the same run id does (#705). Through the real
    primitive, so a read-back of the record, through the handle or around it, sees `other`."""

    def __init__(self, record: Path, other: str) -> None:
        super().__init__()
        self._record = record
        self._other = other

    def write_guarded(self, path: Any, text: Any, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(IoCall("write_guarded", (path, text, *args), dict(kwargs)))
        result = _io.write_guarded(path, text, *args, **kwargs)
        if Path(path) == self._record:
            _io.write_guarded(path, self._other, mode="replace")
        return result


def _text(payload: str | bytes) -> str:
    return payload.decode("utf-8") if isinstance(payload, bytes) else payload


def _plant_crashing_row(run_dir: Path, row: dict) -> None:
    trace = RunPaths(run_dir).tool_trace
    body = trace.read_text(encoding="utf-8")
    assert body.strip(), "precondition: the run has a trace for the renderer to read"
    trace.write_text(body + json.dumps(row) + "\n", encoding="utf-8")


def _make_renderer_unimportable(monkeypatch) -> None:
    """The renderer module cannot be imported — #922 C12's failure (a deleted symbol it imports
    breaks it AT IMPORT), produced without editing the module: `None` in `sys.modules` makes any
    import of it raise `ModuleNotFoundError`. The package attribute is removed as well, because
    `from package import module` answers an attribute the package already carries (set by any
    earlier import in this worker) without consulting `sys.modules`. `monkeypatch` restores both.

    The precondition is asserted in the same statement form the step uses, so a fault that did
    not take stops the test here rather than passing it vacuously."""
    import importlib

    package = importlib.import_module("defender.scripts.visualize")
    monkeypatch.setitem(sys.modules, RENDERER_MODULE, None)
    monkeypatch.delattr(package, "visualize_run", raising=False)
    with pytest.raises(ImportError):
        from defender.scripts.visualize import visualize_run  # noqa: F401


# ---------------------------------------------------------------------------------------
# O1 — the page is saved through the run's own handle
# ---------------------------------------------------------------------------------------


def test_1110_o1_the_post_run_step_saves_the_page_through_the_runs_tenant_bound_handle(tmp_path):
    """O1 (and M1). `render_page(run_dir)` GENERATES the page and writes nothing — the run
    dir's listing is unchanged by it. The post-run step `run_common.visualize(run)` then hands
    that page to the run's own handle: the `io` injected into the tenant-bound handle captures
    exactly one `write_guarded` of the `runtime_html` record, a whole-document `replace`, whose
    text IS the generated page (and carries this run's final turn). The write really happened:
    the record on disk holds the same text.

    The platform's store backend sits behind that `io`, which is why the capture is the
    obligation: it receives the page with no page-specific code."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    io = ArgRecordingIo()
    run = tenant_run(run_dir, io=io)
    record = run.observability.runtime_html.path
    assert record == RunPaths(run_dir).runtime_html, "precondition: the record's address"

    listing = sorted(p.name for p in run_dir.iterdir())
    page = vr.render_page(run_dir)
    assert MARKER in page, "render_page did not generate this run's page"
    assert sorted(p.name for p in run_dir.iterdir()) == listing, (
        "render_page wrote into the run dir — generation must write nothing (M1)")

    run_common.visualize(run)

    writes = io.writes_to(record)
    assert len(writes) == 1, (
        f"the handle's io saw {len(writes)} writes of {record.name}; ops: "
        f"{[c.op for c in io.calls]}")
    (write,) = writes
    assert write.kwargs.get("mode") == "replace", (
        f"the page record was not written as a whole-document replace: {write.kwargs!r}")
    assert _text(write.args[1]) == page, "the handle was handed something other than the page"
    assert record.read_text(encoding="utf-8") == page, "the record on disk is not the page"


class _ReplayLifecycle:
    """`run.py main`'s lifecycle seam, doing what an investigation does to the run dir `main`
    materialized: the real driver over it, with the replayed model `driven_run` uses (so its
    page carries `MARKER`). `crash_row`, when set, is appended to the run's trace afterwards —
    an input the renderer is observed to crash on. `after`, when set, runs last, once the
    investigation is over (a fault the post-run step alone should meet)."""

    def __init__(self, *, crash_row: dict | None = None,
                 after: Callable[[], None] | None = None) -> None:
        self.crash_row = crash_row
        self.after = after
        self.run_dirs: list[Path] = []

    def __call__(self, *, run_dir: Path, **_kw: Any) -> dict:
        self.run_dirs.append(run_dir)
        drive(run_dir, run_id=run_dir.name, main=golden_replay(run_dir))
        if self.crash_row is not None:
            _plant_crashing_row(run_dir, self.crash_row)
        if self.after is not None:
            self.after()
        return {"output": "done", "requests": 3, "truncated_by": None}


@pytest.fixture
def entrypoint_env(tmp_path, monkeypatch) -> Path:
    """What the real `run.py main` needs to get past its startup and into its tail: a runs
    base and a learning state root under tmp (distinct — the runs base refuses to share one),
    and a key per provider so nothing credentialed is reached. Answers the runs base."""
    from defender.runtime import providers

    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "spec1110-not-used")
    runs_base = tmp_path / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs_base))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    return runs_base


def _main(**seams: Callable[..., Any]) -> int:
    from defender import run as run_py

    return run_py.main([str(GOLDEN / "alert.json"), "--no-learn"],
                       preflight=lambda _model: 0, **seams)


def test_1110_o1_run_main_saves_the_page_through_the_handle_it_materialized(
        tmp_path, entrypoint_env):
    """O1 through the entry point. `main` materializes the run with the real builder
    (`run_common.materialize_run`, answering the tenant-bound `Run`); the `materialize` seam
    re-binds that same address — same tenant, same run id, same runs base — to a handle whose
    `io` is the recorder, exactly as `Run.for_tenant` builds any handle. `visualize` is left at
    its production default. After `main` returns 0, the recorder captured the page record's
    write: one whole-document replace of THIS run's page, as `render_page` generates it.

    Positive control built in: the lifecycle ran in the run dir of the handle `main` was given,
    so the capture is of the run `main` drove, not of some other directory."""
    from defender._run_handle import Run

    io = ArgRecordingIo()
    handles: list[Run] = []

    def materialize(alert: Path, run_id: str | None, **kw: Any) -> Run:
        real = run_common.materialize_run(alert, run_id, **kw)
        assert real.runs_base == entrypoint_env, "the builder bound another runs base"
        run = Run.for_tenant(real.tenant_id, real.run_dir.name, runs_base=real.runs_base, io=io)
        handles.append(run)
        return run

    lifecycle = _ReplayLifecycle()
    assert _main(lifecycle=lifecycle, materialize=materialize) == 0

    (run,) = handles
    assert lifecycle.run_dirs == [run.run_dir], "main drove a different run dir than it built"
    record = run.observability.runtime_html.path
    writes = io.writes_to(record)
    assert len(writes) == 1, (
        f"the run's handle saw {len(writes)} writes of {record.name}; ops: "
        f"{sorted({c.op for c in io.calls})}")
    (write,) = writes
    assert write.kwargs.get("mode") == "replace"
    page = _text(write.args[1])
    assert MARKER in page, "the record written is not this run's page"
    assert page == _renderer().render_page(run.run_dir)
    assert record.read_text(encoding="utf-8") == page


# ---------------------------------------------------------------------------------------
# O2 / S1 — production writes nothing outside the run's records; dev writes only the copy
# ---------------------------------------------------------------------------------------


def _records_of(run) -> Callable[[Path], bool]:
    """The run's records, as the design defines them: the run dir, its runs-base sidecars, and
    its session store — the store's transient `-wal`/`-shm` included."""
    from defender.runtime import session_store

    store = session_store.resolve_store_path(run.run_dir)
    exact = {run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path,
             *(Path(f"{store}{suffix}") for suffix in ("", "-wal", "-shm", "-journal"))}

    def is_record(path: Path) -> bool:
        return path in exact or path == run.run_dir or run.run_dir in path.parents

    return is_record


def _tree_snapshot(root: Path, skip: Callable[[Path], bool]) -> dict[str, tuple | None]:
    """Every entry under `root` not skipped: files and links by (mode, size, mtime_ns),
    directories by presence (a directory's mtime moves when a transient file comes and goes,
    which is not a write anyone would read)."""
    out: dict[str, tuple | None] = {}
    for here, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            p = Path(here) / name
            if skip(p):
                continue
            st = p.lstat()
            out[str(p)] = None if stat.S_ISDIR(st.st_mode) else (
                st.st_mode, st.st_size, st.st_mtime_ns)
        dirs[:] = [d for d in dirs if not skip(Path(here) / d)]
    return out


def _changed(before: dict, after: dict) -> set[str]:
    """Entries created, removed, or changed. By KEY first: a directory is recorded by presence
    (its value is `None`), so a value-only comparison would read a new directory as unchanged."""
    return (set(before) ^ set(after)) | {k for k in set(before) & set(after)
                                         if before[k] != after[k]}


def _render_and_diff(run) -> list[str]:
    """Render once through the post-run step, and answer every entry OUTSIDE the run's
    records that the render created, changed or removed: under the test's temp base (the runs
    base, the `sessions/` sibling, the conftest's copy override all live there), under this
    checkout's `defender/`, and at a real checkout's top-level copy name for this run (#1084's
    default resolutions: the main checkout, and the folder holding `defender/`)."""
    base = run.run_dir.parent.parent
    is_record = _records_of(run)
    strays = [root / "run-visualizations" / run.run_dir.name / PAGE
              for root in (run_common.REPO_ROOT, _main_checkout_by_git())]

    tmp_before = _tree_snapshot(base, is_record)
    code_before = _defender_snapshot()
    strays_before = [_stray_state(p) for p in strays]

    run_common.visualize(run)

    tmp_after = _tree_snapshot(base, is_record)
    code_after = _defender_snapshot()
    changed = [*_changed(tmp_before, tmp_after)]
    changed += [f"defender/{k}" for k in _changed(code_before, code_after)]
    changed += [str(p) for p, was in zip(strays, strays_before, strict=True)
                if _stray_state(p) != was]
    return sorted(changed)


def _base_holds(run_dir: Path, override: Path) -> bool:
    """The snapshot's root (the test's temp base) holds the conftest's copy override — so a
    copy that lands there is IN the diff rather than beside it."""
    return run_dir.parent.parent in override.parents


@pytest.mark.parametrize("deployment", [None, "production"], ids=["unset", "production"])
def test_1110_o2_s1_a_production_render_leaves_nothing_outside_the_runs_records(
        tmp_path, monkeypatch, run_visualizations_dir, deployment):
    """O2/S1. With `DEFENDER_DEPLOYMENT` unset (the default a worker gets) or `production`, a
    render through the post-run step changes nothing outside the run's records: no copy in the
    override, no page at a real checkout's copy name, nothing next to the code. The positive
    leg on the same render: the record itself IS written, with this run's page — so an empty
    diff is not a render that did nothing. The dev-side positive control for the snapshot is
    the next test."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    if deployment is None:
        assert DEPLOYMENT_ENV not in os.environ, "precondition: the conftest unsets it"
    else:
        monkeypatch.setenv(DEPLOYMENT_ENV, deployment)
    assert _base_holds(run_dir, run_visualizations_dir), "precondition: the snapshot sees it"

    outside = _render_and_diff(run)

    assert outside == [], f"a {deployment or 'unset'} render wrote outside the run's records: {outside}"
    assert sorted(run_visualizations_dir.iterdir()) == [], "a copy landed in the override"
    _assert_record_written(run_dir)


def test_1110_o2_s1_positive_control_the_same_render_under_dev_shows_only_the_copy(
        tmp_path, monkeypatch, run_visualizations_dir):
    """The positive control for O2/S1's snapshot, on the same address: under `dev`, the SAME
    render's diff outside the run's records is exactly the copy — `<override>/<run>/` and
    `<override>/<run>/runtime.html`, byte-identical to the record. A snapshot that could not
    see the override, or a filter that dropped it, fails here rather than passing the
    production case vacuously."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")

    outside = _render_and_diff(run)

    folder = run_visualizations_dir / run_dir.name
    assert outside == sorted([str(folder), str(folder / PAGE)]), (
        f"under dev the render's footprint outside its records should be the copy alone: "
        f"{outside}")
    assert (folder / PAGE).read_bytes() == (run_dir / PAGE).read_bytes()


# ---------------------------------------------------------------------------------------
# O4 / O5 — VisualizeFailed means the record was not written; a copy failure is a warning
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["unwritable-destination", "no-destination"])
def test_1110_o4_o5_a_failed_copy_is_a_warning_not_a_failed_render(
        tmp_path, monkeypatch, caplog, run_visualizations_dir, fault):
    """O4/O5 under `dev`. The copy fails two real ways — its destination sits under a regular
    FILE (the copy resolves, then cannot be written), or the override is removed under pytest
    (the resolver refuses: `MirrorRootRefused`, no destination at all). Either way the post-run
    step does NOT raise `VisualizeFailed`, the run's page record is written, and the failure is
    a WARNING: naming the destination when one resolved, else the resolver's reason.

    Positive control on the same run: with the override back on a writable folder, the copy
    lands and nothing is warned — so the warning is this fault's, not one every render emits."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    if fault == "unwritable-destination":
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"a file, not a folder\n")
        monkeypatch.setenv(MIRROR_ENV, str(blocker / "run-visualizations"))
    else:
        monkeypatch.delenv(MIRROR_ENV)
    caplog.set_level(logging.DEBUG)

    run_common.visualize(run)  # a failed copy is not a failed render: no VisualizeFailed

    _assert_record_written(run_dir)
    if fault == "unwritable-destination":
        _assert_warned(caplog, str(blocker / "run-visualizations" / run_dir.name / PAGE))
        assert blocker.read_bytes() == b"a file, not a folder\n"
    else:
        warned = _warnings(caplog)
        assert any("MirrorRootRefused" in w or "is unset under pytest" in w for w in warned), (
            f"the refused copy was not warned with the resolver's reason; warnings: {warned!r}")

    monkeypatch.setenv(MIRROR_ENV, str(run_visualizations_dir))
    caplog.clear()
    run_common.visualize(run)
    assert (run_visualizations_dir / run_dir.name / PAGE).read_bytes() == (run_dir / PAGE).read_bytes()
    assert _warnings(caplog) == [], f"a copy that landed was warned about: {_warnings(caplog)!r}"


def test_1110_o4_a_run_whose_store_cannot_be_resolved_is_not_rendered_and_writes_no_page(
        tmp_path):
    """O4 (the render precondition, M1). A run dir relocated without its session-store pointer
    is refused BEFORE anything is written: the post-run step raises `VisualizeFailed` naming
    the run dir, no page record exists, and the handle's `io` never saw a write of the record.

    Positive control on the same run: the pointer restored, the same call writes the record."""
    run_dir = driven_run(tmp_path)
    io = ArgRecordingIo()
    run = tenant_run(run_dir, io=io)
    record = run.observability.runtime_html.path
    pointer = RunPaths(run_dir).session_pointer
    saved = pointer.read_bytes()
    pointer.unlink()

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    assert str(run_dir) in str(failed.value), "the failure does not name the run it could not render"
    assert not record.exists(), "a refused render left a page behind for a reader to trust"
    assert io.writes_to(record) == [], "the record was written before the precondition refused"

    pointer.write_bytes(saved)
    run_common.visualize(run)
    _assert_record_written(run_dir)
    assert len(io.writes_to(record)) == 1


@pytest.mark.parametrize("crash", sorted(CRASHING_TRACE_ROWS))
def test_1110_o4_o7_a_renderer_crash_is_visualize_failed_and_writes_no_page(tmp_path, crash):
    """O4/O7 (the step half). A trace row the renderer genuinely crashes on makes the post-run
    step raise `VisualizeFailed`, NOT the renderer's raw exception (which `run.py main` does not
    catch: it would escape and change the exit code), chained from that error so the cause is
    not lost. No page record is written. Two rows, raising two different exception classes
    (`AttributeError`, `TypeError`): the step's boundary is "any failure to render", not the
    classes someone has seen.

    Positive control on the same run, before the row is planted: the step renders and writes
    the record — so it is the row, not the run, that fails the render."""
    row, cause_type, cause_text = CRASHING_TRACE_ROWS[crash]
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    record = RunPaths(run_dir).runtime_html
    run_common.visualize(run)
    _assert_record_written(run_dir)
    record.unlink()
    _plant_crashing_row(run_dir, row)

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    cause = failed.value.__cause__
    assert type(cause).__name__ == cause_type, (
        f"VisualizeFailed is not chained from the renderer's own error: {cause!r}")
    assert cause_text in str(cause), f"not the observed renderer crash: {cause!r}"
    assert not record.exists(), "a crashed render left a page behind"


def test_1110_o4_o7_a_renderer_that_cannot_be_imported_is_visualize_failed(tmp_path, monkeypatch):
    """O4/O7 — the renderer fails AT IMPORT (#922 C12: the live investigation's renderer breaks
    when a symbol it imports is deleted). The step imports the renderer lazily; that import is
    part of rendering, so its failure is `VisualizeFailed` like any other failed render — an
    import placed outside the step's boundary lets the `ImportError` out raw, which `run.py
    main` does not catch. Chained from the import error; no page record is written.

    Positive control on the same run, before the module is made unimportable: the step renders
    and writes the record."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    record = RunPaths(run_dir).runtime_html
    run_common.visualize(run)
    _assert_record_written(run_dir)
    record.unlink()
    _make_renderer_unimportable(monkeypatch)

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    assert isinstance(failed.value.__cause__, ImportError), (
        f"VisualizeFailed is not chained from the import failure: {failed.value.__cause__!r}")
    assert not record.exists(), "a render that could not import its renderer left a page"


def test_1110_m2_the_dev_copy_is_the_in_memory_page_not_the_record_read_back(
        tmp_path, monkeypatch, run_visualizations_dir):
    """M2: under `dev` the copy is of the page the step just RENDERED, held in memory — never
    the record read back. A read-back is indistinguishable while the record holds exactly what
    was written, so the handle's `io` here models the case where it does not: a second render
    driver over the same run id (#705's two drivers) replaces the record right after this
    step's write. The copy must still be byte-identical to `render_page`'s output — whether a
    read-back went through the handle or around it, it would carry the other driver's page.

    Positive control, same test: the record on disk DOES hold the other driver's page, so a
    read-back would have been observable; and the handle was handed this step's page."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    record = RunPaths(run_dir).runtime_html
    other = "<!doctype html><title>ANOTHER DRIVER'S PAGE</title>\n"
    io = _RecordReplacedAfterWriteIo(record, other)
    run = tenant_run(run_dir, io=io)
    page = vr.render_page(run_dir)

    run_common.visualize(run)

    (write,) = io.writes_to(record)
    assert _text(write.args[1]) == page, "the handle was not handed this step's page"
    assert record.read_text(encoding="utf-8") == other, (
        "positive control: the other driver's replace did not land, so a read-back is invisible")
    copy = run_visualizations_dir / run_dir.name / PAGE
    assert copy.read_bytes() == page.encode("utf-8"), (
        "the dev copy is not the page this step rendered — it was read back from the record")


@pytest.mark.parametrize("squatter", ["link", "directory"])
def test_1110_o4_a_record_write_the_handle_refuses_is_visualize_failed(tmp_path, squatter):
    """O4 (the record-write half), with a REAL fault through the REAL primitive: an entry
    planted at `runtime.html` — a symlink to a file outside the run, or a non-empty directory
    — which the handle's write refuses (observed: `OSError` ELOOP, "refusing to write through
    a non-plain or aliased entry"). The post-run step raises `VisualizeFailed`, chained from
    that refusal; nothing is written through the link (S2) and the directory keeps its
    content.

    Positive control on the same run: the squatter removed, the same call writes the record."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    record = RunPaths(run_dir).runtime_html
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"OUTSIDE\n")
    if squatter == "link":
        os.symlink(outside, record)
    else:
        record.mkdir()
        (record / "keep").write_bytes(b"KEEP\n")

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    assert getattr(failed.value.__cause__, "errno", None) == errno.ELOOP, (
        f"VisualizeFailed is not the handle's refusal: {failed.value.__cause__!r}")
    assert outside.read_bytes() == b"OUTSIDE\n", "the page was written through the planted link"
    if squatter == "link":
        assert record.is_symlink(), "the planted link was replaced"
        assert os.readlink(record) == str(outside), "the planted link was re-aimed"
        record.unlink()
    else:
        assert (record / "keep").read_bytes() == b"KEEP\n"
        (record / "keep").unlink()
        record.rmdir()

    run_common.visualize(run)
    _assert_record_written(run_dir)


# ---------------------------------------------------------------------------------------
# O6 — an unrecognised deployment: production, loudly, never fatal
# ---------------------------------------------------------------------------------------


def test_1110_o6_an_unrecognised_deployment_renders_the_record_makes_no_copy_and_errors(
        tmp_path, monkeypatch, caplog, run_visualizations_dir):
    """O6 end to end. `DEFENDER_DEPLOYMENT=staging` — a value the setting does not know. The
    post-run step does not abort (no raise), writes the record, and makes NO copy (a typo is
    `production`, never `dev`); the read is logged as an ERROR naming the variable and value.

    Positive control on the same run and override: set to `dev`, the copy lands — so "no copy"
    above is the setting's answer, not a copy that could not have happened."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    monkeypatch.setenv(DEPLOYMENT_ENV, "staging")
    caplog.set_level(logging.DEBUG)

    run_common.visualize(run)

    _assert_record_written(run_dir)
    assert sorted(run_visualizations_dir.iterdir()) == [], "a typo'd deployment made the copy"
    errors = [r.getMessage() for r in caplog.records
              if r.levelno == logging.ERROR and DEPLOYMENT_ENV in r.getMessage()]
    assert errors, "the unrecognised deployment was not logged as an error"
    assert all("staging" in e for e in errors), f"the error does not name the value: {errors!r}"

    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    run_common.visualize(run)
    assert (run_visualizations_dir / run_dir.name / PAGE).read_bytes() == (run_dir / PAGE).read_bytes()


# ---------------------------------------------------------------------------------------
# O7 — the run's exit code survives a genuine renderer crash
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("crash", sorted(CRASHING_TRACE_ROWS))
def test_1110_o7_run_main_exits_0_over_a_run_whose_renderer_crashes(
        tmp_path, entrypoint_env, crash):
    """O7 through the entry point, everything real but the model and the preflight: `main`
    materializes the run, the lifecycle drives it and leaves a trace row the renderer crashes
    on (two rows, two exception classes), and the production `visualize` renders in-process.
    `main` returns 0 — the crash did not escape it — and no page record exists, which is what
    makes the 0 mean something: the render really failed.

    Positive control: `test_1110_o1_run_main_saves_the_page_through_the_handle_it_materialized`
    — the same entry point over the same replay without the row writes the record."""
    lifecycle = _ReplayLifecycle(crash_row=CRASHING_TRACE_ROWS[crash][0])

    assert _main(lifecycle=lifecycle) == 0

    (run_dir,) = lifecycle.run_dirs
    assert run_dir.parent == entrypoint_env, "precondition: main built the run under the runs base"
    assert not RunPaths(run_dir).runtime_html.exists(), (
        "the page record exists — the renderer did not crash, so the 0 proves nothing")


def test_1110_o7_run_main_exits_0_when_the_renderer_cannot_be_imported(
        tmp_path, entrypoint_env, monkeypatch):
    """O7 through the entry point, for a renderer that fails AT IMPORT (#922 C12). The module is
    made unimportable once the investigation is over — the post-run step is the first thing
    that needs it — and `main` still returns 0, with no page record: the import failure is a
    failed render, not an exception out of the run.

    Positive control: `test_1110_o1_run_main_saves_the_page_through_the_handle_it_materialized`
    — the same entry point, the renderer importable, writes the record."""
    lifecycle = _ReplayLifecycle(after=lambda: _make_renderer_unimportable(monkeypatch))

    assert _main(lifecycle=lifecycle) == 0

    (run_dir,) = lifecycle.run_dirs
    assert not RunPaths(run_dir).runtime_html.exists(), (
        "the page record exists — the renderer was importable after all, so the 0 proves nothing")


# ---------------------------------------------------------------------------------------
# O8 — the standalone re-render keeps working over a finished run
# ---------------------------------------------------------------------------------------


def _standalone(run_dir: Path, **env: str) -> subprocess.CompletedProcess:
    script = run_common.DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"
    return subprocess.run(  # noqa: S603 — this interpreter, the renderer script, the run dir
        [sys.executable, str(script), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8", check=False,
        env={**os.environ, **env})


def test_1110_o8_the_standalone_re_render_writes_the_record_and_copies_only_under_dev(
        tmp_path, run_visualizations_dir):
    """O8. `python visualize_run.py <run_dir>` — the operator's re-render, a real child
    process — over a finished run exits 0 and writes the page at the run's `runtime_html`
    record: this run's page, exactly as `render_page` generates it. Under `production` (the
    inherited, conftest-unset environment) it copies nothing into the override.

    Positive control: the same command with `DEFENDER_DEPLOYMENT=dev` lands the copy in the
    same override — so the empty override above is the deployment's answer."""
    run_dir = driven_run(tmp_path)
    record = RunPaths(run_dir).runtime_html
    assert not record.exists(), "precondition: no page before the re-render"

    child = _standalone(run_dir)

    assert child.returncode == 0, f"the re-render failed: {child.stderr}"
    assert record.read_text(encoding="utf-8") == _renderer().render_page(run_dir)
    assert MARKER in record.read_text(encoding="utf-8")
    assert sorted(run_visualizations_dir.iterdir()) == [], "a production re-render made a copy"

    child = _standalone(run_dir, **{DEPLOYMENT_ENV: "dev"})

    assert child.returncode == 0, f"the dev re-render failed: {child.stderr}"
    assert (run_visualizations_dir / run_dir.name / PAGE).read_bytes() == record.read_bytes()


def test_1110_o8_s2_the_standalone_re_render_refuses_a_link_planted_at_the_record(
        tmp_path, run_visualizations_dir):
    """O8/S2 (and M6: the re-render goes through the same step, over a handle). A symlink is
    planted at `runtime.html`, aimed at a file OUTSIDE the run. The re-render must not write
    through it: the handle's write refuses the link, the child exits non-zero (a refused record
    is not a rendered run), the outside file is byte-for-byte unchanged, and the link is still
    the link it was. A re-render that wrote its own page with a plain `write_text` follows the
    link and overwrites the outside file.

    Positive control on the same run: the link removed, the same command exits 0 and writes the
    record (as the unplanted O8 case above does)."""
    run_dir = driven_run(tmp_path)
    record = RunPaths(run_dir).runtime_html
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"OUTSIDE\n")
    os.symlink(outside, record)

    child = _standalone(run_dir)

    assert child.returncode != 0, (
        f"the re-render reported success over a refused record: {child.stdout!r}")
    assert outside.read_bytes() == b"OUTSIDE\n", "the re-render wrote through the planted link"
    assert record.is_symlink(), "the planted link was replaced"
    assert os.readlink(record) == str(outside), "the planted link was re-aimed"

    record.unlink()
    child = _standalone(run_dir)
    assert child.returncode == 0, f"the re-render failed: {child.stderr}"
    assert MARKER in record.read_text(encoding="utf-8")


def _fresh_dirs(tmp_path: Path) -> tuple[Path, Path]:
    temp, home = tmp_path / "system-temp", tmp_path / "home"
    temp.mkdir()
    home.mkdir()
    return temp, home


def test_1110_o2_s1_a_production_re_render_writes_nothing_to_the_temp_dir_or_home(
        tmp_path, run_visualizations_dir):
    """O2/S1 beyond the snapshot's universe: the system temp dir and the home directory. A
    production render in a child whose `TMPDIR` and `HOME` are fresh, empty folders leaves both
    empty — no page staged in `/tmp` "for later", nothing cached under `~`. The standalone
    re-render is the vehicle because the child's interpreter reads both variables at start,
    where this process has long since fixed its own temp dir.

    Positive controls: the child's interpreter really resolves the system temp dir and home to
    those folders (so a write there would be seen), and the re-render wrote the record (so two
    empty folders are not a child that did nothing). And the override stays empty: production."""
    run_dir = driven_run(tmp_path / "runs-base")
    temp, home = _fresh_dirs(tmp_path)
    env = {"TMPDIR": str(temp), "HOME": str(home)}
    resolved = subprocess.run(  # noqa: S603 — this interpreter, asked where it would write
        [sys.executable, "-c",
         "import os, tempfile; print(tempfile.gettempdir()); print(os.path.expanduser('~'))"],
        capture_output=True, text=True, encoding="utf-8", check=True,
        env={**os.environ, **env}).stdout.split()
    assert resolved == [str(temp), str(home)], f"precondition: the child resolves {resolved}"

    child = _standalone(run_dir, **env)

    assert child.returncode == 0, f"the re-render failed: {child.stderr}"
    assert MARKER in RunPaths(run_dir).runtime_html.read_text(encoding="utf-8")
    assert sorted(temp.rglob("*")) == [], "a production render wrote into the system temp dir"
    assert sorted(home.rglob("*")) == [], "a production render wrote into the home directory"
    assert sorted(run_visualizations_dir.iterdir()) == [], "a production re-render made a copy"


@pytest.mark.parametrize("deployment", [None, "staging"], ids=["unset", "unrecognised"])
def test_1110_o2_a_production_render_does_not_create_the_copy_root(
        tmp_path, monkeypatch, deployment):
    """O2: the copy root is the copy's, and production makes no copy — so a production render
    does not create it either. The override points at `run-visualizations/` under a folder that
    does NOT exist yet (as `<folder holding defender/>/run-visualizations/` does not, in a
    worker image); after a render under an unset or an unrecognised deployment, neither exists.
    The conftest's override is pre-created, which is why the snapshot tests cannot see this.

    Positive control on the same run and override: under `dev`, the render creates the root
    and puts the copy in it."""
    run_dir = driven_run(tmp_path / "runs-base")
    run = tenant_run(run_dir)
    stand_in = tmp_path / "stand-in-for-the-folder-holding-defender"
    root = stand_in / "run-visualizations"
    monkeypatch.setenv(MIRROR_ENV, str(root))
    if deployment is not None:
        monkeypatch.setenv(DEPLOYMENT_ENV, deployment)

    run_common.visualize(run)

    _assert_record_written(run_dir)
    assert not stand_in.exists(), f"a production render created the copy root's folder {stand_in}"

    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    run_common.visualize(run)
    assert (root / run_dir.name / PAGE).read_bytes() == (run_dir / PAGE).read_bytes()
