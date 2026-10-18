"""#1110 e2e: the run page is saved as the run's record through the run's tenant-bound handle (post-run step and run.py main); a failed dev copy is only a warning, while an unrenderable/unimportable renderer or a refused record write is VisualizeFailed (run.py main still exits 0); the standalone re-render refuses a link planted at the record."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import errno
import json
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _env, _io, run_common
from defender.run_repository import Run
from defender.run_repository import RunPaths
from defender.tests._spec1077 import bound_arguments
from defender.tests.e2e._replay_harness import GOLDEN, drive
from defender.tests.e2e.test_922_renderer import MARKER, driven_run, golden_replay, tenant_run
from defender.tests.e2e.test_1084_mirror_e2e import (
    _assert_one_warning_naming_the_destination_once,
    _assert_record_written,
    _warnings,
)

pytestmark = pytest.mark.e2e

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


def _repository_run() -> tuple[str, Path]:
    """`(T, run_dir)`: a driven run where the run page's repository opens it, by id, under T."""
    from defender import _tenant
    from defender.tests._data_root_1078 import current_data_root, ensure_d9_tenant

    tenant = ensure_d9_tenant()
    runs = current_data_root() / tenant / "runs"
    run_dir = driven_run(runs)
    _tenant.ensure_runs_base_record(runs, _tenant.TenantId(tenant))
    return tenant, run_dir


def _run_page_argv(tenant: str, run_dir: Path) -> list[str]:
    return ["visualize_run.py", "--tenant", tenant, run_dir.name]


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

    def bound(self) -> dict[str, Any]:
        """The call's arguments by name (`_spec1077.bound_arguments`)."""
        return bound_arguments(self.op, self.args, self.kwargs)

    @property
    def target(self) -> Path:
        """A rooted call's record: its trust root joined with the name relative to it."""
        b = self.bound()
        return Path(b["root"]) / PurePosixPath(b["name"])

    @property
    def text(self) -> Any:
        return self.bound()["text"]

    @property
    def mode(self) -> Any:
        return self.bound()["mode"]


class ArgRecordingIo:
    """A pass-through recorder over the real `defender._io`, entering through the `Run` handle's `io=` injection..."""

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
        """Every `rooted_write` of the record at `path` (#1111:"""
        return [c for c in self.calls if c.op == "rooted_write" and c.target == path]


def _text(payload: str | bytes) -> str:
    return payload.decode("utf-8") if isinstance(payload, bytes) else payload


def _assert_a_render_failure(failed, run_dir: Path) -> None:
    """#1110 review:"""
    message = str(failed.value)
    assert str(run_dir) in message, f"the render failure does not name the run: {message!r}"
    words = message.replace(str(run_dir), "<run>").lower()
    assert "render" in words, f"the failure does not say the page was not rendered: {message!r}"
    assert "sav" not in words, f"a render failure reads as a save failure: {message!r}"
    assert "load" not in words, f"a render failure reads as a load failure: {message!r}"


def _assert_a_load_failure(failed: BaseException, run_dir: Path) -> None:
    """#1110 second review:"""
    message = str(failed)
    assert type(failed).__name__ == "VisualizeFailed", f"not a VisualizeFailed: {failed!r}"
    assert isinstance(failed.__cause__, ImportError), (
        f"the load failure is not chained from the import error: {failed.__cause__!r}")
    words = message.replace(str(run_dir), "<run>").lower()
    assert "load" in words, f"the failure does not say the renderer could not be loaded: {message!r}"


def _assert_a_save_failure(failed, run_dir: Path, record: Path) -> None:
    """#1110 review:"""
    message = str(failed.value)
    assert str(record) in message, f"the save failure does not name the record: {message!r}"
    words = message.replace(str(record), "<record>").replace(str(run_dir), "<run>").lower()
    assert "sav" in words, f"the failure does not say the record was not saved: {message!r}"


def _chain(exc: BaseException | None) -> list[BaseException]:
    seen: list[BaseException] = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _assert_main_warned_with_the_chain(
        caplog, reaches: Callable[[BaseException], bool]) -> BaseException:
    """#1110 review:"""
    carried = [r for r in caplog.records
               if r.levelno == logging.WARNING and r.exc_info and r.exc_info[1] is not None]
    chains = [_chain(r.exc_info[1]) for r in carried]
    matching = [c[0] for c in chains
                if type(c[0]).__name__ == "VisualizeFailed" and any(reaches(e) for e in c)]
    assert matching, (
        "main did not log the failed render as a WARNING carrying its traceback down to the "
        f"renderer's error; warnings with exc_info: "
        f"{[[type(e).__name__ for e in c] for c in chains]!r}; all warnings: "
        f"{[r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]!r}")
    return matching[0]


def _json_lines(stderr: str) -> list[dict]:
    """The child's structured log lines (`DEFENDER_LOG_FORMAT=json`):"""
    out = []
    for line in stderr.splitlines():
        if line.startswith("{"):
            out.append(json.loads(line))
    return out


def _plant_crashing_row(run_dir: Path, row: dict) -> None:
    trace = RunPaths(run_dir).tool_trace
    body = trace.read_text(encoding="utf-8")
    assert body.strip(), "precondition: the run has a trace for the renderer to read"
    trace.write_text(body + json.dumps(row) + "\n", encoding="utf-8")


def _make_renderer_unimportable(monkeypatch) -> None:
    """The renderer module cannot be imported — #922 C12's failure (a deleted symbol it imports breaks it AT..."""
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
    """O1 (and M1)."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    io = ArgRecordingIo()
    run = tenant_run(run_dir, io=io)
    record = run.observability.runtime_html.path
    assert record == RunPaths(run_dir).runtime_html, "precondition: the record's address"

    listing = sorted(p.name for p in run_dir.iterdir())
    page = vr.render_page(_run_handle_1165(run_dir))
    assert MARKER in page, "render_page did not generate this run's page"
    assert sorted(p.name for p in run_dir.iterdir()) == listing, (
        "render_page wrote into the run dir — generation must write nothing (M1)")

    run_common.visualize(run)

    writes = io.writes_to(record)
    assert len(writes) == 1, (
        f"the handle's io saw {len(writes)} writes of {record.name}; ops: "
        f"{[c.op for c in io.calls]}")
    (write,) = writes
    assert write.mode == "replace", (
        f"the page record was not written as a whole-document replace: {write.bound()!r}")
    assert _text(write.text) == page, "the handle was handed something other than the page"
    assert record.read_text(encoding="utf-8") == page, "the record on disk is not the page"


class _ReplayLifecycle:
    """`run.py main`'s lifecycle seam, doing what an investigation does to the run dir `main` materialized:"""

    def __init__(self, *, crash_row: dict | None = None,
                 after: Callable[[], None] | None = None) -> None:
        self.crash_row = crash_row
        self.after = after
        self.run_dirs: list[Path] = []

    def __call__(self, *, run: Any, **_kw: Any) -> dict:
        run_dir = run.run_dir
        self.run_dirs.append(run_dir)
        drive(run_dir, run_id=run_dir.name, main=golden_replay(run_dir))
        if self.crash_row is not None:
            _plant_crashing_row(run_dir, self.crash_row)
        if self.after is not None:
            self.after()
        return {"output": "done", "requests": 3, "truncated_by": None}


@pytest.fixture
def entrypoint_env(tmp_path, monkeypatch) -> Path:
    """What the real `run.py main` needs to get past its startup and into its tail:"""
    from defender import _tenant
    from defender.runtime import providers
    from defender.tests._data_root_1078 import current_data_root, set_up_tenant

    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "spec1110-not-used")
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    return _tenant.runs_base_for(set_up_tenant(current_data_root()))


def _main(**seams: Callable[..., Any]) -> int:
    from defender import run as run_py

    from defender.tests._data_root_1078 import D9_TENANT_ID

    return run_py.main([str(GOLDEN / "alert.json"), "--tenant", D9_TENANT_ID, "--no-learn"],
                       preflight=lambda _model: 0, **seams)


def test_1110_o1_run_main_saves_the_page_through_the_handle_it_materialized(
        tmp_path, entrypoint_env):
    """O1 through the entry point."""
    from defender.run_repository import Run

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
    assert write.mode == "replace"
    page = _text(write.text)
    assert MARKER in page, "the record written is not this run's page"
    assert page == _renderer().render_page(_run_handle_1165(run.run_dir))
    assert record.read_text(encoding="utf-8") == page


# ---------------------------------------------------------------------------------------
# O2 / S1 — production writes nothing outside the run's records; dev writes only the copy
# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# O4 / O5 — VisualizeFailed means the record was not written; a copy failure is a warning
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["unwritable-destination", "no-destination"])
def test_1110_o4_o5_a_failed_copy_is_a_warning_not_a_failed_render(
        tmp_path, monkeypatch, caplog, run_visualizations_dir, fault):
    """O4/O5 under `dev`."""
    run_dir = driven_run(tmp_path)
    # The drive that made the run takes production's unboxed mode (#1255 C6), whose opt-out
    # logs a WARNING; it is the drive's, not the page step's. Counted from here, every
    # logger's warnings are the page step's.
    caplog.clear()
    run = tenant_run(run_dir)
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")
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
        _assert_one_warning_naming_the_destination_once(
            caplog, blocker / "run-visualizations" / run_dir.name / PAGE)
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
    """O4 (the render precondition, M1)."""
    run_dir = driven_run(tmp_path)
    io = ArgRecordingIo()
    run = tenant_run(run_dir, io=io)
    record = run.observability.runtime_html.path
    pointer = RunPaths(run_dir).session_pointer()
    saved = pointer.read_bytes()
    pointer.unlink()

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    _assert_a_render_failure(failed, run_dir)
    assert not record.exists(), "a refused render left a page behind for a reader to trust"
    assert io.writes_to(record) == [], "the record was written before the precondition refused"

    pointer.write_bytes(saved)
    run_common.visualize(run)
    _assert_record_written(run_dir)
    assert len(io.writes_to(record)) == 1


@pytest.mark.parametrize("crash", sorted(CRASHING_TRACE_ROWS))
def test_1110_o4_o7_a_renderer_crash_is_visualize_failed_and_writes_no_page(tmp_path, crash):
    """O4/O7 (the step half)."""
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
    _assert_a_render_failure(failed, run_dir)
    assert not record.exists(), "a crashed render left a page behind"


def test_1110_o4_o7_a_renderer_that_cannot_be_imported_is_visualize_failed(tmp_path, monkeypatch):
    """O4/O7 — the renderer fails AT IMPORT (#922 C12:"""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    record = RunPaths(run_dir).runtime_html
    run_common.visualize(run)
    _assert_record_written(run_dir)
    record.unlink()
    _make_renderer_unimportable(monkeypatch)

    with pytest.raises(run_common.VisualizeFailed) as failed:
        run_common.visualize(run)

    _assert_a_load_failure(failed.value, run_dir)
    assert not record.exists(), "a render that could not import its renderer left a page"


@pytest.mark.parametrize("squatter", ["link", "directory"])
def test_1110_o4_a_record_write_the_handle_refuses_is_visualize_failed(tmp_path, squatter):
    """O4 (the record-write half), with a REAL fault through the REAL primitive:"""
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
    _assert_a_save_failure(failed, run_dir, record)
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


# ---------------------------------------------------------------------------------------
# O7 — the run's exit code survives a genuine renderer crash
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("crash", sorted(CRASHING_TRACE_ROWS))
def test_1110_o7_run_main_exits_0_over_a_run_whose_renderer_crashes(
        tmp_path, entrypoint_env, caplog, crash):
    """O7 through the entry point, everything real but the model and the preflight:"""
    row, cause_type, _cause_text = CRASHING_TRACE_ROWS[crash]
    lifecycle = _ReplayLifecycle(crash_row=row)
    caplog.set_level(logging.DEBUG)

    assert _main(lifecycle=lifecycle) == 0

    _assert_main_warned_with_the_chain(caplog, lambda e: type(e).__name__ == cause_type)

    (run_dir,) = lifecycle.run_dirs
    assert run_dir.parent == entrypoint_env, "precondition: main built the run under the runs base"
    assert not RunPaths(run_dir).runtime_html.exists(), (
        "the page record exists — the renderer did not crash, so the 0 proves nothing")


def test_1110_o7_run_main_exits_0_when_the_renderer_cannot_be_imported(
        tmp_path, entrypoint_env, monkeypatch, caplog):
    """O7 through the entry point, for a renderer that fails AT IMPORT (#922 C12)."""
    lifecycle = _ReplayLifecycle(after=lambda: _make_renderer_unimportable(monkeypatch))
    caplog.set_level(logging.DEBUG)

    assert _main(lifecycle=lifecycle) == 0

    logged = _assert_main_warned_with_the_chain(caplog, lambda e: isinstance(e, ImportError))

    (run_dir,) = lifecycle.run_dirs
    _assert_a_load_failure(logged, run_dir)
    assert not RunPaths(run_dir).runtime_html.exists(), (
        "the page record exists — the renderer was importable after all, so the 0 proves nothing")


# ---------------------------------------------------------------------------------------
# O8 — the standalone re-render keeps working over a finished run
# ---------------------------------------------------------------------------------------


def _standalone(tenant: str, run_dir: Path, **env: str) -> subprocess.CompletedProcess:
    """`python visualize_run.py --tenant T <run_id>` over a `_repository_run` (#1105 PR 2, declared change 7:"""
    script = run_common.DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"
    return subprocess.run(  # noqa: S603 — this interpreter, the renderer script, tenant, run id
        [sys.executable, str(script), *_run_page_argv(tenant, run_dir)[1:]],
        capture_output=True, text=True, encoding="utf-8", check=False,
        env={**os.environ, **env})


def test_1110_o8_s2_the_standalone_re_render_refuses_a_link_planted_at_the_record(
        tmp_path, run_visualizations_dir):
    """O8/S2 (and M6:"""
    tenant, run_dir = _repository_run()
    record = RunPaths(run_dir).runtime_html
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"OUTSIDE\n")
    os.symlink(outside, record)

    child = _standalone(tenant, run_dir, DEFENDER_LOG_FORMAT="json")

    assert child.returncode == 1, (
        f"the re-render did not answer a refused record with exit 1 (got {child.returncode}): "
        f"{child.stderr[-600:]!r}")
    # #1110 review: the failure is LOGGED, with its traceback, inside the run's context — a
    # structured line a collector can tie to the run, not a bare interpreter traceback.
    carried = [line for line in _json_lines(child.stderr)
               if "VisualizeFailed" in (line.get("exception") or "")]
    assert carried, f"no JSON log line carries the VisualizeFailed traceback: {child.stderr!r}"
    assert all(line.get("run_id") == run_dir.name for line in carried), (
        f"the failure's log line is not bound to the run: {carried!r}")
    assert outside.read_bytes() == b"OUTSIDE\n", "the re-render wrote through the planted link"
    assert record.is_symlink(), "the planted link was replaced"
    assert os.readlink(record) == str(outside), "the planted link was re-aimed"

    record.unlink()
    child = _standalone(tenant, run_dir)
    assert child.returncode == 0, f"the re-render failed: {child.stderr}"
    assert MARKER in record.read_text(encoding="utf-8")
