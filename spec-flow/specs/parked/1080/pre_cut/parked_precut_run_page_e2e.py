# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_run_page_e2e.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite, or were parked whole (their canonical copy is
# ../parked_run_page_e2e.py, annotated with their owners). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
"""#1080 — the run page after the move into `defender/reports/`, over REAL runs (group `runpage`).

Every test here renders a run dir the replay harness drove (`test_922_renderer.driven_run`: one
hermetic run whose final turn is `MARKER`), or a run the real `run.py main` materialized and drove
through `test_1110_run_page_record_e2e`'s replaying lifecycle. The renderer, its mirror writer,
its failure type and its assets are reached through the `_spec1080` locator at call time; the
"as today" side of every comparison is the base's, frozen in `goldens/runpage.json` (and the
by-path page under `goldens/runpage/`), through the one page normalisation `_normalize_page`
and the one value scrub `test_1080_run_page._scrub`.

Two writer lanes exist, as today: when this process is root and the mirror's parent belongs to
another uid, the copy is written by a child that dropped to that uid (`_mirror_write.py` run
`-I` by path); otherwise in-process. `_writer_tree` builds the folder each lane needs, so the
observed outcome (`copied` / `failed`, the record, the folder) is the same word in both, and the
golden holds for either. Where an observation exists in one lane only, the test says so.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import run_common
from defender._run_handle import Run
from defender._run_paths import RunPaths
from defender.tests.e2e.test_922_renderer import MARKER, driven_run, tenant_run
from defender.tests.e2e._replay_harness import GOLDEN
from defender.tests.e2e.test_1110_run_page_record_e2e import (
    CRASHING_TRACE_ROWS,
    _plant_crashing_row,
    _ReplayLifecycle,
)
from defender.tests.scripts_1080_split import _spec1080 as S
from defender.tests.scripts_1080_split.test_1080_run_page import (
    DEPLOYMENT_ENV,
    MIRROR_ENV,
    MIRROR_NAME,
    PAGE_NAME,
    _assert_golden,
    _assert_golden_page,
    _fingerprint,
    _owned_dir,
    _renderer,
    _renderer_dotted,
    _scrub,
    _shadow_checkout,
    _shadow_env,
    _visualize_failed,
    _writer_path,
    _writer_tree,
)

pytestmark = pytest.mark.e2e

#: The two whole pages frozen from the base, under `goldens/runpage/`.
BY_PATH_PAGE = "by_path_page.html"
S177_PAGE = "hostile_fields_page.html"

# ======================================================================================
# The one page normalisation (capture and tests both use it)
# ======================================================================================

_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
_WALL_RE = re.compile(r'(<span class="ts-wall">)[^<]*(</span>)')
_TX_DURATION_RE = re.compile(r"( · )(?:—|\d+s|\d+m\d{2}s)( · )")
#: The replayed model's token counts are ESTIMATED from the prompt text, which carries this
#: environment's paths (a path component holding `.` or `:` splits into more "tokens").
_TOKENS_RE = re.compile(r"\b\d[\d,]* tok\b")


def _normalize_page(text: str, *paths: Path) -> str:
    """A rendered page with what differs between two renders of the same run removed: the run
    folder's path (each of `paths`, longest first, as `<PATH0>`, `<PATH1>`...), clock times
    (`<TS>`), measured durations (`<DUR>`) and the replayed model's estimated token counts
    (`<TOK> tok`). Nothing else is touched."""
    for i, p in sorted(enumerate(paths), key=lambda ip: -len(str(ip[1]))):
        text = text.replace(str(p), f"<PATH{i}>")
    text = _TS_RE.sub("<TS>", text)
    text = _WALL_RE.sub(r"\1<DUR>\2", text)
    text = _TOKENS_RE.sub("<TOK> tok", text)
    return _TX_DURATION_RE.sub(r"\1<DUR>\2", text)


def _page_text(path: Path) -> str:
    """A page file's exact text: its bytes decoded, with no newline translation."""
    return path.read_bytes().decode("utf-8")


def _digest(text: str) -> dict[str, Any]:
    data = text.encode("utf-8", "surrogatepass")
    return {"sha256": hashlib.sha256(data).hexdigest(), "chars": len(text)}


# ======================================================================================
# Shared drivers
# ======================================================================================


@pytest.fixture
def run_main_env(tmp_path, monkeypatch) -> Path:
    """What the real `run.py main` needs to reach its tail (`test_1110`'s `entrypoint_env`): a
    runs base and a learning state root under tmp, and a placeholder key per provider."""
    from defender import _tenant
    from defender.runtime import providers
    from defender.tests._data_root_1078 import current_data_root, set_up_tenant

    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "spec1080-not-used")
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    return _tenant.runs_base_for(set_up_tenant(current_data_root()))


def _run_main(run_id: str, **seams: Any) -> int:
    """The real `run.py main` over the replay fixture's alert under the test tenant, as
    `test_1110`'s `_main` drives it, with an explicit run id (two runs in one test)."""
    from defender import run as run_py
    from defender.tests._data_root_1078 import D9_TENANT_ID

    return run_py.main([str(GOLDEN / "alert.json"), "--tenant", D9_TENANT_ID, "--no-learn",
                        "--run-id", run_id], preflight=lambda _model: 0, **seams)


def _seed_work_files(run_dir: Path) -> Path:
    """The replay fixture's report and work log, put in the run dir as files (the driven run's
    own `write_file` turns are refused by its gate, so it has neither): a run dir with the
    records a finished investigation leaves. Answers `run_dir`."""
    paths = RunPaths(run_dir)
    shutil.copy(GOLDEN / "report.md", paths.report)
    shutil.copy(GOLDEN / "investigation.md", paths.investigation)
    return run_dir


def _publish(run) -> str:
    """The moved `publish_page(run)`: render, save the record through the handle, copy."""
    return _publisher()(run)


def _publisher() -> Callable[..., str]:
    """The moved `publish_page` itself — resolved BEFORE an `S.outcome` wraps a call, so a
    missing home fails the test with the locator's message instead of being recorded as the
    publisher's outcome."""
    return S.moved("publish_page", home=S.REPORTS)


def _make_unimportable(monkeypatch, dotted: str) -> None:
    """`dotted` cannot be imported for the rest of the test: `None` in `sys.modules`, and the
    attribute its package may already carry removed (`test_1110`'s pattern; monkeypatch
    restores both). The precondition is asserted so a fault that did not take stops here."""
    package, _, leaf = dotted.rpartition(".")
    monkeypatch.setitem(sys.modules, dotted, None)
    with_pkg = sys.modules.get(package) or importlib.import_module(package)
    monkeypatch.delattr(with_pkg, leaf, raising=False)
    with pytest.raises(ImportError):
        importlib.import_module(dotted)


def _warnings(caplog, *, logger: str | None = None) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.WARNING
            and (logger is None or r.name == logger)]


def _page_warnings(caplog) -> list[logging.LogRecord]:
    """The WARNINGs `run.py main` logs about the page step: on the `defender.run` logger,
    carrying an exception or naming the run page (its other warnings, e.g. the replay
    harness's missing scrub verdict, are not the page step's)."""
    return [r for r in _warnings(caplog, logger="defender.run")
            if r.exc_info or "run page" in r.getMessage()]


def _strays(folder: Path) -> list[str]:
    """Anything in `folder` but the page itself (a stage file left behind, a second copy)."""
    return sorted(p.name for p in folder.iterdir() if p.name != PAGE_NAME) if folder.is_dir() else []


def _as_writer(uid: int, gid: int) -> dict[str, Any]:
    """`subprocess` arguments that run a child as the copy's writer: dropped to `uid` with no
    supplementary groups when this process is root (the renderer's own drop), else as itself."""
    return {"user": uid, "group": gid, "extra_groups": []} if os.geteuid() == 0 else {}


def _lane_precondition(uid: int, gid: int) -> None:
    probe = subprocess.run(  # noqa: S603 — the interpreter itself, as the writer, doing nothing
        [sys.executable, "-I", "-c", "pass"], capture_output=True, check=False,
        **_as_writer(uid, gid))
    assert probe.returncode == 0, (
        f"infrastructure: uid {uid} cannot run {sys.executable}: {probe.stderr!r}")


# ======================================================================================
# s_run_end_publishes_page (and J-PO1's failure branch through run.py main)
# ======================================================================================


def _observe_run_main_page_failure(fault: str, monkeypatch, caplog) -> dict[str, Any]:
    """`run.py main` (real builder, replaying lifecycle, production `visualize`) over a run whose
    page fails: `render` — a trace row the renderer is observed to crash on (test_1110's
    `message-not-an-object`) — or `load` — the moved renderer module unimportable once the
    investigation is over. What `main` returns, whether the `runtime_html` record exists, and
    every WARNING on the `defender.run` logger with the exception it carries and that
    exception's cause (J-PO1: no recorded reason exists, so none is looked for)."""
    if fault == "render":
        lifecycle = _ReplayLifecycle(crash_row=CRASHING_TRACE_ROWS["message-not-an-object"][0])
    else:
        lifecycle = _ReplayLifecycle(
            after=lambda: _make_unimportable(monkeypatch, _renderer_dotted()))
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    rc = _run_main(f"spec1080-jpo1-{fault}", lifecycle=lifecycle)
    (run_dir,) = lifecycle.run_dirs
    rows = []
    for r in _page_warnings(caplog):
        exc = r.exc_info[1] if r.exc_info else None
        rows.append({"message": r.getMessage(),
                     "exc": type(exc).__name__ if exc is not None else None,
                     "exc_message": str(exc) if exc is not None else None,
                     "cause": type(exc.__cause__).__name__ if exc is not None
                     and exc.__cause__ is not None else None})
    return _scrub({"rc": rc, "runtime_html": RunPaths(run_dir).runtime_html.exists(),
                   "warnings": rows}, {str(run_dir): "<RUN_DIR>"})


def test_1080_run_end_publishes_the_run_page_through_the_moved_renderer(
        tmp_path, monkeypatch, caplog, run_main_env):
    """`run_common.visualize(run)` publishes the run page through the renderer in its new home.
    A render failure surfaces as the moved `VisualizeFailed`. The page record lands where it
    did before.

    Observed over a real driven run: `run_common.visualize` names the moved failure type (the
    same class object); it writes the run's `runtime_html` record at the run dir's
    `runtime.html` (the base's place, golden), and that record is exactly what the moved
    `render_page` generates and carries this run's final turn. A trace row the renderer crashes
    on makes the same call raise the moved `VisualizeFailed`, chained from the renderer's own
    error, and leaves no record. Through `run.py main` (J-PO1, golden): a render failure and a
    renderer that cannot be loaded each end with exit 0, no `runtime_html`, and exactly one
    page-step WARNING on `defender.run` — `the run page was not saved` — whose `exc_info` is the
    moved `VisualizeFailed` with its cause; no reason is recorded anywhere, so none is
    asserted."""
    vr = _renderer()
    failed_type = _visualize_failed()
    assert run_common.VisualizeFailed is failed_type, (
        "run_common does not raise the moved VisualizeFailed")

    run_dir = driven_run(tmp_path / "published")
    run = tenant_run(run_dir)
    run_common.visualize(run)
    record = RunPaths(run_dir).runtime_html
    page = _page_text(record)
    assert MARKER in page, "the record is not this run's page"
    assert page == vr.render_page(run_dir), "the record is not what the moved renderer renders"

    record.unlink()
    _plant_crashing_row(run_dir, CRASHING_TRACE_ROWS["message-not-an-object"][0])
    with pytest.raises(failed_type) as failed:
        run_common.visualize(run)
    assert type(failed.value.__cause__).__name__ == "AttributeError"
    assert not record.exists(), "a failed render left a page record"

    observed = {"record_name": S.rel(record, run_dir)}
    for fault in ("render", "load"):
        observed[fault] = _observe_run_main_page_failure(fault, monkeypatch, caplog)
        carried = [r.exc_info[1] for r in _page_warnings(caplog) if r.exc_info]
        assert carried, f"{fault}: main logged no warning carrying an exception"
        assert all(isinstance(e, failed_type) for e in carried), (
            f"{fault}: main's warning does not carry the moved VisualizeFailed: {carried!r}")
    _assert_golden("s_run_end_publishes_page", observed)


# ======================================================================================
# by_path_page_tests_survive_as_in_process_calls
# ======================================================================================


def _observe_in_process_publish(tmp_path: Path) -> tuple[dict[str, Any], str]:
    """The moved in-process publish over the by-path tests' fixture run (finished), and over the
    same run with its session-store pointer removed (test_projection_move_705's refused case):
    what it answers or raises, and whether a record exists. Answers the observation and the
    finished run's normalised page."""
    out: dict[str, Any] = {}
    run_dir = driven_run(tmp_path / "finished")
    publish = _publisher()
    out["finished"] = S.outcome(publish, Run.at(run_dir))
    record = RunPaths(run_dir).runtime_html
    out["finished_record"] = record.is_file()
    page = _normalize_page(_page_text(record), run_dir)

    broken = driven_run(tmp_path / "pointer-missing")
    RunPaths(broken).session_pointer.unlink()
    got = S.outcome(publish, Run.at(broken))
    out["pointer_missing"] = _scrub(got, {str(broken): "<RUN_DIR>"})
    out["pointer_missing_record"] = RunPaths(broken).runtime_html.exists()
    return out, page


def test_1080_the_in_process_publish_yields_the_page_and_record_the_by_path_run_yielded(tmp_path):
    """Once the run-page `__main__` block is dropped (M-D (a)), the in-process publish of the same
    run directory that the by-path tests use (test_1110_run_page_record_e2e,
    test_projection_move_705, test_1078_env) yields exactly the page bytes and the page record
    that the base's by-path run yielded for that fixture, taken as a golden from the base. A
    stale by-path call fails loud (s093); this is the substitute that replaces it.

    Golden: the base's `python visualize_run.py <run_dir>` over `driven_run` (the fixture
    test_1110 O8 re-renders) exited 0 and left the page record frozen in
    `goldens/runpage/by_path_page.html` (normalised by `_normalize_page`); over the same run
    with its store pointer removed it exited 1 and left no record. Observed: the moved
    `publish_page(Run.at(run_dir))` in this process writes a record whose normalised text is
    that page byte for byte and answers what the base's in-process call answered (`skipped`:
    no `dev` deployment); over the pointer-less run it raises `VisualizeFailed` and writes no
    record — the in-process form of the by-path exit 1."""
    observed, page = _observe_in_process_publish(tmp_path)
    _assert_golden_page(BY_PATH_PAGE, page)
    _assert_golden("by_path_page_tests_survive_as_in_process_calls", observed)


# ======================================================================================
# s020 / s065 / s067 / s207 — the mirror copy's two lanes
# ======================================================================================


def _writer_lane_ancestors(writer: Path) -> dict[str, Any]:
    """Every folder strictly below `defender/` on the way to the writer that a uid other than
    the owner cannot traverse (what lies above `defender/` the old and new paths share, so the
    move cannot change it), and whether such a uid can read the writer itself."""
    blocked = [S.rel(d) for d in [writer.parent, *writer.parent.parents]
               if d.is_relative_to(S.DEFENDER) and d != S.DEFENDER
               and not d.stat().st_mode & 0o001]
    return {"untraversable_folders": blocked,
            "writer_world_readable": bool(writer.stat().st_mode & 0o004)}


def test_mirror_writer_child_runs_as_the_folder_owner_from_its_new_path(
        tmp_path, monkeypatch, caplog):
    """The mirror copy of the run page lands as today and the run's own page lands. The writer
    file (`_mirror_write.py`, stdlib-only, spawned `-I`) is opened from its new path by the
    dropped- privilege child (owner uid, no supplementary groups) with the same access as
    before: the move adds no directory the owner cannot traverse that the old path did not
    already require, and a copy that cannot be written is reported rather than counted as
    mirrored. (O5: the run page and its mirror; F18.)

    Observed: (1) no folder from the checkout root down to the moved writer is closed to other
    uids, and the file is world-readable (the base's golden: none, readable). (2) A `dev` publish
    into a mirror whose parent the writer uid owns — as root, the drop-privilege lane — answers
    `copied`, the copy is the record byte for byte and every path it made belongs to that uid;
    the writer run by its moved path as that uid with no supplementary groups also writes a page.
    (3) Into a mirror folder that uid cannot write, the publish answers `failed`, warns once,
    leaves the folder untouched and still saves the record (golden for both)."""
    writer = _writer_path()
    observed: dict[str, Any] = {"access": _writer_lane_ancestors(writer)}
    run_dir = driven_run(tmp_path)
    run = Run.at(run_dir)
    record = RunPaths(run_dir).runtime_html
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    caplog.set_level(logging.DEBUG)
    with _writer_tree() as (base, checkout, uid, gid):
        _lane_precondition(uid, gid)
        mirror = checkout / MIRROR_NAME
        monkeypatch.setenv(MIRROR_ENV, str(mirror))
        word = _publish(run)
        copy = mirror / run_dir.name / PAGE_NAME
        made = [mirror, copy.parent, copy]
        observed["lands"] = {
            "publish": word,
            "copy_is_the_record": copy.read_bytes() == record.read_bytes(),
            "made_by_the_writer_uid": all(
                (os.lstat(p).st_uid, os.lstat(p).st_gid) == (uid, gid) for p in made)}
        direct = base / "direct"
        _owned_dir(direct, uid, gid)
        child = subprocess.run(  # noqa: S603 — the renderer's own argv, as the writer
            [sys.executable, "-I", str(writer), str(direct / "r" / PAGE_NAME)], input=b"DIRECT",
            capture_output=True, check=False, cwd="/", **_as_writer(uid, gid))
        observed["lands"]["direct_child_rc"] = child.returncode
        assert (direct / "r" / PAGE_NAME).read_bytes() == b"DIRECT", child.stderr

    with _writer_tree() as (_base, checkout, uid, gid):
        mirror = _owned_dir(checkout / MIRROR_NAME, uid, gid, 0o555)
        before = _fingerprint(mirror)
        monkeypatch.setenv(MIRROR_ENV, str(mirror))
        record.unlink()
        caplog.clear()
        word = _publish(run)
        observed["unwritable"] = {"publish": word, "record": record.is_file(),
                                  "warnings": len(_warnings(caplog)),
                                  "folder_untouched": _fingerprint(mirror) == before}
    _assert_golden("s020", observed)


def _s065_case(name: str, checkout: Path, uid: int, gid: int) -> tuple[Path, Callable[[], bool]]:
    """The mirror root for one destination-folder shape, and how to tell it was left alone."""
    mirror = checkout / MIRROR_NAME
    if name == "missing":
        return mirror, lambda: True
    if name == "not-writable":
        _owned_dir(mirror, uid, gid, 0o555)
    elif name == "a-regular-file":
        mirror.write_bytes(b"a file, not a folder\n")
        if os.geteuid() == 0:
            os.chown(mirror, uid, gid)
    elif name == "owned-by-another-user":
        if os.geteuid() != 0:
            # not root: a folder this uid cannot create anything in, owned by root
            target = Path("/usr")
            assert os.lstat(target).st_uid != os.geteuid()
            return target, lambda: True
        mirror.mkdir()
        os.chmod(mirror, 0o755)  # root's, inside a checkout the writer uid owns
    before = _fingerprint(mirror)
    return mirror, lambda: _fingerprint(mirror) == before


S065_CASES = ("missing", "not-writable", "a-regular-file", "owned-by-another-user")


def test_mirror_destination_folder_is_missing_unwritable_or_owned_by_another_user(
        tmp_path, monkeypatch, caplog):
    """When the mirror destination folder is missing, not writable, a regular file or owned by
    another user, the run's own page (runtime_html) still lands and the run exits as today; the
    mirror failure is handled as today (not a failure of the page write). Preserved behavior.
    (O5: the run page and its mirror.)

    Observed per shape through the moved `publish_page` under `dev` (the writer uid owns the
    mirror's parent, so as root the drop-privilege lane writes): what it answers, whether the
    record landed, how many warnings, and whether the destination folder was left as it was —
    each equal to the base's golden (`copied` for a missing folder; `failed`, record saved, one
    warning, folder untouched otherwise). No `VisualizeFailed` escapes, so the run exits as
    today."""
    run_dir = driven_run(tmp_path)
    run = Run.at(run_dir)
    record = RunPaths(run_dir).runtime_html
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    caplog.set_level(logging.DEBUG)
    observed = {}
    for name in S065_CASES:
        with _writer_tree() as (_base, checkout, uid, gid):
            _lane_precondition(uid, gid)
            mirror, untouched = _s065_case(name, checkout, uid, gid)
            monkeypatch.setenv(MIRROR_ENV, str(mirror))
            record.unlink(missing_ok=True)
            caplog.clear()
            word = _publish(run)
            observed[name] = {"publish": word, "record": record.is_file(),
                              "warnings": len(_warnings(caplog)), "untouched": untouched()}
    _assert_golden("s065", observed)


def test_mirror_writer_child_exits_nonzero_or_hangs_after_reading_part_of_the_page(
        tmp_path, monkeypatch, caplog):
    """A mirror child that exits nonzero, is killed or stops reading leaves the parent's
    publish outcome and the destination exactly as today: the run's page is unaffected, and
    the destination holds a complete earlier or complete new page, not a partial one (the
    writer is the stdlib-only `_mirror_write.write_page`, moved unchanged). The parent's wait
    behavior is unchanged.

    Observed with an earlier complete page already at the destination: (1) the writer fails
    (its folder is one the writer uid cannot write — as root the dropped child exits nonzero):
    the publish answers `failed`, the record lands, the destination still holds the earlier
    page and nothing else; (2) the moved writer run by path, exactly as the renderer spawns it,
    is killed after reading part of a new page: the destination holds the earlier page and no
    stage file; (3) the same writer given the whole page replaces it with the complete new one.
    Each equal to the base's golden. A child that hangs is not driven (no seam spawns a
    different child; see the report's probe request), so the parent's wait is not asserted."""
    writer = _writer_path()
    run_dir = driven_run(tmp_path)
    run = Run.at(run_dir)
    record = RunPaths(run_dir).runtime_html
    earlier = b"<html>EARLIER COMPLETE PAGE</html>"
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    caplog.set_level(logging.DEBUG)
    observed: dict[str, Any] = {}
    with _writer_tree() as (_base, checkout, uid, gid):
        _lane_precondition(uid, gid)
        mirror = _owned_dir(checkout / MIRROR_NAME, uid, gid)
        folder = _owned_dir(mirror / run_dir.name, uid, gid)
        dest = folder / PAGE_NAME
        dest.write_bytes(earlier)
        if os.geteuid() == 0:
            os.chown(dest, uid, gid)
        os.chmod(folder, 0o555)
        monkeypatch.setenv(MIRROR_ENV, str(mirror))
        caplog.clear()
        word = _publish(run)
        observed["nonzero"] = {"publish": word, "record": record.is_file(),
                               "dest_is_earlier": dest.read_bytes() == earlier,
                               "strays": _strays(folder)}
        os.chmod(folder, 0o755)

        new_page = record.read_bytes()
        killed = subprocess.Popen(  # noqa: S603 — the renderer's own argv, as the writer
            [sys.executable, "-I", str(writer), str(dest)], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd="/", **_as_writer(uid, gid))
        assert killed.stdin is not None
        killed.stdin.write(new_page[: len(new_page) // 2])
        killed.stdin.flush()
        killed.send_signal(signal.SIGKILL)
        rc = killed.wait(timeout=60)
        killed.stdin.close()
        observed["killed"] = {"returncode": rc, "dest_is_earlier": dest.read_bytes() == earlier,
                              "strays": _strays(folder)}

        done = subprocess.run(  # noqa: S603 — the renderer's own argv, as the writer
            [sys.executable, "-I", str(writer), str(dest)], input=new_page, capture_output=True,
            check=False, cwd="/", **_as_writer(uid, gid))
        observed["completed"] = {"returncode": done.returncode,
                                 "dest_is_new": dest.read_bytes() == new_page,
                                 "strays": _strays(folder)}
    _assert_golden("s067", observed)


def test_run_page_published_a_second_time_over_an_existing_page(tmp_path, monkeypatch, caplog):
    """Publishing the page of a finished run a second time leaves the freshest page on disk and
    one mirror copy per run id: the copy is replaced, not duplicated and not left stale, exactly
    as a republish behaves today. (O5: the run page and its mirror.)

    Observed through the moved `publish_page` under `dev`, twice over one run, with the run's
    work log changed in between (so the second page differs from the first): both publishes
    answer `copied`; the mirror then holds exactly one entry for the run id with exactly one
    file, the page, and that copy is the second record byte for byte (it carries the change, the
    first page did not) — equal to the base's golden."""
    run_dir = _seed_work_files(driven_run(tmp_path))
    run = Run.at(run_dir)
    record = RunPaths(run_dir).runtime_html
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    caplog.set_level(logging.DEBUG)
    change = "\n\nREPUBLISH-1080-FRESHER\n"
    with _writer_tree() as (_base, checkout, uid, gid):
        _lane_precondition(uid, gid)
        mirror = checkout / MIRROR_NAME
        monkeypatch.setenv(MIRROR_ENV, str(mirror))
        first = _publish(run)
        first_page = record.read_bytes()
        investigation = RunPaths(run_dir).investigation
        investigation.write_text(investigation.read_text(encoding="utf-8") + change,
                                 encoding="utf-8")
        second = _publish(run)
        copy = mirror / run_dir.name / PAGE_NAME
        observed = {
            "publish": [first, second],
            "mirror_holds_only_this_run": sorted(os.listdir(mirror)) == [run_dir.name],
            "run_folder_listing": sorted(os.listdir(copy.parent)),
            "copy_is_the_second_record": copy.read_bytes() == record.read_bytes(),
            "second_differs_from_first": record.read_bytes() != first_page,
            "copy_carries_the_change": "REPUBLISH-1080-FRESHER" in copy.read_text(encoding="utf-8"),
        }
    _assert_golden("s207", observed)


# ======================================================================================
# s176 / s177 — the publisher's inputs
# ======================================================================================


def _form(name: str, source: Path, case: Path, monkeypatch) -> Path:
    """The run-dir form `name` built under `case` from a copy of the driven run `source`; the
    path to hand `Run.at`."""
    case.mkdir(parents=True)
    run = case / "run"
    if name == "empty":
        run.mkdir()
        return run
    if name == "regular-file":
        run.write_bytes(b"not a run dir\n")
        return run
    if name == "space-and-non-ascii-name":
        run = case / "rün with space ✓"
    shutil.copytree(source, run, symlinks=True)
    paths = RunPaths(run)
    if name == "no-report":
        paths.report.unlink()
    elif name == "no-investigation":
        paths.investigation.unlink()
    elif name == "died-before-its-session-store":
        paths.session_pointer.unlink()
    elif name == "relative":
        monkeypatch.chdir(case)
        return Path("run")
    elif name == "symlinked":
        link = case / "link"
        link.symlink_to(run, target_is_directory=True)
        return link
    return run


S176_FORMS = ("finished", "no-report", "no-investigation", "died-before-its-session-store",
              "empty", "relative", "symlinked", "space-and-non-ascii-name", "regular-file")


def _observe_forms(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    publisher = _publisher()
    source = _seed_work_files(driven_run(tmp_path / "source"))
    out = {}
    for name in S176_FORMS:
        case = tmp_path / "forms" / name
        given = _form(name, source, case, monkeypatch)

        def publish(given: Path = given) -> str:
            return publisher(Run.at(given))

        got = S.outcome(publish)
        real = (case / given).resolve() if not given.is_absolute() else given.resolve()
        record = real / PAGE_NAME if real.is_dir() else None
        page = _page_text(record) if record is not None and record.is_file() else None
        out[name] = _scrub({
            "outcome": got,
            "record": page is not None,
            "page": _digest(_normalize_page(
                page, *sorted({p for p in (given, real, source) if p.is_absolute()}, key=str)))
            if page is not None else None,
        }, {str(case): "<CASE>", str(source): "<SOURCE>"})
        monkeypatch.chdir(tmp_path)
    return out


def test_run_dir_forms_given_to_the_page_publisher(tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A run dir with no report, investigation file or session
    store, an empty one, a relative or symlinked one, one with a space or non-ASCII name, or a
    regular file is published, degraded or refused exactly as today, including the run that died
    before creating its session store.

    Observed per form (each a copy of one driven run, changed as named) through the moved
    `publish_page(Run.at(<form>))`: what it answers or raises (class and message), whether the
    record exists, and the normalised page's digest — equal to the base's golden."""
    _assert_golden("s176", _observe_forms(tmp_path, monkeypatch))


#: Hostile text whose rendered page is frozen whole (`goldens/runpage/hostile_fields_page.html`).
HOSTILE = {
    "markup": "<b onmouseover=alert(1)>HOSTILE-MARKUP</b>",
    "script-close": "</script><script>alert('HOSTILE-SCRIPT')</script>",
    "attribute-quote": "\" onerror=\"alert(1)\" data-x='HOSTILE-QUOTE'",
    "already-escaped": "&lt;b&gt;HOSTILE-ESCAPED&amp;amp;&lt;/b&gt;",
}
#: Hostile control characters, rendered in a page of their own and frozen by digest, so no
#: committed golden file carries a NUL or a bidi override.
HOSTILE_CONTROL = {
    "nul": "HOSTILE-NUL\x00after",
    "rtl-override": "HOSTILE-RTL\u202eevil",
}
#: The marker each hostile string carries, counted in the page to show it was rendered.
HOSTILE_MARKER = {"markup": "HOSTILE-MARKUP", "script-close": "HOSTILE-SCRIPT",
                  "attribute-quote": "HOSTILE-QUOTE", "nul": "HOSTILE-NUL",
                  "rtl-override": "HOSTILE-RTL", "already-escaped": "HOSTILE-ESCAPED"}
LONE_SURROGATE = "HOSTILE-SURROGATE\ud800after"
TEN_MEGABYTES = "<HOSTILE-TEN-MB " + "A" * 10_000_000 + " >"


def _plant(run_dir: Path, texts: list[str], *, raw: bytes | None = None) -> None:
    """Append each text as its own paragraph to the run's report body and work log (`raw`:
    append these bytes instead, for text no codec writes)."""
    paths = RunPaths(run_dir)
    for target in (paths.report, paths.investigation):
        with target.open("ab") as fh:
            if raw is not None:
                fh.write(b"\n\n" + raw + b"\n")
            for t in texts:
                fh.write(("\n\n" + t + "\n").encode("utf-8"))


def _render_case(source: Path, case: Path, texts: list[str], *, raw: bytes | None = None
                 ) -> tuple[dict[str, Any], str | None]:
    run = case / "run"
    shutil.copytree(source, run, symlinks=True)
    _plant(run, texts, raw=raw)
    got = S.outcome(_publisher(), Run.at(run))
    record = RunPaths(run).runtime_html
    page = _page_text(record) if record.is_file() else None
    # The copy's transcript still names the run it was copied from: both paths are scrubbed.
    normalized = _normalize_page(page, run, source) if page is not None else None
    return _scrub({"outcome": got, "record": page is not None}, {str(run): "<RUN_DIR>"}), normalized


def _observe_hostile(tmp_path: Path) -> tuple[dict[str, Any], str]:
    esc_untrusted = S.moved("esc_untrusted", home=S.REPORTS)
    out: dict[str, Any] = {"esc_untrusted": {}}
    for key, text in {**HOSTILE, **HOSTILE_CONTROL, "lone-surrogate": LONE_SURROGATE}.items():
        out["esc_untrusted"][key] = esc_untrusted(text)
    out["esc_untrusted"]["ten-megabytes"] = _digest(esc_untrusted(TEN_MEGABYTES))

    source = _seed_work_files(driven_run(tmp_path / "source"))
    combined, page = _render_case(source, tmp_path / "combined", list(HOSTILE.values()))
    assert page is not None, f"the hostile page did not render: {combined}"
    combined["raw_in_page"] = {k: v in page for k, v in HOSTILE.items()}
    combined["rendered_markers"] = {k: page.count(HOSTILE_MARKER[k]) for k in HOSTILE}
    out["combined"] = combined

    control, cpage = _render_case(source, tmp_path / "control-chars", list(HOSTILE_CONTROL.values()))
    assert cpage is not None, f"the control-character page did not render: {control}"
    control["raw_in_page"] = {k: v in cpage for k, v in HOSTILE_CONTROL.items()}
    control["rendered_markers"] = {k: cpage.count(HOSTILE_MARKER[k]) for k in HOSTILE_CONTROL}
    control["page"] = _digest(cpage)
    out["control-characters"] = control

    surrogate, spage = _render_case(source, tmp_path / "surrogate", [],
                                    raw=LONE_SURROGATE.encode("utf-8", "surrogatepass"))
    surrogate["page"] = _digest(spage) if spage is not None else None
    out["lone-surrogate-bytes"] = surrogate

    big, bpage = _render_case(source, tmp_path / "big", [TEN_MEGABYTES])
    big["page"] = _digest(bpage) if bpage is not None else None
    out["ten-megabytes"] = big
    return out, page


def test_untrusted_text_in_rendered_report_fields(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Report or investigation fields with markup, a closing
    script tag, an attribute-breaking quote, NUL, lone surrogates, RTL override, a ten-megabyte
    string or already-escaped text are escaped exactly as today: no new injection, no
    double-escaping change.

    Observed: the moved `esc_untrusted` over each string (the ten-megabyte one by digest); and
    the moved publisher over a driven run whose report body and work log carry the strings —
    the whole normalised page (golden file `goldens/runpage/hostile_fields_page.html`), whether
    each raw string survives into it, and how often each one's marker is rendered; the NUL and
    bidi-override strings likewise in a page of their own, frozen by digest; a work log holding
    a lone surrogate's bytes, and one holding the ten-megabyte string, by outcome and page
    digest. Each equal to the base's golden."""
    observed, page = _observe_hostile(tmp_path)
    _assert_golden_page(S177_PAGE, page)
    _assert_golden("s177", observed)


# ======================================================================================
# s037 — every fail-open lazy site pinned by its real output
# ======================================================================================


# PRE-CUT 2026-10-04 (scope cut): deleted from the live suite; owner #1105.
def _site_run_page(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    run_dir = driven_run(tmp_path / "site-run")
    run = tenant_run(run_dir)
    record = RunPaths(run_dir).runtime_html

    def observe() -> dict[str, Any]:
        record.unlink(missing_ok=True)
        try:
            run_common.visualize(run)
            raised = None
        except Exception as e:  # noqa: BLE001 — the failed render IS the observed outcome
            raised = type(e).__name__
        page = record.read_text(encoding="utf-8") if record.is_file() else ""
        styled = re.search(r"<style>\s*\S", page) is not None
        scripted = re.search(r"<script>\s*\S", page) is not None
        return {"real": MARKER in page and styled and scripted, "raised": raised}

    return observe


# PRE-CUT 2026-10-04 (scope cut): deleted from the live suite; owner #1105.
def _site_workspace_map(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    from defender.runtime import orient

    run_dir = tmp_path / "site-orient" / "run"
    run_dir.mkdir(parents=True)
    alert = run_dir / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": "rule-1080"}}), encoding="utf-8")

    def observe() -> dict[str, Any]:
        out = orient.orientation(run_dir, S.DEFENDER, alert, systems=(),
                                 shim=lambda argv, env: None)
        roots = [f"- DEFENDER_DIR: `{S.DEFENDER}`", f"- REPO_ROOT: `{S.REPO_ROOT}`",
                 f"- RUN_DIR: `{run_dir}`"]
        return {"real": "## Workspace\n# Workspace map\n" in out and all(r in out for r in roots),
                "fallback": "## Workspace\n_(unavailable:" in out}

    return observe


def _lesson_fixture(tmp_path: Path):
    from defender.tests._lessons_corpus import _main_deps, _write_lesson

    tmp_path.mkdir(parents=True, exist_ok=True)
    deps, _run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir(parents=True, exist_ok=True)
    _write_lesson(corpus, "lazy-site-1080-lesson", nodes=("type: compute, slot: class",))
    doc = ("```invlang\n"
           ":V prologue.vertices [id|type|class|ident|attrs?]\n"
           "v-001|compute|??|x|\n"
           "```\n")
    return deps, doc


def _site_lessons_push(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    from defender.runtime import lessons_push

    deps, doc = _lesson_fixture(tmp_path / "site-push")

    def observe() -> dict[str, Any]:
        text, after = lessons_push.compose_fold(deps, "ROW-1080", doc)
        return {"real": text.startswith("ROW-1080\n\n") and "lazy-site-1080-lesson" in text
                and after is not None,
                "fallback": text == "ROW-1080" and after is None}

    return observe


def _site_document_tool(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    from defender.runtime.tools import _frontier_recall

    deps, doc = _lesson_fixture(tmp_path / "site-document")

    def observe() -> dict[str, Any]:
        block = _frontier_recall(deps, "", doc)
        return {"real": "lazy-site-1080-lesson" in block, "fallback": block == ""}

    return observe


# PRE-CUT 2026-10-04 (scope cut): deleted from the live suite; owner #1105.
def _site_episode_page(tmp_path: Path, caplog) -> Callable[[], dict[str, Any]]:
    from defender.learning.branch import cli
    from defender.tests import _episode_1025 as E

    ep = E.sample_episode(tmp_path / "site-episode")
    page = ep.dir / E.PAGE_NAME

    def observe() -> dict[str, Any]:
        page.unlink(missing_ok=True)
        caplog.clear()
        cli._render_page(ep.dir, episode_id="e-1080")
        text = page.read_text(encoding="utf-8") if page.is_file() else ""
        return {"real": E.BASE_STORY in text and "<style>" in text,
                "fallback": any("could not be rendered" in r.getMessage()
                                for r in _warnings(caplog))}

    return observe


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s037); the cut cells are owned by #1105 (the run page, workspace map and episode page sites).
def test_lazy_import_repointed_to_a_path_that_does_not_exist(tmp_path, monkeypatch, caplog):
    """Each fail-open site (run page at run end, workspace map in message zero, frontier block
    in the lessons pushes, episode page) is pinned by a test that observes the real output, not
    the absence of an error: the page file with content, the map's root lines (not the fallback
    text), the frontier block in the push, the episode page. A lazy import repointed to a
    missing module or a missing name therefore turns a test red even though the census is
    clean, every module-level import resolves and the run exits 0.

    Observed at each of the five sites through its own entry point (the run end's
    `run_common.visualize`, `orientation` through its shim seam, `compose_fold`, the document tool's
    `_frontier_recall`, the launcher's `_render_page`): with the moved module importable, the
    REAL output is there — the page with its style, script and final turn; the map's
    `# Workspace map` and its three root lines; the push and the recall carrying the planted
    lesson; the episode page with the episode's story. Then the moved module each site lazily
    imports is made unimportable (what a stale repoint gives): every site still fails open — no
    exception reaches the caller but the run page's `VisualizeFailed` — and the real-output
    check is FALSE at every one, so these assertions are the ones a stale lazy import turns
    red."""
    caplog.set_level(logging.DEBUG)
    sites = {
        "run_page": (_site_run_page(tmp_path), ("publish_page", S.REPORTS)),
        "workspace_map": (_site_workspace_map(tmp_path), ("workspace_map", None)),
        "lessons_push": (_site_lessons_push(tmp_path), ("FOLD_LEAD", None)),
        "document_tool": (_site_document_tool(tmp_path), ("WRITE_RETURN_LEAD", None)),
        "episode_page": (_site_episode_page(tmp_path, caplog), ("render_episode", S.REPORTS)),
    }
    for name, (observe, _target) in sites.items():
        got = observe()
        assert got["real"], f"{name}: the real output is missing with every module in place: {got}"
        assert not got.get("fallback"), f"{name}: the fallback showed with the module in place"

    for name, (observe, (symbol, home)) in sites.items():
        with monkeypatch.context() as m:
            _make_unimportable(m, S.dotted(S.home_of(symbol, home=home)))
            got = observe()
        assert not got["real"], (
            f"{name}: the real-output check still passes with the lazily imported module gone, "
            f"so it cannot catch a stale repoint: {got}")
        if name == "run_page":
            assert got["raised"] == "VisualizeFailed", got
        else:
            assert got["fallback"], f"{name}: the site did not fail open as today: {got}"


# ======================================================================================
# s066 / s045 — a fault planted in a shadow copy of the renderer's folder
# ======================================================================================

#: Run from a shadow: optionally import the frontend build, then the run end over argv[1] (and,
#: with an episode dir in argv[2], the launcher's episode page), reporting each lane's outcome.
_LANES_CHILD = r'''
import importlib, json, logging, sys
from pathlib import Path
seen = []
class _Rec(logging.Handler):
    def emit(self, r):
        seen.append([r.levelname, r.getMessage()])
logging.getLogger().addHandler(_Rec())
logging.getLogger().setLevel(logging.DEBUG)
run_dir, episode, asset, renderer = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
out = {}
def caught(e):
    c = e.__cause__
    return {"raises": type(e).__name__, "message": str(e).replace(str(run_dir), "<RUN_DIR>"),
            "cause": type(c).__name__ if c is not None else None,
            "names_asset": bool(asset) and (asset in str(e) or (c is not None and asset in str(c)))}
if episode:
    try:
        importlib.import_module("defender.learning.frontend.build")
        out["frontend_build"] = "imports"
    except Exception as e:
        out["frontend_build"] = caught(e)
        out["frontend_build"].pop("message")  # names the asset by its own (moved) path
from defender import run_common
from defender._run_handle import Run
out["run_common_file"] = str(Path(run_common.__file__).resolve())
try:
    run_common.visualize(Run.at(run_dir))
    out["run_end"] = {"raises": None}
except Exception as e:
    out["run_end"] = caught(e)
out["run_end"]["record"] = (run_dir / "runtime.html").is_file()
if episode:
    from defender.learning.branch import cli
    seen.clear()
    cli._render_page(Path(episode), episode_id="e-1080")
    out["episode"] = {"page": (Path(episode) / "learning.html").is_file(),
                      "warnings": sum(1 for lvl, _m in seen if lvl == "WARNING")}
try:
    vr = importlib.import_module(renderer)
    out["mirror_writer"] = str(vr._MIRROR_WRITER)
except Exception as e:
    out["mirror_writer"] = None
out["warnings"] = [m.replace(str(run_dir), "<RUN_DIR>") for lvl, m in seen if lvl == "WARNING"]
print(json.dumps(out))
'''


def _lanes_from(shadow: Path, run_dir: Path, *, episode: Path | None = None, asset: str = "",
                **env: str) -> dict[str, Any]:
    child = S.python("-c", _LANES_CHILD, str(run_dir), str(episode or ""), asset,
                     _renderer_dotted(), cwd=shadow, env=_shadow_env(shadow, **env))
    assert child.returncode == 0, child.stderr.decode(errors="replace")[-3000:]
    out = json.loads(child.stdout.decode().strip().splitlines()[-1])
    imported_from = Path(out.pop("run_common_file"))
    assert imported_from.is_relative_to(shadow), (
        f"precondition: the child ran this tree's code ({imported_from}), not the shadow's")
    return out


def _shadow_file(shadow: Path, name: str) -> Path:
    """The one file called `name` in the shadow's copied renderer folder."""
    from defender.tests.scripts_1080_split.test_1080_run_page import _renderer_folder

    hits = sorted((shadow / _renderer_folder()).rglob(name))
    assert len(hits) == 1, f"expected one {name} in the renderer's folder, found {hits}"
    return hits[0]


def test_mirror_writer_file_is_absent_or_not_readable_at_the_path_the_renderer_points_to(
        tmp_path, monkeypatch):
    """The mirror writer's path is computed from where `_mirror_write.py` lives (it follows the
    module), so after the move it is found beside the module that spawns it; a test pins that
    the mirror copy appears. When the file is absent, unreadable or a directory, the outcome
    (and whether it is distinguishable from a failed page write) is as today; the doc adds no
    new signal.

    Observed by running the run end from a shadow copy of the renderer's folder (a child, `dev`,
    the override on a folder in tmp): untouched, the renderer's `_MIRROR_WRITER` is the shadow's
    own writer beside it and the copy lands; with the writer file removed, or replaced by a
    folder, the outcome of the run end — what it raises, whether the record exists, whether a
    copy landed — equals the base's golden. As root, with the writer unreadable, both lanes are
    observed too: in-process (root reads it anyway) and the dropped child (which cannot); a
    non-root run cannot build the drop lane, so that row is asserted only as root."""
    run_dir = driven_run(tmp_path / "run-base")
    record = RunPaths(run_dir).runtime_html
    observed: dict[str, Any] = {}

    def run_end(shadow: Path, mirror: Path) -> dict[str, Any]:
        record.unlink(missing_ok=True)
        got = _lanes_from(shadow, run_dir, **{DEPLOYMENT_ENV: "dev", MIRROR_ENV: str(mirror)})
        landed = mirror / run_dir.name / PAGE_NAME
        got["copy_landed"] = landed.is_file() and landed.read_bytes() == (
            record.read_bytes() if record.is_file() else b"")
        writer = got.pop("mirror_writer")
        got["warnings"] = len(got["warnings"])
        got["mirror_writer_is_the_shadows_own"] = (
            None if writer is None else Path(writer) == (shadow / S.rel(_writer_path())).resolve())
        return _scrub(got, {str(tmp_path): "<TMP>"})

    shadow = _shadow_checkout(tmp_path / "control")
    observed["untouched"] = run_end(shadow, tmp_path / "mirror-control")
    for fault in ("absent", "directory"):
        shadow = _shadow_checkout(tmp_path / fault)
        writer = _shadow_file(shadow, _writer_path().name)
        writer.unlink()
        if fault == "directory":
            writer.mkdir()
        observed[fault] = run_end(shadow, tmp_path / f"mirror-{fault}")
    _assert_golden("s066", observed)

    if os.geteuid() != 0:
        return
    rows = {}
    shadow = Path(tempfile.mkdtemp(prefix="spec1080-s066-", dir="/tmp"))
    try:
        os.chmod(shadow, 0o755)
        _shadow_checkout(shadow / "tree")
        writer = _shadow_file(shadow / "tree", _writer_path().name)
        os.chmod(writer, 0)
        rows["in_process"] = run_end(shadow / "tree", tmp_path / "mirror-unreadable")
        with _writer_tree() as (_base, checkout, uid, gid):
            _lane_precondition(uid, gid)
            rows["dropped_child"] = run_end(shadow / "tree", checkout / MIRROR_NAME)
    finally:
        shutil.rmtree(shadow, ignore_errors=True)
    _assert_golden("s066_unreadable_as_root", rows)


S045_ASSETS = ("styles.css", "runtime.js", "episode.css")


def test_each_of_the_three_renderer_asset_files_is_missing_in_turn(tmp_path):
    """Each asset (styles.css, runtime.js, episode.css) travels with its reader, so on a correct
    move nothing is missing. A missing asset is felt at the same point and with the same
    handling as today, because assets are read when the page modules are imported: the learning
    frontend build (module-level import) fails at import; the run end converts it to
    VisualizeFailed without changing the run's exit status; the episode lane logs a warning and
    writes no page. Settled as preserved behavior; the page tests pin that the page renders with
    its style and script.

    Observed from a shadow copy of the renderer's folder (a child per case): with every asset in
    place, the frontend build imports, the run end writes the record and the episode lane writes
    its page; with each asset removed in turn from the copy, what the frontend build's import
    raises, what the run end raises (the moved `VisualizeFailed` with its cause, naming the
    file) and whether it wrote a record, and whether the episode lane warned and wrote its page —
    each equal to the base's golden. Each asset is one file in the renderer's folder."""
    from defender.tests import _episode_1025 as E

    run_dir = driven_run(tmp_path / "run-base")
    record = RunPaths(run_dir).runtime_html
    episode = E.sample_episode(tmp_path / "episode-base").dir
    observed = {}
    for case in ("control", *S045_ASSETS):
        shadow = _shadow_checkout(tmp_path / f"shadow-{case}")
        if case != "control":
            _shadow_file(shadow, case).unlink()
        ep = tmp_path / f"episode-{case}"
        shutil.copytree(episode, ep, symlinks=True)
        (ep / E.PAGE_NAME).unlink(missing_ok=True)
        record.unlink(missing_ok=True)
        got = _lanes_from(shadow, run_dir, episode=ep, asset="" if case == "control" else case)
        got.pop("mirror_writer")
        got.pop("warnings")
        observed[case] = got
    _assert_golden("s045", observed)
