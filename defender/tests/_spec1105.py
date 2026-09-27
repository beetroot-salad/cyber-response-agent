"""Shared machinery for #1105's executable spec — NOT a test module (the leading underscore keeps
pytest from collecting it). Imported by the `test_1105_*.py` files, which live directly under
`defender/tests/` because `spec-graph binds` scans that directory non-recursively.

Every `form: test` demand of `spec-flow/specs/spec_graph_1105.yaml` is exactly one test in those
files, named by the demand's `discharged_by`; the test's docstring carries the demand's prose.

RED AGAINST ed5386bc IS THE EXPECTED STATE. `defender/run_service/`, `defender/host_env.py` and
`scripts/lint/lint_run_layout_imports.py` do not exist there, and `run_common.py` /
`runtime/branch/` still do. So every reference to a module that is BORN or DIES in #1105 is LAZY
— `svc()`, `sym()`, `host_env()`, `lint()` reach it inside the test that needs it — and every
module still COLLECTS both at the base commit and after the move; a missing target is one failing
test, never a collection error that hides the rest.

THE FAULT-INJECTION HIERARCHY, applied (phases/author.md):

  tier 1 — REAL input through the REAL primitive, in the test itself. A bad tenant record is
  written, linked, hard-linked, replaced by a directory; an unreadable file or unsearchable base
  is made with `chmod` and read by a reader that cannot bypass the mode bits (`unprivileged`,
  below); a vanished run is `rmtree`d; a symlink loop is planted; a moved visualize script is a
  real deleted file in a real copy of the tree; an interpreter that cannot be spawned is a real
  deleted interpreter path.

  tier 2 — a fake whose fault CONTENT cites the ledger claim that observed it. One is used:
  `EioOnRecord` answers the tenant record's read with the `(None, "<EIO strerror>")` pair the
  real `_io.read_guarded` returns when the read fails with EIO — dep-PO14 / author-P1 (executed
  at ed5386bc, EIO injected at `os.open`) observed exactly that fold. It enters through an `io=`
  keyword on `open_run`, which the design does not name: that seam is recorded as a coinage in
  80-author-digest.md rather than reached around.

  tier 3 — an author-imagined fault is banned; none is used.

No `monkeypatch.setattr` anywhere: fakes enter through `run.main`'s own seams (`lifecycle=`,
`visualize=`, `enqueue=`, `preflight=`, `materialize=`), the launcher's (`spawn=`, `door=`,
`questioner=`, `adapters=`, `invoke=`, `preflight=`, `live_tree=`), `_run_investigation_lifecycle`'s
(`start_box=`, `stop_box=`, `scrub=`, `investigate=`) and `_drive_investigation`'s `investigate=`.
`monkeypatch.setenv` is used for the two configured roots; it is outside the ratcheted gate.

THE GRAPH'S COINAGES are routed through ONE helper each, so reconciliation touches one line:
  * `source_runs_base` — the manifest field J5 grows (AM-1): `SOURCE_RUNS_BASE_FIELD`.
  * the merged source-alert screen's function name (F11) is NOT pinned: the screen is reached
    through its two doors (`run.py --resume` and the launcher), and its `RunServiceError` is
    read off the door's exception chain (`chain_types`).
  * `bound_runs`' listing (`absent`, `reason`, iteration of `(run_id, Bound)`): `walk`.
  * the new lint's entry point `scan(root)` over a planted tree, with `.display` findings, in
    the shape `lint_run_records.scan(root)` already has: `lint_findings`.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import errno
import importlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

from defender.tests._by_path import DEFENDER, LINT_DIR, WORKTREE, load_lint_gate

# --------------------------------------------------------------------------------------
# the per-test import — every module #1105 creates or deletes is reached HERE, lazily
# --------------------------------------------------------------------------------------

SERVICE = "defender.run_service"
HOST_ENV = "defender.host_env"
LINT_STEM = "lint_run_layout_imports"


def svc():
    """`defender.run_service` — the package #1105 creates (D1)."""
    return importlib.import_module(SERVICE)


def sym(name: str) -> Any:
    """One name off the service's PUBLIC surface: `from defender.run_service import <name>`."""
    return getattr(svc(), name)


def host_env():
    """`defender.host_env` — the five names D7 moves out of `run_common`."""
    return importlib.import_module(HOST_ENV)


def mod(dotted: str):
    """`defender.<dotted>`, imported per test."""
    return importlib.import_module(f"defender.{dotted}")


def run_py():
    """`defender/run.py` — the service's CLI, which STAYS at `defender/run.py` (D1)."""
    return importlib.import_module("defender.run")


def cli():
    """The episode tool (`learning/branch/cli.py`), which stays and keeps `LauncherRefused`."""
    return importlib.import_module("defender.learning.branch.cli")


def lint():
    """`scripts/lint/lint_run_layout_imports.py`, loaded the way CI runs it (D5)."""
    return load_lint_gate(LINT_STEM)


# --------------------------------------------------------------------------------------
# ids — each one a member the graph's `run_id` domain names
# --------------------------------------------------------------------------------------

#: A host-minted id: lower case, so `is_case_stable_id` holds and `open_run` builds
#: `Run.for_tenant` (D3 step 3).
CASE_STABLE_ID = "20260921t143000z-case-a"
#: The pre-#1077 spelling O3 names (upper-case T/Z, Y2): valid, NOT case-stable → `Run.at`.
PRE_1077_ID = "20260728T161745Z-fresh-case"
#: The fixture spelling O3 names (X3): valid, not case-stable.
FIXTURE_ID = "caseA"
#: The three names O3 says `open_run` opens.
O3_OPENS = ("caseA", "turnN-A", PRE_1077_ID)
#: Names that could never be run ids (O4.2): `is_valid_run_id` refuses each.
NEVER_IDS = ("has space", ".hidden", "_x", "héllo")

TENANT_RECORD = "_tenant.json"
DEFAULT_TENANT = "default"


def is_case_stable(run_id: str) -> bool:
    return run_id == run_id.casefold()


# --------------------------------------------------------------------------------------
# runs bases and tenant records — tier 1: the real bytes, links and directories
# --------------------------------------------------------------------------------------


def record_doc(tenant_id: Any = DEFAULT_TENANT) -> dict[str, Any]:
    """A tenant record in `_tenant.TENANT_FIELDS`' shape (`ensure_tenant` writes this shape)."""
    return {"tenant_id": tenant_id, "base_world_id": "0" * 32,
            "created_at": "2026-09-21T14:30:00+00:00"}


def write_record(base: Path, tenant_id: Any = DEFAULT_TENANT) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    path = base / TENANT_RECORD
    path.write_text(json.dumps(record_doc(tenant_id)) + "\n", encoding="utf-8")
    return path


#: Every PRESENT-BUT-BAD record shape the graph binds on `tenant_record.domain` (O3, O4.1, J4),
#: mapped to the refusal class `open_run` must raise. `TenantRecordCorrupt` subclasses
#: `ValueError` (K4), so a shape pinned `ValueError` is pinned by EXACT type.
CORRUPT, FOREIGN = "TenantRecordCorrupt", "ValueError"
BAD_RECORDS: dict[str, str] = {
    "corrupt": CORRUPT, "empty": CORRUPT, "link": CORRUPT, "hardlink": CORRUPT,
    "dangling_link": CORRUPT, "directory": CORRUPT, "other_tenant": FOREIGN,
}


def plant_bad_record(base: Path, shape: str, *, elsewhere: Path) -> Path:
    """Put a record of `shape` at `<base>/_tenant.json`. `elsewhere` is a directory OUTSIDE the
    base where a link's target lives, so the link is a real link to a real, valid record."""
    base.mkdir(parents=True, exist_ok=True)
    elsewhere.mkdir(parents=True, exist_ok=True)
    path = base / TENANT_RECORD
    if shape == "corrupt":
        path.write_text("{not json", encoding="utf-8")
    elif shape == "empty":
        path.write_text("", encoding="utf-8")
    elif shape == "link":
        target = write_record(elsewhere / "linked")
        path.symlink_to(target)
    elif shape == "hardlink":
        target = write_record(elsewhere / "hardlinked")
        os.link(target, path)
    elif shape == "dangling_link":
        path.symlink_to(elsewhere / "no-such-record.json")
    elif shape == "directory":
        path.mkdir()
    elif shape == "other_tenant":
        write_record(base, "acme")
    else:  # pragma: no cover — a shape nobody named is a test bug
        raise AssertionError(f"unknown record shape {shape!r}")
    return path


def make_run(base: Path, run_id: str, *, lessons: list[str] | None = None,
             report: str | None = None) -> Path:
    """A run directory under `base`, optionally with `lessons_loaded.jsonl` rows naming
    `lessons` (the rows `trace_lesson.in_context_cases` selects on) and a `report.md`."""
    d = base / run_id
    d.mkdir(parents=True, exist_ok=True)
    if lessons:
        (d / "lessons_loaded.jsonl").write_text(
            "".join(json.dumps({"lesson_name": n, "loaded_at": "2026-07-28T17:00:00Z",
                                "ts": "2026-07-28T17:00:00Z"}) + "\n"
                    for n in lessons), encoding="utf-8")
    if report is not None:
        (d / "report.md").write_text(report, encoding="utf-8")
    return d


def refusal(fn) -> BaseException:
    """Drive `fn` and hand back what it raised — failing the test if it returned.

    Deliberately NOT `pytest.raises(ValueError)`: a module that does not exist yet raises
    `ModuleNotFoundError`, which the caller must see as a failure, and `refusal` returns the
    exception for an exact-class assertion rather than accepting any subclass."""
    try:
        got = fn()
    except Exception as e:  # noqa: BLE001 — returned for the caller's exact-class assertion
        if isinstance(e, (ModuleNotFoundError, ImportError, AttributeError, NameError)):
            raise
        return e
    raise AssertionError(f"expected a refusal, got {got!r}")


def type_name(e: BaseException) -> str:
    return type(e).__name__


def chain_types(e: BaseException | None) -> list[str]:
    """The class names on `e`'s cause/context chain, outermost first — how a door's
    translation (`LauncherRefused`, `SystemExit`) is seen to have come FROM a service refusal."""
    out: list[str] = []
    seen: set[int] = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        out.append(type(e).__name__)
        e = e.__cause__ or e.__context__
    return out


# --------------------------------------------------------------------------------------
# the non-root reader — root ignores mode bits, so a mode-000 file is only a fault for a reader
# that cannot bypass them. Measured on this box (80-author-digest.md): dropping CAP_DAC_OVERRIDE
# and CAP_DAC_READ_SEARCH from the bounding set with `setpriv` makes uid 0 obey the owner bits,
# and the tmp tree (root-owned, 0700 parents) stays reachable — uid 65534 could not reach it.
# CI's runner is non-root, where the same child runs with nothing dropped.
# --------------------------------------------------------------------------------------

_DROP = "-dac_override,-dac_read_search"


def _pythonpath(first: Path) -> str:
    """`first` ahead of whatever `PYTHONPATH` this process was given — a worktree run passes
    `PYTHONPATH=<worktree>` so the child imports the tree under test, never the main checkout."""
    inherited = os.environ.get("PYTHONPATH")
    return os.pathsep.join([str(first), *([inherited] if inherited else [])])


def unprivileged(code: str, *, cwd: Path, env: dict[str, str] | None = None) -> Any:
    """Run `code` in a fresh interpreter whose reader obeys mode bits, and return the JSON
    value its LAST stdout line prints. `cwd` is the test's own tmp dir, never a checkout, so a
    `sys.path[0]` of the cwd cannot shadow the tree under test."""
    argv = [sys.executable, "-c", textwrap.dedent(code)]
    if os.geteuid() == 0:
        setpriv = shutil.which("setpriv")
        assert setpriv, "a root test run needs setpriv to drop the DAC capabilities"
        argv = [setpriv, "--bounding-set", _DROP, *argv]
    child_env = {**os.environ, "PYTHONPATH": _pythonpath(WORKTREE),
                 "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
    proc = subprocess.run(argv, cwd=cwd, env=child_env, capture_output=True, text=True,
                          encoding="utf-8", check=False, timeout=180)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert proc.returncode == 0, f'the unprivileged probe failed (rc {proc.returncode}):\n{proc.stdout}\n{proc.stderr}'
    assert lines, f'the unprivileged probe failed (rc {proc.returncode}):\n{proc.stdout}\n{proc.stderr}'
    return json.loads(lines[-1])


@contextlib.contextmanager
def restoring_modes(*paths: Path):
    """Hand the tree back to pytest's cleanup readable, whatever the test did to its modes."""
    try:
        yield
    finally:
        for p in paths:
            with contextlib.suppress(OSError):
                p.chmod(0o755 if p.is_dir() else 0o644)


def fresh_interpreter(code: str, *, cwd: Path, env: dict[str, str] | None = None,
                      python: str | None = None, pythonpath: Path | None = None,
                      argv: list[str] | None = None) -> subprocess.CompletedProcess:
    """`code` (or `argv`) in a FRESH interpreter — the only honest observer of what an import
    loads (`sys.modules`) and of a process's exit status and streams."""
    child_env = {**os.environ, "PYTHONPATH": _pythonpath(pythonpath or WORKTREE),
                 "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
    cmd = argv if argv is not None else [python or sys.executable, "-c", textwrap.dedent(code)]
    return subprocess.run(cmd, cwd=cwd, env=child_env, capture_output=True, text=True,
                          encoding="utf-8", check=False, timeout=300)


def last_json(proc: subprocess.CompletedProcess) -> Any:
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert proc.returncode == 0, f'child failed (rc {proc.returncode}):\n{proc.stdout}\n{proc.stderr}'
    assert lines, f'child failed (rc {proc.returncode}):\n{proc.stdout}\n{proc.stderr}'
    return json.loads(lines[-1])


# --------------------------------------------------------------------------------------
# tier 2 — the one fake: EIO at the tenant record's read (dep-PO14 / author-P1)
# --------------------------------------------------------------------------------------

#: What the REAL `_io.read_guarded` returns when the read of a present file fails with EIO —
#: it catches the `OSError` and hands back `(None, str(e))`. dep-PO14 (executed at ed5386bc,
#: EIO injected at `os.open` for the one path) observed this fold and the
#: `TenantRecordCorrupt('… could not be read: …')` `read_tenant` raises over it.
EIO_REASON = str(OSError(errno.EIO, os.strerror(errno.EIO)))


class EioOnRecord:
    """The real `_io` module, except that the tenant record's read fails with EIO.

    INJECTS ONLY: it never decides what a failed read means — `read_tenant` / `open_run` do.
    RECORDS what it was asked, so a test sees the record read was actually attempted."""

    def __init__(self) -> None:
        from defender import _io

        self._io = _io
        self.asked: list[Path] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._io, name)

    def read_guarded(self, path: Path, *args: Any, **kw: Any):
        self.asked.append(Path(path))
        if Path(path).name == TENANT_RECORD:
            return None, EIO_REASON
        return self._io.read_guarded(path, *args, **kw)


# --------------------------------------------------------------------------------------
# bound_runs — J8's listing, read one way everywhere
# --------------------------------------------------------------------------------------


def walk(runs_base: Path) -> tuple[Any, list[tuple[str, Any]]]:
    """`bound_runs(runs_base)` used as J8 fixes it: a context manager whose listing carries
    `absent`/`reason` and yields `(run_id, Bound)` pairs while the block is open. Returns the
    listing and the pairs (the Bounds are CLOSED once this returns — see J8's own test)."""
    with sym("bound_runs")(runs_base) as listing:
        pairs = list(listing)
    return listing, pairs


# --------------------------------------------------------------------------------------
# the lint — D5, driven over a planted tree the way `lint_run_records.scan(root)` is
# --------------------------------------------------------------------------------------

#: A module outside every category (no category could plausibly list it).
OUTSIDER = "learning/ops/zz_1105_outsider.py"
#: The gated names D5 fixes, and the helper names it admits (F6).
GATED = ("RunLayout", "WireLogNames", "resolve_run_bundle")
ADMITTED = ("artifact_file", "artifact_dir", "plain_file", "contained_payload", "LEAD_ID_RE")


def lint_root(tmp_path: Path, *, run_paths_extra: str = "") -> Path:
    """A `defender/`-shaped tree under `tmp_path` holding a REAL copy of `_run_paths.py` — the
    module whose exports the lint gates by default-deny — plus `run_paths_extra` appended to it.
    The lint reads the gated set off the swept tree's own owner module, so a name added here is
    an export the lint has never seen listed."""
    root = tmp_path / "defender"
    root.mkdir(parents=True, exist_ok=True)
    text = (DEFENDER / "_run_paths.py").read_text(encoding="utf-8")
    (root / "_run_paths.py").write_text(text + run_paths_extra, encoding="utf-8")
    return root


def plant(root: Path, rel: str, text: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        p.write_bytes(text)
    else:
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def lint_findings(root: Path) -> list[Any]:
    """The lint's whole sweep over `root` — the pinned entry point `scan(root)`."""
    return list(lint().scan(root))


def displays(found: list[Any]) -> str:
    return "\n".join(getattr(f, "display", str(f)) for f in found)


def flags(found: list[Any], rel: str, name: str | None = None) -> bool:
    """Is there a finding naming the file `rel` (and, when given, the gated `name`)?"""
    for f in found:
        text = getattr(f, "display", str(f))
        if rel in text and (name is None or name in text):
            return True
    return False


def category_members() -> dict[str, list[str]]:
    """`CATEGORIES` as `{category: [module rel path, ...]}`, whatever container the lint uses."""
    cats = lint().CATEGORIES
    return {str(k): [str(m) for m in v] for k, v in dict(cats).items()}


# --------------------------------------------------------------------------------------
# episodes — build on #947's harness (`_triplet_947`), never beside it
# --------------------------------------------------------------------------------------

#: J5's manifest field (AM-1: the base manifest records only `source_run_dir` and
#: `source_run_id`, and `_FAMILY_FIELDS` is closed). The name is the graph's coinage.
SOURCE_RUNS_BASE_FIELD = "source_runs_base"


def manifest_doc(src: Path, **over: Any) -> dict[str, Any]:
    """A post-#1105 family manifest for source run `src`: the launcher's derived half plus the
    source's IDENTITY — its runs base and run id (J5)."""
    from defender.tests import _triplet_947 as T

    doc = T.family_doc(source_run_dir=str(src), source_run_id=src.name)
    doc[SOURCE_RUNS_BASE_FIELD] = str(src.parent)
    doc.update(over)
    return doc


#: A manifest written BEFORE #1105 has no helper here on purpose: J5a's test spells it out as
#: data (`test_1105_episode_doors._base_shape_manifest`), because the helper route by
#: which existing fixtures gain `source_runs_base` is a default in `_triplet_947.family_doc`
#: (phase-F §7 R3), and a legacy manifest built through that helper would stop being legacy.


class Recorder:
    """A `run.main` seam that records it was reached and with what, and returns `result`."""

    def __init__(self, result: Any = None, *, then: Any = None) -> None:
        self.calls: list[tuple[tuple, dict]] = []
        self.result = result
        self.then = then

    def __call__(self, *args: Any, **kw: Any) -> Any:
        self.calls.append((args, kw))
        if self.then is not None:
            return self.then(*args, **kw)
        return self.result


def no_preflight(_model: str | None = None) -> int:
    return 0


def fake_materialize(base: Path, run_id: str = "run-1105"):
    """`run.main`'s `materialize=` seam: records the alert it was handed and makes a bare dir."""
    rec = Recorder()

    def make(alert: Path, rid: str | None, *, model: str | None = None, world: Any = None):
        rec.calls.append(((alert, rid), {"model": model, "world": world}))
        d = base / (rid or run_id)
        d.mkdir(parents=True, exist_ok=True)
        return d

    make.calls = rec.calls  # type: ignore[attr-defined]
    return make


def quiet_lifecycle(**kw: Any) -> dict[str, Any]:
    """`run.main`'s `lifecycle=` seam for a run whose investigation is not under test."""
    return {"output": "done", "requests": 0, "truncated_by": None}


# --------------------------------------------------------------------------------------
# a sibling, driven through the REAL lifecycle and the REAL driver, hermetically
# --------------------------------------------------------------------------------------


class NeverAsked:
    """A model that must not be called: a refused branch point ends the run at STORE SETUP,
    before one model turn (D6), so any call is the failure."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, messages: Any, info: Any) -> Any:
        self.calls += 1
        raise AssertionError("the model was asked a turn on a run whose branch point refused")


def drive_sibling(manifest: Path, world: str, *, main: Any = None,
                  after_materialize: Any = None, wrap_resume: Any = None
                  ) -> tuple[int, list[dict], list[dict]]:
    """`run.py --resume <manifest> --world <world>` through `run.main`, with the REAL
    materialize, the REAL `_run_investigation_lifecycle` (box seams faked — no daemon), the REAL
    `_drive_investigation` and the REAL `driver.run_investigation`; only the model and the
    review bundle are hermetic.

    Returns `(rc, summaries, drive_kwargs)`: what the driver returned, and what
    `_drive_investigation` handed the driver — including the `resume=` value run.py injects.
    `after_materialize(run_dir)` runs between materialize and the lifecycle (the window J5's
    "source moved after launch" names); `wrap_resume(opener)` may wrap the injected opener in a
    recording proxy before the driver sees it."""
    import asyncio
    import functools

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.runtime import driver
    from defender.runtime.providers import BuiltModel
    from defender.tests import _review_bundle

    run = run_py()
    model = main if main is not None else NeverAsked()
    summaries: list[dict] = []
    handed: list[dict] = []

    def the_driver(**kw: Any) -> dict[str, Any]:
        handed.append(dict(kw))
        if wrap_resume is not None and kw.get("resume") is not None:
            kw["resume"] = wrap_resume(kw["resume"])
        built = BuiltModel(FunctionModel(model), None)
        with override_allow_model_requests(False):
            return asyncio.run(driver.run_investigation(
                **kw, make_model=lambda name, effort: built,
                review_stages=_review_bundle.bundle(
                    composer=_review_bundle.composer_reply("holds"))))

    def lifecycle(**kw: Any) -> dict[str, Any]:
        if after_materialize is not None:
            after_materialize(kw["run_dir"])
        summary = run._run_investigation_lifecycle(
            **kw,
            investigate=functools.partial(run._drive_investigation, investigate=the_driver),
            start_box=lambda *a, **k: None, stop_box=lambda *a, **k: None,
            scrub=lambda *a, **k: None)
        summaries.append(summary)
        return summary

    rc = run.main(["--resume", str(manifest), "--world", world], lifecycle=lifecycle,
                  visualize=lambda p: None, preflight=no_preflight)
    return rc, summaries, handed


class Proxy:
    """A recording proxy over the service's injected opener: every attribute the driver reads
    off it is recorded, then answered by the real opener. Fakes record what they receive."""

    def __init__(self, inner: Any) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "seen", [])

    def __getattr__(self, name: str) -> Any:
        self.seen.append(name)
        return getattr(self._inner, name)


# --------------------------------------------------------------------------------------
# a source run with a session store whose clock the TEST chooses
# --------------------------------------------------------------------------------------

#: T0 for the sessions this spec seeds — every part is stamped with it, so `branch_point_time`
#: (the max over the prefix, truncated to seconds) answers exactly this.
AT = dt.datetime(2026, 7, 28, 16, 18, 45, tzinfo=dt.UTC)
AT_Z = "2026-07-28T16:18:45Z"
BRANCH_MESSAGE_ID = 59
#: Of the golden's seven fences, three are appended BEFORE message 59 and four after — so the
#: count AT the branch point (3) differs from the document's total (7). Measured at ed5386bc
#: through `cli._fence_count` (80-author-digest.md, probe e/p_seed2.py).
FENCES_AT_BRANCH, FENCES_TOTAL = 3, 7


def clocked_source(base: Path, run_id: str, *, case_id: str = "case-1105") -> Path:
    """A finished source run under `base` named `run_id`, branchable at message 59, whose
    session is stamped at `AT` — the golden investigation (7 fences) with 3 of them appended
    before the branch point. One captured call, a stamp, an alert: the shape `_triplet_947.
    runs_base` builds, with a clock the test knows."""
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        ToolCallPart,
        ToolReturnPart,
        UserPromptPart,
    )

    from defender.runtime import session_store as ss
    from defender.tests import _triplet_947 as T
    from defender.tests.e2e._replay_harness import GOLDEN, _split_at_fences

    src = base / run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    (src / "alert.json").write_text(json.dumps({"rule": {"id": "v2-cross-tier-ssh-pivot"}}),
                                    encoding="utf-8")
    golden = (GOLDEN / "investigation.md").read_text(encoding="utf-8")
    (src / "investigation.md").write_text(golden, encoding="utf-8")
    (src / "report.md").write_text(T.report_text("malicious"), encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    T.capture_call(src)
    (src / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    chunks = _split_at_fences(golden, FENCES_TOTAL)
    store = ss.open_store(case_id=case_id, runs_base=base)
    try:
        ss.write_case_pointer(src, case_id=case_id, store_path=store.path)
        sid = store.new_session(agent_id="main")
        store.append(sid, [ModelRequest(parts=[UserPromptPart(content="go", timestamp=AT)],
                                        timestamp=AT)], agent_id="main")

        def append(i: int, tool: str, args: dict) -> None:
            store.append(sid, [
                ModelResponse(parts=[ToolCallPart(tool_name=tool, args=args,
                                                  tool_call_id=f"{tool}-{i}")], timestamp=AT),
                ModelRequest(parts=[ToolReturnPart(tool_name=tool, content="ok",
                                                   tool_call_id=f"{tool}-{i}", timestamp=AT)],
                             timestamp=AT)], agent_id="main")

        for i, chunk in enumerate(chunks[:FENCES_AT_BRANCH]):
            append(i, "append_block", {"text": chunk})
        k = 0
        while BRANCH_MESSAGE_ID not in ss.path_row_ids(store, sid):
            k += 1
            append(k, "read_file", {"path": "alert.json"})
        for i, chunk in enumerate(chunks[FENCES_AT_BRANCH:], start=FENCES_AT_BRANCH):
            append(i, "append_block", {"text": chunk})
    finally:
        store.close()
    return src


def storeless_copy(src: Path, dest: Path, *, newest: int = 1785000123) -> Path:
    """`src` copied to `dest` WITHOUT its session pointer — an imported run with its evidence
    and no session — every file stamped at one moment and `report.md` at `newest`, so the
    launcher's file-time fallback for T0 has one right answer."""
    shutil.copytree(src, dest)
    (dest / "session_store_pointer.json").unlink()
    for p in dest.rglob("*"):
        os.utime(p, (newest - 1000, newest - 1000))
    os.utime(dest / "report.md", (newest, newest))
    return dest


def configure_roots(tmp_path: Path, monkeypatch: Any) -> Path:
    """The three CONFIGURED roots, inside `tmp_path`: the runs base, the episodes root (outside
    it, as `episodes_root` requires) and the learning state root (distinct from both, as
    `resolve_runs_base` requires). Returns the runs base. `setenv` only — no attribute patched."""
    runs = tmp_path / "defender-runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-root"))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learning-state"))
    return runs


def launch(tmp_path: Path, src: Path | str, **seams: Any) -> tuple[int, Path]:
    """One episode through the REAL launcher (`cli.main`) with #947's declarative fakes. `src`
    is handed over AS SPELLED (a `str` keeps a trailing slash a `Path` would drop)."""
    from defender.tests import _triplet_947 as T

    seams.setdefault("spawn", T.FakeSpawn())
    seams.setdefault("door", T.FakeDoor())
    seams.setdefault("questioner", T.FakeAgent(T.family_doc(), T.world_doc("b"),
                                               T.world_doc("c")))
    seams.setdefault("adapters", T.FakeAdapters())
    seams.setdefault("invoke", T.FakeAgent(*["same"] * 24))
    seams.setdefault("preflight", T.no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    # THE JUDGE IS NEVER THE PRODUCTION SEAM HERE: an episode that verifies reaches the grade,
    # whose default is a live model. #921's fake answers the first call with the class P9
    # executed on the real seam (`RunUnprocessable`), which the launcher's grade boundary
    # reports and survives — no scenario in this spec is about the grade.
    if "judge" not in seams:
        from defender.tests import _judge_921 as J

        seams["judge"] = J.FakeJudge(fault=T.Fault(raise_after=0))
    rc = cli().main([src if isinstance(src, str) else str(src), str(T.BRANCH_MESSAGE_ID),
                     "--continuation-prompt", "go"], **seams)
    return rc, episode_dir_of(Path(src).resolve())


def episode_dir_of(src: Path) -> Path:
    from defender.tests import _triplet_947 as T

    return cli().episode_dir_for(cli().episode_id_for(src.name, T.BRANCH_MESSAGE_ID))


def read_manifest(episode_dir: Path) -> dict[str, Any]:
    import yaml

    return yaml.safe_load((episode_dir / "family.yaml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# observing a child process's launch — no attribute of `subprocess` is replaced
# --------------------------------------------------------------------------------------


@contextlib.contextmanager
def watching_waits():
    """Record every `Popen.communicate` / `Popen.wait` call made while the block runs — in this
    thread and in threads started inside it — with the child's argv and the `timeout` it was
    given. Read through the interpreter's own profiling hook (`sys.setprofile`,
    `threading.setprofile`), so the real launch runs unmodified: a timeout the launch passes is
    OBSERVED on the real call, and the call itself is the positive control that the launch
    happened while the hook was watching."""
    import threading

    targets = {subprocess.Popen.communicate.__code__, subprocess.Popen.wait.__code__}
    seen: list[dict[str, Any]] = []

    def hook(frame, event, _arg):
        if event == "call" and frame.f_code in targets:
            proc = frame.f_locals.get("self")
            seen.append({"call": frame.f_code.co_name, "timeout": frame.f_locals.get("timeout"),
                         "argv": [str(a) for a in (getattr(proc, "args", None) or [])]})

    previous = sys.getprofile()
    sys.setprofile(hook)
    threading.setprofile(hook)
    try:
        yield seen
    finally:
        sys.setprofile(previous)
        threading.setprofile(None)  # type: ignore[arg-type]


def deletable_interpreter(tmp_path: Path) -> Path:
    """An interpreter path that can be DELETED while the process it started keeps running: a
    venv-shaped directory whose `bin/python` is a symlink to this interpreter's binary, with this
    venv's `pyvenv.cfg` and `lib` beside it so the child resolves the same site-packages. The
    child's `sys.executable` is that symlink; unlinking it makes the next `[sys.executable, …]`
    spawn fail for real (dep-PO2's "interpreter cannot be spawned")."""
    venv = tmp_path / "deletable-venv"
    (venv / "bin").mkdir(parents=True)
    prefix = Path(sys.prefix)
    if (prefix / "pyvenv.cfg").is_file():
        shutil.copy(prefix / "pyvenv.cfg", venv / "pyvenv.cfg")
        (venv / "lib").symlink_to(prefix / "lib")
    python = venv / "bin" / "python"
    python.symlink_to(os.path.realpath(sys.executable))
    return python


# --------------------------------------------------------------------------------------
# a real driven run (the run page's input), and names the design fixes by VALUE (D8)
# --------------------------------------------------------------------------------------


def driven_run(tmp_path: Path, *, text: str = "done") -> Path:
    """One real investigation driven through the replay harness with the store attached — the
    run dir a run page renders from (a session pointer naming a real store)."""
    from defender.tests._session_store_705 import store_factory
    from defender.tests.e2e._replay_harness import GOLDEN, ReplayFn, Turn, drive, materialize

    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    drive(run_dir, run_id="visualize-1105", main=ReplayFn([Turn(text=text)]),
          store_factory=store_factory(tmp_path, sink=opened))
    for store in opened:
        with contextlib.suppress(Exception):
            store.close()
    return run_dir


#: Where D8's location-derived values lived at ed5386bc — searched after the service's own
#: modules, so a value the move left in place is still found (and one it moved is found first).
LOCATION_MODULES = ("defender.scripts.visualize.visualize_run",
                    "defender.scripts.visualize.visualize_primitives")


def defining_module(name: str, *, packages: tuple[str, ...] = (SERVICE,),
                    fallback: tuple[str, ...] = LOCATION_MODULES):
    """The first module whose own namespace defines `name`: every module of the service package
    first, then `fallback` — how a test reaches a location-derived value D8 names
    (`_MIRROR_WRITER`, `mirror_root`, `ASSETS`) wherever the move put its module, without
    spelling that module's private path. Only named modules are imported: a blind walk of
    `scripts/visualize` would import `visualize_messages` first, the one order its known
    import cycle breaks (author-P5)."""
    import pkgutil

    candidates: list[str] = []
    for dotted in packages:
        try:
            pkg = importlib.import_module(dotted)
        except ModuleNotFoundError:
            continue
        candidates += [pkg.__name__] + [
            info.name for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + ".")]
    for mod_name in [*candidates, *fallback]:
        try:
            module = importlib.import_module(mod_name)
        except Exception:  # noqa: BLE001 — a module that cannot import defines nothing here
            continue
        if name in vars(module):
            return module
    raise AssertionError(f"no module under {packages} or {fallback} defines {name!r}")


def module_named(stem: str, *, fallback: str) -> Any:
    """The module whose last dotted component is `stem` — inside the service package if the move
    put it there, else `fallback` (its ed5386bc home). For a module D8 names BY NAME
    (`visualize_primitives`), where an attribute search would find a re-importer first."""
    import pkgutil

    try:
        pkg = importlib.import_module(SERVICE)
        for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            if info.name.rsplit(".", 1)[-1] == stem:
                return importlib.import_module(info.name)
    except ModuleNotFoundError:
        pass
    return importlib.import_module(fallback)


def main_checkout(start: Path = WORKTREE) -> Path:
    """The checkout a worktree's `.git` file points back to, or `start` itself — computed here
    from the gitdir pointer the same way the file system records it, as the expected value of
    the run page's mirror root (#1084 D3)."""
    dot_git = start / ".git"
    if not dot_git.is_file():
        return start
    pointer = dot_git.read_text(encoding="utf-8").strip()
    admin = (start / pointer[len("gitdir:"):].strip()).resolve()
    common = (admin / (admin / "commondir").read_text(encoding="utf-8").strip()).resolve()
    return common.parent if (common.parent / "defender").is_dir() else start


# --------------------------------------------------------------------------------------
# copies of the tree, for faults that need a file gone that the checkout must keep
# --------------------------------------------------------------------------------------

_TREE_IGNORE = shutil.ignore_patterns(".venv", "tests", "__pycache__", "*.pyc", "fixtures-e2e",
                                      "docs", "node_modules", ".pytest_cache")


def tree_copy(tmp_path: Path) -> Path:
    """A copy of `defender/` (code and data, no venv, no tests) under `tmp_path/copy/defender`,
    returned as the directory to put on `PYTHONPATH`. A file deleted from THIS tree is really
    gone for a child interpreter importing `defender` from it."""
    root = tmp_path / "copy"
    shutil.copytree(DEFENDER, root / "defender", ignore=_TREE_IGNORE, symlinks=True)
    return root


__all__ = [name for name in dir() if not name.startswith("_")] + [
    "LINT_DIR", "DEFENDER", "WORKTREE"]
