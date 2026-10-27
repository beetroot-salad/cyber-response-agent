"""Suite-wide hooks and autouse fixtures for `defender/tests/`, plus learning-loop helpers.

`tmp_repo` is an isolated tmp git repo with the learning author sources copied in and one
`LoopPaths` / `AuthorConfig` over it (`ctx.paths` / `ctx.cfg`); tests thread those into
`author.run_batch(paths=…, cfg=…)` and inject a fake curator via
`dataclasses.replace(cfg, invoke_agent=fake)` — no module-global setattr, no `importlib.reload`.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest


#: What `-n auto` means off CI. xdist's one worker per core suits a runner that owns its box,
#: not a developer machine several sessions share (each worker grows to hundreds of MB). A set
#: `PYTEST_XDIST_AUTO_NUM_WORKERS` (the devcontainer declares it) still wins; `-n logical`,
#: `-n N` and CI are untouched. `optionalhook` so a run with `-p no:xdist` does not trip
#: pluggy's unknown-hook check.
_LOCAL_AUTO_WORKERS = 4


@pytest.hookimpl(optionalhook=True)
def pytest_xdist_auto_num_workers(config: pytest.Config) -> int | None:
    if os.environ.get("CI") or os.environ.get("PYTEST_XDIST_AUTO_NUM_WORKERS"):
        return None
    if config.option.numprocesses != "auto":
        return None
    return _LOCAL_AUTO_WORKERS


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--shard", default=None, metavar="I/N",
                     help="run only shard I of N: whole test files, balanced by recorded cost "
                          "(see tests/_shard.py); the shards together run every test once")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    spec = config.getoption("--shard")
    if not spec:
        return
    from defender.tests import _shard

    index, count = _shard.parse_shard(spec)
    mine = _shard.shard_of_files([item.nodeid for item in items], index, count)
    kept = [item for item in items if _shard.file_of(item.nodeid) in mine]
    config.hook.pytest_deselected(items=[item for item in items if item not in kept])
    items[:] = kept


REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"


@pytest.fixture(scope="session")
def checkout_roster():
    """The real checkout's adapters roster, read ONCE per session — the value a production
    process reads at its composition root and hands down."""
    from defender._paths import PATHS
    from defender.systems.verbs import read_roster

    return read_roster(PATHS.adapters_dir)


@pytest.fixture(autouse=True)
def _held_capabilities(checkout_roster):
    """Every test starts with the `nothing-to-try` gate holding the real checkout's roster, as a
    production process does at start, and ends with it released, so a test that pointed the gate
    at another tree cannot leak it to the next. The gate never reads for itself: without this, a
    `nothing-to-try` receipt would raise `CapabilitiesNotRead` from every validator call. A test
    of the unheld state calls `release_capabilities()` itself."""
    from defender.skills.invlang.validate import hold_capabilities, release_capabilities

    hold_capabilities(checkout_roster)
    try:
        yield
    finally:
        release_capabilities()


#: The run-page mirror's location override (#1084), spelled here so this conftest never imports
#: the resolver (`defender.configuration.publish_root`).
RUN_VISUALIZATIONS_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"


@pytest.fixture(autouse=True)
def run_visualizations_dir(tmp_path_factory, monkeypatch) -> Path:
    """Every test's run-page mirror lands in a per-test tmp dir, never in a real checkout's
    `run-visualizations/`. A test that removes the variable has no publish root at all, so no
    copy lands anywhere; the refused copy is a logged warning, not a failed render."""
    mirror = tmp_path_factory.mktemp("run-visualizations")
    monkeypatch.setenv(RUN_VISUALIZATIONS_ENV, str(mirror))
    return mirror


#: The deployment type: `dev` turns the run page's local copy on; unset means `production`.
#: Spelled here so this conftest never imports `_env`.
DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"


@pytest.fixture(autouse=True)
def deployment_unset(monkeypatch) -> None:
    """Every test starts `production`, even when the launching shell inherited the
    devcontainer's `DEFENDER_DEPLOYMENT: dev` (CI has none), so the suite's copy behaviour does
    not depend on where it runs. A dev-copy test sets `dev` with its own `monkeypatch.setenv`,
    which wins (same function-scoped instance, later)."""
    monkeypatch.delenv(DEPLOYMENT_ENV, raising=False)


@pytest.fixture(autouse=True, scope="session")
def session_data_root(tmp_path_factory) -> Iterator[Path]:
    """The data root for module- and class-scoped fixtures, which are set up before a test's own
    `data_root`: without it they would see the launching shell's value (in the devcontainer, the
    host's real data root) and set a tenant up there. One session tmp dir per xdist worker."""
    from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV

    root = tmp_path_factory.mktemp("session-data-root")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(DATA_ROOT_ENV, str(root))
        yield root


#: Whether the test's call phase passed, for fixtures that clean up only after a pass.
_CALL_PASSED = pytest.StashKey[bool]()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Iterator[pytest.TestReport]:
    report = yield
    if report.when == "call":
        item.stash[_CALL_PASSED] = report.passed
    return report


@pytest.fixture(autouse=True)
def data_root(tmp_path_factory, monkeypatch, request) -> Iterator[Path]:
    """Every test's `DEFENDER_DATA_ROOT` is its own fresh tmp directory (#1078). Emptied once the
    test passes, as `tmp_path` is removed; a failed test's is kept to inspect. The directory
    itself stays: removed, its number would go to the next test, which would then meet whatever
    support code left beside it under the same name (e.g. `data-rootN-p4-forge`)."""
    from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV

    root = tmp_path_factory.mktemp("data-root")
    monkeypatch.setenv(DATA_ROOT_ENV, str(root))
    yield root
    if request.node.stash.get(_CALL_PASSED, False):
        for entry in root.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)


@pytest.fixture
def d9_tenant(data_root) -> str:
    """D9's one tenant, created in this test's data root through the real `create_tenant`,
    and returned as the id a test hands to `--tenant`."""
    from defender.tests.support.shared.contracts._data_root_1078 import ensure_d9_tenant

    return ensure_d9_tenant()


def _resolve_malloc_trim():
    """Bind glibc's `malloc_trim`, or a no-op off glibc (musl has no such symbol)."""
    try:
        trim = ctypes.CDLL("libc.so.6").malloc_trim
    except (OSError, AttributeError):
        return lambda: None
    trim.argtypes = [ctypes.c_size_t]
    trim.restype = ctypes.c_int
    return lambda: trim(0)


_malloc_trim = _resolve_malloc_trim()


@pytest.fixture(scope="module", autouse=True)
def _return_freed_arenas():
    """Hand freed allocator arenas back to the OS at every module boundary."""
    yield
    _malloc_trim()



@pytest.fixture
def tmp_repo(tmp_path: Path):
    """An isolated git repo with the learning author sources copied in. Returns a namespace
    with `root`, `author` (the author module), `paths` / `cfg` / `state` over the repo, and
    `run_git` (git inside it)."""
    repo = tmp_path / "repo"
    (repo / "defender" / "learning").mkdir(parents=True)
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / ".gitkeep").write_text("")

    for rel in (
        "author/lessons/run.py",
        "author/lessons/prompt.md",
        "author/shared.py",
    ):
        dst = repo / "defender" / "learning" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(LEARNING_SRC / rel, dst)

    def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            check=check,
        )

    (repo / ".gitignore").write_text(
        "defender/learning/_pending/\n"
        "defender/learning/_author.lock\n"
        "defender/learning/runs/\n"
    )

    run_git("init", "-q", "-b", "main")
    run_git("config", "user.email", "test@example.com")
    run_git("config", "user.name", "Test")
    run_git("add", "-A")
    run_git("commit", "-q", "-m", "init")

    from defender.learning.author.lessons import run as author_mod  # type: ignore[import-not-found]
    from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]
    from defender.tests.support.learning.curation._curator1134 import author_trees

    paths = LoopPaths(repo_root=repo, state_dir=repo / "defender" / "learning")
    from defender.tests.support.learning.curation._curator1134 import open_state
    state = open_state(paths)
    cfg = author_mod.build_author_config(paths, state=state, trees=author_trees(paths))

    class Ctx:
        def __init__(self) -> None:
            self.root = repo
            self.author = author_mod
            self.paths = paths
            self.cfg = cfg
            self.state = state
            self.run_git = run_git

    return Ctx()


def write_finding(
    pending_file: Path,
    *,
    finding_id: str,
    run_id: str,
    type_: str = "lead-set",
    subject: str = "subj",
    finding: str = "narrative",
    direction: str = "family",
) -> dict:
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    import json
    entry = {
        "schema_version": 1,
        "finding_id": finding_id,
        "run_id": run_id,
        "alert_rule_key": "rule-5710",
        "direction": direction,
        "type": type_,
        "subject": subject,
        "finding": finding,
        "citations": [{"source": "investigation", "quote": "..."}],
        "source_run_dir": f"episodes/{run_id}",
        # The three fields `_gate_family` reads as a family row's ground truth (#1234).
        "contrast_evidence": ["worlds/b/report.md", "worlds/a/report.md"],
        "on_verdict_path": True,
        "world_label_doubted": False,
    }
    with pending_file.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


@pytest.fixture
def helpers():
    class H:
        write_finding = staticmethod(write_finding)
    return H()


# ---------------------------------------------------------------------------
# #773 — the scene-builder seam, bound to its target in ONE place
# ---------------------------------------------------------------------------
# The #773 suite reaches `drain.run_batch` only through `_spec773.Scene.run()`, which the
# static, name-based `spec-graph calls` checker cannot follow. The checker does union the
# names of the suite dir's conftest functions that reach the target into every test file, and
# an attribute tail counts as a reference; so these two fixtures, named like the builders the
# tests already call (`S.build_scene(...)`, `S.build_questioner_scene(...)`) and wrapping those
# very builders, make the existing call sites legible, truthfully. No test requests them.
# Imports stay function-local: this conftest loads for all of `defender/tests/`, so a
# module-scope #773 import would turn its breakage into a collection error everywhere.


@pytest.fixture(scope="session", autouse=True)
def _logging_as_a_program_sets_it_up():
    """Tests run with logging configured the way every entry point configures it (text form,
    for readable failures). The handler writes to whatever `sys.stderr` is at the moment of
    writing, so `capsys` / `capfd` see log lines exactly as an operator's terminal would — and a
    silence check (`err == ""`) cannot pass over a line that moved from `print` to the log."""
    from defender import _log

    _log.configure(fmt="text", level="INFO")


@pytest.fixture
def build_scene():
    """`_spec773.build_scene` as a factory — one lessons-channel tick, wired through the
    config's own injection seams, driving `drain` through `lessons_run.run_batch`."""
    from defender.learning.author import drain
    from defender.tests.support.learning.curation import _spec773

    def _factory(tmp_path, **kwargs):
        scene = _spec773.build_scene(tmp_path, **kwargs)
        # References the target, for the call checker: the scene's runner reaches
        # `drain.run_batch`, not a stand-in.
        assert drain.run_batch is not None
        return scene

    return _factory


@pytest.fixture
def build_questioner_scene():
    """`_spec773.build_questioner_scene` as a factory — the SIBLING channel's tick, through
    the same `drain` front door."""
    from defender.learning.author import drain
    from defender.tests.support.learning.curation import _spec773

    def _factory(tmp_path, **kwargs):
        scene = _spec773.build_questioner_scene(tmp_path, **kwargs)
        assert drain.run_batch is not None
        return scene

    return _factory


@pytest.fixture(autouse=True)
def _records_planted(request):
    """The older suites build runs and episodes the way the front door leaves them (#1222: each
    carries its alert's record); #1222's own suite plants those itself, absence included."""
    from defender.tests.support.learning.branch import _triplet_947

    own = "alert_front_door_1222" in request.node.nodeid
    _triplet_947.PLANT_RECORDS = not own
    yield
    _triplet_947.PLANT_RECORDS = False
