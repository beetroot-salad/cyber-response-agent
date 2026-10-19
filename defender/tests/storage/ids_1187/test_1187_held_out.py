"""Held-out launches record opaque run IDs before execution and scoring reads that index."""
from __future__ import annotations

import io
import json
import os
from collections.abc import Callable, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.tests.storage.ids_1187 import _spec1187 as S

SLUG = "m05-lsass-access"
OTHER = "b01-benign-logon"
#: The tenant `launch` names for run.py, which requires one (Flow 5).
LAUNCH_TENANT = "playground"
STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"
INDEX_NAME = "held-out-index.jsonl"
#: The failure bucket an absent or recordless indexed run lands in (recheck X2, quoted).
NO_RUN_RECORD = "launched, no run record"
# Inputs on the real filesystem

def _fixtures(root: Path, truths: dict[str, str]) -> Path:
    """A held-out fixture set: `<root>/<slug>/alert.json` plus a labelled `ground_truth.yaml` per slug, the shape `load_held_out_fixtures` admits."""
    for slug, disposition in truths.items():
        member = root / slug
        member.mkdir(parents=True)
        (member / "alert.json").write_text('{"alert": "held-out"}\n', encoding="utf-8")
        (member / "ground_truth.yaml").write_text(
            f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    return root


def _report_text(disposition: str) -> str:
    """`report.md` in the close gate's frontmatter shape (`_triplet_947.report_text`'s)."""
    return ("---\n"
            f"disposition: {disposition}\n"
            "outcome: stands\n"
            "cause: the disposition was recorded without a challenge review\n"
            "---\n"
            "Disposition recorded by the close gate.\n")


def _run(runs: Path, run_id: str | None = None, *, says: str | None,
         record: bool = True) -> Path:
    """Create a run with an alert record and an optional disposition report."""
    from defender.run_repository import RunPaths

    run_dir = S.make_run(runs, run_id)
    paths = RunPaths(run_dir)
    if not record:
        paths.alert_record.unlink()
    if says is not None:
        paths.report.write_text(_report_text(says), encoding="utf-8")
    return run_dir


def _index(path: Path, *rows: tuple[str, str]) -> Path:
    """F holding `rows` (`(slug, run_id)`, oldest first) as the contract pins it: JSON Lines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"slug": slug, "run_id": run_id}) + "\n"
                            for slug, run_id in rows), encoding="utf-8")
    return path


def _rows(text: str | None) -> list[tuple[str, str]]:
    """F's rows as `(slug, run_id)`, read by the TEST (plain JSON Lines)."""
    if not text:
        return []
    out = []
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            out.append((row["slug"], row["run_id"]))
    return out
# The CLI, driven through `held_out.main`

@dataclass
class Outcome:
    """What one `held_out.main` call did."""

    rc: int | None
    out: str
    err: str
    exit_text: str = ""
    crashed: BaseException | None = None

    @property
    def said(self) -> str:
        return f"{self.exit_text}\n{self.err}"

    def verdicts(self) -> dict[str, str]:
        """`{slug: "OK" | "WRONG"}` from the report's per-fixture lines."""
        found: dict[str, str] = {}
        for line in self.out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
                found[parts[1][:-1]] = parts[0]
        return found

    def line_for(self, slug: str) -> str:
        hits = [ln for ln in self.out.splitlines()
                if ln.split()[1:2] == [f"{slug}:"] and ln.split()[0] in ("OK", "WRONG")]
        return hits[0] if hits else ""

    def section(self, header: str) -> list[str]:
        """The indented lines under the report's `## <header>...` heading."""
        lines = self.out.splitlines()
        starts = [i for i, ln in enumerate(lines) if ln.startswith(f"## {header}")]
        if not starts:
            return []
        body = []
        for ln in lines[starts[0] + 1:]:
            if not ln.strip() or ln.startswith("#"):
                break
            body.append(ln.strip())
        return body

    def failures(self) -> dict[str, str]:
        """`{slug: reason}` from the failure bucket (` <slug>: <reason>`)."""
        out = {}
        for ln in self.section("Failure bucket"):
            slug, _, reason = ln.partition(":")
            out[slug.strip()] = reason.strip()
        return out

    def not_run(self) -> list[str]:
        return self.section("Not run")

    def accuracy(self) -> tuple[int, int] | None:
        for ln in self.out.splitlines():
            if ln.startswith("Aggregate accuracy:"):
                c, _, t = ln.split(":", 1)[1].split()[0].partition("/")
                if c.isdigit() and t.isdigit():
                    return int(c), int(t)
        return None


def _cli(argv: Sequence[object], **seams: Any) -> Outcome:
    """`held_out.main([str(a) ...], **seams)`, capturing stdout and stderr."""
    from evaluations import held_out

    out, err = io.StringIO(), io.StringIO()
    rc: int | None = None
    exit_text = ""
    crashed: BaseException | None = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = held_out.main([str(a) for a in argv], **seams)
    except SystemExit as stop:
        if isinstance(stop.code, str):
            rc, exit_text = 1, stop.code
        else:
            rc = 0 if stop.code is None else stop.code
    except BaseException as exc:  # noqa: BLE001 — a launch whose run.py died is observed, not raised
        crashed = exc
    return Outcome(rc, out.getvalue(), err.getvalue(), exit_text, crashed)


def _score(runs: Path, index: Path, fixtures: Path, *extra: object) -> Outcome:
    """`held_out.py <runs> --index <index> --fixtures-dir <fixtures>`."""
    return _cli([runs, "--index", index, "--fixtures-dir", fixtures, *extra])


@dataclass
class SpawnCall:
    argv: list[str]
    #: F's text at the instant run.py was started (`None`: F did not exist).
    index_then: str | None


@dataclass
class FakeSpawn:
    """Record each launch command and the index contents visible before it starts."""

    index: Path
    exit_code: int = 0
    raises: BaseException | None = None
    effect: Callable[[list[str]], None] | None = None
    calls: list[SpawnCall] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], *, env: Any = None, **_: Any) -> int:
        then = self.index.read_text(encoding="utf-8") if self.index.is_file() else None
        self.calls.append(SpawnCall([str(a) for a in argv], then))
        if self.effect is not None:
            self.effect([str(a) for a in argv])
        if self.raises is not None:
            raise self.raises
        return self.exit_code


def _after_run_py(argv: Sequence[str]) -> list[str]:
    """What follows the `run.py` element of the command line `spawn` was handed."""
    names = [Path(a).name for a in argv]
    assert "run.py" in names, f"spawn was not handed a command line that runs run.py: {argv}"
    return list(argv[names.index("run.py") + 1:])


def _launched_run_id(call: SpawnCall, alert: Path) -> str:
    """Assert `call` ran `run.py <alert> --tenant playground --run-id <uuid> --no-learn` (flags in any order, nothing else), and return the uuid."""
    rest = _after_run_py(call.argv)
    assert rest, f"run.py was handed no arguments: {call.argv}"
    assert Path(rest[0]).resolve() == alert.resolve(), (
        f"run.py's alert is {rest[0]!r}, not the fixture's {alert}")
    flags = rest[1:]
    assert len(flags) == 5, f"run.py's flags are not exactly --tenant/--run-id/--no-learn: {flags}"
    assert flags.count("--no-learn") == 1, flags
    assert "--tenant" in flags, flags
    assert flags[flags.index("--tenant") + 1] == LAUNCH_TENANT, flags
    assert "--run-id" in flags, flags
    run_id = flags[flags.index("--run-id") + 1]
    assert S.is_canonical_uuid(run_id), f"the minted run id {run_id!r} is not a canonical UUID"
    return run_id
# The launch scene: the data root, a separate learning state root, the operator's own folder

@dataclass
class Scene:
    tmp: Path
    data_root: Path
    state: Path
    fixtures: Path
    ops: Path

    def alert(self, slug: str = SLUG) -> Path:
        return self.fixtures / slug / "alert.json"

    def launch(self, index: Path, spawn: FakeSpawn, slug: str = SLUG) -> Outcome:
        return _cli(["launch", slug, "--index", index, "--fixtures-dir", self.fixtures],
                    spawn=spawn)


@pytest.fixture
def scene(tmp_path: Path, data_root: Path, monkeypatch: pytest.MonkeyPatch) -> Scene:
    """`DEFENDER_DATA_ROOT` is conftest's per-test root (outside `tmp_path`)."""
    state = tmp_path / "learning-state"
    state.mkdir()
    monkeypatch.setenv(STATE_ENV, str(state))
    ops = tmp_path / "ops"
    ops.mkdir()
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious", OTHER: "benign"})
    return Scene(tmp_path, Path(data_root), state, fixtures, ops)


def _assert_refused(res: Outcome, index: Path, what: str) -> None:
    assert res.crashed is None, f"{what}: the command crashed instead of refusing: {res.crashed!r}"
    assert res.rc not in (0, None), f"{what}: exit {res.rc}, not a refusal:\n{res.out}\n{res.err}"
    assert "unrecognized arguments" not in res.err, (
        f"{what}: the argv was not understood, so nothing was judged:\n{res.err}")
    assert index.name in res.said, f"{what}: the refusal does not name the index:\n{res.said}"


def _assert_launch_accepted(scene: Scene, index: Path) -> None:
    """Check the positive launch control through the same CLI and index as refusal cases."""
    before = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    assert res.crashed is None, f"control: the launch crashed: {res.crashed!r}"
    assert len(spawn.calls) == 1, f"control: run.py was started {len(spawn.calls)} times"
    run_id = _launched_run_id(spawn.calls[0], scene.alert())
    assert _rows(index.read_text(encoding="utf-8")) == [*before, (SLUG, run_id)], (
        "control: the accepted index did not gain exactly the launched row")
# Launch: the row first, then run.py

def test_launch_appends_the_row_before_run_py_starts_and_hands_run_py_that_id(scene):
    index = scene.ops / INDEX_NAME
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    assert res.crashed is None, f"the launch crashed: {res.crashed!r}\n{res.err}"
    assert len(spawn.calls) == 1, f"run.py was started {len(spawn.calls)} times, not once"
    run_id = _launched_run_id(spawn.calls[0], scene.alert())
    assert spawn.calls[0].index_then is not None, "F did not exist when run.py was started"
    assert _rows(spawn.calls[0].index_then) == [(SLUG, run_id)], (
        "when run.py was started, F did not already hold the row naming the run it was handed:\n"
        f"{spawn.calls[0].index_then!r}")
    assert _rows(index.read_text(encoding="utf-8")) == [(SLUG, run_id)]


def test_a_second_launch_appends_beside_the_rows_already_there_with_a_fresh_id(scene):
    earlier = (OTHER, S.new_id())
    index = _index(scene.ops / INDEX_NAME, earlier)
    prefix = index.read_bytes()
    first, second = FakeSpawn(index), FakeSpawn(index)
    for spawn in (first, second):
        res = scene.launch(index, spawn)
        assert res.crashed is None, f"the launch crashed: {res.crashed!r}\n{res.err}"
        assert len(spawn.calls) == 1, f"run.py was started {len(spawn.calls)} times, not once"
    id1 = _launched_run_id(first.calls[0], scene.alert())
    id2 = _launched_run_id(second.calls[0], scene.alert())
    assert id1 != id2, "two launches minted the same run id"
    assert index.read_bytes().startswith(prefix), "the rows already in F were rewritten"
    assert _rows(second.calls[0].index_then) == [earlier, (SLUG, id1), (SLUG, id2)], (
        "the second run.py started before its own row was appended after the first")
    assert _rows(index.read_text(encoding="utf-8")) == [earlier, (SLUG, id1), (SLUG, id2)]


@pytest.mark.parametrize("dies", [
    pytest.param({"exit_code": 1}, id="run-py-exits-1"),
    pytest.param({"raises": RuntimeError("run.py crashed")}, id="run-py-crashes"),
    pytest.param({"raises": KeyboardInterrupt()}, id="launch-interrupted"),
])
def test_a_run_that_fails_crashes_or_is_interrupted_still_has_its_row(scene, dies):
    index = scene.ops / INDEX_NAME
    spawn = FakeSpawn(index, **dies)
    scene.launch(index, spawn)
    assert len(spawn.calls) == 1, f"run.py was started {len(spawn.calls)} times, not once"
    run_id = _launched_run_id(spawn.calls[0], scene.alert())
    assert _rows(index.read_text(encoding="utf-8") if index.is_file() else None) == [
        (SLUG, run_id)], "a run that died left no row in F"


def test_launch_as_the_operator_runs_it_really_starts_run_py(scene):
    import subprocess
    import sys

    index = scene.ops / INDEX_NAME
    worktree = S.H5.WORKTREE
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join(filter(None, [str(worktree),
                                                       os.environ.get("PYTHONPATH")]))}
    before = S.tree(scene.data_root)
    child = subprocess.run(  # noqa: S603 — this interpreter, the checkout's own CLI
        [sys.executable, str(worktree / "evaluations" / "held_out.py"), "launch", SLUG,
         "--index", str(index), "--fixtures-dir", str(scene.fixtures)],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env,
        cwd=str(worktree), timeout=600)
    said = f"{child.stdout}\n{child.stderr}"

    rows = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
    assert [slug for slug, _run_id in rows] == [SLUG], (
        f"launch did not append one row for {SLUG}: {rows}\n{said[-1500:]}")
    assert S.is_canonical_uuid(rows[0][1]), f"the row's run id is {rows[0][1]!r}"
    playground = str(Path(scene.data_root) / LAUNCH_TENANT)
    refusals = [line for line in said.splitlines() if "[run.py]" in line and playground in line]
    assert refusals, (
        "launch's real spawn never ran run.py --tenant playground under this data root: no "
        f"refusal of its own naming {playground} in the output:\n{said[-1500:]}")
    assert S.tree(scene.data_root) == before, "the refused run.py made something"
# Launch: locations that cannot hold the host-owned index.

def _under_data_root(scene: Scene) -> Path:
    return scene.data_root / INDEX_NAME


def _in_a_tenants_run_folder(scene: Scene) -> Path:
    """Inside a natural run folder: the box of that run holds it read-write."""
    return S.make_run(S.natural_runs(scene.data_root, LAUNCH_TENANT)) / INDEX_NAME


def _in_another_tenants_arm(scene: Scene) -> Path:
    """Place the index inside another tenant's writable arm to test the whole data-root boundary."""
    ep = S.make_episode(scene.data_root, "acme", labels=("a",), arms=True)
    arm = next(p for p in (ep / "runs").iterdir())
    return arm / INDEX_NAME


def _in_learning_state_root(scene: Scene) -> Path:
    return scene.state / INDEX_NAME


def _under_learning_state_root(scene: Scene) -> Path:
    folder = scene.state / "runs" / "some-case"
    folder.mkdir(parents=True)
    return folder / INDEX_NAME


@pytest.mark.parametrize("place", [
    pytest.param(_under_data_root, id="the-data-root"),
    pytest.param(_in_a_tenants_run_folder, id="a-playground-run-folder"),
    pytest.param(_in_another_tenants_arm, id="another-tenants-arm-folder"),
    pytest.param(_in_learning_state_root, id="the-learning-state-root"),
    pytest.param(_under_learning_state_root, id="below-the-learning-state-root"),
])
def test_launch_refuses_an_index_under_the_data_root_or_the_learning_state_root(scene, place):
    index = _index(place(scene), (OTHER, S.new_id()))
    before = {root: S.tree(root) for root in (scene.data_root, scene.state, scene.ops)}
    held = index.read_bytes()
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    _assert_refused(res, index, "an index under a root the box or the loop can reach")
    assert spawn.calls == [], "run.py was started although the index was refused"
    assert index.read_bytes() == held, "a row was appended to a refused index"
    for root, tree in before.items():
        assert S.tree(root) == tree, f"the refused launch changed {root}"
    _assert_launch_accepted(scene, scene.ops / INDEX_NAME)


def test_launch_judges_the_resolved_data_root_not_its_spelling(scene, monkeypatch):
    real = scene.tmp / "real-data-root"
    real.mkdir()
    link = scene.tmp / "data-root-link"
    os.symlink(real, link)
    monkeypatch.setenv(S.DATA_ROOT_ENV, str(link))
    index = real / INDEX_NAME
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    _assert_refused(res, index, "an index under the data root's real folder")
    assert spawn.calls == [], "run.py was started although the index was refused"
    assert not index.exists(), "a refused index was created"
    _assert_launch_accepted(scene, scene.ops / INDEX_NAME)


def _link_at_the_index(scene: Scene) -> tuple[Path, Path]:
    """F is itself a link to a file outside both roots."""
    real = _index(scene.tmp / "elsewhere" / "real-index.jsonl", (OTHER, S.new_id()))
    index = scene.ops / INDEX_NAME
    os.symlink(real, index)
    return index, real


def _link_at_a_parent(scene: Scene) -> tuple[Path, Path]:
    """F's folder is a link to a folder outside both roots."""
    real = _index(scene.tmp / "elsewhere" / INDEX_NAME, (OTHER, S.new_id()))
    linked = scene.tmp / "ops-link"
    os.symlink(real.parent, linked)
    return linked / INDEX_NAME, real


def _link_at_a_grandparent(scene: Scene) -> tuple[Path, Path]:
    real = _index(scene.tmp / "elsewhere" / "deeper" / INDEX_NAME, (OTHER, S.new_id()))
    linked = scene.tmp / "ops-link"
    os.symlink(real.parent.parent, linked)
    return linked / "deeper" / INDEX_NAME, real


@pytest.mark.parametrize("plant", [
    pytest.param(_link_at_the_index, id="link-at-the-index"),
    pytest.param(_link_at_a_parent, id="link-at-its-folder"),
    pytest.param(_link_at_a_grandparent, id="link-higher-up"),
])
def test_launch_refuses_an_index_reached_through_a_link(scene, plant):
    index, real = plant(scene)
    held = real.read_bytes()
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    _assert_refused(res, index, "an index reached through a link")
    assert spawn.calls == [], "run.py was started although the index was refused"
    assert real.read_bytes() == held, "a row was appended through the refused link"
    _assert_launch_accepted(scene, real)


_INDEX_SWAP_CHILD = """
import json, os, sys
from pathlib import Path
from evaluations import held_out
index, elsewhere, fixtures = map(Path, sys.argv[1:4])
slug, mode = sys.argv[4:6]
swap_kind = sys.argv[6]
aside = index.parent.with_name(index.parent.name + '-held-original')
active, swapped, calls = True, False, []
def audit(event, args):
    global swapped
    if not active or swapped or mode == 'control' or event != 'open':
        return
    path = args[0]
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    targets = {str(index), index.name}
    if mode != 'held-control' and swap_kind == 'parent':
        targets.update({str(index.parent), index.parent.name})
    if os.fsdecode(path) in targets:
        swapped = True
        if swap_kind == 'index':
            index.rename(index.with_name(index.name + '-held-original'))
            index.symlink_to(elsewhere / index.name)
        else:
            index.parent.rename(aside)
            index.parent.symlink_to(elsewhere, target_is_directory=True)
def spawn(argv, *, env=None):
    calls.append(list(map(str, argv)))
    return 0
sys.addaudithook(audit)
rc, crashed = None, None
try:
    if mode == 'unsafe-control':
        # A check followed by an absolute-path open follows the link planted at open time.
        index.lstat()
        with index.open('a', encoding='utf-8') as stream:
            stream.write('UNSAFE FOLLOW\\n')
        rc = 0
    elif mode == 'held-control':
        # A held parent still names the original after its spelling is redirected.
        fd = os.open(index.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            leaf = os.open(index.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=fd)
            os.write(leaf, b'HELD ORIGINAL\\n')
            os.close(leaf)
        finally:
            os.close(fd)
        rc = 0
    else:
        rc = held_out.main(['launch', slug, '--index', str(index),
                            '--fixtures-dir', str(fixtures)], spawn=spawn)
except SystemExit as exc:
    rc = (1 if isinstance(exc.code, str) else exc.code or 0)
except BaseException as exc:
    crashed = type(exc).__name__ + ': ' + str(exc)
finally:
    active = False
print('INDEX_SWAP_RESULT ' + json.dumps(dict(swapped=swapped, calls=calls, rc=rc,
                                            crashed=crashed)))
"""


def _index_swap_child(scene: Scene, index: Path, elsewhere: Path, mode: str,
                      *, swap_kind: str = "parent") -> dict:
    """The audit hook runs only in a child; the launcher's only injected dependency is spawn."""
    import subprocess
    import sys

    worktree = S.H5.WORKTREE
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": os.pathsep.join(filter(None, [str(worktree),
                                                       os.environ.get("PYTHONPATH")]))}
    child = subprocess.run(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _INDEX_SWAP_CHILD, str(index), str(elsewhere),
         str(scene.fixtures), SLUG, mode, swap_kind],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env,
        cwd=str(worktree), timeout=300)
    rows = [line.removeprefix("INDEX_SWAP_RESULT ") for line in child.stdout.splitlines()
            if line.startswith("INDEX_SWAP_RESULT ")]
    assert child.returncode == 0, (
        f"index-swap child failed: {child.stdout[-1500:]} {child.stderr[-1500:]}")
    assert len(rows) == 1, f"missing index-swap result: {child.stdout[-1500:]}"
    return json.loads(rows[0])


def _index_swap_scene(scene: Scene, name: str) -> tuple[Path, Path, Path, bytes]:
    """An operator index and a same-named canary in a simulated box-writable run folder."""
    index = _index(scene.tmp / name / INDEX_NAME, (OTHER, S.new_id()))
    elsewhere = scene.data_root / LAUNCH_TENANT / "runs" / S.new_id()
    canary = _index(elsewhere / INDEX_NAME, (OTHER, S.new_id()))
    return index, elsewhere, canary, canary.read_bytes()


@pytest.mark.parametrize("swap_kind", ["parent", "index"])
def test_launch_never_appends_through_an_index_parent_swapped_at_open_time(scene, swap_kind):
    control, other, canary, before = _index_swap_scene(scene, "index-control-ops")
    outcome = _index_swap_child(scene, control, other, "control")
    assert outcome["crashed"] is None, outcome
    assert outcome["rc"] in (0, None), outcome
    assert len(outcome["calls"]) == 1, outcome
    assert not outcome["swapped"], outcome
    run_id = _launched_run_id(SpawnCall(outcome["calls"][0], None), scene.alert())
    assert _rows(control.read_text(encoding="utf-8"))[-1] == (SLUG, run_id)
    assert canary.read_bytes() == before

    index, other, canary, before = _index_swap_scene(scene, "index-race-ops")
    prefix = index.read_bytes()
    outcome = _index_swap_child(scene, index, other, "swap", swap_kind=swap_kind)
    assert outcome["swapped"], f"launch never reached the index's open: {outcome}"
    assert outcome["crashed"] is None, f"launch crashed instead of refusing: {outcome}"
    assert canary.read_bytes() == before, "launch appended through the swapped index parent"
    original = (index.with_name(index.name + "-held-original") if swap_kind == "index" else
                index.parent.with_name(index.parent.name + "-held-original") / index.name)
    if outcome["rc"] in (0, None):
        assert len(outcome["calls"]) == 1, outcome
        run_id = _launched_run_id(SpawnCall(outcome["calls"][0], None), scene.alert())
        assert original.read_bytes().startswith(prefix)
        assert _rows(original.read_text(encoding="utf-8"))[-1] == (SLUG, run_id)
    else:
        assert outcome["calls"] == [], "a refused index still started run.py"
        assert original.read_bytes() == prefix, "a refused index was changed"


def test_the_index_swap_hook_distinguishes_a_path_append_from_a_held_parent(scene):
    for swap_kind in ("parent", "index"):
        index, other, canary, before = _index_swap_scene(scene, "unsafe-ops-" + swap_kind)
        outcome = _index_swap_child(scene, index, other, "unsafe-control", swap_kind=swap_kind)
        assert outcome["swapped"], outcome
        assert outcome["crashed"] is None, outcome
        assert canary.read_bytes() == before + b"UNSAFE FOLLOW\n"

    index, other, canary, before = _index_swap_scene(scene, "held-index-ops")
    # Open the original parent first, then redirect at the leaf open, like a secure walk.
    # The parent-open event must not trigger this control's swap.
    outcome = _index_swap_child(scene, index, other, "held-control")
    assert outcome["swapped"], outcome
    assert outcome["crashed"] is None, outcome
    assert canary.read_bytes() == before
    original = index.parent.with_name(index.parent.name + "-held-original") / index.name
    assert original.read_bytes().endswith(b"HELD ORIGINAL\n")


def test_launch_refuses_when_the_data_root_is_unset(scene, monkeypatch):
    root = os.environ[S.DATA_ROOT_ENV]
    monkeypatch.delenv(S.DATA_ROOT_ENV)
    index = scene.ops / INDEX_NAME
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    assert res.crashed is None, f"the launch crashed instead of refusing: {res.crashed!r}"
    assert res.rc not in (0, None), f"exit {res.rc}: an unset data root was not refused"
    assert S.DATA_ROOT_ENV in res.said, f"the refusal does not name the variable:\n{res.said}"
    assert spawn.calls == [], "run.py was started with no data root to judge the index against"
    assert not index.exists(), "a row was appended with no data root to judge the index against"
    monkeypatch.setenv(S.DATA_ROOT_ENV, root)
    _assert_launch_accepted(scene, index)
# Scoring: the newest row per slug, by id (recheck X2)

@pytest.fixture
def scoring(tmp_path: Path) -> tuple[Path, Path, Path]:
    """`(runs dir, index path, ops folder)`: the runs dir scoring is handed, and F in the operator's own folder beside it (outside the runs dir)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    return runs, ops / INDEX_NAME, ops


def test_scoring_takes_the_newest_row_per_slug_not_the_newest_folder(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious"})
    right = _run(runs, says="malicious")
    wrong = _run(runs, says="benign")
    os.utime(wrong, (1_800_000_000, 1_800_000_000))
    os.utime(right, (1_800_000_600, 1_800_000_600))

    _index(index, (SLUG, right.name), (SLUG, wrong.name))
    res = _score(runs, index, fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {SLUG: "WRONG"}, (
        f"the newest row's run was not the one scored:\n{res.out}\n{res.err}")
    assert "'benign'" in res.line_for(SLUG), res.out
    assert res.accuracy() == (0, 1), res.out

    _index(index, (SLUG, wrong.name), (SLUG, right.name))
    res = _score(runs, index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: reversing the rows changed nothing:\n{res.out}"
    assert res.accuracy() == (1, 1), res.out
    assert res.rc == 0, f"exit {res.rc} with a scored fixture"


def test_a_row_naming_an_absent_or_recordless_run_scores_wrong_not_not_run(tmp_path, scoring):
    runs, index, _ = scoring
    truths = {"absent-case": "malicious", "recordless-case": "benign",
              "no-report-case": "benign", "scored-case": "benign"}
    fixtures = _fixtures(tmp_path / "fixtures", truths)
    recordless = _run(runs, says="benign", record=False)
    no_report = _run(runs, says=None)
    scored = _run(runs, says="benign")
    _index(index, ("absent-case", S.new_id()), ("recordless-case", recordless.name),
           ("no-report-case", no_report.name), ("scored-case", scored.name))

    res = _score(runs, index, fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {"absent-case": "WRONG", "recordless-case": "WRONG",
                              "no-report-case": "WRONG", "scored-case": "OK"}, (
        f"an indexed run with no record did not count as wrong:\n{res.out}\n{res.err}")
    assert res.accuracy() == (1, 4), f"the denominator lost a launched slug:\n{res.out}"
    failures = res.failures()
    for slug in ("absent-case", "recordless-case"):
        assert NO_RUN_RECORD in failures.get(slug, ""), (
            f"{slug} is not in the {NO_RUN_RECORD!r} bucket:\n{res.out}")
    assert "report.md" in failures.get("no-report-case", ""), res.out
    assert NO_RUN_RECORD not in failures.get("no-report-case", ""), res.out
    assert "scored-case" not in failures, res.out
    assert res.not_run() == [], f"a slug with a row was reported not run:\n{res.out}"
    assert res.rc == 0


def test_a_slug_with_no_row_is_not_run_whatever_folders_are_named_after_it(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign", OTHER: "benign"})
    for name in (SLUG, f"{SLUG}-n5-a", f"20260718t101500z-{SLUG}", f"sec-eval-gen7-{SLUG}-ab12cd34"):
        _run(runs, name, says="malicious")
    indexed = _run(runs, says="benign")
    decoy = _run(runs, OTHER, says="malicious")
    os.utime(indexed, (1_800_000_000, 1_800_000_000))
    os.utime(decoy, (1_800_000_600, 1_800_000_600))
    _index(index, (OTHER, indexed.name))

    res = _score(runs, index, fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {OTHER: "OK"}, (
        f"a folder was matched to a fixture by its name:\n{res.out}\n{res.err}")
    assert res.not_run() == [SLUG], f"the unindexed slug is not reported not run:\n{res.out}"
    assert res.accuracy() == (1, 1), res.out


def test_scoring_without_an_index_scores_no_folder_by_its_name(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    _run(runs, SLUG, says="benign")
    res = _cli([runs, "--fixtures-dir", fixtures])
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {}, f"a folder was scored by its name with no index:\n{res.out}"

    indexed = _run(runs, says="benign")
    _index(index, (SLUG, indexed.name))
    res = _score(runs, index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: the indexed run was not scored:\n{res.out}"


def test_the_folder_name_matcher_is_gone():
    from evaluations import held_out

    assert not hasattr(held_out, "_claimed_slug"), "the folder-name matcher is still defined"
# Scoring: where F may not be, and what scoring never reads (recheck X3, J50)

def _in_the_runs_dir(runs: Path, tmp: Path) -> tuple[Path, Path]:
    return runs, runs / INDEX_NAME


def _in_a_run_folder(runs: Path, tmp: Path) -> tuple[Path, Path]:
    """Inside a run folder: the box of that run holds it read-write."""
    return runs, S.make_run(runs) / INDEX_NAME


def _spelled_outside_but_inside(runs: Path, tmp: Path) -> tuple[Path, Path]:
    """F spelled under a folder outside the runs dir that is a link into a run folder: the file itself is inside the runs dir."""
    link = tmp / "ops-link"
    os.symlink(S.make_run(runs), link)
    return runs, link / INDEX_NAME


def _runs_dir_handed_through_a_link(runs: Path, tmp: Path) -> tuple[Path, Path]:
    """The runs dir handed through a linked spelling, F spelled at its real place inside it."""
    link = tmp / "runs-link"
    os.symlink(runs, link)
    return link, runs / INDEX_NAME


@pytest.mark.parametrize("place", [
    pytest.param(_in_the_runs_dir, id="in-the-runs-dir"),
    pytest.param(_in_a_run_folder, id="in-a-run-folder"),
    pytest.param(_spelled_outside_but_inside, id="spelled-outside-through-a-link-into-it"),
    pytest.param(_runs_dir_handed_through_a_link, id="runs-dir-handed-through-a-link"),
])
def test_scoring_refuses_an_index_inside_its_runs_dir(tmp_path, scoring, place):
    runs, ops_index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    handed, index = place(runs, tmp_path)
    _index(index, (SLUG, good.name))
    held = index.read_bytes()

    res = _score(handed, index, fixtures)
    _assert_refused(res, index, "an index inside the runs dir")
    assert res.verdicts() == {}, f"scoring went ahead with an index inside its runs dir:\n{res.out}"
    assert res.accuracy() is None, res.out
    assert index.read_bytes() == held

    _index(ops_index, (SLUG, good.name))
    res = _score(runs, ops_index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: an index outside was not scored:\n{res.out}"


def test_a_link_in_a_run_folder_pointing_at_the_index_does_not_put_it_inside(tmp_path, scoring):
    runs, index, ops = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    _index(index, (SLUG, good.name))
    planted = S.make_run(runs)
    os.symlink(index, planted / "points-at-the-index")
    os.symlink(ops, planted / "points-at-its-folder")

    res = _score(runs, index, fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {SLUG: "OK"}, (
        f"a link in a run folder made scoring treat the index as inside:\n{res.out}\n{res.err}")


@pytest.mark.parametrize("value", [None, "relative/garbage"], ids=["unset", "not-absolute"])
def test_scoring_never_resolves_the_data_root(tmp_path, scoring, monkeypatch, value):
    from defender.tenancy._tenant import resolve_data_root

    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    _index(index, (SLUG, good.name))
    if value is None:
        monkeypatch.delenv(S.DATA_ROOT_ENV, raising=False)
    else:
        monkeypatch.setenv(S.DATA_ROOT_ENV, value)
    assert S.raised(resolve_data_root) is not None, (
        "fixture: this value resolves, so it cannot show a resolution")

    res = _score(runs, index, fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {SLUG: "OK"}, (
        f"scoring depended on the data root:\n{res.out}\n{res.said}")
    assert res.rc == 0


def test_scoring_takes_no_tenant(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    _index(index, (SLUG, good.name))
    res = _score(runs, index, fixtures, "--tenant", LAUNCH_TENANT)
    assert res.rc == 2, f"scoring accepted a tenant (exit {res.rc}):\n{res.err}"
    assert "--tenant" in res.err, res.err
    assert res.verdicts() == {}, res.out
    res = _score(runs, index, fixtures)
    assert res.verdicts() == {SLUG: "OK"}, f"control: scoring without a tenant failed:\n{res.out}"
# Flow 5 end to end: launch writes the rows scoring reads

def test_launch_then_score_counts_a_launch_whose_run_never_started_as_wrong(scene, tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    index = scene.ops / INDEX_NAME
    answers = {SLUG: "malicious", OTHER: "benign"}

    def finished_run(argv: list[str]) -> None:
        rest = _after_run_py(argv)
        slug = Path(rest[0]).parent.name
        run_id = rest[rest.index("--run-id") + 1]
        _run(runs, run_id, says=answers[slug])

    for slug, spawn in ((SLUG, FakeSpawn(index, effect=finished_run)),
                        (OTHER, FakeSpawn(index, effect=finished_run)),
                        (SLUG, FakeSpawn(index, exit_code=1))):
        res = scene.launch(index, spawn, slug)
        assert res.crashed is None, f"the launch crashed: {res.crashed!r}\n{res.err}"
        assert len(spawn.calls) == 1, f"run.py was started {len(spawn.calls)} times for {slug}"

    res = _score(runs, index, scene.fixtures)
    assert res.crashed is None, f"scoring crashed: {res.crashed!r}\n{res.err}"
    assert res.verdicts() == {SLUG: "WRONG", OTHER: "OK"}, (
        f"scoring did not read the rows launch wrote:\n{res.out}\n{res.err}")
    assert NO_RUN_RECORD in res.failures().get(SLUG, ""), res.out
    assert res.accuracy() == (1, 2), f"a launch whose run never started left the denominator:\n{res.out}"
    assert res.not_run() == [], res.out
