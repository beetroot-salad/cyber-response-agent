"""Held-out launches record opaque run IDs before execution and scoring reads that index."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as process
from itertools import takewhile

SLUG = "m05-lsass-access"
OTHER = "b01-benign-logon"
#: The tenant `launch` names for run.py, which requires one (Flow 5).
LAUNCH_TENANT = fixture_uuid("tenant:playground")
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


def _run(runs: Path, run_id: str | None = None, *, says: str | None,
         record: bool = True) -> Path:
    """Create a run with an alert record and an optional disposition report."""
    from defender.run_repository import RunPaths

    run_dir = S.make_run(runs, run_id)
    paths = RunPaths(run_dir)
    if not record:
        paths.alert_record.unlink()
    if says is not None:
        paths.report.write_text(P.T.report_text(says), encoding="utf-8")
    return run_dir


def _legacy(slug: str, run_id: str) -> dict:
    """A pre-#1279 row: `{slug, run_id}`, no launch id (still admitted, #1279 O7)."""
    return {"slug": slug, "run_id": run_id}


def _launch_row(slug: str, launch_id: str, at: str = "2026-10-24T10:00:00+00:00") -> dict:
    """A launch row: `{slug, launch_id, launched_at}` (#1279 O7)."""
    return {"slug": slug, "launch_id": launch_id, "launched_at": at}


def _id_row(slug: str, launch_id: str, run_id: str) -> dict:
    """The id row of a launch: `{slug, launch_id, run_id}` (#1279 O7)."""
    return {"slug": slug, "launch_id": launch_id, "run_id": run_id}


def _index(path: Path, *rows: tuple[str, str] | dict) -> Path:
    """F holding `rows` oldest first, as JSON Lines. A `(slug, run_id)` pair is a legacy row; a
    dict is written as given (use `_launch_row` / `_id_row`)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(_legacy(*row) if isinstance(row, tuple) else row) + "\n"
                            for row in rows), encoding="utf-8")
    return path


def _rows(text: str | None) -> list[dict]:
    """F's rows, read by the TEST (plain JSON Lines)."""
    if not text:
        return []
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _is_launch(row: dict) -> bool:
    return "launch_id" in row and "run_id" not in row


def _assert_launch_row(row: dict, slug: str = SLUG) -> str:
    """`row` is exactly a launch row for `slug`; returns its launch id."""
    assert set(row) == {"slug", "launch_id", "launched_at"}, f"not a launch row: {row}"
    assert row["slug"] == slug, row
    assert S.is_canonical_uuid(row["launch_id"]), f"launch id is not a UUID: {row}"
    assert isinstance(row["launched_at"], str), row
    assert row["launched_at"], row
    return row["launch_id"]
# The CLI, driven through `held_out.main`

@dataclass
class Outcome(P.CliResult):
    """What one `held_out.main` call did."""

    crashed: BaseException | None = None

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
        body = self.out.partition(f"## {header}")[2].partition("\n")[2]
        return [line.strip() for line in takewhile(
            lambda line: bool(line.strip()) and not line.startswith("#"), body.splitlines())]

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

    def assert_score(self, verdicts: dict[str, str], accuracy: tuple[int, int], *, not_run=()):
        assert self.crashed is None, self.crashed
        assert self.rc == 0, self.said
        assert self.verdicts() == verdicts, self.out
        assert self.accuracy() == accuracy, self.out
        assert self.not_run() == list(not_run), self.out


def _cli(argv: Sequence[object], **seams: Any) -> Outcome:
    from evaluations import held_out

    crashed = None

    def invoke(args):
        nonlocal crashed
        try:
            return held_out.main(args, **seams)
        except SystemExit:
            raise
        except BaseException as exc:  # noqa: BLE001 — injected child failures are observations
            crashed = exc
            return None

    got = P.drive_cli(invoke, list(map(str, argv)))
    return Outcome(got.rc, got.out, got.err, got.raised, crashed)


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
    """The spawn seam's fake (#1279 A6): `spawn(argv, *, env=None, on_line) -> exit code`. It
    streams the child's stdout lines (no terminator) to `on_line`, one at a time, then returns the
    exit code (or raises `raises` after the lines). `lines` is a sequence, or a function of the
    argv that makes it. `seen[i]` is F's text right after line i was delivered, so a test observes
    what was durable while the child was still running."""

    index: Path
    lines: Sequence[str] | Callable[[list[str]], Sequence[str]] = ()
    exit_code: int = 0
    raises: BaseException | None = None
    effect: Callable[[list[str]], None] | None = None
    calls: list[SpawnCall] = field(default_factory=list)
    seen: list[str | None] = field(default_factory=list)
    #: The `env=` each call was handed (`None`: the child inherits the launcher's).
    envs: list[Any] = field(default_factory=list)

    def _text(self) -> str | None:
        return self.index.read_text(encoding="utf-8") if self.index.is_file() else None

    def __call__(self, argv: Sequence[str], *, env: Any = None,
                 on_line: Callable[[str], None], **_: Any) -> int:
        args = [str(a) for a in argv]
        self.calls.append(SpawnCall(args, self._text()))
        self.envs.append(env)
        if self.effect is not None:
            self.effect(args)
        for line in (self.lines(args) if callable(self.lines) else self.lines):
            on_line(line)
            self.seen.append(self._text())
        if self.raises is not None:
            raise self.raises
        return self.exit_code


def _after_run_py(argv: Sequence[str]) -> list[str]:
    """What follows the `run.py` element of the command line `spawn` was handed."""
    names = [Path(a).name for a in argv]
    assert "run.py" in names, f"spawn was not handed a command line that runs run.py: {argv}"
    return list(argv[names.index("run.py") + 1:])


def _assert_run_py_argv(call: SpawnCall, alert: Path) -> None:
    """Assert `call` ran `run.py <alert> --tenant <tenant-uuid> --no-learn` (flags in any order,
    nothing else): a caller never names the run id (#1279 P-B, O5)."""
    rest = _after_run_py(call.argv)
    assert rest, f"run.py was handed no arguments: {call.argv}"
    assert Path(rest[0]).resolve() == alert.resolve(), (
        f"run.py's alert is {rest[0]!r}, not the fixture's {alert}")
    flags = rest[1:]
    assert not any(f.startswith("--run-id") for f in call.argv), f"--run-id on the argv: {call.argv}"
    assert len(flags) == 3, f"run.py's flags are not exactly --tenant/--no-learn: {flags}"
    assert flags.count("--no-learn") == 1, flags
    assert "--tenant" in flags, flags
    assert flags[flags.index("--tenant") + 1] == LAUNCH_TENANT, flags
# The launch scene: the data root, tenant learning state, the operator's own folder

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
        return _cli(["launch", slug, "--tenant", LAUNCH_TENANT, "--index", index, "--fixtures-dir", self.fixtures],
                    spawn=spawn)


@pytest.fixture
def scene(tmp_path: Path, data_root: Path) -> Scene:
    """`DEFENDER_DATA_ROOT` is conftest's per-test root (outside `tmp_path`)."""
    state = Path(data_root) / LAUNCH_TENANT / "learning"
    state.mkdir(parents=True)
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


def _assert_launch_accepted(scene: Scene, index: Path, *, spawn: FakeSpawn,
                            announced: str | None = None) -> str:
    """One launch ran: run.py was started once, with a launch row (and only that) already durable;
    after it F holds `before + [launch row]` plus `announced`'s id row when the child announced it.
    Returns the launch id."""
    before = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
    res = scene.launch(index, spawn)
    if spawn.raises is None:
        assert res.crashed is None, res.said
        assert res.rc == spawn.exit_code, res.said
    else:
        assert res.crashed is spawn.raises
    assert len(spawn.calls) == 1, spawn.calls
    call = spawn.calls[0]
    _assert_run_py_argv(call, scene.alert())
    then = _rows(call.index_then)
    assert then[:len(before)] == before, f"spawn did not follow exactly one launch row: {then}"
    assert len(then) == len(before) + 1, f"spawn did not follow exactly one launch row: {then}"
    launch_id = _assert_launch_row(then[-1])
    expected = [*then, _id_row(SLUG, launch_id, announced)] if announced else then
    assert _rows(index.read_text(encoding="utf-8")) == expected
    return launch_id


@pytest.mark.parametrize("scenario", ["empty", "append-twice", "exit-1", "crash", "interrupt"])
def test_launch_records_each_fresh_launch_before_start_even_when_the_child_fails(scene, scenario):
    index = scene.ops / INDEX_NAME
    if scenario == "append-twice":
        _index(index, (OTHER, S.new_id()))
    prefix = index.read_bytes() if index.exists() else b""
    failures = {"exit-1": {"exit_code": 1}, "crash": {"raises": RuntimeError("run.py crashed")},
                "interrupt": {"raises": KeyboardInterrupt()}}
    ids = [_assert_launch_accepted(scene, index, spawn=FakeSpawn(index, **failures.get(scenario, {})))
           for _ in range(2 if scenario == "append-twice" else 1)]
    assert len(set(ids)) == len(ids), "launches reused a launch id"
    assert index.read_bytes().startswith(prefix), "pre-existing rows were rewritten"


@pytest.mark.parametrize("tenant_id", [None, "playground", LAUNCH_TENANT.upper(), LAUNCH_TENANT.replace("-", "")])
def test_launch_requires_an_explicit_canonical_tenant_before_appending(scene, tenant_id):
    index = scene.ops / INDEX_NAME
    spawn = FakeSpawn(index)
    argv = ["launch", SLUG, "--index", index, "--fixtures-dir", scene.fixtures]
    if tenant_id is not None:
        argv += ["--tenant", tenant_id]
    before = S.tree(scene.tmp)
    refused = _cli(argv, spawn=spawn)
    assert refused.rc == 2, refused.said
    assert refused.crashed is None, refused.crashed
    assert "tenant" in refused.said.casefold(), refused.said
    assert spawn.calls == []
    assert S.tree(scene.tmp) == before, "an invalid tenant changed the index"
    _assert_launch_accepted(scene, index, spawn=FakeSpawn(index))


def test_launch_as_the_operator_runs_it_really_starts_run_py_and_records_a_launch_only(scene):
    index = scene.ops / INDEX_NAME
    before = S.tree(location_path(scene.data_root))
    child = process.run_script(
        S.H5.WORKTREE / "evaluations" / "held_out.py", "launch", SLUG, "--tenant", LAUNCH_TENANT,
        "--index", str(index), "--fixtures-dir", str(scene.fixtures), root=location_path(scene.data_root))
    said = f"{child.stdout}\n{child.stderr}"

    rows = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
    assert [row["slug"] for row in rows] == [SLUG], (
        f"launch did not append one row for {SLUG}: {rows}\n{said[-1500:]}")
    # run.py refuses at tenant acceptance before announcing: an ordinary launch with no id.
    _assert_launch_row(rows[0])
    playground = str(Path(location_path(scene.data_root)) / LAUNCH_TENANT)
    refusals = [line for line in said.splitlines() if "[run.py]" in line and playground in line]
    assert refusals, (
        "launch's real spawn never ran run.py --tenant playground under this data root: no "
        f"refusal of its own naming {playground} in the output:\n{said[-1500:]}")
    assert S.tree(location_path(scene.data_root)) == before, "the refused run.py made something"
# Launch: locations that cannot hold the host-owned index.

_LAUNCH_REFUSALS = (
    "data-root", "natural-run", "foreign-arm", "state-root", "state-descendant",
    "resolved-data-root", "link-index", "link-parent", "link-grandparent", "unset-data-root",
)


def _refused_launch_index(scene: Scene, place: str, monkeypatch) -> tuple[Path, Path]:
    """Return the forbidden spelling and the valid operator spelling used as its control."""
    control = scene.ops / INDEX_NAME
    if place == "unset-data-root":
        monkeypatch.delenv(S.DATA_ROOT_ENV)
        return control, control
    if place == "resolved-data-root":
        real, link = scene.tmp / "real-data-root", scene.tmp / "data-root-link"
        real.mkdir()
        link.symlink_to(real)
        monkeypatch.setenv(S.DATA_ROOT_ENV, str(link))
        return real / INDEX_NAME, control
    if place.startswith("link-"):
        folder = scene.tmp / "elsewhere"
        real = _index(folder / ("deeper/" if place == "link-grandparent" else "") / INDEX_NAME,
                      (OTHER, S.new_id()))
        link = scene.ops / (INDEX_NAME if place == "link-index" else "linked-folder")
        target = real if place == "link-index" else folder
        link.symlink_to(target)
        index = link if place == "link-index" else link / real.relative_to(folder)
        return index, real
    roots = {"data-root": location_path(scene.data_root), "state-root": scene.state,
             "state-descendant": scene.state / "runs" / "some-case"}
    if place == "natural-run":
        root = S.make_run(S.natural_runs(location_path(scene.data_root), LAUNCH_TENANT))
    elif place == "foreign-arm":
        episode = S.make_episode(location_path(scene.data_root), fixture_uuid("tenant:acme"), labels=("a",), arms=True)
        root = next((episode / "runs").iterdir())
    else:
        root = roots[place]
    return _index(root / INDEX_NAME, (OTHER, S.new_id())), control


@pytest.mark.parametrize("place", _LAUNCH_REFUSALS)
def test_launch_refuses_untrusted_index_locations_without_writing_or_spawning(scene, monkeypatch, place):
    original_root = os.environ[S.DATA_ROOT_ENV]
    index, control = _refused_launch_index(scene, place, monkeypatch)
    roots = (location_path(scene.data_root), scene.state, scene.tmp)
    before = {root: S.tree(root) for root in roots}
    spawn = FakeSpawn(index)
    res = scene.launch(index, spawn)
    if place == "unset-data-root":
        assert res.crashed is None
        assert res.rc not in (0, None)
        assert S.DATA_ROOT_ENV in res.said
    else:
        _assert_refused(res, index, place)
    assert spawn.calls == [], "a refused index started run.py"
    assert {root: S.tree(root) for root in roots} == before, "a refused launch changed bytes"
    monkeypatch.setenv(S.DATA_ROOT_ENV, original_root)
    _assert_launch_accepted(scene, control, spawn=FakeSpawn(control))


_INDEX_SWAP_CHILD = """
import json, os, sys
from pathlib import Path
from evaluations import held_out
index, elsewhere, fixtures = map(Path, sys.argv[1:4])
slug, mode = sys.argv[4:6]
tenant_id = sys.argv[7]
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
def spawn(argv, *, env=None, on_line=None):
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
        rc = held_out.main(['launch', slug, '--tenant', tenant_id, '--index', str(index),
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
    child = process.run_script(
        Path("-c"), _INDEX_SWAP_CHILD, str(index), str(elsewhere), str(scene.fixtures),
        SLUG, mode, swap_kind, LAUNCH_TENANT, root=location_path(scene.data_root))
    rows = [line.removeprefix("INDEX_SWAP_RESULT ") for line in child.stdout.splitlines()
            if line.startswith("INDEX_SWAP_RESULT ")]
    assert child.returncode == 0, (
        f"index-swap child failed: {child.stdout[-1500:]} {child.stderr[-1500:]}")
    assert len(rows) == 1, f"missing index-swap result: {child.stdout[-1500:]}"
    return json.loads(rows[0])


def _index_swap_scene(scene: Scene, name: str) -> tuple[Path, Path, Path, bytes]:
    """An operator index and a same-named canary in a simulated box-writable run folder."""
    index = _index(scene.tmp / name / INDEX_NAME, (OTHER, S.new_id()))
    elsewhere = location_path(scene.data_root) / LAUNCH_TENANT / "runs" / S.new_id()
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
    _assert_run_py_argv(SpawnCall(outcome["calls"][0], None), scene.alert())
    _assert_launch_row(_rows(control.read_text(encoding="utf-8"))[-1])
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
        _assert_run_py_argv(SpawnCall(outcome["calls"][0], None), scene.alert())
        assert original.read_bytes().startswith(prefix)
        _assert_launch_row(_rows(original.read_text(encoding="utf-8"))[-1])
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


@pytest.fixture
def scoring(tmp_path: Path) -> tuple[Path, Path, Path]:
    """`(runs dir, index path, ops folder)`: the runs dir scoring is handed, and F in the operator's own folder beside it (outside the runs dir)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    ops = tmp_path / "ops"
    ops.mkdir()
    return runs, ops / INDEX_NAME, ops


@pytest.mark.parametrize(("latest", "verdict", "accuracy"), [
    ("wrong", "WRONG", (0, 1)), ("right", "OK", (1, 1)),
])
def test_scoring_uses_index_order_instead_of_folder_age(tmp_path, scoring, latest, verdict, accuracy):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious"})
    right, wrong = _run(runs, says="malicious"), _run(runs, says="benign")
    os.utime(wrong, (1_800_000_000, 1_800_000_000))
    os.utime(right, (1_800_000_600, 1_800_000_600))
    first, last = (right, wrong) if latest == "wrong" else (wrong, right)
    _index(index, (SLUG, first.name), (SLUG, last.name))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: verdict}, accuracy)
    if latest == "wrong":
        assert "'benign'" in res.line_for(SLUG), res.out


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
    res.assert_score({"absent-case": "WRONG", "recordless-case": "WRONG",
                      "no-report-case": "WRONG", "scored-case": "OK"}, (1, 4))
    failures = res.failures()
    for slug in ("absent-case", "recordless-case"):
        assert NO_RUN_RECORD in failures.get(slug, ""), (
            f"{slug} is not in the {NO_RUN_RECORD!r} bucket:\n{res.out}")
    assert "report.md" in failures.get("no-report-case", ""), res.out
    assert NO_RUN_RECORD not in failures.get("no-report-case", ""), res.out
    assert "scored-case" not in failures, res.out


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
    res.assert_score({OTHER: "OK"}, (1, 1), not_run=[SLUG])


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

@pytest.mark.parametrize("place", ["runs-root", "run-folder", "linked-index-parent", "linked-runs-root"])
def test_scoring_refuses_an_index_inside_its_runs_dir(tmp_path, scoring, place):
    runs, ops_index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    handed, index = runs, runs / INDEX_NAME
    if place == "run-folder":
        index = S.make_run(runs) / INDEX_NAME
    elif place == "linked-index-parent":
        link = tmp_path / "ops-link"
        link.symlink_to(S.make_run(runs))
        index = link / INDEX_NAME
    elif place == "linked-runs-root":
        handed = tmp_path / "runs-link"
        handed.symlink_to(runs)
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


@pytest.mark.parametrize("scope", ["root-unset", "root-relative", "tenant-argument", "links-from-run"])
def test_scoring_depends_only_on_the_index_and_given_runs(tmp_path, scoring, monkeypatch, scope):
    from defender.tenancy._tenant import resolve_data_root

    runs, index, ops = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "benign"})
    good = _run(runs, says="benign")
    _index(index, (SLUG, good.name))
    if scope.startswith("root-"):
        if scope == "root-unset":
            monkeypatch.delenv(S.DATA_ROOT_ENV, raising=False)
        else:
            monkeypatch.setenv(S.DATA_ROOT_ENV, "relative/garbage")
        assert S.raised(resolve_data_root) is not None, "control root unexpectedly resolves"
    elif scope == "links-from-run":
        planted = S.make_run(runs)
        (planted / "points-at-the-index").symlink_to(index)
        (planted / "points-at-its-folder").symlink_to(ops)
    else:
        refused = _score(runs, index, fixtures, "--tenant", LAUNCH_TENANT)
        assert refused.rc == 2, refused.err
        assert "--tenant" in refused.err
        assert refused.verdicts() == {}
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_launch_then_score_counts_a_launch_whose_run_never_started_as_wrong(scene, tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    index = scene.ops / INDEX_NAME
    answers = {SLUG: "malicious", OTHER: "benign"}

    def announcing_a_finished_run(argv: list[str]) -> list[str]:
        slug = Path(_after_run_py(argv)[0]).parent.name
        return [f"run_id={_run(runs, says=answers[slug]).name}"]

    for slug, spawn in ((SLUG, FakeSpawn(index, lines=announcing_a_finished_run)),
                        (OTHER, FakeSpawn(index, lines=announcing_a_finished_run)),
                        (SLUG, FakeSpawn(index, exit_code=1))):
        res = scene.launch(index, spawn, slug)
        assert res.crashed is None, f"the launch crashed: {res.crashed!r}\n{res.err}"
        assert len(spawn.calls) == 1, f"run.py was started {len(spawn.calls)} times for {slug}"

    res = _score(runs, index, scene.fixtures)
    res.assert_score({SLUG: "WRONG", OTHER: "OK"}, (1, 2))
    assert res.failures().get(SLUG, "").startswith(NO_RUN), res.out


# #1279 O7 / P-E (A6): a launch row precedes the spawn; the announced id is recorded as an id row
# while the child still runs; a launch no id row names scores wrong.

NO_RUN = "launched, no run"


def _announce(run_id: str) -> str:
    return f"run_id={run_id}"


def test_1279_a_run_that_fails_before_announcing_its_id_scores_wrong_over_an_older_correct_run(
        scene: Scene):
    """O7: the newest row for the slug is a launch with no id row, so an older correct run cannot
    stand in (preflight or the settings check failed today)."""
    runs = scene.tmp / "runs"
    runs.mkdir()
    yesterday = S.new_id()
    _run(runs, yesterday, says="malicious")
    index = _index(scene.ops / INDEX_NAME, (SLUG, yesterday))
    assert _score(runs, index, scene.fixtures).verdicts()[SLUG] == "OK", "precondition"

    # The real run.py, spawned by the real default: the scene's tenant has no row, so run.py
    # exits at tenant acceptance, before setup mints or announces an id (no stdout line).
    launched = _cli(["launch", SLUG, "--tenant", LAUNCH_TENANT, "--index", index,
                     "--fixtures-dir", scene.fixtures])
    assert launched.crashed is None, launched.crashed
    assert launched.rc not in (0, None), f"a run.py that never started reported success: {launched.said}"

    rows = _rows(index.read_text(encoding="utf-8"))
    assert rows[0] == _legacy(SLUG, yesterday)
    assert len(rows) == 2, rows
    _assert_launch_row(rows[1])

    scored = _score(runs, index, scene.fixtures)
    assert scored.rc == 0, scored.said
    assert scored.verdicts()[SLUG] == "WRONG", scored.out
    assert scored.failures().get(SLUG, "").startswith(NO_RUN), scored.out


def test_1279_the_announced_id_is_recorded_while_the_child_still_runs(scene: Scene):
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    spawn = FakeSpawn(index, lines=[_announce(rid), "first later line", "second later line"],
                      exit_code=3)
    launch_id = _assert_launch_accepted(scene, index, spawn=spawn, announced=rid)
    # F held the id row as soon as the first line was consumed, before any later line, before exit.
    assert len(spawn.seen) == 3
    for text in spawn.seen:
        assert _rows(text)[-1] == _id_row(SLUG, launch_id, rid), spawn.seen
    assert len(_rows(spawn.seen[0])) == len(_rows(spawn.calls[0].index_then)) + 1
    assert len(_rows(spawn.seen[-1])) == len(_rows(spawn.seen[0])), "a later line added a row"


def test_1279_a_launch_and_its_id_row_are_each_synced_to_disk_when_appended(scene: Scene, monkeypatch):
    """O7: the index file itself is fsynced after the launch row and before run.py starts, and
    after the id row before the next line; the last sync of it saw every row."""
    index = scene.ops / INDEX_NAME
    events: list[Any] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        st = os.fstat(fd)
        events.append(("sync", (st.st_dev, st.st_ino),
                       len(_rows(index.read_text(encoding="utf-8") if index.is_file() else None))))
        real_fsync(fd)

    def lines(_argv):
        yield _announce(rid)
        events.append(("after-announce",))
        yield "a later line"
        events.append(("after-later",))

    # `held_out` holds F's folder through the real `_io` over `os`, with no fsync seam: the one
    # targeted patch of this test, a pass-through that records the synced file's identity.
    monkeypatch.setattr(os, "fsync", spy)
    rid = S.new_id()
    spawn = FakeSpawn(index, lines=lines, effect=lambda _argv: events.append(("spawn",)))

    _assert_launch_accepted(scene, index, spawn=spawn, announced=rid)

    st = index.stat()
    ident = (st.st_dev, st.st_ino)
    kinds = [e[0] for e in events]
    assert kinds.count("spawn") == 1, events
    assert "after-later" in kinds, events
    synced = [(k, e[2]) for k, e in enumerate(events) if e[0] == "sync" and e[1] == ident]
    assert synced, f"the index file was never synced: {events}"
    at = {name: kinds.index(name) for name in ("spawn", "after-announce", "after-later")}
    rows_at_spawn = len(_rows(spawn.calls[0].index_then))
    assert any(k < at["spawn"] and n == rows_at_spawn for k, n in synced), (
        f"no sync of the index followed the launch row before run.py started: {events}")
    assert any(at["spawn"] < k < at["after-announce"] and n == rows_at_spawn + 1 for k, n in synced), (
        f"no sync of the index followed the id row before the next line: {events}")
    assert synced[-1][1] == rows_at_spawn + 1, f"the last sync of the index missed a row: {events}"


def test_1279_launch_spawns_run_py_with_no_run_id_in_its_environment(scene: Scene):
    """P-B: the launcher hands the child no run id through its environment, as it hands none on argv."""
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    spawn = FakeSpawn(index, lines=[_announce(rid)])

    _assert_launch_accepted(scene, index, spawn=spawn, announced=rid)

    assert len(spawn.envs) == 1, spawn.envs
    # Name-free: the child gets the inherited environment, nothing added under any name.
    assert spawn.envs[0] is None or dict(spawn.envs[0]) == dict(os.environ), (
        "the launcher added or changed something in the child's environment")


def test_1279_the_announced_id_survives_a_launcher_killed_after_the_announce(scene: Scene):
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    spawn = FakeSpawn(index, lines=[_announce(rid)], raises=KeyboardInterrupt())
    _assert_launch_accepted(scene, index, spawn=spawn, announced=rid)


_ANNOUNCING_CHILD = """
import os, sys, time
print("run_id=" + sys.argv[1])
sys.stdout.flush()
deadline = time.monotonic() + 10
while not os.path.exists(sys.argv[2]):
    if time.monotonic() > deadline:
        sys.exit(9)
    time.sleep(0.02)
"""


def test_1279_a6_the_default_spawn_streams_the_announce_while_the_child_is_alive(scene: Scene):
    """A6/P-E: through the REAL default spawn (`held_out._spawn_run_py`, which is `main`'s default
    `spawn`, asserted below), `launch` has appended the id row while the child is still running.
    The child blocks on a sentinel that a watcher creates after it sees the id row in F; a spawn
    that replays output after exit never gets there: the watcher times out with no id row, so
    `seen_while_alive` stays empty and the assertion fails. (The sentinel is written in `finally`,
    so the child still exits 0 once the watcher gives up; the failure is the empty list.)"""
    import inspect
    import sys
    import threading
    import time

    from evaluations import held_out

    assert inspect.signature(held_out.main).parameters["spawn"].default is held_out._spawn_run_py, (
        "the launch command's default spawn is not the one this test drives")
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    child = scene.tmp / "announcing_child.py"
    child.write_text(_ANNOUNCING_CHILD, encoding="utf-8")
    sentinel = scene.tmp / "id-row-seen"
    seen_while_alive: list[list[dict]] = []

    def watch() -> None:
        try:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                try:
                    rows = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
                except ValueError:  # a line caught half-written; look again
                    time.sleep(0.02)
                    continue
                if any("run_id" in row for row in rows):
                    seen_while_alive.append(rows)
                    break
                time.sleep(0.02)
        finally:  # whatever happened, never leave the child blocked
            sentinel.write_text("go", encoding="utf-8")

    def default_spawn_of_a_stand_in_child(argv: Sequence[str], **kw: Any) -> int:
        # The default spawn is the thing under test; only run.py is swapped for a tiny child.
        return held_out._spawn_run_py([sys.executable, str(child), rid, str(sentinel)], **kw)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    res = scene.launch(index, default_spawn_of_a_stand_in_child)
    watcher.join(timeout=15)

    assert res.crashed is None, res.crashed
    assert seen_while_alive, ("the id row was not in F while the child was alive (a spawn that "
                              f"only replays output after exit?):\n{res.said}")
    assert res.rc == 0, f"the child never saw its sentinel (exit {res.rc}):\n{res.said}"
    rows = _rows(index.read_text(encoding="utf-8"))
    launch_id = _assert_launch_row(rows[0])
    assert rows == [rows[0], _id_row(SLUG, launch_id, rid)]
    assert seen_while_alive[0] == rows


def test_1279_the_rest_of_the_child_stdout_is_forwarded(scene: Scene):
    index = scene.ops / INDEX_NAME
    spawn = FakeSpawn(index, lines=[_announce(S.new_id()), "triage under way", "disposition: benign"])
    res = scene.launch(index, spawn)
    assert res.rc == 0, res.said
    assert "triage under way" in res.out, res.out
    assert "disposition: benign" in res.out, res.out
    assert res.out.index("triage under way") < res.out.index("disposition: benign"), res.out
    assert "announce" not in res.err.casefold(), res.err


def test_1279_a_child_with_no_stdout_is_an_ordinary_launch_without_an_id(scene: Scene):
    index = scene.ops / INDEX_NAME
    for code in (0, 1, 7):
        spawn = FakeSpawn(index, exit_code=code)
        _assert_launch_accepted(scene, index, spawn=spawn)
        assert spawn.seen == []
    assert [_is_launch(r) for r in _rows(index.read_text(encoding="utf-8"))] == [True] * 3


_BROKEN_FIRST_LINES = {
    "chatter": "starting up",
    "empty-line": "",
    "empty-id": "run_id=",
    "not-a-uuid": "run_id=not-a-uuid",
    "slug-as-id": f"run_id={SLUG}",
    "wrong-key": "RUN_ID={rid}",
    "bare-uuid": "{rid}",
    "uppercase-id": "run_id={RID}",
    "undashed-id": "run_id={bare}",
    "braced-id": "run_id={{{rid}}}",
    "trailing-text": "run_id={rid} extra",
    "leading-space": " run_id={rid}",
    "leading-tab": "\trun_id={rid}",
}


@pytest.mark.parametrize("child_code", [0, 1])
@pytest.mark.parametrize("kind", sorted(_BROKEN_FIRST_LINES))
def test_1279_a_broken_first_line_records_nothing_and_fails_the_launch(scene, kind, child_code):
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    first = _BROKEN_FIRST_LINES[kind].format(rid=rid, RID=rid.upper(), bare=rid.replace("-", ""))
    # A valid announce after the broken first line must not repair it: only line one counts.
    spawn = FakeSpawn(index, lines=[first, _announce(rid)], exit_code=child_code)
    res = scene.launch(index, spawn)
    assert res.crashed is None, res.crashed
    assert res.rc not in (0, None), f"{kind}: a broken announce still launched clean:\n{res.said}"
    assert "announce" in res.err.casefold(), f"{kind}: stderr does not name the broken announce:\n{res.err}"
    rows = _rows(index.read_text(encoding="utf-8"))
    assert len(rows) == 1, f"{kind}: more than the launch row was recorded: {rows}"
    _assert_launch_row(rows[0])


def test_1279_only_the_first_line_announces(scene: Scene):
    index = scene.ops / INDEX_NAME
    rid = S.new_id()
    spawn = FakeSpawn(index, lines=[_announce(rid), _announce(S.new_id()), _announce(rid)])
    _assert_launch_accepted(scene, index, spawn=spawn, announced=rid)


def test_1279_no_launch_puts_a_run_id_on_the_childs_argv(scene: Scene):
    index = scene.ops / INDEX_NAME
    for lines in ((), [_announce(S.new_id())], ["junk"]):
        spawn = FakeSpawn(index, lines=lines)
        scene.launch(index, spawn)
        assert not any("run-id" in a or "run_id" in a for a in spawn.calls[0].argv), spawn.calls[0].argv


# Scoring by file position (O7).

@pytest.fixture
def board(tmp_path: Path, scoring) -> tuple[Path, Path, Path]:
    """`(runs, index, fixtures)` with SLUG labelled malicious."""
    runs, index, _ = scoring
    return runs, index, _fixtures(tmp_path / "fixtures", {SLUG: "malicious"})


def _lid() -> str:
    return S.new_id()


def test_1279_a_launch_with_its_id_row_scores_the_run_it_names(board):
    runs, index, fixtures = board
    right, lid = _run(runs, says="malicious"), _lid()
    _index(index, _launch_row(SLUG, lid), _id_row(SLUG, lid, right.name))
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_1279_an_id_row_naming_an_absent_run_scores_in_the_no_run_record_bucket(board):
    runs, index, fixtures = board
    lid = _lid()
    _index(index, _launch_row(SLUG, lid), _id_row(SLUG, lid, S.new_id()))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "WRONG"}, (0, 1))
    assert NO_RUN_RECORD in res.failures().get(SLUG, ""), res.out


def test_1279_a_launch_no_id_row_names_scores_wrong_launched_no_run(board):
    runs, index, fixtures = board
    _index(index, _launch_row(SLUG, _lid()))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "WRONG"}, (0, 1))
    assert res.failures().get(SLUG, "").startswith(NO_RUN), res.out
    assert res.not_run() == [], res.out


def test_1279_a_newer_launch_without_an_id_beats_an_older_launch_with_a_correct_run(board):
    runs, index, fixtures = board
    right, old, new = _run(runs, says="malicious"), _lid(), _lid()
    _index(index, _launch_row(SLUG, old), _id_row(SLUG, old, right.name), _launch_row(SLUG, new))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "WRONG"}, (0, 1))
    assert res.failures().get(SLUG, "").startswith(NO_RUN), res.out


def test_1279_interleaved_launches_launch_1_launch_2_id_for_1_score_wrong(board):
    runs, index, fixtures = board
    right, one, two = _run(runs, says="malicious"), _lid(), _lid()
    _index(index, _launch_row(SLUG, one), _launch_row(SLUG, two), _id_row(SLUG, one, right.name))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "WRONG"}, (0, 1))
    assert res.failures().get(SLUG, "").startswith(NO_RUN), res.out


def test_1279_interleaved_launches_score_the_newest_launchs_own_id_row(board):
    runs, index, fixtures = board
    right, wrong = _run(runs, says="malicious"), _run(runs, says="benign")
    one, two = _lid(), _lid()
    _index(index, _launch_row(SLUG, one), _launch_row(SLUG, two),
           _id_row(SLUG, two, right.name), _id_row(SLUG, one, wrong.name))
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_1279_file_position_decides_not_launched_at(board):
    runs, index, fixtures = board
    right, wrong = _run(runs, says="malicious"), _run(runs, says="benign")
    one, two = _lid(), _lid()
    # The later row carries the EARLIER time; position wins.
    _index(index, _launch_row(SLUG, one, "2026-10-24T12:00:00+00:00"), _id_row(SLUG, one, wrong.name),
           _launch_row(SLUG, two, "2026-10-24T08:00:00+00:00"), _id_row(SLUG, two, right.name))
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_1279_legacy_rows_are_still_admitted_and_scored_as_before(board):
    runs, index, fixtures = board
    wrong, right = _run(runs, says="benign"), _run(runs, says="malicious")
    _index(index, (SLUG, wrong.name), (SLUG, right.name))
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_1279_a_launch_after_legacy_rows_is_the_newest(board):
    runs, index, fixtures = board
    right = _run(runs, says="malicious")
    _index(index, (SLUG, right.name), _launch_row(SLUG, _lid()))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "WRONG"}, (0, 1))
    assert res.failures().get(SLUG, "").startswith(NO_RUN), res.out


def test_1279_a_legacy_row_after_launches_is_the_newest(board):
    runs, index, fixtures = board
    wrong, right, lid = _run(runs, says="benign"), _run(runs, says="malicious"), _lid()
    _index(index, _launch_row(SLUG, lid), _id_row(SLUG, lid, wrong.name), (SLUG, right.name))
    _score(runs, index, fixtures).assert_score({SLUG: "OK"}, (1, 1))


def test_1279_each_slug_is_judged_by_its_own_newest_launch(tmp_path, scoring):
    runs, index, _ = scoring
    fixtures = _fixtures(tmp_path / "fixtures", {SLUG: "malicious", OTHER: "benign"})
    ok, lid, crashed = _run(runs, says="malicious"), _lid(), _lid()
    _index(index, _launch_row(SLUG, lid), _launch_row(OTHER, crashed), _id_row(SLUG, lid, ok.name))
    res = _score(runs, index, fixtures)
    res.assert_score({SLUG: "OK", OTHER: "WRONG"}, (1, 2))
    assert res.failures().get(OTHER, "").startswith(NO_RUN), res.out


def _refused_rows(kind: str, run_id: str) -> list[dict]:
    one, two = _lid(), _lid()
    return {
        "id-before-its-launch": [_id_row(SLUG, one, run_id), _launch_row(SLUG, one)],
        "id-names-no-launch": [_launch_row(SLUG, one), _id_row(SLUG, two, run_id)],
        "id-names-no-launch-at-all": [_id_row(SLUG, one, run_id)],
        "two-id-rows-for-one-launch": [_launch_row(SLUG, one), _id_row(SLUG, one, run_id),
                                       _id_row(SLUG, one, S.new_id())],
        "same-id-row-twice": [_launch_row(SLUG, one), _id_row(SLUG, one, run_id),
                              _id_row(SLUG, one, run_id)],
        "repeated-launch-id": [_launch_row(SLUG, one), _launch_row(SLUG, one)],
        "repeated-launch-id-across-slugs": [_launch_row(SLUG, one), _launch_row(OTHER, one)],
        "id-row-run-id-not-canonical": [_launch_row(SLUG, one), _id_row(SLUG, one, "not-a-uuid")],
        "launch-id-not-text": [{**_launch_row(SLUG, one), "launch_id": 7}],
        "id-slug-differs-from-its-launch": [_launch_row(SLUG, one), _id_row(OTHER, one, run_id)],
        "launch-without-launched-at": [{"slug": SLUG, "launch_id": one}],
        "launched-at-not-text": [{**_launch_row(SLUG, one), "launched_at": 7}],
        "mixed-launch-and-id-row": [{**_launch_row(SLUG, one), "run_id": run_id}],
        "mixed-row-after-its-launch": [_launch_row(SLUG, one),
                                       {**_launch_row(SLUG, one), "run_id": run_id}],
        "extra-key-on-a-launch-row": [{**_launch_row(SLUG, one), "note": "x"}],
        "extra-key-on-an-id-row": [_launch_row(SLUG, one),
                                   {**_id_row(SLUG, one, run_id), "note": "x"}],
        "extra-key-on-a-legacy-row": [{**_legacy(SLUG, run_id), "note": "x"}],
    }[kind]


@pytest.mark.parametrize("kind", [
    "id-before-its-launch", "id-names-no-launch", "id-names-no-launch-at-all",
    "two-id-rows-for-one-launch", "same-id-row-twice", "repeated-launch-id",
    "repeated-launch-id-across-slugs", "id-row-run-id-not-canonical", "launch-id-not-text",
    "id-slug-differs-from-its-launch", "launch-without-launched-at", "launched-at-not-text",
    "mixed-launch-and-id-row", "mixed-row-after-its-launch", "extra-key-on-a-launch-row",
    "extra-key-on-an-id-row", "extra-key-on-a-legacy-row"])
def test_1279_scoring_refuses_an_index_that_cannot_be_trusted(board, kind):
    runs, index, fixtures = board
    good = _run(runs, says="malicious")
    _index(index, *_refused_rows(kind, good.name))
    res = _score(runs, index, fixtures)
    _assert_refused(res, index, kind)
    assert res.verdicts() == {}, f"{kind}: scoring went ahead:\n{res.out}"
    assert res.accuracy() is None, f"{kind}: scoring went ahead:\n{res.out}"
