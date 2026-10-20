"""Held-out launches record opaque run IDs before execution and scoring reads that index."""
from __future__ import annotations

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
    """Assert `call` ran `run.py <alert> --tenant <tenant-uuid> --run-id <uuid> --no-learn` (flags in any order, nothing else), and return the uuid."""
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


def _assert_launch_accepted(scene: Scene, index: Path, *, spawn: FakeSpawn) -> str:
    before = _rows(index.read_text(encoding="utf-8") if index.is_file() else None)
    res = scene.launch(index, spawn)
    if spawn.raises is None:
        assert res.crashed is None, res.said
        assert res.rc == spawn.exit_code, res.said
    else:
        assert res.crashed is spawn.raises
    assert len(spawn.calls) == 1, spawn.calls
    call = spawn.calls[0]
    run_id = _launched_run_id(call, scene.alert())
    assert _rows(call.index_then) == [*before, (SLUG, run_id)], "spawn preceded its index row"
    assert _rows(index.read_text(encoding="utf-8")) == [*before, (SLUG, run_id)]
    return run_id


@pytest.mark.parametrize("scenario", ["empty", "append-twice", "exit-1", "crash", "interrupt"])
def test_launch_records_each_fresh_id_before_start_even_when_the_child_fails(scene, scenario):
    index = scene.ops / INDEX_NAME
    if scenario == "append-twice":
        _index(index, (OTHER, S.new_id()))
    prefix = index.read_bytes() if index.exists() else b""
    failures = {"exit-1": {"exit_code": 1}, "crash": {"raises": RuntimeError("run.py crashed")},
                "interrupt": {"raises": KeyboardInterrupt()}}
    ids = [_assert_launch_accepted(scene, index, spawn=FakeSpawn(index, **failures.get(scenario, {})))
           for _ in range(2 if scenario == "append-twice" else 1)]
    assert len(set(ids)) == len(ids), "launches reused an ID"
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


def test_launch_as_the_operator_runs_it_really_starts_run_py(scene):
    index = scene.ops / INDEX_NAME
    before = S.tree(scene.data_root)
    child = process.run_script(
        S.H5.WORKTREE / "evaluations" / "held_out.py", "launch", SLUG, "--tenant", LAUNCH_TENANT,
        "--index", str(index), "--fixtures-dir", str(scene.fixtures), root=scene.data_root)
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
    roots = {"data-root": scene.data_root, "state-root": scene.state,
             "state-descendant": scene.state / "runs" / "some-case"}
    if place == "natural-run":
        root = S.make_run(S.natural_runs(scene.data_root, LAUNCH_TENANT))
    elif place == "foreign-arm":
        episode = S.make_episode(scene.data_root, fixture_uuid("tenant:acme"), labels=("a",), arms=True)
        root = next((episode / "runs").iterdir())
    else:
        root = roots[place]
    return _index(root / INDEX_NAME, (OTHER, S.new_id())), control


@pytest.mark.parametrize("place", _LAUNCH_REFUSALS)
def test_launch_refuses_untrusted_index_locations_without_writing_or_spawning(scene, monkeypatch, place):
    original_root = os.environ[S.DATA_ROOT_ENV]
    index, control = _refused_launch_index(scene, place, monkeypatch)
    roots = (scene.data_root, scene.state, scene.tmp)
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
        SLUG, mode, swap_kind, LAUNCH_TENANT, root=scene.data_root)
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
    res.assert_score({SLUG: "WRONG", OTHER: "OK"}, (1, 2))
    assert NO_RUN_RECORD in res.failures().get(SLUG, ""), res.out
