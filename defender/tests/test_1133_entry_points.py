"""#1133 — each migrated write, through its real entry point and its rev-2 signature (D3'),
refuses a planted link and writes nothing where it points (O1, O2, O3, O4, D1', D2', D3').

`test_1133_episode_handle.py` pins the handle's guard matrix on the handle itself; this suite
pins that each MIGRATED SITE still reaches it. A site silently reverted to a link-following
write (builtin `open(path, "w")`, `os.makedirs`) passes every handle test, so each site is driven
here through the smallest real entry point, with its own injection seams (`cli.main`'s
`questioner=` / `door=` / `adapters=` / `invoke=` / `spawn=`, `start_family`'s `spawn=`,
`prepare_episode`'s `prime=`, `grade_episode`'s `judge=`, the `Episode`'s `io=`) and never
`monkeypatch.setattr`. Every plant is a real filesystem entry, and every negative is paired with
a positive control on the same address.

The writers take the `Episode` now (D3'): `start_family(episode, ...)`,
`verify_family(episode, ...)`, `archive_episode(episode, run_dirs)`,
`record_staged(episode, row)`, `prime_base(source_run_dir, episode)`,
`load_family(episode)` / `manifest_digest(episode)` / `check_manifest_digest(episode, digest)`;
`prepare_episode(...)` returns the `Episode`. The doors keep their path signatures:
`cli.main`, `grade_episode(episode_dir, ...)`.

Every link is planted twice over: pointing at a host folder OUTSIDE the episode, and at a folder
elsewhere INSIDE the episode. An owner accessor's containment resolve stops an outside link, so
only the inside one reaches a reverted write, and only the handle's no-follow walk refuses both.

- H1 the migrated sites: a symlink at a folder the site ensures, or at a holding folder of it;
  a symlink (live or dangling) at a record the site writes. The entry point refuses (or, where
  the site is best-effort, contains the refusal), what the link reaches is unchanged, and the
  plant is left in place: `cli.start_family`'s `runs.ensure()`, `cli.verify_family`'s
  `worlds.ensure()` and family stamp, the rejected episode's `worlds.ensure()`,
  `archive.archive_episode`'s `world.dir.ensure()` and run-dir pointer, the judge's two
  `draws.ensure()`, its draw write, its framed wire log (contained) and `judge.yaml`.
- O3 / O6 through the judge's door: while the judge is paid, exactly one descriptor is open on
  the episode dir (the pass reads through its own `Episode`'s view, never a second `bind` by
  path); and a pass whose episode dir is renamed mid-pass writes its draws and `judge.yaml` in
  the moved folder (no writer reopens the episode by name).
- H2 `review.review`'s default write (no seam injected) is the episode's `review` record.
- H3 `staging.record_staged(episode, row)` is D1's `staged: append_durable`: through the `io=`
  seam, its ONE held call is `write(LAYOUT.staged, <row>, mode="append", durable=True)`, on the
  episode the caller holds (no second `hold`).
- H4 the priming claim alone keeps a second launcher out while the first primes; the primed base
  alone refuses a rival base that lands just before its create (a recording `Held` plants it,
  then delegates the create — D7' replaces rev 1's FIFO interleaving, S3).
- H5 the manifest readers (`load_family`, `manifest_digest`, `check_manifest_digest`), handed the
  `Episode`, refuse a symlink or a hard link at `family.yaml` without reading what it reaches.
- H7 `defender._io.Bound`'s public surface is exactly `read`, `read_jsonl`, `entries`, `under`,
  `close` (O3) — for a `bind` and for `episode.view()`.

The census that holds every migrated module to the handle is `test_1133_census.py`.

Red before rev 2: every site handed an `Episode` (rev 1's signatures take paths), H3, H4's
returned `Episode` and the H4 base test. Green today and pinned to stay: the sites driven through
`cli.main` / `grade_episode` (H1 launcher and judge rows, H2).
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import json
import logging
import os
import shutil
import stat
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender._episode_paths import LAYOUT
from defender._run_paths import WIRE_LOG_NAMES
from defender.tests import _judge_921 as J
from defender.tests import _spec1133 as S
from defender.tests import _triplet_947 as T
from defender.tests.test_947_capture_prime import append_call, call_row, source_run

EPISODE_ID = "ep-1133"
#: Where a primer waits for its rival, and a launcher for the other: generous, since a wedged
#: wait costs one failed test, never a hung worker.
WAIT = 10.0
#: Where a planted link points: a host folder outside the episode, or a folder elsewhere inside
#: it (see the module docstring).
REACH = ("outside", "inside")
#: A link at a record's own name: to a file, or dangling (a write that followed it would CREATE
#: its target).
LEAF_LINKS = ("symlink", "dangling")


@pytest.fixture
def roots(tmp_path, monkeypatch):
    """The configured roots inside `tmp_path` (environment steering, the resolvers' own seam):
    the runs base, the episodes root and the learning state root the judge's queue lands in."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


@pytest.fixture
def host(tmp_path: Path) -> Path:
    """A host folder outside every episode: where an outside link points."""
    h = tmp_path / "host"
    h.mkdir()
    (h / "keep").write_bytes(S.HOST_BYTES)
    return h


@dataclasses.dataclass
class Linked:
    """A symlink planted at `link`, and what it reaches."""

    link: Path
    target: Path
    reach: str

    def state(self) -> tuple:
        """What the link reaches, judged without following: a folder's whole tree, a file's
        bytes and link count, or its absence."""
        if self.target.is_dir() and not self.target.is_symlink():
            return ("folder", S.census(self.target))
        if os.path.lexists(self.target):
            st = os.lstat(self.target)
            return ("file", self.target.read_bytes(), st.st_nlink)
        return ("absent",)

    def assert_left(self) -> None:
        assert self.link.is_symlink(), f"the link planted at {self.link} was replaced or removed"
        assert os.readlink(self.link) == str(self.target), (
            f"the link planted at {self.link} was repointed")

    def remove(self) -> None:
        self.link.unlink()


def _base(reach: str, ep: Path, host: Path) -> Path:
    return host if reach == "outside" else ep


def _clear(at: Path) -> None:
    at.parent.mkdir(parents=True, exist_ok=True)
    if at.is_symlink() or at.is_file():
        at.unlink()
    elif at.is_dir():
        shutil.rmtree(at)


def link_folder(at: Path, *, reach: str, ep: Path, host: Path) -> Linked:
    """A symlink at `at` (the folders above it made real; anything already there replaced) to a
    real folder holding one file, outside the episode or elsewhere inside it."""
    target = _base(reach, ep, host) / f"elsewhere-{at.relative_to(ep).as_posix().replace('/', '-')}"
    target.mkdir()
    (target / "keep").write_bytes(S.HOST_BYTES)
    _clear(at)
    at.symlink_to(target, target_is_directory=True)
    return Linked(at, target, reach)


def link_file(at: Path, kind: str, *, reach: str, ep: Path, host: Path) -> Linked:
    """A symlink at `at` to a file holding `HOST_BYTES` (`symlink`) or to nothing (`dangling`),
    outside the episode or elsewhere inside it."""
    target = _base(reach, ep, host) / f"elsewhere-{at.relative_to(ep).as_posix().replace('/', '-')}"
    if kind == "symlink":
        target.write_bytes(S.HOST_BYTES)
    _clear(at)
    at.symlink_to(target)
    return Linked(at, target, reach)


def assert_folder_refusal(exc: BaseException | None, planted: Linked, *, where: str) -> None:
    """The refusal of a link at a folder. An inside link reaches the handle, whose walk answers
    the core's row for it; an outside one may be stopped sooner by an owner accessor's own
    containment resolve (a marked ELOOP) — refused either way."""
    refused = refusal_in(exc)
    if planted.reach == "inside":
        S.assert_refusal(refused, "folder_link_inside", where=where)
        return
    assert refused is not None, f"{where}: a link outside the episode was not refused ({exc!r})"
    assert refused.errno == errno.ELOOP, f"{where}: {refused!r} is not a link refusal"


def assert_plain_file(path: Path) -> None:
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path} is not a regular file"
    assert st.st_nlink == 1, f"{path} has {st.st_nlink} names"


def assert_real_folder(path: Path) -> None:
    assert not path.is_symlink(), f"{path} is a link"
    assert path.is_dir(), f"{path} is not a folder"


refusal_in = S.refusal_in
warned = S.warned


def branch_cli() -> Any:
    return T.mod("learning.branch.cli")


# =======================================================================================
# H1 — the launcher's folders: the siblings' runs base, `worlds/`
# =======================================================================================

class Spawned:
    """`start_family`'s process seam: records each child it was asked to start."""

    def __init__(self) -> None:
        self.argvs: list[list[str]] = []
        self._lock = threading.Lock()

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        with self._lock:
            self.argvs.append(list(argv))
        return 0


@pytest.mark.parametrize("reach", REACH)
def test_h1_start_family_refuses_a_linked_runs_base_and_starts_no_sibling_there(
        tmp_path, host, reach):
    """`start_family` makes the siblings' runs base with `episode.runs.ensure()`, which refuses
    a link at `runs/`: the core's unmarked ELOOP, raised before the runs-base tenant record is
    minted and before any sibling starts. The folder the link reaches gains nothing (no
    `_tenant.json`) and the link is left.

    A reverted `os.makedirs(runs, exist_ok=True)` accepts the link, mints the tenant record in
    the folder it reaches and hands that folder to every sibling as its runs base.

    Control on the same address: with nothing planted, `runs/` is a real folder holding the
    episode tenant's record and both siblings are started."""
    cli = branch_cli()
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    planted = link_folder(ep / "runs", reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    spawn = Spawned()

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: cli.start_family(
            episode, ["b", "c"], spawn=spawn, tenant_id="acme",
            tenants_root=tmp_path / "tenants"))

    assert_folder_refusal(raised, planted, where="start_family over a linked runs/")
    assert spawn.argvs == [], f"a sibling started over a linked runs base: {spawn.argvs}"
    assert planted.state() == before, "start_family wrote into the folder the runs/ link reaches"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        exits = cli.start_family(episode, ["b", "c"], spawn=spawn, tenant_id="acme",
                                 tenants_root=tmp_path / "tenants")
    assert exits == {"b": 0, "c": 0}
    assert len(spawn.argvs) == 2
    assert_real_folder(ep / "runs")
    assert T.mod("_tenant").read_tenant(ep / "runs").tenant_id == "acme"


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("scrub_ran", [False, True], ids=["nothing-to-archive", "verified"])
def test_h1_verify_family_refuses_a_linked_worlds_folder_before_anything_is_archived(
        tmp_path, host, scrub_ran, reach):
    """`verify_family` makes `worlds/` with `episode.worlds.ensure()` whatever the outcome,
    before the archive: a link at `worlds/` is refused there, so the folder it reaches gains no
    world (with no scrub-verified sibling the refusal is this site's alone: nothing else walks
    `worlds/`) and the link is left.

    A reverted `os.makedirs(worlds, exist_ok=True)` accepts the link and returns the report
    (and, with verified siblings, archives them into the folder the link reaches).

    Control on the same address: with nothing planted, `worlds/` is a real folder."""
    cli = branch_cli()
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(ep / "runs", w, scrub_ran=scrub_ran) for w in T.WORLDS]
    planted = link_folder(ep / "worlds", reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: cli.verify_family(episode, dirs,
                                                       source=T.provenance_record()))

    assert_folder_refusal(raised, planted, where="verify_family over a linked worlds/")
    assert planted.state() == before, "verify_family wrote into the folder worlds/ reaches"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        report = cli.verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == ("accepted" if scrub_ran else "incomplete")
    assert_real_folder(ep / "worlds")
    if scrub_ran:
        assert sorted(p.name for p in (ep / "worlds").iterdir()) == sorted(T.WORLDS)


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_the_family_stamp_refuses_a_link_at_its_name_and_writes_nothing_through_it(
        tmp_path, host, kind, reach):
    """An accepted family's stamp is `episode.family_stamp.write(...)`: a link at
    `provenance.json` is the core's marked ELOOP out of `verify_family`, the file it reaches
    keeps its bytes (a dangling link's target is not created) and the link is left.

    A reverted `open(path, "w")` writes the stamp through the link.

    Control on the same address: with nothing planted, the stamp is a plain, single-linked file
    carrying the agreed commit."""
    cli = branch_cli()
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(ep / "runs", w, commit="cafe1") for w in T.WORLDS]
    planted = link_file(ep / "provenance.json", kind, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: cli.verify_family(
            episode, dirs, source=T.provenance_record(commit="cafe1")))

    S.assert_refusal(refusal_in(raised), kind, where="the family stamp over a link")
    assert planted.state() == before, "the family stamp was written through the link"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        cli.verify_family(episode, dirs, source=T.provenance_record(commit="cafe1"))
    stamp = ep / "provenance.json"
    assert_plain_file(stamp)
    assert json.loads(stamp.read_text(encoding="utf-8"))["agreed"]["commit"] == "cafe1"


# ---- the rejected episode, through the launcher --------------------------------------------

def launch(tmp_path: Path, *, before: Any = None, **seams: Any) -> tuple[Any, Path, Any]:
    """One episode through the real launcher (`cli.main`), every model and cluster seam faked.
    `before(ep)` runs once the episode's path is known and before the launch. Answers the exit
    status, or the refusal `main` raised (an operator exit is a `SystemExit`)."""
    cli = branch_cli()
    _base, src = T.runs_base(tmp_path)
    ep = cli.episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant_paths())
    if before is not None:
        before(ep)
    spawn = T.FakeSpawn()
    seams.setdefault("questioner", T.FakeAgent(T.family_doc(), T.world_doc("b"),
                                               T.world_doc("c")))
    seams.setdefault("adapters", T.FakeAdapters())
    seams.setdefault("invoke", T.FakeAgent(*["same"] * 24))
    try:
        outcome: Any = cli.main(
            [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
            spawn=spawn, door=T.FakeDoor(), preflight=T.no_preflight,
            live_tree=T.source_capture(), **seams)
    except (SystemExit, Exception) as refused:  # noqa: BLE001 — the refusal is the observation
        outcome = refused
    return outcome, ep, spawn


def rejecting_seams() -> dict[str, Any]:
    """A family whose world `b` the review rejects (an exclusion matching no base document,
    `test_947_a_rejected_world_ends_the_episode_and_the_record_archives`)."""
    fam = T.family_doc(worlds=[
        T.base_world(),
        T.world_doc("b", ov=T.overlay(elastic=T.elastic_overlay(exclude={"match_all": {}}))),
    ])
    return {
        "adapters": T.FakeAdapters(by_target={T.world_token("b"): {"hits": [{"_id": "p"}]}}),
        "questioner": T.FakeAgent(fam, T.world_doc("b")),
        "invoke": T.FakeAgent(*["contradiction"] * 24),
    }


@pytest.mark.parametrize("reach", REACH)
def test_h1_a_rejected_episode_refuses_a_linked_worlds_folder(tmp_path, roots, host, reach):
    """A rejected episode still makes `worlds/`, with `episode.worlds.ensure()`: a link planted
    there before the launch is refused, which ends the launch as a refusal (not the quiet
    rejected exit); no sibling starts, the folder the link reaches gains nothing and the link
    is left.

    A reverted `os.makedirs(worlds, exist_ok=True)` accepts the link and the launch exits 1 as
    if nothing were planted."""
    holder: dict[str, Any] = {}

    def plant(ep: Path) -> None:
        ep.mkdir(parents=True, exist_ok=True)
        holder["planted"] = link_folder(ep / "worlds", reach=reach, ep=ep, host=host)
        holder["before"], holder["host"] = holder["planted"].state(), S.census(host)

    outcome, ep, spawn = launch(tmp_path, before=plant, **rejecting_seams())
    planted = holder["planted"]

    assert T.review_doc(ep)["episode"]["decision"] == "rejected", (
        "the scenario did not reach the rejected-episode path")
    assert isinstance(outcome, BaseException), (
        f"the launch exited {outcome!r} over a linked worlds/ — the rejected episode's "
        "worlds.ensure() accepted the link instead of refusing it")
    assert_folder_refusal(outcome, planted, where="the rejected episode's worlds/ ensure")
    assert spawn.launches == []
    assert planted.state() == holder["before"], (
        "the rejected episode wrote into the folder the worlds/ link reaches")
    assert S.census(host) == holder["host"]
    planted.assert_left()


def test_h1_a_rejected_episode_makes_a_real_worlds_folder(tmp_path, roots):
    """Control for the test above, on the same address: nothing planted, the same family is
    the ordinary rejected exit and `worlds/` is a real folder."""
    outcome, ep, spawn = launch(tmp_path, **rejecting_seams())
    assert outcome == 1, outcome
    assert T.review_doc(ep)["episode"]["decision"] == "rejected"
    assert spawn.launches == []
    assert_real_folder(ep / "worlds")


# =======================================================================================
# H1 — the archive
# =======================================================================================

@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("at", ["worlds", "worlds/b"])
def test_h1_the_archive_refuses_a_linked_world_folder_and_copies_nothing_through_it(
        tmp_path, host, at, reach):
    """`archive_episode` makes each world's folder with `episode.world(label).dir.ensure()`,
    which refuses a link at `worlds/` or at `worlds/<label>/` before the copy lane runs: the
    folder the link reaches gains no world artifact, and the link is left.

    A reverted `os.makedirs(world_dir, exist_ok=True)` makes (or accepts) the world folder
    through an inside link, and the copy lane writes the world's artifacts there.

    Control on the same address: with nothing planted the world is archived into a real
    folder."""
    archive = T.mod("learning.branch.archive")
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(ep / "runs", "b")
    if at == "worlds/b":
        (ep / "worlds").mkdir(exist_ok=True)
    planted = link_folder(ep / at, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: archive.archive_episode(episode, {"b": run_dir}))

    assert_folder_refusal(raised, planted, where=f"the archive over a link at {at}")
    assert planted.state() == before, f"the archive wrote through the link at {at}"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        archived = archive.archive_episode(episode, {"b": run_dir})
    world = ep / "worlds" / "b"
    assert archived == {"b": world}
    assert_real_folder(world)
    assert (world / "report.md").is_file()


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_the_archive_refuses_a_link_at_the_run_dir_pointer(tmp_path, host, kind, reach):
    """The pointer is written last, with `episode.world(label).run_dir_pointer.write(...)`: a
    link at `worlds/<label>/run_dir` (which the copy lane's destination screen does not judge)
    is the core's marked ELOOP, the file it reaches keeps its bytes (a dangling link's target is
    not created) and the link is left.

    A reverted `open(pointer, "w")` writes the run dir's path through the link.

    Control on the same address: the pointer is a plain file naming the run dir."""
    archive = T.mod("learning.branch.archive")
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(ep / "runs", "b")
    planted = link_file(ep / "worlds" / "b" / "run_dir", kind, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: archive.archive_episode(episode, {"b": run_dir}))

    S.assert_refusal(refusal_in(raised), kind, where="the archive's run_dir pointer over a link")
    assert planted.state() == before, "the run_dir pointer was written through the link"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        archive.archive_episode(episode, {"b": run_dir})
    pointer = ep / "worlds" / "b" / "run_dir"
    assert_plain_file(pointer)
    assert pointer.read_text(encoding="utf-8") == f"{run_dir}\n"


# =======================================================================================
# H1 — the judge
# =======================================================================================

class ScriptedJudge:
    """The judge seam (`judge=`): a good reply for every call — or, for a label in `failing`, a
    raised call, which the pass records as a failed draw — recording each agent id, and running
    `on_first()` once, on the first call (a plant made mid-pass)."""

    def __init__(self, on_first: Any = None, *, failing: tuple[str, ...] = ()) -> None:
        self.reply = J.as_reply_text(J.reply_doc())
        self.on_first = on_first
        self.failing = failing
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.agent_ids.append(agent_id)
        if self.on_first is not None:
            act, self.on_first = self.on_first, None
            act()
        if agent_id.split(":")[1] in self.failing:
            raise RuntimeError(f"{agent_id}: the model call failed")
        return self.reply

    def called_for(self, label: str) -> list[str]:
        return [a for a in self.agent_ids if a.startswith(f"judge:{label}:")]


def judged_episode(tmp_path: Path) -> Path:
    """An accepted, archived episode whose world `b` is graded (it carries a staged row)."""
    return J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})


def grade(tmp_path: Path, ep: Path, judge: ScriptedJudge) -> Any:
    """The judge pass, or the refusal it raised."""
    try:
        return J.mod("learning.judge").grade_episode(
            ep, judge=judge, runs_base=tmp_path / "defender-runs", draws=2)
    except Exception as refused:  # noqa: BLE001 — the refusal is the observation
        return refused


def regrade(tmp_path: Path, ep: Path, judge: ScriptedJudge) -> Any:
    """The pass again, its earlier record removed (a recorded grade short-circuits the pass)."""
    with contextlib.suppress(FileNotFoundError):
        (ep / "judge.yaml").unlink()
    got = grade(tmp_path, ep, judge)
    assert not isinstance(got, BaseException), f"the control pass was refused: {got!r}"
    return got


@pytest.mark.parametrize("reach", REACH)
def test_h1_a_linked_world_draws_folder_is_refused_before_any_draw_is_paid_for(
        tmp_path, roots, host, reach):
    """The world's prompt is prepared with `episode.world(label).draws.ensure()`: a link at
    `worlds/b/judge/` is refused there, contained to world `b` — recorded as its
    `draws_failed_reason`, zero draws — so the judge is never called for `b`, the folder the
    link reaches gains no draw and the link is left.

    A reverted `os.makedirs(draws, exist_ok=True)` accepts an inside link, pays for `b`'s draws
    and writes them where the link points (or refuses only at the draw write, after paying).

    Control on the same address: with nothing planted, `b`'s draws land in a real folder."""
    ep = judged_episode(tmp_path)
    planted = link_folder(ep / "worlds" / "b" / "judge", reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    judge = ScriptedJudge()

    got = grade(tmp_path, ep, judge)

    assert not isinstance(got, BaseException), f"the pass was refused: {got!r}"
    assert judge.called_for("b") == [], (
        f"the judge was paid for world b's draws over a linked draws folder: "
        f"{judge.called_for('b')}")
    row = J.world_rows(J.judge_record(ep))["b"]
    assert row["completed_draws"] == 0, row
    assert str(row.get("draws_failed_reason", "")).startswith("OSError"), (
        f"world b's setup refusal was not recorded: {row}")
    assert planted.state() == before, "a draw was written into the folder the link reaches"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    judge = ScriptedJudge()
    regrade(tmp_path, ep, judge)
    assert judge.called_for("b") == ["judge:b:0", "judge:b:1"]
    draws = ep / "worlds" / "b" / "judge"
    assert_real_folder(draws)
    assert sorted(p.name for p in draws.iterdir()) == ["0.yaml", "1.yaml"]


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("at", ["worlds/family", "worlds/family/judge"])
def test_h1_a_linked_family_draws_folder_is_refused_and_contained_to_the_family_call(
        tmp_path, roots, host, at, reach):
    """The family-level call makes its folder with `episode.world("family").draws.ensure()`:
    a link at `worlds/family/` or `worlds/family/judge/` is refused and contained to the family
    call — recorded as `family_failed_reason` — so the judge is never called for it, the folder
    the link reaches gains nothing and the link is left.

    A reverted `os.makedirs(draws, exist_ok=True)` makes the draws folder through an inside
    link and writes the family's draws there.

    Control on the same address: with nothing planted, the family's draws land in a real
    `worlds/family/judge/` (each call here fails, which the pass records as a draw)."""
    ep = judged_episode(tmp_path)
    if at == "worlds/family/judge":
        (ep / "worlds" / "family").mkdir(parents=True, exist_ok=True)
    planted = link_folder(ep / at, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    judge = ScriptedJudge(failing=("family",))

    got = grade(tmp_path, ep, judge)

    assert not isinstance(got, BaseException), f"the pass was refused: {got!r}"
    assert judge.called_for("family") == [], (
        f"the judge was paid for the family call over a linked folder: "
        f"{judge.called_for('family')}")
    reason = J.judge_record(ep).get("family_failed_reason") or ""
    assert reason.startswith("OSError"), (
        f"the family call's setup refusal was not recorded: {reason!r}")
    assert planted.state() == before, f"the family call wrote through the link at {at}"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    judge = ScriptedJudge(failing=("family",))
    regrade(tmp_path, ep, judge)
    assert judge.called_for("family") == ["judge:family:0", "judge:family:1"]
    draws = ep / "worlds" / "family" / "judge"
    assert_real_folder(draws)
    assert sorted(p.name for p in draws.iterdir()) == ["0.yaml", "1.yaml"]


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_a_link_at_a_draws_name_refuses_the_pass_and_is_written_through_by_nothing(
        tmp_path, roots, host, kind, reach):
    """A good draw is written with `episode.world(label).draw(n).write(...)`, and a link at its
    sink is not contained: the pass is refused (`JudgeRefused` over the core's marked ELOOP),
    the file the link reaches keeps its bytes (a dangling link's target is not created) and the
    link is left.

    A reverted `open(draw, "w")` writes the draw through an inside link and the pass completes.

    Control on the same address: the draw lands as a plain file."""
    ep = judged_episode(tmp_path)
    planted = link_file(ep / "worlds" / "b" / "judge" / "0.yaml", kind, reach=reach, ep=ep,
                        host=host)
    before, host_before = planted.state(), S.census(host)

    got = grade(tmp_path, ep, ScriptedJudge())

    assert isinstance(got, J.mod("learning.judge").JudgeRefused), (
        f"the pass was not refused over a link at the draw's sink: {got!r}")
    S.assert_refusal(refusal_in(got), kind, where="the draw write over a link")
    assert planted.state() == before, "the draw was written through the link"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    regrade(tmp_path, ep, ScriptedJudge())
    draw = ep / "worlds" / "b" / "judge" / "0.yaml"
    assert_plain_file(draw)
    assert yaml.safe_load(draw.read_text(encoding="utf-8"))["findings"]


FRAMED = WIRE_LOG_NAMES.agent_framed_trace("judge:b:0")


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("at", ["leaf-symlink", "leaf-dangling", "wire_logs"])
def test_h1_the_framed_wire_log_refuses_a_link_contains_it_and_writes_nothing_through_it(
        tmp_path, roots, host, caplog, at, reach):
    """The judge's framed wire log is `episode.wire_log(name).write(...)`, best-effort: a link
    at `wire_logs/<name>` (to a file, or dangling) or at `wire_logs/` (to a folder) is refused
    and the refusal CONTAINED — logged, the pass completes and the draw is still written —
    while what the link reaches is unchanged (no framed trace written through it, a dangling
    link's target not created) and the link is left.

    A reverted `os.makedirs` + `open(path, "w")` writes the trace through the link.

    Control on the same address: the framed trace lands as a plain file under a real
    `wire_logs/`."""
    ep = judged_episode(tmp_path)
    if at == "wire_logs":
        planted = link_folder(ep / "wire_logs", reach=reach, ep=ep, host=host)
    else:
        (ep / "wire_logs").mkdir(exist_ok=True)
        planted = link_file(ep / "wire_logs" / FRAMED, at.removeprefix("leaf-"), reach=reach,
                            ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    caplog.set_level(logging.WARNING)

    got = grade(tmp_path, ep, ScriptedJudge())

    assert not isinstance(got, BaseException), (
        f"a refused wire log cost the grade (it is best-effort): {got!r}")
    assert planted.state() == before, f"the framed wire log was written through the link ({at})"
    assert S.census(host) == host_before
    planted.assert_left()
    assert warned(caplog, "wire log"), "the refused wire log was not logged"
    assert (ep / "worlds" / "b" / "judge" / "0.yaml").is_file(), "the draw itself was lost"

    planted.remove()
    regrade(tmp_path, ep, ScriptedJudge())
    trace = ep / "wire_logs" / FRAMED
    assert_real_folder(ep / "wire_logs")
    assert_plain_file(trace)
    assert json.loads(trace.read_text(encoding="utf-8").splitlines()[0])["agent_id"] == "judge:b:0"


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_judge_yaml_refuses_a_link_planted_mid_pass_and_writes_nothing_through_it(
        tmp_path, roots, host, kind, reach):
    """The family record is `episode.judge.write(...)`. A link planted at `judge.yaml` while the
    pass runs (by the judge seam's first call: a link there BEFORE the pass is the idempotency
    read's refusal, which never reaches the write) is refused at the write — `JudgeRefused`
    over the core's marked ELOOP — the file it reaches keeps its bytes and the link is left.

    A reverted `open(judge_yaml, "w")` writes the record through the link.

    Control on the same address: the record lands as a plain file."""
    ep = judged_episode(tmp_path)
    holder: dict[str, Any] = {}

    def plant() -> None:
        holder["planted"] = link_file(ep / "judge.yaml", kind, reach=reach, ep=ep, host=host)
        holder["before"], holder["host"] = holder["planted"].state(), S.census(host)

    got = grade(tmp_path, ep, ScriptedJudge(on_first=plant))

    assert "planted" in holder, "the pass never reached the judge seam"
    planted = holder["planted"]
    assert isinstance(got, J.mod("learning.judge").JudgeRefused), (
        f"the pass was not refused over a link at judge.yaml: {got!r}")
    S.assert_refusal(refusal_in(got), kind, where="judge.yaml over a link")
    assert planted.state() == holder["before"], "judge.yaml was written through the link"
    assert S.census(host) == holder["host"]
    planted.assert_left()

    planted.remove()
    regrade(tmp_path, ep, ScriptedJudge())
    assert_plain_file(ep / "judge.yaml")
    assert J.world_rows(J.judge_record(ep))["b"]["completed_draws"] == 2


def test_o3_the_judge_pass_reads_and_writes_through_one_held_descriptor(tmp_path, roots):
    """O3: the pass's reads go through the view of the pass's own `Episode`, which shares its
    handle — so while the judge is being paid, exactly ONE descriptor is open on the episode
    dir. A pass that opens the `Episode` for its writes but keeps a `bind` of the episode dir by
    path for its reads holds two roots, which a rename or a swap can split. Afterwards none is
    left open."""
    ep = judged_episode(tmp_path)
    seen: list[list[int]] = []
    judge = ScriptedJudge(on_first=lambda: seen.append(S.open_fds_on(ep)))

    got = grade(tmp_path, ep, judge)

    assert not isinstance(got, BaseException), f"the pass was refused: {got!r}"
    assert len(seen) == 1, "the pass never reached the judge seam"
    assert len(seen[0]) == 1, (
        f"descriptors open on the episode dir while the judge was paid: {seen[0]}")
    assert S.open_fds_on(ep) == [], "the pass left the episode dir open"


def test_o6_a_judge_pass_whose_episode_dir_is_renamed_mid_pass_records_in_the_moved_folder(
        tmp_path, roots):
    """O6 through the judge's door: the episode is held, not remembered. The episode dir is
    renamed while the pass runs (by the judge seam's first call); every later write — the draws
    and `judge.yaml` — lands in the MOVED folder, and nothing reappears at the old name. A
    writer that reopens the episode by name (an alias of `Episode.open` called on
    `episode.dir`) finds nothing there, and the pass is refused."""
    ep = judged_episode(tmp_path)
    moved = ep.parent / f"{ep.name}-moved"

    got = grade(tmp_path, ep, ScriptedJudge(on_first=lambda: ep.rename(moved)))

    assert not isinstance(got, BaseException), (
        f"the pass was refused after its episode dir was renamed: {got!r}")
    assert not os.path.lexists(ep), "the pass recreated the episode dir's old name"
    assert_plain_file(moved / "judge.yaml")
    assert J.world_rows(J.judge_record(moved))["b"]["completed_draws"] == 2
    assert sorted(p.name for p in (moved / "worlds" / "b" / "judge").iterdir()) == [
        "0.yaml", "1.yaml"]


# =======================================================================================
# H2 — `review.review`'s default write
# =======================================================================================

@pytest.mark.parametrize(("kind", "reach"), [
    ("symlink", "outside"), ("symlink", "inside"), ("dangling", "outside"),
    ("dangling", "inside"), ("hardlink", "outside")])
def test_h2_the_reviews_default_write_refuses_a_link_at_review_yaml(
        tmp_path, roots, host, kind, reach):
    """With no `write=` injected (the launcher's own call), `review.review` writes through the
    episode's `review` record: a link at `review.yaml` (planted before the launch) ends the
    launch at the review step as a refusal of the core's row, no sibling starts, what the link
    reaches keeps its bytes (a dangling link's target is not created) and the plant is left.

    Control on the same address: `test_h2_the_reviews_default_write_lands_a_plain_record`."""
    holder: dict[str, Any] = {}

    def plant(ep: Path) -> None:
        ep.mkdir(parents=True, exist_ok=True)
        if kind == "hardlink":
            S.plant_leaf(ep / "review.yaml", kind, host=host)
        else:
            holder["planted"] = link_file(ep / "review.yaml", kind, reach=reach, ep=ep,
                                          host=host)
            holder["before"] = holder["planted"].state()
        holder["host"] = S.census(host)

    outcome, ep, spawn = launch(tmp_path, before=plant)

    assert isinstance(outcome, BaseException), (
        f"the launch exited {outcome!r} over a {kind} at review.yaml")
    S.assert_refusal(refusal_in(outcome), kind, where=f"the review's write over a {kind}")
    assert spawn.launches == []
    assert S.census(host) == holder["host"], "the review was written through the plant"
    if kind == "hardlink":
        assert os.lstat(ep / "review.yaml").st_nlink == 2, "the hard link was replaced"
    else:
        assert holder["planted"].state() == holder["before"], (
            "the review was written through the link")
        holder["planted"].assert_left()


def test_h2_the_reviews_default_write_lands_a_plain_record(tmp_path, roots):
    """Control for the test above, on the same address."""
    outcome, ep, _spawn = launch(tmp_path)
    assert outcome == 0, outcome
    assert_plain_file(ep / "review.yaml")
    assert set(T.review_doc(ep)["worlds"]) == {"a", "b", "c"}


# =======================================================================================
# H3 — the staging record's durable append
# =======================================================================================

def test_h3_record_staged_is_one_durable_append_on_the_episode_the_caller_holds(tmp_path):
    """D1's row `staged: create, append_durable`: `record_staged(episode, row)` makes ONE call
    on the held root — `write(LAYOUT.staged, <the row as a YAML list item>, mode="append",
    durable=True)`, synced to disk before it returns, since this row is the only record that a
    cluster name is about to exist — and opens nothing itself (the episode it was handed is the
    only `hold_new` / `hold`). The row is on disk afterwards."""
    staging = T.mod("learning.branch.staging")
    ep = tmp_path / "episodes" / EPISODE_ID
    rec_io = S.RecordingIo()
    row = {"name": "wv-e1133.b-logs-x", "kind": "index", "world": "b"}

    with S.create_episode(ep, io=rec_io) as episode:
        mark = len(rec_io.calls)
        got = staging.record_staged(episode, row)
        calls = rec_io.calls[mark:]

    assert [c.method for c in calls] == ["write"], f"record_staged made {calls}"
    [call] = calls
    assert call.name == LAYOUT.staged, call.name
    assert call.kwargs.get("mode") == "append", call.kwargs
    assert call.kwargs.get("durable") is True, "the staging row is appended without a sync"
    assert yaml.safe_load(call.text) == [row]
    assert rec_io.opened == [("hold_new", (ep.parent, EPISODE_ID))], (
        f"record_staged opened the episode again: {rec_io.opened}")
    assert got == row
    assert (ep / "staged.yaml").read_text(encoding="utf-8") == call.text


# =======================================================================================
# H4 — the priming claim alone; the primed base alone
# =======================================================================================

def test_h4_the_priming_claim_alone_keeps_a_second_launcher_out_while_the_first_primes(
        tmp_path, roots):
    """Two launchers on one episode. The first holds the claim and its primer waits until the
    second has finished (the primer writes no base, so nothing but the claim stands between
    them): the second is the "another launcher is priming" `LedgerError` and its primer never
    runs. The first then completes, releases the claim and returns its `Episode`.

    Control on the same address: once released, the next launcher's primer runs, handed the
    episode `prepare_episode` returns."""
    cli = branch_cli()
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    _base, src = T.runs_base(tmp_path)
    tenant = T.current_tenant_paths()
    ep = cli.episode_dir_for(T.EPISODE_ID, tenant=tenant)
    claim = ep / "served" / ".priming"
    priming, second_done = threading.Event(), threading.Event()
    first: dict[str, Any] = {}

    def waits_for_the_second(_source: Path, _episode: Any) -> Any:
        priming.set()
        if not second_done.wait(WAIT):
            raise AssertionError("the second launcher never finished")
        return capture.PrimeReport(primed=1)

    def run_first() -> None:
        try:
            first["value"] = cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant,
                                                 prime=waits_for_the_second)
        except BaseException as e:  # noqa: BLE001 — handed back to the test's thread
            first["error"] = e

    thread = threading.Thread(target=run_first, daemon=True)
    thread.start()
    second_primed: list[Any] = []
    try:
        assert priming.wait(WAIT), f"the first launcher never reached its primer: {first}"
        assert stat.S_ISREG(os.lstat(claim).st_mode), "the first launcher holds no claim"
        with pytest.raises(ledger.LedgerError, match="another launcher is priming"):
            cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant,
                                prime=lambda *a: second_primed.append(a))
        assert second_primed == [], "the second launcher's primer ran past a held claim"
    finally:
        second_done.set()
        thread.join(WAIT)
    assert not thread.is_alive()
    assert "error" not in first, first
    assert isinstance(first["value"], S.Episode()), (
        f"prepare_episode returned {first['value']!r}, not the Episode it opened")
    with first["value"] as held:
        assert Path(held.dir) == ep
    assert not os.path.lexists(claim), "the first launcher did not release its claim"

    third: list[Any] = []

    def records(_source: Path, episode: Any) -> Any:
        third.append(episode)
        return capture.PrimeReport(primed=1)

    with cli.prepare_episode(T.EPISODE_ID, src, tenant=tenant, prime=records) as got:
        assert Path(got.dir) == ep
        assert third == [got], "the primer was not handed the episode prepare_episode returns"


def test_h4_the_primed_base_alone_refuses_a_rival_base_that_lands_just_before_its_create(
        tmp_path):
    """`prime_base(source_run_dir, episode)` reads the whole capture, then writes the base with
    ONE exclusive create — the create itself is the check. A recording `Held` behind the
    episode's `io=` seam plants a rival base (a plain file, by path) just before it delegates
    that create: the create's collision is the "already primed" `LedgerError`, and the rival
    keeps its bytes. A check-then-write, a replace or an append would clobber it.

    Control on the same address: with no rival, the same capture primes the base, by one
    `create` and nothing else."""
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    base = ep / "served" / "base.jsonl"
    rival = b'{"rival": "a base primed by someone else"}\n'
    planted: list[bool] = []

    def plant_rival(method: str, args: tuple, kwargs: dict) -> None:
        name = args[0] if args else kwargs.get("name")
        if method == "write" and S.as_rel(name) == LAYOUT.served_base:
            base.parent.mkdir(parents=True, exist_ok=True)
            base.write_bytes(rival)
            planted.append(True)

    rec_io = S.RecordingIo(before=plant_rival)
    with S.open_episode(ep, io=rec_io) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))

    assert planted, "prime_base never wrote the base through the episode's held root"
    assert isinstance(raised, ledger.LedgerError), (
        f"a base that landed just before the create was not refused: {raised!r}")
    assert "already holds a primed base" in str(raised)
    assert base.read_bytes() == rival, "the rival base was overwritten or appended to"
    assert os.lstat(base).st_nlink == 1

    base.unlink()
    rec_io = S.RecordingIo()
    with S.open_episode(ep, io=rec_io) as episode:
        capture.prime_base(run_dir, episode)
    writes = [c for c in rec_io.calls if c.method == "write" and c.name == LAYOUT.served_base]
    assert [c.kwargs.get("mode") for c in writes] == ["create"], writes
    rows = [json.loads(line) for line in base.read_text(encoding="utf-8").splitlines()]
    assert [r["source"] for r in rows] == [ledger.CAPTURED]


# =======================================================================================
# H5 — the manifest readers never follow a link at family.yaml
# =======================================================================================

MARKER = "host-manifest-1133-never-read"


def _readers(fam: Any, digest: str) -> dict[str, Any]:
    return {
        "load_family": fam.load_family,
        "manifest_digest": fam.manifest_digest,
        "check_manifest_digest": lambda episode: fam.check_manifest_digest(episode, digest),
    }


@pytest.mark.parametrize("entry", ["load_family", "manifest_digest", "check_manifest_digest"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_h5_the_manifest_readers_refuse_a_link_at_family_yaml_without_reading_it(
        tmp_path, entry, kind):
    """`load_family(episode)`, `manifest_digest(episode)` and `check_manifest_digest(episode,
    digest)` read `family.yaml` as the episode's `family` record, which follows nothing below
    the episode dir and refuses a hard link: over a symlink to a host file holding a valid
    manifest, or a hard link whose other name is that host file, each raises `FamilyError`,
    returns nothing, and never reads what the link reaches — the host manifest's text appears
    in no message.

    Control on the same address: the same bytes as a plain `family.yaml` load, digest to the
    digest the check is handed, and check clean."""
    fam = T.mod("runtime.branch._family")
    doc = T.family_doc()
    doc["worlds"][1]["story"] = MARKER
    ep = T.episode(tmp_path, doc=doc)
    manifest = ep / "family.yaml"
    good = manifest.read_bytes()
    with S.open_episode(ep) as episode:
        digest = fam.manifest_digest(episode)
    call = _readers(fam, digest)[entry]

    host = tmp_path / "host"
    host.mkdir()
    other = host / "host-manifest.yaml"
    other.write_bytes(good)
    manifest.unlink()
    if kind == "symlink":
        manifest.symlink_to(other)
    else:
        os.link(other, manifest)

    answered: list[Any] = []
    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: answered.append(call(episode)))
    assert answered == [], f"{entry} answered {answered!r} over a {kind} at family.yaml"
    assert isinstance(raised, fam.FamilyError), f"{entry} over a {kind}: {raised!r}"
    text = "".join(str(e) for e in (raised, raised.__cause__) if e is not None)
    assert MARKER not in text, f"{entry} read through the {kind}: {text}"
    assert os.path.lexists(manifest), f"the {kind} at family.yaml was removed"
    assert other.read_bytes() == good

    manifest.unlink()
    manifest.write_bytes(good)
    with S.open_episode(ep) as episode:
        got = call(episode)
    if entry == "load_family":
        assert [w.story for w in got.worlds][1] == MARKER
    elif entry == "manifest_digest":
        assert got == digest
    else:
        assert got is None


# =======================================================================================
# H7 — the judge's read view grows no writer
# =======================================================================================

def test_h7_bounds_public_surface_is_exactly_its_readers_and_close(tmp_path):
    """O3: a read view stays write-free by type. The public attributes of a `Bound` — from
    `bind(root)`, and from `episode.view()` over the same held handle the episode writes
    through — are exactly `read`, `read_jsonl`, `entries`, `under` and `close`."""
    from defender._io import bind

    root = tmp_path / "root"
    root.mkdir()
    want = {"read", "read_jsonl", "entries", "under", "close"}
    with bind(root) as bound:
        public = {name for name in dir(bound) if not name.startswith("_")}
    assert public == want, sorted(public)
    with S.open_episode(root) as episode:
        view = episode.view()
        public = {name for name in dir(view) if not name.startswith("_")}
    assert public == want, sorted(public)
