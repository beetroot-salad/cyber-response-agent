from __future__ import annotations

import contextlib
import dataclasses
import errno
import functools
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

from defender.episodes._episode_paths import LAYOUT
from defender.run_repository import WIRE_LOG_NAMES
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.storage import _spec1133 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.branch.test_947_capture_prime import append_call, call_row, source_run
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state
from defender.tests.support.shared._fixture_uuid import fixture_uuid

#: #1187: an episode id is a uuid4 (`fixture_uuid` of the readable label).
EPISODE_ID = fixture_uuid("ep-1133")
WORLD_B = T.fixture_world_id("b")
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
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


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


def start_family(episode: Any, spawn: Any) -> dict[str, int]:
    """The launcher's RUNS step for tenant `acme` (#1105 PR 2): the siblings' container made
    through the episode's view (the `runs/` ensure `start_family` no longer does; #1187 R2:
    `view.start_runs(<every manifest world>)` replaces `create_container` — `runs/`, then the
    arm roster), then the siblings started."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    acme = set_up_tenant(Path(os.environ["DEFENDER_DATA_ROOT"]), fixture_uuid("tenant:acme"))
    acme.runs_repository().episode(episode.dir.name, held=episode).start_runs([T.world_id(episode.dir, label) for label in T.WORLDS])
    return branch_cli().start_family(episode, [T.world_id(episode.dir, label) for label in ("b", "c")], spawn=spawn, tenant_id=acme.id)


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
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    T.write_family(ep, T.family_doc(episode_id=EPISODE_ID))
    planted = link_folder(ep / "runs", reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    spawn = Spawned()

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: start_family(episode, spawn))

    assert_folder_refusal(raised, planted, where="start_family over a linked runs/")
    assert spawn.argvs == [], f"a sibling started over a linked runs base: {spawn.argvs}"
    assert planted.state() == before, "start_family wrote into the folder the runs/ link reaches"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        exits = start_family(episode, spawn)
    assert exits == {T.world_id(ep, label): 0 for label in ("b", "c")}
    assert len(spawn.argvs) == 2
    assert_real_folder(ep / "runs")
    # #1187 declared change 6 (R1): the arm container holds no `_tenant.json`; an arm's tenant
    # is the one whose folder holds the episode.
    assert not (ep / "runs" / "_tenant.json").exists(), (
        "start_family wrote the retired tenant record into the arm container")


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("scrub_ran", [False, True], ids=["nothing-to-archive", "verified"])
def test_h1_verify_family_refuses_a_linked_worlds_folder_before_anything_is_archived(
        tmp_path, host, scrub_ran, reach):
    cli = branch_cli()
    ep = T.episode(tmp_path)
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w, scrub_ran=scrub_ran)
    planted = link_folder(ep / "worlds", reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        arms = T.family_arms(episode, T.WORLDS)
        raised = S.raised_by(lambda: cli.verify_family(episode, arms,
                                                       source=T.provenance_record()))

    assert_folder_refusal(raised, planted, where="verify_family over a linked worlds/")
    assert planted.state() == before, "verify_family wrote into the folder worlds/ reaches"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        report = cli.verify_family(episode, T.family_arms(episode, T.WORLDS),
                                   source=T.provenance_record())
    assert report["comparable"] is scrub_ran, report
    assert_real_folder(ep / "worlds")
    if scrub_ran:
        assert sorted(p.name for p in (ep / "worlds").iterdir()) == sorted(T.world_id(ep, label) for label in T.WORLDS)


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_the_family_stamp_refuses_a_link_at_its_name_and_writes_nothing_through_it(
        tmp_path, host, kind, reach):
    cli = branch_cli()
    ep = T.episode(tmp_path)
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w, commit="cafe1")
    planted = link_file(ep / "provenance.json", kind, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        arms = T.family_arms(episode, T.WORLDS)
        raised = S.raised_by(lambda: cli.verify_family(
            episode, arms, source=T.provenance_record(commit="cafe1")))

    S.assert_refusal(refusal_in(raised), kind, where="the family stamp over a link")
    assert planted.state() == before, "the family stamp was written through the link"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        cli.verify_family(episode, T.family_arms(episode, T.WORLDS),
                          source=T.provenance_record(commit="cafe1"))
    stamp = ep / "provenance.json"
    assert_plain_file(stamp)
    assert json.loads(stamp.read_text(encoding="utf-8"))["agreed"]["commit"] == "cafe1"


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("at", ["worlds", f"worlds/{WORLD_B}"])
def test_h1_the_archive_refuses_a_linked_world_folder_and_copies_nothing_through_it(
        tmp_path, host, at, reach):
    archive = T.mod("learning.branch.archive")
    ep = T.episode(tmp_path)
    # The scene's explicit RUNS step (`runs/`, then the roster naming every manifest world):
    # the arm planter reads the roster and never writes one (review-3 F33).
    T.plant_roster(ep)
    run_dir = T.sibling_run_dir(ep / "runs", "b")
    if at == f"worlds/{WORLD_B}":
        (ep / "worlds").mkdir(exist_ok=True)
    planted = link_folder(ep / at, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: archive.archive_episode(episode, {T.world_id(ep, "b"): run_dir}))

    assert_folder_refusal(raised, planted, where=f"the archive over a link at {at}")
    assert planted.state() == before, f"the archive wrote through the link at {at}"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    with S.open_episode(ep) as episode:
        archived = archive.archive_episode(episode, {T.world_id(ep, "b"): run_dir})
    world = ep / "worlds" / WORLD_B
    assert archived == {T.world_id(ep, "b"): world}
    assert_real_folder(world)
    assert (world / "report.md").is_file()


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
        self.failing = {"family" if label == "family" else T.fixture_world_id(label) for label in failing}
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
        identity = "family" if label == "family" else T.fixture_world_id(label)
        return [a for a in self.agent_ids if a.startswith(f"judge:{identity}:")]


def judged_episode(tmp_path: Path) -> Path:
    """An accepted, archived episode whose world `b` is graded (it carries an oracle row)."""
    return J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})


def grade(tmp_path: Path, ep: Path, judge: ScriptedJudge) -> Any:
    """The judge pass, or the refusal it raised."""
    try:
        return J.grade_at(
            ep, judge=judge, draws=2, state=env_state())
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
    ep = judged_episode(tmp_path)
    planted = link_folder(ep / "worlds" / WORLD_B / "judge", reach=reach, ep=ep, host=host)
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
    assert judge.called_for("b") == [f"judge:{WORLD_B}:0", f"judge:{WORLD_B}:1"]
    draws = ep / "worlds" / WORLD_B / "judge"
    assert_real_folder(draws)
    assert sorted(p.name for p in draws.iterdir()) == ["0.yaml", "1.yaml"]


@pytest.mark.parametrize("reach", REACH)
def test_h1_a_linked_family_draws_folder_is_refused_and_contained_to_the_family_call(
        tmp_path, roots, host, reach):
    ep = judged_episode(tmp_path)
    at = LAYOUT.family_draws
    planted = link_folder(ep / at, reach=reach, ep=ep, host=host)
    before, host_before = planted.state(), S.census(host)
    judge = ScriptedJudge(failing=("family",))

    got = grade(tmp_path, ep, judge)

    assert not isinstance(got, BaseException), f"the pass was refused: {got!r}"
    assert judge.called_for("family") == [], (
        f"the judge was paid for the family call over a linked folder: "
        f"{judge.called_for('family')}")
    reason = (J.judge_record(ep).get("family") or {}).get("draws_failed_reason") or ""
    assert reason.startswith("OSError"), (
        f"the family call's setup refusal was not recorded: {reason!r}")
    assert planted.state() == before, f"the family call wrote through the link at {at}"
    assert S.census(host) == host_before
    planted.assert_left()

    planted.remove()
    judge = ScriptedJudge(failing=("family",))
    regrade(tmp_path, ep, judge)
    assert judge.called_for("family") == ["judge:family:0", "judge:family:1"]
    draws = ep / LAYOUT.family_draws
    assert_real_folder(draws)
    assert sorted(p.name for p in draws.iterdir()) == ["0.yaml", "1.yaml"]


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_a_link_at_a_draws_name_refuses_the_pass_and_is_written_through_by_nothing(
        tmp_path, roots, host, kind, reach):
    ep = judged_episode(tmp_path)
    planted = link_file(ep / "worlds" / WORLD_B / "judge" / "0.yaml", kind, reach=reach, ep=ep,
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
    draw = ep / "worlds" / WORLD_B / "judge" / "0.yaml"
    assert_plain_file(draw)
    assert yaml.safe_load(draw.read_text(encoding="utf-8"))["investigator_findings"]


FRAMED = WIRE_LOG_NAMES.agent_framed_trace(f"judge:{WORLD_B}:0")


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("at", ["leaf-symlink", "leaf-dangling", "wire_logs"])
def test_h1_the_framed_wire_log_refuses_a_link_contains_it_and_writes_nothing_through_it(
        tmp_path, roots, host, caplog, at, reach):
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
    assert (ep / "worlds" / WORLD_B / "judge" / "0.yaml").is_file(), "the draw itself was lost"

    planted.remove()
    regrade(tmp_path, ep, ScriptedJudge())
    trace = ep / "wire_logs" / FRAMED
    assert_real_folder(ep / "wire_logs")
    assert_plain_file(trace)
    assert json.loads(trace.read_text(encoding="utf-8").splitlines()[0])["agent_id"] == f"judge:{WORLD_B}:0"


@pytest.mark.parametrize("reach", REACH)
@pytest.mark.parametrize("kind", LEAF_LINKS)
def test_h1_judge_yaml_refuses_a_link_planted_mid_pass_and_writes_nothing_through_it(
        tmp_path, roots, host, kind, reach):
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
    ep = judged_episode(tmp_path)
    moved = ep.parent / f"{ep.name}-moved"

    got = grade(tmp_path, ep, ScriptedJudge(on_first=lambda: ep.rename(moved)))

    assert not isinstance(got, BaseException), (
        f"the pass was refused after its episode dir was renamed: {got!r}")
    assert not os.path.lexists(ep), "the pass recreated the episode dir's old name"
    assert_plain_file(moved / "judge.yaml")
    assert J.world_rows(J.judge_record(moved))["b"]["completed_draws"] == 2
    assert sorted(p.name for p in (moved / "worlds" / WORLD_B / "judge").iterdir()) == [
        "0.yaml", "1.yaml"]


def test_h4_the_priming_claim_alone_keeps_a_second_launcher_out_while_the_first_primes(
        tmp_path, roots):
    cli = branch_cli()
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    _base, src = T.runs_base(tmp_path)
    # #1187 (O9): an episode is the tenant's own `<T>/episodes/<id>`; the configured
    # `episode_dir` resolver is retired, so the address is the tenant's folder.
    ep = T.current_tenant().episodes / T.EPISODE_ID
    claim = ep / "served" / ".priming"
    priming, second_done = threading.Event(), threading.Event()
    first: dict[str, Any] = {}

    def waits_for_the_second(_source: Path, _episode: Any) -> Any:
        priming.set()
        if not second_done.wait(WAIT):
            raise AssertionError("the second launcher never finished")
        return capture.PrimeReport(primed=1)

    with S.create_episode(ep) as first_ep:
        def run_first() -> None:
            try:
                first["value"] = cli._prime_once(first_ep, T.EPISODE_ID, src,
                                                 waits_for_the_second)
            except BaseException as e:  # noqa: BLE001 — handed back to the test's thread
                first["error"] = e

        thread = threading.Thread(target=run_first, daemon=True)
        thread.start()
        second_primed: list[Any] = []
        try:
            assert priming.wait(WAIT), f"the first launcher never reached its primer: {first}"
            assert stat.S_ISREG(os.lstat(claim).st_mode), "the first launcher holds no claim"
            with S.open_episode(ep) as second_ep, pytest.raises(
                    ledger.LedgerError, match="another launcher is priming"):
                cli._prime_once(second_ep, T.EPISODE_ID, src,
                                lambda *a: second_primed.append(a))
            assert second_primed == [], "the second launcher's primer ran past a held claim"
        finally:
            second_done.set()
            thread.join(WAIT)
        assert not thread.is_alive()
        assert "error" not in first, first
        assert not os.path.lexists(claim), "the first launcher did not release its claim"

    third: list[Any] = []

    def records(_source: Path, episode: Any) -> Any:
        third.append(episode)
        return capture.PrimeReport(primed=1)

    with S.open_episode(ep) as got:
        cli._prime_once(got, T.EPISODE_ID, src, records)
        assert third == [got], "the primer was not handed the episode it primes"


def test_h4_the_primed_base_alone_refuses_a_rival_base_that_lands_just_before_its_create(
        tmp_path):
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


MARKER = "host-manifest-1133-never-read"


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_h5_the_manifest_reader_refuses_a_link_at_family_yaml_without_reading_it(tmp_path, kind):
    fam = T.mod("runtime.branch._family")
    doc = T.family_doc()
    doc["worlds"][1]["story"] = MARKER
    ep = T.episode(tmp_path, doc=doc)
    manifest = ep / "family.yaml"
    good = manifest.read_bytes()
    # #1187 R5 (review-4 F36): the expected id is a required keyword, the episode's own folder
    # name, so a refusal below is the link's, never a missing argument's.
    call = functools.partial(fam.load_family, expected_episode_id=ep.name)

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
        raised = S.raised_by(lambda: answered.append(call(episode.view())))
    assert answered == [], f"load_family answered {answered!r} over a {kind} at family.yaml"
    assert isinstance(raised, fam.FamilyError), f"load_family over a {kind}: {raised!r}"
    text = "".join(str(e) for e in (raised, raised.__cause__) if e is not None)
    assert MARKER not in text, f"load_family read through the {kind}: {text}"
    assert str(LAYOUT.family) in str(raised), "load_family's refusal does not name the record"
    assert os.path.lexists(manifest), f"the {kind} at family.yaml was removed"
    assert other.read_bytes() == good

    manifest.unlink()
    manifest.write_bytes(good)
    with S.open_episode(ep) as episode:
        got = call(episode.view())
    assert [w.story for w in got.worlds][1] == MARKER
