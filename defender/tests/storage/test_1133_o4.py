from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.tenancy._launch_publish_p4 import RunWithPublish

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import errno
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender import _io
from defender.episodes._episode_paths import LAYOUT
from defender._io import read_jsonl_rows
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.storage import _spec1133 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.filesystem._umask import umask
from defender.tests.learning.branch.test_947_capture_prime import append_call, call_row, source_run
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._state1135 import env_state

EPISODE_ID = "ep-1133"
WORLD_B = T.fixture_world_id("b")
WORLD_C = T.fixture_world_id("c")


@pytest.fixture
def roots(tmp_path, monkeypatch):
    """The configured roots inside `tmp_path` (environment steering, the resolvers' own seam):
    the runs base, the episodes root and the learning state root the judge's queue lands in."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def bare_episode(tmp_path: Path) -> tuple[Path, Path]:
    """(an episode dir under an episodes root, a host folder outside it)."""
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    return ep, host


def _source_with_one_call(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    return run_dir


def test_o4_3_prime_base_refuses_a_linked_served_folder_and_writes_nothing_where_it_points(
        tmp_path):
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    base = ep / "served" / "base.jsonl"
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))
    assert not isinstance(raised, ledger.LedgerError), (
        f"a linked served/ was read as an existing base: {raised!r}")
    S.assert_refusal(raised, "folder_link_outside", where="prime_base through a linked served/")
    assert S.census(tmp_path) == before, "the primer wrote through the linked served/"
    assert list(elsewhere.iterdir()) == []

    (ep / "served").unlink()
    with S.open_episode(ep) as episode:
        report = capture.prime_base(run_dir, episode)
        assert report.primed == 1
        assert [r["source"] for r in read_jsonl_rows(base)] == [ledger.CAPTURED]
        assert stat.S_ISREG(os.lstat(base).st_mode)
        assert os.lstat(base).st_nlink == 1
        original = base.read_bytes()
        with pytest.raises(ledger.LedgerError, match="already holds a primed base"):
            capture.prime_base(run_dir, episode)
    assert base.read_bytes() == original


@pytest.mark.parametrize("kind", ["plain", "symlink", "dangling", "hardlink", "fifo",
                                  "directory"])
def test_o4_8_3_anything_at_the_base_is_the_one_already_primed_refusal(tmp_path, kind):
    capture = T.mod("learning.branch.capture")
    ledger = T.mod("learning.branch.ledger")
    run_dir = _source_with_one_call(tmp_path)
    ep, host = bare_episode(tmp_path)
    base = ep / "served" / "base.jsonl"
    fifo = None
    if kind == "plain":
        base.parent.mkdir(parents=True)
        base.write_bytes(b'{"an": "earlier prime"}\n')
    else:
        fifo = S.plant_leaf(base, kind, host=host).fifo
    before = S.census(tmp_path)

    with S.open_episode(ep) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode), fifo=fifo)

    assert isinstance(raised, ledger.LedgerError), f"a {kind} at the base: {raised!r}"
    assert "already holds a primed base" in str(raised), raised
    assert S.census(tmp_path) == before, f"priming over a {kind} changed the tree"


def _ledger_episode(tmp_path: Path) -> tuple[Path, Path]:
    ep, host = bare_episode(tmp_path)
    (ep / "served").mkdir()
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    return ep, host


def _call(ledger: Any, world_id: str = WORLD_B) -> Any:
    return ledger.ServedCall(system="cmdb", verb="get-host", params={"host": "canary-1"},
                             payload_text=json.dumps({"owner": "live"}),
                             source=ledger.PASSTHROUGH, world_id=world_id)


@pytest.mark.parametrize("kind", ["dangling", "symlink", "hardlink", "fifo"])
def test_o4_4_a_plant_at_the_world_ledger_refuses_declare_and_record(tmp_path, kind):
    ledger = T.mod("learning.branch.ledger")
    ep, host = _ledger_episode(tmp_path)
    world_file = ep / "served" / f"{WORLD_B}.jsonl"
    planted = S.plant_leaf(world_file, kind, host=host)
    with S.open_episode(ep) as episode:
        book = ledger.Ledger.for_world(episode, WORLD_B)
        before = S.census(tmp_path)
        S.assert_refusal(S.raised_by(book.declare, fifo=planted.fifo), kind,
                         where="declare() into a plant")
        S.assert_refusal(S.raised_by(lambda: book.record(_call(ledger)), fifo=planted.fifo),
                         kind, where="record() into a plant")
        assert S.census(tmp_path) == before, "a refused ledger write changed the tree"

        planted.remove()
        book = ledger.Ledger.for_world(episode, WORLD_B)
        assert book.declare() is book
        assert world_file.read_bytes() == b""
        book.record(_call(ledger))
    assert read_jsonl_rows(world_file) == [_call(ledger).row()]


def test_o4_4_a_linked_served_folder_refuses_the_world_ledgers_declare(tmp_path):
    """A symlinked `served/` (to a real folder holding a base, so the ledger still builds) is
    refused by `declare()`'s walk, and the linked folder gains no world file."""
    ledger = T.mod("learning.branch.ledger")
    ep, host = bare_episode(tmp_path)
    elsewhere = host / "served-elsewhere"
    elsewhere.mkdir()
    (elsewhere / "base.jsonl").write_text("", encoding="utf-8")
    (ep / "served").symlink_to(elsewhere, target_is_directory=True)
    with S.open_episode(ep) as episode:
        book = ledger.Ledger.for_world(episode, WORLD_B)
        before = S.census(tmp_path)
        S.assert_refusal(S.raised_by(book.declare), "folder_link_outside",
                         where="declare() through a linked served/")
    assert S.census(tmp_path) == before
    assert sorted(p.name for p in elsewhere.iterdir()) == ["base.jsonl"]


@pytest.mark.parametrize("world_id", [
    pytest.param("e1133.B", id="label-not-case-stable"),
    pytest.param("e1133.b/x", id="two-components"),
    pytest.param("../escape", id="climbs"),
    pytest.param("..", id="dotdot"),
    pytest.param(".", id="dot"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
    pytest.param(7, id="int"),
    pytest.param("base", id="the-capture-itself"),
    pytest.param("e1133.Base", id="capture-case-folded"),
    pytest.param("e1133.b\n", id="newline"),
    pytest.param("e1133.b\x00", id="nul"),
    pytest.param("e1133." + "b" * 250, id="longer-than-a-file-name"),
    # Rev 3's patch: the WHOLE token must be case-stable, not only the text after its last dot.
    pytest.param("Control", id="dotless-not-case-stable"),
    pytest.param("E1133.b", id="head-not-case-stable"),
])
def test_o4_8_1_a_bad_world_id_is_a_ledger_error_at_construction(tmp_path, world_id):
    ledger = T.mod("learning.branch.ledger")
    ep, _host = _ledger_episode(tmp_path)
    with S.open_episode(ep) as episode:
        before = S.census(tmp_path)
        with pytest.raises(ledger.LedgerError):
            ledger.Ledger.for_world(episode, world_id)
        assert S.census(tmp_path) == before, "for_world wrote before refusing its id"

        book = ledger.Ledger.for_world(episode, WORLD_B)
        assert Path(book.path) == ep / "served" / f"{WORLD_B}.jsonl"
        assert Path(book.base_path) == ep / "served" / "base.jsonl"
        book.declare()
    assert (ep / "served" / f"{WORLD_B}.jsonl").read_bytes() == b""


class Primed:
    """`prepare_episode`'s `prime=` seam, `(source_run_dir, episode)`: records what it was
    handed and the claim as it stands while priming runs, then does `act(claim)` if given."""

    def __init__(self, act: Any = None) -> None:
        self.act = act
        self.seen: dict[str, Any] = {}

    def __call__(self, source_run_dir: Path, episode: Any) -> Any:
        claim = Path(episode.dir) / "served" / ".priming"
        st = os.lstat(claim)
        folder = os.lstat(episode.dir)
        self.seen = {"source": Path(source_run_dir), "episode": episode,
                     "mode": stat.S_IMODE(st.st_mode), "regular": stat.S_ISREG(st.st_mode),
                     "nlink": st.st_nlink, "inode": (folder.st_dev, folder.st_ino)}
        if self.act is not None:
            self.act(claim)
        return T.mod("learning.branch.capture").PrimeReport(primed=1)


def _prime_setup(tmp_path: Path) -> tuple[Any, Path, Any]:
    """`(cli, the source run dir, T's runs repository)` — the O4.5 claim guards' STATED
    DESTINATION (review-3 F30(a) / F31(f), review-4 F37). #1187 declared change 3: the
    launcher's entry is `cli.prepare_episode(runs, source, *, prime=) -> EpisodeRuns`
    (interface sheet): it claims a fresh UUID under `<T>/episodes/` with `runs.create_episode()`,
    copies the source's input in, primes once under the claim, and returns the view held —
    closing it, and re-raising the same exception, on any error after the claim. The guards
    whose scene a launch can produce go through it (the claim's mode and single link, its
    release, the primer handed the view's own held episode, a refused release never masking
    the primer's error, the launcher's close on that error); the guards over a claim planted
    BEFORE priming — a state a launch, which always claims a fresh episode, cannot reach — drive
    the claim body `cli._prime_once` over `runs.create_episode()`'s held episode."""
    cli = T.mod("learning.branch.cli")
    _base, src = location_path(T.runs_base)(tmp_path)
    return cli, src, T.current_tenant().runs_repository()


def _fds_on_episode(primed: Primed) -> list[int]:
    """This process's open descriptors on the episode dir the primer was handed, matched by the
    inode recorded while it ran — so the check holds whether or not the dir is still at its
    name afterwards (whether a failed launch leaves its folder is not pinned here)."""
    out = []
    for name in os.listdir("/proc/self/fd"):
        try:
            st = os.stat(f"/proc/self/fd/{name}")
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == primed.seen["inode"]:
            out.append(int(name))
    return sorted(out)


def _source(src: Path) -> Any:
    """The source run the launcher primes from, as the launcher holds it (a `Run`)."""
    from defender.run_repository import Run

    return Run.at(src)


def test_o4_5_prepare_episode_returns_the_held_episode_and_the_claim_is_released(
        tmp_path, roots):
    """`prepare_episode(runs, source, prime=)` (`_prime_setup`: #1187 declared change 3,
    review-4 F37) claims a fresh UUID episode under `<T>/episodes/` and hands back its view
    HELD; its priming claims with `priming_lock.create("")` — a plain, single-linked regular
    file of mode 0644 while the primer runs — hands the primer the source run and THE SAME held
    `Episode` the returned view holds, and releases the claim; the view holds the episode dir
    until its `with` ends (the positive control for the close-on-error tests below)."""
    import uuid

    cli, src, runs = _prime_setup(tmp_path)
    prime = Primed()
    with umask(0o022), cli.prepare_episode(runs, _source(src), prime=prime) as view:
        episode = view.episode
        ep = Path(episode.dir)
        assert isinstance(episode, S.Episode()), f"the view holds {episode!r}"
        assert ep.name == view.episode_id
        assert str(uuid.UUID(view.episode_id)) == view.episode_id, (
            f"the launcher claimed {view.episode_id!r}, not a fresh UUID (declared change 3)")
        assert ep.parent == Path(location_path(T.current_tenant().episodes)), (
            f"the launcher claimed {ep}, not an episode under <T>/episodes/")
        assert prime.seen["episode"] is episode, "the primer was handed another episode"
        assert prime.seen["source"] == src
        assert prime.seen["regular"]
        assert prime.seen["nlink"] == 1
        assert prime.seen["mode"] == 0o644, f"the claim's mode is {oct(prime.seen['mode'])}"
        assert not os.path.lexists(ep / "served" / ".priming"), "the claim was not released"
        assert S.open_fds_on(ep), "the view does not hold the episode dir"
    assert S.open_fds_on(ep) == [], "leaving the view's `with` did not release the episode"


@pytest.mark.parametrize("kind", ["plain", "symlink", "dangling", "hardlink"])
def test_o4_5_an_occupied_or_aliased_claim_is_the_same_ledger_error_and_primes_nothing(
        tmp_path, roots, kind):
    """An occupied claim (a plain file: another launcher) and an alias at the claim are the one
    `LedgerError` naming another launcher; the primer never runs and the claim is left exactly
    as it was. Driven through the claim body `_prime_once` (a contract seam, interface sheet,
    review-4 F37) on the walk's held episode (`_prime_setup`), the claim planted in it BEFORE
    priming: a launch never adopts an existing directory (#1187 declared change 3:
    `create_episode()` mints a fresh UUID), so `prepare_episode` cannot reach this scene, and
    only the claim stands between two primers of one episode."""
    cli, src, runs = _prime_setup(tmp_path)
    host = tmp_path / "host"
    host.mkdir()

    def never(*_a: Any, **_kw: Any) -> Any:
        pytest.fail("the primer ran past an occupied or aliased claim")

    with runs.create_episode() as view:
        ep = Path(view.episode.dir)
        claim = ep / "served" / ".priming"
        if kind == "plain":
            claim.parent.mkdir(parents=True, exist_ok=True)
            claim.write_text("", encoding="utf-8")
        else:
            S.plant_leaf(claim, kind, host=host)
        # The episode lives under the data root, outside `tmp_path`: both trees are counted.
        before = (S.census(ep), S.census(tmp_path))
        with pytest.raises(T.mod("learning.branch.ledger").LedgerError,
                           match="another launcher is priming") as refused:
            cli._prime_once(view.episode, view.episode_id, src, never)
        assert (S.census(ep), S.census(tmp_path)) == before
    assert refused.value is not None
    assert S.open_fds_on(ep) == [], "the refused claim left a descriptor open on the episode dir"


class PrimerFailed(Exception):
    """The primer's own failure, which the claim's release must never mask."""


def _swap_claim(kind: str, claim: Path, host: Path) -> Any:
    """Replace the held claim with a `kind` plant, and answer a check that the plant is still
    there as planted."""
    served = claim.parent
    claim.unlink()
    if kind == "directory":
        claim.mkdir()
        (claim / "keep").write_text("kept\n", encoding="utf-8")
        return lambda: claim.is_dir() and (claim / "keep").read_text(encoding="utf-8") == "kept\n"
    if kind == "symlink":
        target = host / "claim-target"
        target.write_bytes(S.HOST_BYTES)
        claim.symlink_to(target)
        return lambda: (claim.is_symlink() and os.readlink(claim) == str(target)
                        and target.read_bytes() == S.HOST_BYTES)
    if kind == "hardlink":
        other = host / "other-name-of-the-claim"
        other.write_bytes(S.HOST_BYTES)
        os.link(other, claim)
        return lambda: os.lstat(claim).st_nlink == 2 and other.read_bytes() == S.HOST_BYTES
    if kind == "fifo":
        os.mkfifo(claim)
        return lambda: stat.S_ISFIFO(os.lstat(claim).st_mode)
    served.rmdir()
    if kind == "served-file":
        served.write_bytes(S.HOST_BYTES)
        return lambda: stat.S_ISREG(os.lstat(served).st_mode) and served.read_bytes() == (
            S.HOST_BYTES)
    if kind == "served-link":
        elsewhere = host / "served-elsewhere"
        elsewhere.mkdir()
        (elsewhere / claim.name).write_bytes(S.HOST_BYTES)
        served.symlink_to(elsewhere, target_is_directory=True)
        return lambda: (served.is_symlink() and os.readlink(served) == str(elsewhere)
                        and (elsewhere / claim.name).read_bytes() == S.HOST_BYTES)
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["directory", "symlink", "hardlink", "fifo", "served-file",
                                  "served-link"])
def test_o4_5_a_claim_release_refused_in_finally_never_masks_the_primers_exception(
        tmp_path, roots, caplog, kind):
    """The claim's `delete()` in the priming step's `finally` suppresses EVERY refusal it can
    raise: the primer swaps the claim for a plant and fails; the refusal is logged, the
    primer's own exception propagates out of `prepare_episode` (the same object, unwrapped),
    the plant is left as planted, and the launcher closes the episode it claimed as the
    exception leaves it (review-4 F37: the launcher's close-on-error, not a `with` of the
    test's; the held-view control is
    `test_o4_5_prepare_episode_returns_the_held_episode_and_the_claim_is_released`)."""
    cli, src, runs = _prime_setup(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    still_planted: dict[str, Any] = {}
    own = PrimerFailed("the primer failed")

    def swap_then_fail(claim: Path) -> None:
        still_planted["check"] = _swap_claim(kind, claim, host)
        raise own

    primer = Primed(swap_then_fail)
    caplog.set_level(logging.WARNING)
    with pytest.raises(PrimerFailed) as failed:
        cli.prepare_episode(runs, _source(src), prime=primer)
    assert still_planted["check"](), f"the {kind} plant was changed by the claim's release"
    assert S.warned(caplog, ".priming"), "the refused release was not logged"
    assert failed.value is own, f"the primer's error was replaced: {failed.value!r}"
    assert _fds_on_episode(primer) == [], (
        "the launcher left its claimed episode open on the primer's error")


def test_o4_5_the_launcher_closes_the_episode_it_claimed_when_its_primer_fails(tmp_path, roots):
    """The launcher's close-on-error (`cli.py:229-232` at base; review-4 F37): when the primer
    raises, `prepare_episode` closes the view it claimed — no descriptor of this process is left
    on the episode dir — releases the priming claim, and the primer's OWN exception propagates,
    the same object, not wrapped or replaced.

    Positive control on the same observation channel: with a primer that succeeds, the view it
    hands back holds the episode dir (`open_fds_on` sees it) until the caller's `with` closes it.
    A launcher that leaves the claim open on the error is seen by the same check."""
    cli, src, runs = _prime_setup(tmp_path)

    ok = Primed()
    with cli.prepare_episode(runs, _source(src), prime=ok) as view:
        held = Path(view.episode.dir)
        assert _fds_on_episode(ok), "control: the observation sees no descriptor on a held view"
    assert _fds_on_episode(ok) == [], "control: closing the view left a descriptor open"

    own = PrimerFailed("the primer failed")

    def fail(_claim: Path) -> None:
        raise own

    failing = Primed(fail)
    with pytest.raises(PrimerFailed) as failed:
        cli.prepare_episode(runs, _source(src), prime=failing)
    assert failed.value is own, f"the primer's error was replaced: {failed.value!r}"
    ep = Path(failing.seen["episode"].dir)
    assert ep != held, "the second launch did not claim an episode of its own"
    assert not os.path.lexists(ep / "served" / ".priming"), "the priming claim was not released"
    assert _fds_on_episode(failing) == [], (
        "the launcher left the episode it claimed open when its primer failed")


def test_o4_5_a_link_planted_at_the_claim_is_left_in_place_by_its_release(
        tmp_path, roots, caplog):
    """The primer swaps the claim for a symlink to a host file and succeeds: the release in
    `finally` refuses the link (marked) and leaves it for the reap scan; the refusal is logged
    and suppressed, so `prepare_episode` still completes and hands back the episode it claimed
    (`_prime_setup`). The link's target is untouched."""
    cli, src, runs = _prime_setup(tmp_path)
    target = tmp_path / "host-claim-target"
    target.write_bytes(S.HOST_BYTES)

    def swap(claim: Path) -> None:
        claim.unlink()
        claim.symlink_to(target)

    caplog.set_level(logging.WARNING)
    with cli.prepare_episode(runs, _source(src), prime=Primed(swap)) as view:
        ep = Path(view.episode.dir)
    claim = ep / "served" / ".priming"
    assert claim.is_symlink(), "the link planted at the claim was removed"
    assert os.readlink(claim) == str(target), "the link planted at the claim was repointed"
    assert target.read_bytes() == S.HOST_BYTES
    assert S.warned(caplog, ".priming", "aliased"), "the refused release was not logged"


class ScriptedJudge:
    """The judge seam (`judge=`): `by_agent[agent_id]` or `default`, recording each call."""

    def __init__(self, by_agent: dict[str, str], default: str) -> None:
        self.by_agent = by_agent
        self.default = default
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.agent_ids.append(agent_id)
        return self.by_agent.get(agent_id, self.default)


def _draw0_asks() -> list[str]:
    """Every ask of world `b`'s draw 0: the first and its re-asks after a refused reply (N22,
    `judge._REPLY_ATTEMPTS` asks per draw)."""
    attempts = J.mod("learning.judge")._REPLY_ATTEMPTS
    return [f"judge:{WORLD_B}:0", *(f"judge:{WORLD_B}:0:{a}" for a in range(1, attempts))]


def _malformed_first() -> ScriptedJudge:
    """Every ask of draw 0 answered malformed, so the draw writes nothing (its stale file is
    removed) and each ask counts a malformed reply; every other ask answered well."""
    good = J.as_reply_text(J.reply_doc())
    bad = J.as_reply_text(J.reply_doc(), malformed="lookalike-bucket")
    return ScriptedJudge(dict.fromkeys(_draw0_asks(), bad), default=good)


def _judged_episode(tmp_path: Path) -> Path:
    """An accepted, archived episode whose world `b` is graded (it carries an oracle row)."""
    return J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})


@pytest.mark.parametrize("target", ["inside", "outside"])
def test_o4_6_a_link_at_a_malformed_draws_name_is_refused_logged_and_left_and_the_loop_goes_on(
        tmp_path, roots, caplog, target):
    enqueue = J.mod("learning.judge.enqueue")
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / WORLD_B / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    outside = (ep / "worlds" / WORLD_B / "planted-draw.yaml" if target == "inside"
               else tmp_path / "outside-draw.yaml")
    outside.write_text("findings: [{bucket: planted}]\n", encoding="utf-8")
    (draw_dir / "0.yaml").symlink_to(outside)

    caplog.set_level(logging.WARNING)
    judge = _malformed_first()
    J.grade_at(ep, judge=judge, draws=2, state=env_state())

    assert f"judge:{WORLD_B}:1" in judge.agent_ids, "the draw loop stopped at the refused removal"
    link = draw_dir / "0.yaml"
    assert link.is_symlink(), "the link planted at the malformed draw's name was removed"
    assert os.readlink(link) == str(outside), "the planted link was repointed"
    assert outside.read_text(encoding="utf-8") == "findings: [{bucket: planted}]\n"
    assert (draw_dir / "1.yaml").is_file(), "the loop did not go on to write draw 1"
    row = J.world_rows(J.judge_record(ep))["b"]
    assert (row["malformed_replies"], row["completed_draws"]) == (len(_draw0_asks()), 1), row
    assert S.warned(caplog, "0.yaml", "aliased"), "the refused draw removal was not logged"
    with _io.bind(ep) as view:
        draws, report = enqueue.draws_on_disk_report(view, WORLD_B)
    assert sorted(draws) == [1], f"the disk read picked up {sorted(draws)}"
    assert report.unreadable == 1, f"the linked draw was not counted unreadable: {report}"


def test_o4_6_a_plain_stale_draw_at_a_malformed_index_is_still_removed(tmp_path, roots):
    """Positive control on the same address: a plain file an earlier pass left at
    `worlds/b/judge/0.yaml` is removed when this pass's draw 0 is malformed."""
    ep = _judged_episode(tmp_path)
    draw_dir = ep / "worlds" / WORLD_B / "judge"
    draw_dir.mkdir(parents=True, exist_ok=True)
    (draw_dir / "0.yaml").write_text("findings: [{bucket: stale}]\n", encoding="utf-8")

    J.grade_at(ep, judge=_malformed_first(), draws=2, state=env_state())

    assert not os.path.lexists(draw_dir / "0.yaml"), "the stale plain draw survived"
    assert (draw_dir / "1.yaml").is_file()


def _run_draws(episode: Any, judge: ScriptedJudge) -> Any:
    """`judge._run_world_draws(episode, "b", ...)`: the draw loop, handed the pass's Episode.
    Returns its `(completed, documents, malformed, last refusal's reason)` (#1234)."""
    return J.mod("learning.judge")._run_world_draws(
        episode, "b", world_id=WORLD_B, judge=judge, draws=2, model="judge-model", effort="low",
        prompt="the framed prompt")


def _stale_draw(ep: Path) -> Path:
    draw = ep / "worlds" / WORLD_B / "judge" / "0.yaml"
    draw.parent.mkdir(parents=True, exist_ok=True)
    draw.write_text("findings: [{bucket: stale}]\n", encoding="utf-8")
    return draw


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EROFS, errno.EIO,
                                  errno.ENOTDIR],
                         ids=["EACCES", "EPERM", "EROFS", "EIO", "ENOTDIR"])
def test_s1_any_other_error_removing_a_stale_draw_stops_the_pass_and_keeps_nothing_silently(
        tmp_path, code):
    ep = _judged_episode(tmp_path)
    draw = _stale_draw(ep)
    rel = LAYOUT.world(WORLD_B).draw(0)

    def fault(method: str, args: tuple, kwargs: dict) -> None:
        name = args[0] if args else kwargs.get("name")
        if method == "unlink" and S.as_rel(name) == rel:
            raise OSError(code, os.strerror(code), str(draw))

    judge = _malformed_first()
    with S.open_episode(ep, io=S.RecordingIo(before=fault)) as episode:
        raised = S.raised_by(lambda: _run_draws(episode, judge))
    refused = S.refusal_in(raised)
    assert refused is not None, f"a {errno.errorcode[code]} removing a draw was contained: {raised!r}"
    assert refused.errno == code, raised
    assert judge.agent_ids == _draw0_asks(), (
        f"the loop went on past a {errno.errorcode[code]}: {judge.agent_ids}")
    assert draw.read_text(encoding="utf-8") == "findings: [{bucket: stale}]\n"

    judge = _malformed_first()
    with S.open_episode(ep) as episode:
        completed, documents, malformed, _last_refusal = _run_draws(episode, judge)
    assert judge.agent_ids == [*_draw0_asks(), f"judge:{WORLD_B}:1"]
    assert (completed, malformed) == (1, len(_draw0_asks()))
    assert sorted(documents) == [1]
    assert not os.path.lexists(draw), "control: the stale plain draw survived"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory"])
def test_s1_a_non_plain_draw_is_contained_logged_and_left(tmp_path, caplog, kind):
    ep = _judged_episode(tmp_path)
    draw = ep / "worlds" / WORLD_B / "judge" / "0.yaml"
    host = tmp_path / "host"
    host.mkdir()
    planted = S.plant_leaf(draw, kind, host=host)
    caplog.set_level(logging.WARNING)

    judge = _malformed_first()
    with S.open_episode(ep) as episode:
        completed, _docs, malformed, _last_refusal = S.in_time(
            lambda: _run_draws(episode, judge), fifo=planted.fifo)
    assert judge.agent_ids == [*_draw0_asks(), f"judge:{WORLD_B}:1"], (
        "the loop stopped at a contained row")
    assert (completed, malformed) == (1, len(_draw0_asks()))
    assert os.path.lexists(draw), f"the {kind} at the draw's name was removed"
    assert S.warned(caplog, "0.yaml"), "the refused removal was not logged"


def test_d3_draws_on_disk_report_counts_every_yaml_entry_of_any_kind(tmp_path):
    enqueue = J.mod("learning.judge.enqueue")
    ep = tmp_path / "episodes" / EPISODE_ID
    draw_dir = ep / "worlds" / WORLD_B / "judge"
    draw_dir.mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    (draw_dir / "0.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "01.yaml").write_text("findings: []\n", encoding="utf-8")
    (draw_dir / "x.yaml").write_text("findings: []\n", encoding="utf-8")
    S.plant_leaf(draw_dir / "1.yaml", "symlink", host=host, body=b"findings: []\n")
    S.plant_leaf(draw_dir / "2.yaml", "directory", host=host)
    S.plant_leaf(draw_dir / "3.yaml", "fifo", host=host)
    S.plant_leaf(draw_dir / "4.yaml", "hardlink", host=host, body=b"findings: []\n")

    with _io.bind(ep) as view:
        draws, report = S.in_time(lambda: enqueue.draws_on_disk_report(view, WORLD_B),
                                  fifo=draw_dir / "3.yaml")
        assert enqueue.draws_on_disk(view, WORLD_B) == draws
    assert draws == {0: {"findings": []}}
    assert (report.unreadable, report.skipped) == (5, 1), report
    with S.open_episode(ep) as episode:
        assert enqueue.draws_on_disk(episode.view(), WORLD_B) == {0: {"findings": []}}


@pytest.mark.parametrize("at", ["worlds", f"worlds/{WORLD_B}", f"worlds/{WORLD_B}/judge"])
def test_d3_a_link_at_worlds_or_the_world_or_its_draws_folder_yields_no_draws(tmp_path, at):
    enqueue = J.mod("learning.judge.enqueue")
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    c_draw = {"findings": [{"bucket": "c-only"}]}
    if at == "worlds":
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "b" / "judge").mkdir(parents=True)
        (elsewhere / "b" / "judge" / "0.yaml").write_text(yaml.safe_dump(c_draw),
                                                           encoding="utf-8")
        (ep / "worlds").symlink_to(elsewhere, target_is_directory=True)
    else:
        c_judge = ep / "worlds" / WORLD_C / "judge"
        c_judge.mkdir(parents=True)
        (c_judge / "0.yaml").write_text(yaml.safe_dump(c_draw), encoding="utf-8")
        if at == f"worlds/{WORLD_B}":
            (ep / "worlds" / WORLD_B).symlink_to(ep / "worlds" / WORLD_C, target_is_directory=True)
        else:
            (ep / "worlds" / WORLD_B).mkdir()
            (ep / "worlds" / WORLD_B / "judge").symlink_to(c_judge, target_is_directory=True)

    with _io.bind(ep) as view:
        assert enqueue.draws_on_disk(view, WORLD_B) == {}, f"a link at {at} yielded draws under b"
        draws, _report = enqueue.draws_on_disk_report(view, WORLD_B)
        assert draws == {}
        if at != "worlds":
            assert enqueue.draws_on_disk(view, WORLD_C) == {0: c_draw}, "control: c's own draws"

    (ep / at).unlink()
    real = ep / "worlds" / WORLD_B / "judge"
    real.mkdir(parents=True, exist_ok=True)
    (real / "0.yaml").write_text("findings: [{bucket: b-own}]\n", encoding="utf-8")
    with _io.bind(ep) as view:
        assert enqueue.draws_on_disk(view, WORLD_B) == {0: {"findings": [{"bucket": "b-own"}]}}


@pytest.mark.parametrize("kind", ["missing", "missing-parent", "file"])
def test_o4_8_2_grade_episode_refuses_a_missing_episode_dir_and_does_not_recreate_it(
        tmp_path, roots, kind):
    judge_mod = J.mod("learning.judge")
    tenant = T.current_tenant()
    ep = Path(location_path(tenant.episodes)) / EPISODE_ID
    if kind != "missing-parent":
        ep.parent.mkdir()
    if kind == "file":
        ep.write_bytes(S.HOST_BYTES)
    before = S.census(Path(location_path(tenant.tenant_root)))

    with pytest.raises(judge_mod.JudgeRefused):
        J.grade_at(ep, runs=tenant.runs_repository(),
                   judge=ScriptedJudge({}, default="never called"), state=env_state())
    assert S.census(Path(location_path(tenant.tenant_root))) == before, f"grading a {kind} episode dir created something"

    control = T.episode(tmp_path / "control", episode_id=fixture_uuid("o4-8-2-grade-control"),
                        doc=T.family_doc(episode_id=fixture_uuid("o4-8-2-grade-control")))
    grade = J.grade_at(control, judge=ScriptedJudge({}, default="never called"), state=env_state())
    assert grade.not_graded is not None
    assert (control / "judge.yaml").is_file()


@pytest.mark.parametrize("kind", ["missing", "missing-parent"])
def test_o4_8_2_render_episode_refuses_a_missing_episode_dir_and_does_not_recreate_it(
        tmp_path, kind):
    """`render_episode(runs, episode_id)` keeps raising `JudgeRefused` for a missing episode
    (its door, `runs.episode`, converts the open's `FileNotFoundError`), and creates nothing —
    neither the episode nor a missing episodes base. Control: an existing episode's page is
    written inside it. (#1105 PR 2, declared change 4: the door takes the tenant's repository
    and an id under the configured episodes base, no longer a folder.) #1187 (Layout A, O9):
    the episodes base is the tenant's own `<T>/episodes/` — absent (`missing-parent`) or
    present without the episode (`missing`) — and nothing is configured."""
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    page = T.mod("presentation.visualize_episode")
    tenant = T.current_tenant()
    runs = tenant.runs_repository()
    ep = Path(location_path(tenant.episodes)) / EPISODE_ID
    if kind == "missing":
        ep.parent.mkdir()
    before = S.census(Path(location_path(tenant.tenant_root)))
    with pytest.raises(page.JudgeRefused):
        page.render_episode(runs, EPISODE_ID)
    assert S.census(Path(location_path(tenant.tenant_root))) == before

    control = T.episode(tmp_path / "control", episode_id=fixture_uuid("o4-8-2-control"),
                        doc=T.family_doc(episode_id=fixture_uuid("o4-8-2-control")))
    written = page.render_episode(runs, control.name)
    assert Path(written) == control / "learning.html"
    assert (control / "learning.html").is_file()


class Recorder:
    """`run.main`'s lifecycle seam: records that it ran and leaves a report, as a sibling does."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kw: Any) -> dict[str, Any]:
        self.calls.append(kw)
        (kw["run"].run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}


def _no_preflight(*_a: Any, **_kw: Any) -> int:
    """`run.main`'s role-preflight seam, passing (it is asked with `branching=`)."""
    return 0


def _sibling_argv(episode_id: str) -> list[str]:
    """The sibling's door (#1105 PR 2, declared change 6): `--tenant T --episode <id> --world
    b`, the episode opened by id among T's episodes (#1187 O9: `<T>/episodes/`, no configured
    base)."""
    return ["--tenant", T.SOURCE_TENANT, "--episode", episode_id, "--world", "b"]


def _sibling_episode(tmp_path: Path, src: Path) -> Path:
    """The episode a sibling opens by id, its manifest naming `src`. #1187 (R1, R2, O9,
    declared changes 5 and 6): at the source tenant's `<T>/episodes/<uuid>` (`T.episode`'s
    default), with no container record and no episodes variable; the launcher's RUNS step
    (`T.episode_view`) has made `runs/` and the arm roster the sibling reads world b's arm id
    from (O4b)."""
    from defender.episodes._episode_handle import Episode

    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    with Episode.open(ep) as held:
        T.episode_view(held).close()
    return ep


@pytest.mark.parametrize("spelling", ["path", "case", "separator"])
def test_the_sibling_door_refuses_an_episode_id_outside_the_id_grammar(
        tmp_path, monkeypatch, spelling):
    run = RunWithPublish(T.mod("run"))  # #1108 P4 (OD14, O11): plus the in-process publish
    _base, src = location_path(T.runs_base)(tmp_path)
    ep = _sibling_episode(tmp_path, src)
    bad = {"path": str(ep / LAYOUT.family), "case": ep.name.upper(),
           "separator": f"{ep.name}/{LAYOUT.family}"}[spelling]
    lifecycle = Recorder()
    materialized: list[Any] = []

    def materialize(*a: Any, **kw: Any) -> Any:
        materialized.append((a, kw))
        raise AssertionError("a run dir was materialized for a refused episode id")

    with pytest.raises(SystemExit) as refused:
        run.main(_sibling_argv(bad), lifecycle=lifecycle, visualize=lambda _run, **kw: None,
                 preflight=_no_preflight, materialize=materialize)
    assert refused.value.code not in (0, None), refused.value.code
    assert bad in str(refused.value.code), (
        f"the refusal does not name the refused episode id: {refused.value.code!r}")
    assert materialized == [], "a run dir was materialized"
    assert lifecycle.calls == [], "the lifecycle ran over a refused episode id"

    lifecycle = Recorder()
    rc = run.main(_sibling_argv(ep.name), lifecycle=lifecycle,
                  visualize=lambda _run, **kw: None, preflight=_no_preflight)
    assert rc == 0
    assert len(lifecycle.calls) == 1


def test_the_sibling_door_holds_one_descriptor_on_the_episode_for_the_whole_run(tmp_path,
                                                                              monkeypatch):
    run = RunWithPublish(T.mod("run"))  # #1108 P4 (OD14, O11): plus the in-process publish
    _base, src = location_path(T.runs_base)(tmp_path)
    ep = _sibling_episode(tmp_path, src)
    seen: dict[str, Any] = {}

    class Holding(Recorder):
        def __call__(self, **kw: Any) -> dict[str, Any]:
            seen["fds"] = S.open_fds_on(ep)
            seen["episode"] = kw.get("episode")
            return super().__call__(**kw)

    rc = run.main(_sibling_argv(ep.name), lifecycle=Holding(),
                  visualize=lambda _run, **kw: None, preflight=_no_preflight)
    assert rc == 0
    assert "fds" in seen, "the lifecycle never ran"
    assert len(seen["fds"]) == 1, (
        f"descriptors open on the episode dir while the sibling ran: {seen['fds']}")
    assert seen["episode"] is not None, "the lifecycle was handed no Episode"
    assert Path(seen["episode"].dir) == ep, seen["episode"].dir
    assert S.open_fds_on(ep) == [], "the sibling's door left the episode dir open"
