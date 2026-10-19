"""Legacy retirement renames old entries without copying, replacing, or following aliases."""
from __future__ import annotations

import errno
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

#: The tenant every scene is set up for, and a second one for the scoping cases.
T = H.T_ID
U = H.U_ID
#: The lesson the scene's UUID run loaded, and the tracer's `--all` row for it (one case in
#: context, no MAIN read).
LESSON = "L"
LESSON_ROW = f"{LESSON}\td\t1\t0"
# Drivers.

def _retire(*argv: str) -> P.CliResult:
    """Import the retirement command directly so a missing entrypoint fails the test."""
    command = importlib.import_module(S.COMMAND_MODULE)
    return P.drive_cli(command.main, list(argv))


def _trace(tenant_id: str, lessons: Path) -> P.CliResult:
    """`trace_lesson.py --tenant <tenant_id> --all --lessons-dir <lessons>`, in process."""
    from defender.cli.learning import trace_lesson

    return P.drive_cli(trace_lesson.main,
                       ["--tenant", tenant_id, "--all", "--lessons-dir", str(lessons)])


def _code(got: P.CliResult) -> object:
    """The exit status the operator would see: `main`'s return, or the `SystemExit`'s code (`sys.exit("message")` carries the message)."""
    return got.raised.code if got.raised is not None else got.rc  # type: ignore[union-attr]


def _ok(got: P.CliResult) -> bool:
    return _code(got) == 0


def _refused(got: P.CliResult) -> bool:
    """Exited non-zero: a non-zero return, or `sys.exit` with a message or a non-zero code."""
    return _code(got) not in (0, None)


def _shown(got: P.CliResult) -> str:
    return f"rc={_code(got)!r}\nstdout: {got.out[-800:]}\nsaid: {got.said[-800:]}"
# Scenes — real tenants and real entries on the real filesystem.

@dataclass
class Scene:
    tenant_dir: Path
    runs: Path
    old_root: Path
    lessons: Path
    #: The UUID run ids planted in `<T>/runs`.
    uuid_runs: frozenset[str]
    #: Every top-level name of `<T>/runs` that is a UUID run or a sidecar of one (stays).
    stay: frozenset[str]
    #: Every top-level name of `<T>/runs` the command must move (old runs, their sidecars,
    #: `_tenant.json`, `_episodes`).
    old: frozenset[str]
    #: Every top-level name of the old episodes root (all of it moves).
    old_episodes: frozenset[str]

    @property
    def runs_legacy(self) -> Path:
        return self.tenant_dir / S.RUNS_LEGACY

    @property
    def episodes_legacy(self) -> Path:
        return self.tenant_dir / S.EPISODES_LEGACY


def _lessons(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{LESSON}.md").write_text(
        f"---\nname: {LESSON}\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n",
        encoding="utf-8")
    return folder


def _uuid_runs(runs: Path) -> frozenset[str]:
    """Create two UUID runs with sidecars and distinct loaded lessons."""
    loaded = S.make_run(runs, sidecars=True)
    (loaded / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (loaded / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": LESSON, "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")
    other = S.make_run(runs)
    H.plant_sidecars(runs, other.name, staged=True)
    return frozenset({loaded.name, other.name})


def _scene(data_root: Path, where: Path, *, tenant_id: str = T, old_root: bool = True) -> Scene:
    """Create an accepted tenant containing legacy entries and UUID runs that must survive."""
    S.tenant(data_root, tenant_id)
    runs = S.natural_runs(data_root, tenant_id)
    uuids = _uuid_runs(runs)
    stay = frozenset(os.listdir(runs))
    S.plant_old_natural_entries(data_root, tenant_id)
    old = frozenset(os.listdir(runs)) - stay
    root = Path(where) / "old-episodes"
    if old_root:
        S.plant_old_episodes_root(root)
    return Scene(tenant_dir=S.tenant_dir(data_root, tenant_id), runs=runs, old_root=root,
                 lessons=_lessons(Path(where) / "lessons"), uuid_runs=uuids, stay=stay,
                 old=old, old_episodes=frozenset(os.listdir(root)) if old_root else frozenset())


def _under(tree: dict[str, Any], names: frozenset[str]) -> dict[str, Any]:
    """The entries of `tree` whose top-level name is one of `names` (the entries those top-level entries hold included)."""
    return {rel: v for rel, v in tree.items() if Path(rel).parts[0] in names}


def _world(*roots: Path) -> dict[str, dict[str, Any]]:
    """Every root's tree, by root: the "nothing changed" observation."""
    return {str(r): S.tree(r) for r in roots}


def _names(folder: Path) -> frozenset[str]:
    return frozenset(os.listdir(folder)) if folder.is_dir() else frozenset()


def _full(sc: Scene) -> list[str]:
    return ["--tenant", T, "--old-episodes-root", str(sc.old_root)]


def _inodes(sc: Scene) -> dict[str, dict[str, tuple[int, int]]]:
    """The scene's entries' `(st_dev, st_ino)` before the command, by where each must END."""
    return {"runs_legacy": S.identities(sc.runs, sc.old),
            "episodes_legacy": S.identities(sc.old_root, sc.old_episodes),
            "runs": S.identities(sc.runs, sc.stay)}


def _assert_renamed(sc: Scene, before: dict[str, dict[str, tuple[int, int]]]) -> None:
    """Check renamed entries retain their original device and inode identities."""
    after = {"runs_legacy": S.identities(sc.runs_legacy),
             "episodes_legacy": S.identities(sc.episodes_legacy),
             "runs": S.identities(sc.runs)}
    for where, was in before.items():
        moved = {rel for rel in was if after[where].get(rel) != was[rel]}
        assert not moved, (f"{len(moved)} entr(ies) bound for {where} are not the entries that "
                           f"were planted (copied, not renamed): {sorted(moved)[:6]}")
# O6 / declared changes 6 and 7 — before the command, the listing refuses an old entry and
# the refusal names the command.

def _old_run_folder(runs: Path) -> str:
    return S.make_run(runs, S.OLD_MINTED_ID).name


def _old_pinned_folder(runs: Path) -> str:
    return S.make_run(runs, S.OLD_PINNED_ID).name


def _old_sidecar(runs: Path) -> str:
    """An old run's sidecar alone (its folder already gone): a regular file `<old id><suffix>`."""
    path = runs / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[1]}"
    path.write_text("{}\n", encoding="utf-8")
    return path.name


def _tenant_record(runs: Path) -> str:
    return H.plant_tenant_record(runs, T).name


def _episodes_record(runs: Path) -> str:
    folder = runs / "_episodes"
    folder.mkdir()
    (folder / "placeholder.json").write_text("{}\n", encoding="utf-8")
    return folder.name


#: Each pre-#1187 entry kind a natural container holds today, planted ALONE beside the UUID runs.
_OLD_ENTRIES = {
    "old_minted_run": _old_run_folder,
    "old_pinned_run": _old_pinned_folder,
    "old_sidecar": _old_sidecar,
    "tenant_record": _tenant_record,
    "episodes_record": _episodes_record,
}


def test_1187_o6_a_container_of_uuid_runs_and_their_sidecars_is_served_with_no_record(
        data_root, tmp_path):
    t = S.tenant(data_root, T)
    uuids = _uuid_runs(S.natural_runs(data_root, T))
    lessons = _lessons(tmp_path / "lessons")

    err = H.raised(t.runs_repository().all_runs)
    assert err is None, f"all_runs over UUID runs and their sidecars gave {err!r}"
    assert sorted(str(r.id) for r in t.runs_repository().all_runs()) == sorted(uuids)
    served = _trace(T, lessons)
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW], served.out


@pytest.mark.parametrize("kind", sorted(_OLD_ENTRIES))
def test_1187_o6_the_listing_refuses_an_old_entry_naming_it_and_the_command(
        kind, data_root, tmp_path):
    from defender.run_repository import RunRefused

    t = S.tenant(data_root, T)
    runs = S.natural_runs(data_root, T)
    uuids = _uuid_runs(runs)
    name = _OLD_ENTRIES[kind](runs)

    err = H.raised(t.runs_repository().all_runs)
    assert H.is_a(err, RunRefused), f"all_runs beside {name!r} gave {err!r}"
    text = H.message(err)
    assert S.COMMAND in text, f"the refusal does not name the command: {text!r}"
    assert name in text, f"the refusal does not name {name!r}: {text!r}"

    shutil.move(str(runs / name), str(tmp_path / "moved-away"))
    served = t.runs_repository().all_runs()
    assert sorted(str(r.id) for r in served) == sorted(uuids)


@pytest.mark.parametrize("kind", sorted(_OLD_ENTRIES))
def test_1187_o6_the_tracer_stops_on_an_old_entry_naming_it_and_the_command(
        kind, data_root, tmp_path):
    S.tenant(data_root, T)
    runs = S.natural_runs(data_root, T)
    _uuid_runs(runs)
    lessons = _lessons(tmp_path / "lessons")
    name = _OLD_ENTRIES[kind](runs)

    got = _trace(T, lessons)
    assert _refused(got), f"the tracer ran beside {name!r}: {_shown(got)}"
    assert got.out == "", f"the tracer printed rows before stopping: {got.out!r}"
    assert S.COMMAND in got.said, f"the refusal does not name the command: {got.said!r}"
    assert name in got.said, f"the refusal does not name {name!r}: {got.said!r}"

    shutil.move(str(runs / name), str(tmp_path / "moved-away"))
    served = _trace(T, lessons)
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW], served.out


def test_1187_o6_the_tracer_stops_on_a_pre_1187_container_naming_the_command(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path, old_root=False)
    shutil.rmtree(sc.runs / "_episodes")

    got = _trace(T, sc.lessons)
    assert _refused(got), f"the tracer served a pre-#1187 container: {_shown(got)}"
    assert got.out == "", f"the tracer printed rows before stopping: {got.out!r}"
    assert S.COMMAND in got.said, f"the refusal does not name the command: {got.said!r}"
# O5 / Flow 6 — the command moves old entries aside, intact, and the tenant is served after.

def test_1187_o5_the_command_moves_every_old_entry_aside_intact_and_the_tracer_then_serves(
        data_root, tmp_path):
    command = importlib.import_module(S.COMMAND_MODULE)
    sc = _scene(data_root, tmp_path)
    runs_before = S.tree(sc.runs)
    episodes_before = S.tree(sc.old_root)
    inodes_before = _inodes(sc)
    assert sc.old, "the scene planted no old natural entry"
    assert sc.old_episodes, "the scene planted no old episode"
    assert sc.stay, "the scene planted no UUID run"

    refused = _trace(T, sc.lessons)
    assert _refused(refused), _shown(refused)
    assert S.COMMAND in refused.said, _shown(refused)

    got = P.drive_cli(command.main, _full(sc))
    assert _ok(got), _shown(got)
    assert S.tree(sc.runs) == _under(runs_before, sc.stay), "a UUID run or its sidecar moved"
    assert S.tree(sc.runs_legacy) == _under(runs_before, sc.old), "an old entry is not intact"
    assert S.tree(sc.episodes_legacy) == episodes_before, "an old episode is not intact"
    assert sc.old_root.is_dir(), "the old episodes root itself was moved or deleted"
    assert S.tree(sc.old_root) == {}, "the old episodes root was not emptied"
    for name in sorted(sc.old | sc.old_episodes):
        assert name in got.out, f"stdout does not report moving {name!r}: {got.out!r}"
    _assert_renamed(sc, inodes_before)

    served = _trace(T, sc.lessons)
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW], served.out


def test_1187_o5_the_listing_serves_the_uuid_runs_after_the_command(data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    t = S.tenant(data_root, T)
    assert sorted(str(r.id) for r in t.runs_repository().all_runs()) == sorted(sc.uuid_runs)


def test_1187_o5_without_an_old_episodes_root_only_the_natural_entries_move(
        data_root, tmp_path, monkeypatch):
    sc = _scene(data_root, tmp_path)
    monkeypatch.setenv(S.EPISODES_BASE_ENV, str(sc.old_root))
    episodes_before = S.tree(sc.old_root)

    got = _retire("--tenant", T)
    assert _ok(got), _shown(got)
    assert _names(sc.runs_legacy) == sc.old
    assert _names(sc.runs) == sc.stay
    assert S.tree(sc.old_root) == episodes_before, "an unnamed old episodes root was moved"
    assert S.tree(sc.episodes_legacy) == {}, "episodes moved with no --old-episodes-root"


def test_1187_o5_an_absent_old_episodes_root_is_a_noop_for_that_part(data_root, tmp_path):
    sc = _scene(data_root, tmp_path, old_root=False)
    gone = tmp_path / "no-such-episodes-root"

    got = _retire("--tenant", T, "--old-episodes-root", str(gone))
    assert _ok(got), _shown(got)
    assert _names(sc.runs_legacy) == sc.old
    assert not os.path.lexists(gone), "the absent old episodes root was created"
    assert S.tree(sc.episodes_legacy) == {}


def test_1187_o5_the_named_old_episodes_root_is_held_following_its_spelling(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    spelled = tmp_path / "episodes-base-link"
    os.symlink(sc.old_root, spelled)
    episodes_before = S.tree(sc.old_root)

    got = _retire("--tenant", T, "--old-episodes-root", str(spelled))
    assert _ok(got), _shown(got)
    assert S.tree(sc.episodes_legacy) == episodes_before
    assert S.tree(sc.old_root) == {}
    assert os.path.islink(spelled), "the operator's link to the old root was moved or removed"


def test_1187_o5_a_rerun_after_the_operator_removed_the_emptied_root_succeeds(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    first = _retire(*_full(sc))
    assert _ok(first), _shown(first)
    sc.old_root.rmdir()
    after_first = _world(data_root)

    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _world(data_root) == after_first, "the re-run changed something"


def test_1187_o5_a_second_run_changes_nothing(data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    first = _retire(*_full(sc))
    assert _ok(first), _shown(first)
    after_first = _world(data_root, sc.old_root)

    second = _retire(*_full(sc))
    assert _ok(second), _shown(second)
    assert _world(data_root, sc.old_root) == after_first, "the second run changed something"


def _crash_mid_natural(sc: Scene) -> None:
    """Some natural entries renamed, the rest not; no episode moved yet (natural ones go first)."""
    sc.runs_legacy.mkdir()
    for name in sorted(sc.old)[: len(sc.old) // 2]:
        os.rename(sc.runs / name, sc.runs_legacy / name)


def _crash_mid_episodes(sc: Scene) -> None:
    """Every natural entry renamed, one old episode renamed, the other not."""
    sc.runs_legacy.mkdir()
    for name in sc.old:
        os.rename(sc.runs / name, sc.runs_legacy / name)
    sc.episodes_legacy.mkdir()
    first = sorted(sc.old_episodes)[0]
    os.rename(sc.old_root / first, sc.episodes_legacy / first)


@pytest.mark.parametrize("crash", [_crash_mid_natural, _crash_mid_episodes],
                         ids=["mid_natural", "mid_episodes"])
def test_1187_o5_a_rerun_finishes_a_move_a_crash_interrupted(crash, data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    runs_before = S.tree(sc.runs)
    episodes_before = S.tree(sc.old_root)
    inodes_before = _inodes(sc)
    crash(sc)

    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    assert S.tree(sc.runs) == _under(runs_before, sc.stay)
    assert S.tree(sc.runs_legacy) == _under(runs_before, sc.old)
    assert S.tree(sc.episodes_legacy) == episodes_before
    assert S.tree(sc.old_root) == {}
    _assert_renamed(sc, inodes_before)


def test_1187_r3_a_queued_curation_row_naming_an_old_run_does_not_stop_the_command(
        data_root, tmp_path, monkeypatch):
    from defender.tests.support.learning.core import _state1135

    sc = _scene(data_root, tmp_path)
    state_root = _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    _state1135.env_state().enqueue_curation(
        "case-old", {"case_id": "case-old", "tenant_id": T, "run_id": S.OLD_PINNED_ID})
    queued = S.tree(state_root)
    assert any(rel.endswith("case-old.json") for rel in queued), queued

    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    assert S.OLD_PINNED_ID in _names(sc.runs_legacy)
    assert _names(sc.runs_legacy) == sc.old
    assert S.tree(state_root) == queued, "the command touched the curation queue"


def test_1187_n13_old_episodes_go_to_the_tenant_named_and_no_other_tenant_is_touched(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path / "t")
    other = _scene(data_root, tmp_path / "u", tenant_id=U, old_root=False)
    H.plant_tenant_record(sc.old_root / sorted(sc.old_episodes)[0] / "runs", U)
    episodes_before = S.tree(sc.old_root)
    other_before = S.tree(other.tenant_dir)

    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    assert S.tree(sc.episodes_legacy) == episodes_before
    assert S.tree(other.tenant_dir) == other_before, f"tenant {U}'s tree changed"
# S-move — refuse before ANY move. Each refusal: non-zero exit, every tree byte-identical,
# the refusal names what it found. Positive control: the operator's fix, then the same command
# moves.

def _link_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    """Plant an old-looking run symlink to an external directory."""
    (outside / "target").mkdir()
    (outside / "target" / "kept.txt").write_text("outside\n", encoding="utf-8")
    link = sc.runs / "zz-old-link"
    os.symlink(outside / "target", link)
    return link, "link"


def _uuid_named_link_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    """Plant a UUID-named symlink that must be classified from its own directory entry."""
    target = S.make_run(outside / "elsewhere")
    link = sc.runs / S.new_id()
    os.symlink(target, link)
    return link, "link"


def _fifo_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    return H.make_fifo(sc.runs / "zz-old-fifo"), "special"


def _link_in_old_root(sc: Scene, outside: Path) -> tuple[Path, str]:
    """Plant a legacy latest shortcut pointing to another episode directory."""
    link = sc.old_root / "latest"
    os.symlink(sorted(sc.old_episodes)[-1], link)
    return link, "link"


def _fifo_in_old_root(sc: Scene, outside: Path) -> tuple[Path, str]:
    return H.make_fifo(sc.old_root / "zz-fifo"), "special"


_MOVE_SET_FAULTS = {
    "link_in_runs": _link_in_runs,
    "uuid_named_link_in_runs": _uuid_named_link_in_runs,
    "fifo_in_runs": _fifo_in_runs,
    "link_in_old_episodes_root": _link_in_old_root,
    "fifo_in_old_episodes_root": _fifo_in_old_root,
}


@pytest.mark.parametrize("fault", sorted(_MOVE_SET_FAULTS))
def test_1187_s_move_a_link_or_special_file_in_the_move_set_refuses_before_any_move(
        fault, data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    entry, kind = _MOVE_SET_FAULTS[fault](sc, outside)
    before = _world(data_root, sc.old_root, outside)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command ran over {entry.name!r}: {_shown(got)}"
    assert _world(data_root, sc.old_root, outside) == before, "something moved before refusing"
    assert entry.name in got.said, f"the refusal does not name {entry.name!r}: {got.said!r}"
    if kind == "link":
        assert re.search(r"\brm\b|\bremov", got.said, re.IGNORECASE), (
            f"the refusal does not name removing the link by hand: {got.said!r}")

    os.unlink(entry)
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(sc.runs_legacy) == sc.old
    assert _names(sc.episodes_legacy) == sc.old_episodes


def _link_to_folder(path: Path, outside: Path) -> None:
    (outside / "real-folder").mkdir()
    os.symlink(outside / "real-folder", path)


def _dangling_link(path: Path, outside: Path) -> None:
    os.symlink(outside / "nothing-here", path)


def _regular_file(path: Path, outside: Path) -> None:
    path.write_text("not a folder\n", encoding="utf-8")


_NOT_A_FOLDER = {"link_to_a_folder": _link_to_folder, "dangling_link": _dangling_link,
                 "regular_file": _regular_file}


@pytest.mark.parametrize("shape", sorted(_NOT_A_FOLDER))
@pytest.mark.parametrize("destination", [S.RUNS_LEGACY, S.EPISODES_LEGACY])
def test_1187_s_move_a_destination_that_is_not_a_real_folder_refuses_before_any_move(
        destination, shape, data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    path = sc.tenant_dir / destination
    _NOT_A_FOLDER[shape](path, outside)
    before = _world(data_root, sc.old_root, outside)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command ran with {destination} a {shape}: {_shown(got)}"
    assert _world(data_root, sc.old_root, outside) == before, "something moved before refusing"
    assert destination in got.said, f"the refusal does not name {destination}: {got.said!r}"

    os.unlink(path)
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(sc.runs_legacy) == sc.old
    assert _names(sc.episodes_legacy) == sc.old_episodes


def _taken_old_run_folder(sc: Scene, outside: Path) -> Path:
    """An EMPTY folder at an old run's name: a rename between handles would silently replace it (R2-22)."""
    taken = sc.runs_legacy / S.OLD_PINNED_ID
    taken.mkdir(parents=True)
    return taken


def _taken_old_sidecar(sc: Scene, outside: Path) -> Path:
    """A regular file at an old sidecar's name, other bytes: a rename would replace it."""
    sc.runs_legacy.mkdir()
    taken = sc.runs_legacy / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[0]}"
    taken.write_text('{"older": true}\n', encoding="utf-8")
    return taken


def _taken_old_episode(sc: Scene, outside: Path) -> Path:
    """An EMPTY folder at the old episode's name that would move LAST."""
    taken = sc.episodes_legacy / sorted(sc.old_episodes)[-1]
    taken.mkdir(parents=True)
    return taken


def _dangling_link_at_old_sidecar(sc: Scene, outside: Path) -> Path:
    """A DANGLING link at an old sidecar's name, aimed at a file outside `<T>` that does not."""
    sc.runs_legacy.mkdir()
    taken = sc.runs_legacy / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[0]}"
    os.symlink(outside / "written-through", taken)
    return taken


def _link_to_a_file_at_old_sidecar(sc: Scene, outside: Path) -> Path:
    """A link at an old sidecar's name to a real file outside `<T>` (its bytes must survive)."""
    sc.runs_legacy.mkdir()
    (outside / "someone-elses.json").write_text('{"outside": true}\n', encoding="utf-8")
    taken = sc.runs_legacy / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[0]}"
    os.symlink(outside / "someone-elses.json", taken)
    return taken


def _dangling_link_at_old_run_folder(sc: Scene, outside: Path) -> Path:
    """A DANGLING link at an old run FOLDER's name (a folder copied through it would land outside `<T>`)."""
    sc.runs_legacy.mkdir()
    taken = sc.runs_legacy / S.OLD_PINNED_ID
    os.symlink(outside / "no-such-folder", taken)
    return taken


def _link_to_a_folder_at_old_episode(sc: Scene, outside: Path) -> Path:
    """A link at the last old episode's name in `episodes-legacy/`, to a real folder outside `<T>` (nothing may be written into it)."""
    (outside / "real-folder").mkdir()
    (outside / "real-folder" / "kept.txt").write_text("outside\n", encoding="utf-8")
    sc.episodes_legacy.mkdir()
    taken = sc.episodes_legacy / sorted(sc.old_episodes)[-1]
    os.symlink(outside / "real-folder", taken)
    return taken


_TAKEN = {"old_run_folder": _taken_old_run_folder, "old_sidecar_file": _taken_old_sidecar,
          "old_episode_folder": _taken_old_episode,
          "dangling_link_at_old_sidecar": _dangling_link_at_old_sidecar,
          "link_to_a_file_at_old_sidecar": _link_to_a_file_at_old_sidecar,
          "dangling_link_at_old_run_folder": _dangling_link_at_old_run_folder,
          "link_to_a_folder_at_old_episode": _link_to_a_folder_at_old_episode}


@pytest.mark.parametrize("taken", sorted(_TAKEN))
def test_1187_s_move_a_destination_name_already_taken_refuses_before_any_move(
        taken, data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    planted = _TAKEN[taken](sc, outside)
    before = _world(data_root, sc.old_root, outside)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command ran over the taken {planted.name!r}: {_shown(got)}"
    assert _world(data_root, sc.old_root, outside) == before, (
        "something moved, was replaced, or was written through the planted link")
    assert planted.name in got.said, f"the refusal does not name {planted.name!r}: {got.said!r}"

    if planted.is_symlink() or not planted.is_dir():
        planted.unlink()
    else:
        planted.rmdir()
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(sc.runs_legacy) == sc.old
    assert _names(sc.episodes_legacy) == sc.old_episodes


def test_1187_n15_a_record_an_old_checkout_recreates_is_never_renamed_over_the_moved_one(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    first = _retire(*_full(sc))
    assert _ok(first), _shown(first)
    moved_record = (sc.runs_legacy / "_tenant.json").read_bytes()
    H.plant_tenant_record(sc.runs, T, raw=json.dumps({"tenant_id": T, "recreated": True}) + "\n")
    before = _world(data_root, sc.old_root)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command ran over the moved _tenant.json: {_shown(got)}"
    assert _world(data_root, sc.old_root) == before, "something moved or was replaced"
    assert (sc.runs_legacy / "_tenant.json").read_bytes() == moved_record
    assert "_tenant.json" in got.said, f"the refusal does not name _tenant.json: {got.said!r}"


def test_1187_s_move_a_link_at_the_tenants_runs_folder_refuses_before_any_move(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    elsewhere = tmp_path / "elsewhere-runs"
    S.replace_with_link(sc.runs, elsewhere)
    before = _world(data_root, sc.old_root, elsewhere)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command followed a linked runs folder: {_shown(got)}"
    assert _world(data_root, sc.old_root, elsewhere) == before, "something moved through the link"
    assert "runs" in got.said, got.said

    os.unlink(sc.runs)
    os.rename(elsewhere, sc.runs)
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(sc.runs_legacy) == sc.old


@pytest.mark.parametrize("target", ["another_tenants_folder", "a_folder_outside_the_data_root"])
def test_1187_s_move_a_link_at_the_tenant_folder_refuses_before_any_move(
        target, data_root, tmp_path):
    link = S.tenant_dir(data_root, T)
    if target == "another_tenants_folder":
        sc = _scene(data_root, tmp_path / "u", tenant_id=U, old_root=False)
        os.symlink(sc.tenant_dir, link)
        argv = ["--tenant", T]
        watched = (data_root,)
    else:
        sc = _scene(data_root, tmp_path)
        aside = tmp_path / "elsewhere" / T
        aside.parent.mkdir()
        os.rename(link, aside)
        os.symlink(aside, link)
        argv = _full(sc)
        watched = (data_root, aside, sc.old_root)
    before = _world(*watched)

    got = _retire(*argv)
    assert _refused(got), f"the command followed a linked <T> ({target}): {_shown(got)}"
    assert _world(*watched) == before, f"something moved through the linked <T> ({target})"
    assert link.is_symlink(), "the link at <T> was replaced"

    if target == "another_tenants_folder":
        again = _retire("--tenant", U)
        assert _ok(again), _shown(again)
        assert _names(sc.runs_legacy) == sc.old
    else:
        os.unlink(link)
        os.rename(aside, link)
        again = _retire(*_full(sc))
        assert _ok(again), _shown(again)
        assert _names(sc.runs_legacy) == sc.old
        assert _names(sc.episodes_legacy) == sc.old_episodes


#: The CI-provided folder for the rename-time EXDEV case (adversary F6): a folder on ANOTHER
#: MOUNT of the data root's own filesystem (same `st_dev`, so the plan-time check passes; a
#: rename across the two mounts still fails with EXDEV). Unset here: this container cannot
#: mount (`mount --bind` and `unshare -m` are refused).
OTHER_MOUNT_ENV = "DEFENDER_TEST_SAME_FS_OTHER_MOUNT"


def _two_mounts_of_one_filesystem(data_root: Path) -> Path:
    """Require a configured second mount of the same filesystem, or skip with its missing prerequisite."""
    raw = os.environ.get(OTHER_MOUNT_ENV)
    if not raw:
        pytest.skip(f"{OTHER_MOUNT_ENV} unset: needs a folder on a second mount of the data "
                    "root's filesystem — as root: `mount --bind <dir on that filesystem> <mnt>`, "
                    f"then {OTHER_MOUNT_ENV}=<mnt>/<subdir>")
    other = Path(raw)
    if os.stat(other).st_dev != os.stat(data_root).st_dev:
        pytest.skip(f"{OTHER_MOUNT_ENV}={other} is on another filesystem than the data root")
    probe = Path(tempfile.mkdtemp(prefix="ids1187-probe-", dir=other))
    try:
        (probe / "f").write_text("probe\n", encoding="utf-8")
        try:
            os.rename(probe / "f", data_root / "ids1187-exdev-probe")
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
        else:
            os.unlink(data_root / "ids1187-exdev-probe")
            pytest.skip(f"a rename from {other} into the data root succeeds: not two mounts")
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    return other


def test_1187_s_move_an_exdev_at_rename_time_refuses_naming_both_paths_and_a_rerun_is_safe(
        data_root):
    other = _two_mounts_of_one_filesystem(data_root)
    parent = Path(tempfile.mkdtemp(prefix="ids1187-", dir=other))
    try:
        sc = _scene(data_root, parent)
        episodes_before = S.tree(sc.old_root)

        got = _retire(*_full(sc))
        assert _refused(got), f"the command ran across two mounts: {_shown(got)}"
        assert str(sc.old_root) in got.said, f"the refusal does not name the source: {got.said!r}"
        assert str(sc.tenant_dir) in got.said, (
            f"the refusal does not name the destination under <T>: {got.said!r}")
        for name in sc.old_episodes:
            places = [p for p in (sc.old_root / name, sc.episodes_legacy / name)
                      if os.path.lexists(p)]
            assert len(places) == 1, f"old episode {name!r} is in {len(places)} places: {places}"
        merged = {**S.tree(sc.old_root), **S.tree(sc.episodes_legacy)}
        assert merged == episodes_before, "an old episode's bytes changed or went missing"
        after_first = _world(data_root, sc.old_root)

        again = _retire(*_full(sc))
        assert _refused(again), f"the re-run moved across two mounts: {_shown(again)}"
        assert _world(data_root, sc.old_root) == after_first, "the re-run changed something"
    finally:
        shutil.rmtree(parent, ignore_errors=True)


@pytest.mark.parametrize("where", ["same_filesystem", "other_filesystem"])
def test_1187_s_move_an_old_episodes_root_on_another_filesystem_refuses_before_any_move(
        where, data_root, tmp_path):
    if where == "same_filesystem":
        parent = tmp_path / "same"
        parent.mkdir()
        if os.stat(parent).st_dev != os.stat(data_root).st_dev:
            pytest.skip("tmp_path and the data root are on different filesystems here")
    else:
        shm = Path("/dev/shm")
        if not shm.is_dir() or not os.access(shm, os.W_OK):
            pytest.skip("no writable /dev/shm to stand for another filesystem")
        if os.stat(shm).st_dev == os.stat(data_root).st_dev:
            pytest.skip("/dev/shm shares the data root's filesystem here")
        parent = Path(tempfile.mkdtemp(prefix="ids1187-", dir=shm))
    try:
        sc = _scene(data_root, parent)
        before = _world(data_root, sc.old_root)

        got = _retire(*_full(sc))
        if where == "same_filesystem":
            assert _ok(got), _shown(got)
            assert _names(sc.episodes_legacy) == sc.old_episodes
            assert _names(sc.runs_legacy) == sc.old
            return
        assert _refused(got), f"the command ran over a root on another filesystem: {_shown(got)}"
        assert _world(data_root, sc.old_root) == before, "something moved before refusing"
        assert str(sc.old_root) in got.said, f"the refusal does not name the root: {got.said!r}"
    finally:
        if where == "other_filesystem":
            shutil.rmtree(parent, ignore_errors=True)
# N9 — the help states the precondition; the command is the path the refusal names.

def test_1187_n9_the_help_states_that_no_run_fork_or_drain_may_be_in_flight(data_root):
    got = _retire("--help")
    assert _ok(got), _shown(got)
    text = " ".join(got.out.split()).casefold()
    for word in ("fork", "drain"):
        assert word in text, f"--help does not state the quiescence rule ({word!r}): {got.out!r}"


def test_1187_o6_the_path_the_refusal_names_runs_as_the_operators_command(data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    inodes_before = _inodes(sc)
    script = H.WORKTREE / S.COMMAND
    env = {**os.environ,
           "PYTHONPATH": os.pathsep.join(filter(None, [str(H.WORKTREE),
                                                       os.environ.get("PYTHONPATH")]))}
    child = subprocess.run(  # noqa: S603 — this interpreter, the checkout's own command
        [sys.executable, str(script), *_full(sc)], capture_output=True, text=True,
        encoding="utf-8", check=False, env=env, cwd=str(H.WORKTREE), timeout=300)
    assert child.returncode == 0, (child.stdout + child.stderr)[-1200:]
    assert _names(sc.runs_legacy) == sc.old
    assert _names(sc.episodes_legacy) == sc.old_episodes
    assert _names(sc.runs) == sc.stay
    _assert_renamed(sc, inodes_before)
