"""Legacy retirement renames old entries without copying, replacing, or following aliases."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import errno
import importlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as process
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
    return {"runs_legacy": S.identities(location_path(sc.runs), sc.old),
            "episodes_legacy": S.identities(sc.old_root, sc.old_episodes),
            "runs": S.identities(location_path(sc.runs), sc.stay)}


def _assert_renamed(sc: Scene, before: dict[str, dict[str, tuple[int, int]]]) -> None:
    """Check renamed entries retain their original device and inode identities."""
    after = {"runs_legacy": S.identities(location_path(sc.runs_legacy)),
             "episodes_legacy": S.identities(location_path(sc.episodes_legacy)),
             "runs": S.identities(location_path(sc.runs))}
    for where, was in before.items():
        moved = {rel for rel in was if after[where].get(rel) != was[rel]}
        assert not moved, (f"{len(moved)} entr(ies) bound for {where} are not the entries that "
                           f"were planted (copied, not renamed): {sorted(moved)[:6]}")
# O6 / declared changes 6 and 7 — before the command, the listing refuses an old entry and
# the refusal names the command.

_OLD_ENTRIES = ("old_minted_run", "old_pinned_run", "old_sidecar", "tenant_record", "episodes_record")


def _old_entry(runs: Path, kind: str) -> str:
    if kind in ("old_minted_run", "old_pinned_run"):
        return S.make_run(runs, S.OLD_MINTED_ID if kind == "old_minted_run" else S.OLD_PINNED_ID).name
    if kind == "tenant_record":
        return H.plant_tenant_record(runs, T).name
    if kind == "old_sidecar":
        path = runs / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[1]}"
    else:
        path = runs / "_episodes" / "placeholder.json"
        path.parent.mkdir()
    path.write_text("{}\n", encoding="utf-8")
    return path.name if kind == "old_sidecar" else path.parent.name


@pytest.mark.parametrize("kind", _OLD_ENTRIES)
@pytest.mark.parametrize("consumer", ["listing", "tracer"])
def test_legacy_entry_refuses_before_serving_then_its_removal_restores_service(
        kind, consumer, data_root, tmp_path):
    from defender.run_repository import RunRefused

    tenant = S.tenant(data_root, T)
    runs = S.natural_runs(data_root, T)
    uuids = _uuid_runs(runs)
    lessons = _lessons(tmp_path / "lessons")
    name = _old_entry(runs, kind)
    if consumer == "listing":
        err = H.raised(tenant.runs_repository().all_runs)
        assert H.is_a(err, RunRefused), err
        text = H.message(err)
    else:
        got = _trace(T, lessons)
        assert _refused(got), _shown(got)
        assert got.out == "", "the tracer printed rows before refusing"
        text = got.said
    assert S.COMMAND in text, text
    assert name in text, text
    shutil.move(str(runs / name), str(tmp_path / "moved-away"))
    assert sorted(str(r.id) for r in tenant.runs_repository().all_runs()) == sorted(uuids)
    served = _trace(T, lessons)
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW]


def test_uuid_runs_and_sidecars_need_no_container_record(data_root, tmp_path):
    tenant = S.tenant(data_root, T)
    uuids = _uuid_runs(S.natural_runs(data_root, T))
    assert H.raised(tenant.runs_repository().all_runs) is None
    assert sorted(str(r.id) for r in tenant.runs_repository().all_runs()) == sorted(uuids)
    served = _trace(T, _lessons(tmp_path / "lessons"))
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW]


def test_1187_o6_the_tracer_stops_on_a_pre_1187_container_naming_the_command(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path, old_root=False)
    shutil.rmtree(location_path(sc.runs) / "_episodes")

    got = _trace(T, sc.lessons)
    assert _refused(got), f"the tracer served a pre-#1187 container: {_shown(got)}"
    assert got.out == "", f"the tracer printed rows before stopping: {got.out!r}"
    assert S.COMMAND in got.said, f"the refusal does not name the command: {got.said!r}"
# O5 / Flow 6 — the command moves old entries aside, intact, and the tenant is served after.

def _prepare_retirement(sc: Scene, phase: str, data_root: Path, tmp_path: Path, monkeypatch):
    """Prepare the operator's argument variant or a partially completed move."""
    after_first = None
    argv = _full(sc)
    if phase == "unnamed-root":
        monkeypatch.setenv(S.EPISODES_BASE_ENV, str(sc.old_root))
        argv = ["--tenant", T]
    elif phase == "linked-root":
        link = tmp_path / "episodes-link"
        link.symlink_to(sc.old_root)
        argv[-1] = str(link)
    elif phase.startswith("mid-"):
        location_path(sc.runs_legacy).mkdir()
        names = sorted(sc.old)
        for name in names if phase == "mid-episodes" else names[:len(names) // 2]:
            os.rename(location_path(sc.runs) / name, location_path(sc.runs_legacy) / name)
        if phase == "mid-episodes":
            location_path(sc.episodes_legacy).mkdir()
            name = sorted(sc.old_episodes)[0]
            os.rename(sc.old_root / name, location_path(sc.episodes_legacy) / name)
    if phase == "fresh":
        assert sc.old
        assert sc.old_episodes
        assert sc.stay
        refused = _trace(T, sc.lessons)
        assert _refused(refused), _shown(refused)
        assert S.COMMAND in refused.said, _shown(refused)
    if phase in ("rerun", "removed-root"):
        first = _retire(*argv)
        assert _ok(first), _shown(first)
        if phase == "removed-root":
            sc.old_root.rmdir()
        after_first = _world(data_root, sc.old_root)

    return argv, after_first


@pytest.mark.parametrize("phase", [
    "fresh", "unnamed-root", "absent-root", "linked-root", "rerun", "removed-root",
    "mid-natural", "mid-episodes",
])
def test_retirement_moves_intact_entries_and_is_restartable(phase, data_root, tmp_path, monkeypatch):
    sc = _scene(data_root, tmp_path, old_root=phase != "absent-root")
    runs_before, episodes_before = S.tree(location_path(sc.runs)), S.tree(sc.old_root)
    inodes = _inodes(sc)
    argv, after_first = _prepare_retirement(sc, phase, data_root, tmp_path, monkeypatch)

    got = _retire(*argv)
    assert _ok(got), _shown(got)
    assert S.tree(location_path(sc.runs)) == _under(runs_before, sc.stay), "a UUID run or sidecar moved"
    assert S.tree(location_path(sc.runs_legacy)) == _under(runs_before, sc.old), "legacy bytes changed"
    if phase == "unnamed-root":
        assert S.tree(sc.old_root) == episodes_before, "the unnamed root moved"
        assert S.tree(location_path(sc.episodes_legacy)) == {}
        inodes["episodes_legacy"] = {}
    else:
        assert S.tree(location_path(sc.episodes_legacy)) == episodes_before, "episode bytes changed"
        assert S.tree(sc.old_root) == {}
    _assert_renamed(sc, inodes)
    if phase == "fresh":
        assert sc.old_root.is_dir(), "the source root itself moved"
        for name in sc.old | sc.old_episodes:
            assert name in got.out, got.out
    if phase == "linked-root":
        assert Path(argv[-1]).is_symlink(), "the operator's link was removed"
    if phase == "absent-root":
        assert not os.path.lexists(sc.old_root), "the absent root was created"
    if phase in ("rerun", "removed-root"):
        assert _world(data_root, sc.old_root) == after_first, "the rerun changed entries"
    tenant = S.tenant(data_root, T)
    assert sorted(str(r.id) for r in tenant.runs_repository().all_runs()) == sorted(sc.uuid_runs)
    served = _trace(T, sc.lessons)
    assert _ok(served), _shown(served)
    assert served.out.splitlines() == [LESSON_ROW]


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
    assert S.OLD_PINNED_ID in _names(location_path(sc.runs_legacy))
    assert _names(location_path(sc.runs_legacy)) == sc.old
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
    assert S.tree(location_path(sc.episodes_legacy)) == episodes_before
    assert S.tree(other.tenant_dir) == other_before, f"tenant {U}'s tree changed"
# S-move — refuse before ANY move. Each refusal: non-zero exit, every tree byte-identical,
# the refusal names what it found. Positive control: the operator's fix, then the same command
# moves.

# Every old source, destination root, and occupied destination name is checked before any move.
_OBSTRUCTIONS = [
    ("move", "old-link", "link-folder"),
    ("move", "uuid-link", "link-run"),
    ("move", "runs-fifo", "fifo"),
    ("move", "latest", "relative-link"),
    ("move", "episodes-fifo", "fifo"),
    *[("root", root, shape) for root in (S.RUNS_LEGACY, S.EPISODES_LEGACY)
      for shape in ("link-folder", "dangling-link", "file")],
    ("taken", "old-run", "folder"),
    ("taken", "old-sidecar", "file"),
    ("taken", "old-episode", "folder"),
    ("taken", "old-sidecar", "dangling-link"),
    ("taken", "old-sidecar", "link-file"),
    ("taken", "old-run", "dangling-link"),
    ("taken", "old-episode", "link-folder"),
]


def _obstruction(sc: Scene, outside: Path, group: str, location: str, shape: str) -> Path:
    locations = {
        "old-link": location_path(sc.runs) / "zz-old-link", "uuid-link": location_path(sc.runs) / S.new_id(),
        "runs-fifo": location_path(sc.runs) / "zz-old-fifo", "latest": sc.old_root / "latest",
        "episodes-fifo": sc.old_root / "zz-fifo",
        "old-run": location_path(sc.runs_legacy) / S.OLD_PINNED_ID,
        "old-sidecar": location_path(sc.runs_legacy) / f"{S.OLD_MINTED_ID}{S.SIDECAR_SUFFIXES[0]}",
        "old-episode": location_path(sc.episodes_legacy) / sorted(sc.old_episodes)[-1],
    }
    path = sc.tenant_dir / location if group == "root" else locations[location]
    path.parent.mkdir(parents=True, exist_ok=True)
    if shape == "folder":
        path.mkdir()
    elif shape == "file":
        path.write_text('{"older": true}\n', encoding="utf-8")
    elif shape == "fifo":
        H.make_fifo(path)
    else:
        target = outside / "target"
        if shape == "link-run":
            target = S.make_run(outside / "elsewhere")
        elif shape == "link-folder":
            target.mkdir()
            (target / "kept.txt").write_text("outside\n", encoding="utf-8")
        elif shape == "link-file":
            target.write_text('{"outside": true}\n', encoding="utf-8")
        elif shape == "relative-link":
            target = Path(sorted(sc.old_episodes)[-1])
        path.symlink_to(target)
    return path


@pytest.mark.parametrize(("group", "location", "shape"), _OBSTRUCTIONS,
                         ids=["-".join(case) for case in _OBSTRUCTIONS])
def test_obstruction_refuses_before_any_move_and_removal_restores_service(
        group, location, shape, data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    entry = _obstruction(sc, outside, group, location, shape)
    before = _world(data_root, sc.old_root, outside)
    got = _retire(*_full(sc))
    assert _refused(got), _shown(got)
    assert entry.name in got.said, got.said
    assert _world(data_root, sc.old_root, outside) == before, "refusal moved or replaced entries"
    if group == "move" and "link" in shape:
        assert re.search(r"\brm\b|\bremov", got.said, re.IGNORECASE), got.said
    if entry.is_dir() and not entry.is_symlink():
        entry.rmdir()
    else:
        entry.unlink()
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(location_path(sc.runs_legacy)) == sc.old
    assert _names(location_path(sc.episodes_legacy)) == sc.old_episodes


def test_1187_n15_a_record_an_old_checkout_recreates_is_never_renamed_over_the_moved_one(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    first = _retire(*_full(sc))
    assert _ok(first), _shown(first)
    moved_record = (location_path(sc.runs_legacy) / "_tenant.json").read_bytes()
    H.plant_tenant_record(location_path(sc.runs), T, raw=json.dumps({"tenant_id": T, "recreated": True}) + "\n")
    before = _world(data_root, sc.old_root)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command ran over the moved _tenant.json: {_shown(got)}"
    assert _world(data_root, sc.old_root) == before, "something moved or was replaced"
    assert (location_path(sc.runs_legacy) / "_tenant.json").read_bytes() == moved_record
    assert "_tenant.json" in got.said, f"the refusal does not name _tenant.json: {got.said!r}"


def test_1187_s_move_a_link_at_the_tenants_runs_folder_refuses_before_any_move(
        data_root, tmp_path):
    sc = _scene(data_root, tmp_path)
    elsewhere = tmp_path / "elsewhere-runs"
    S.replace_with_link(location_path(sc.runs), elsewhere)
    before = _world(data_root, sc.old_root, elsewhere)

    got = _retire(*_full(sc))
    assert _refused(got), f"the command followed a linked runs folder: {_shown(got)}"
    assert _world(data_root, sc.old_root, elsewhere) == before, "something moved through the link"
    assert "runs" in got.said, got.said

    os.unlink(location_path(sc.runs))
    os.rename(elsewhere, location_path(sc.runs))
    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _names(location_path(sc.runs_legacy)) == sc.old


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
        assert _names(location_path(sc.runs_legacy)) == sc.old
    else:
        os.unlink(link)
        os.rename(aside, link)
        again = _retire(*_full(sc))
        assert _ok(again), _shown(again)
        assert _names(location_path(sc.runs_legacy)) == sc.old
        assert _names(location_path(sc.episodes_legacy)) == sc.old_episodes


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
            places = [p for p in (sc.old_root / name, location_path(sc.episodes_legacy) / name)
                      if os.path.lexists(p)]
            assert len(places) == 1, f"old episode {name!r} is in {len(places)} places: {places}"
        merged = {**S.tree(sc.old_root), **S.tree(location_path(sc.episodes_legacy))}
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
            assert _names(location_path(sc.episodes_legacy)) == sc.old_episodes
            assert _names(location_path(sc.runs_legacy)) == sc.old
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
    child = process.run_script(script, *_full(sc), root=data_root)
    assert child.returncode == 0, (child.stdout + child.stderr)[-1200:]
    assert _names(location_path(sc.runs_legacy)) == sc.old
    assert _names(location_path(sc.episodes_legacy)) == sc.old_episodes
    assert _names(location_path(sc.runs)) == sc.stay
    _assert_renamed(sc, inodes_before)
