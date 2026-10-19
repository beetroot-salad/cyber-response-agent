"""#1187 slice C — the one-time command and the listing refusal that names it (O5, O6, S-move).

Design rev 2 (issue comments 6192137519 + 6192137980): Flow 6 (the one-time command), Flow 7
(the listing refusal), O5, O6, S-move, R3, N9, N13, N15; declared behaviour changes 6 and 7.
Spellings are the interface sheet's: the command is `defender/ops/retire_legacy_runs.py`
(module `defender.ops.retire_legacy_runs`), `main(argv) -> int`, argv
`--tenant T [--old-episodes-root DIR]`, the data root from `DEFENDER_DATA_ROOT`; it moves old
entries into `<T>/runs-legacy/` and `<T>/episodes-legacy/`; every listing refusal that sends the
operator to it carries the literal `defender/ops/retire_legacy_runs.py`.

* O6 / changes 6 and 7: before the command has run, the listing (`runs.all_runs()`) and the
  tracer (`learning/ops/trace_lesson.py`, the only production caller of a listing, R2-08)
  refuse an old run folder, an old sidecar, `_tenant.json` and `_episodes`, naming the entry
  and the command; the tracer stops (prints no row). Positive control on the same channel: the
  container holding only UUID runs and their sidecars lists, and the tracer prints its row.
* O5 / Flow 6: the command moves every entry of `<T>/runs` that is not a UUID run folder or a
  sidecar of one into `<T>/runs-legacy/`, and every entry of `--old-episodes-root` into
  `<T>/episodes-legacy/`, by rename (bytes identical, nothing deleted), reports each move on
  stdout, and is idempotent and resumable; afterwards the tracer serves the tenant.
* S-move: a link or special file in the move set, a destination that is not a real folder, a
  destination name already taken, or an old episodes root on another filesystem refuses the
  whole command before anything moves (the trees byte-identical), naming what it found. Each
  refusal's positive control is the operator's fix followed by the same command, which moves.
* R3: a queued curation row naming an old run does not stop the command. N13: old episodes go
  to the tenant named, whatever record they carry. N15: a `_tenant.json` an old checkout
  re-creates is never renamed over the one already moved. N9: the help states that no run,
  fork or drain may be in flight.

Observation: the trees under the data root and the old episodes root, judged without following
links (`_spec1187.tree`: kind plus bytes, or link target). Expected trees come from what each
test planted — which top-level names it made as UUID runs and their sidecars, which as old
entries — never from production's classifier.

`_log.configure_from_env()` first (Flow 6) is left to `scripts/lint/lint_log_setup.py`, which
gates every `__main__` block; no cheap observable distinguishes it here.

STATE AT BASE d50c16ad: `defender.ops` does not exist, so every command test fails at its import
(one `ModuleNotFoundError` per test, collection unaffected). The listing tests are red for the
reasons each docstring states.
"""
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

from defender.tests.ids_1187 import _spec1187 as S
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

#: The tenant every scene is set up for, and a second one for the scoping cases.
T = H.T_ID
U = H.U_ID
#: The lesson the scene's UUID run loaded, and the tracer's `--all` row for it (one case in
#: context, no MAIN read).
LESSON = "L"
LESSON_ROW = f"{LESSON}\td\t1\t0"


# ==========================================================================================
# Drivers.
# ==========================================================================================

def _retire(*argv: str) -> P.CliResult:
    """The one-time command's `main(argv)`, imported here (so a missing module fails the calling
    test alone), stdout and stderr captured; a `SystemExit` is handed back, never raised."""
    command = importlib.import_module(S.COMMAND_MODULE)
    return P.drive_cli(command.main, list(argv))


def _trace(tenant_id: str, lessons: Path) -> P.CliResult:
    """`trace_lesson.py --tenant <tenant_id> --all --lessons-dir <lessons>`, in process."""
    from defender.learning.ops import trace_lesson

    return P.drive_cli(trace_lesson.main,
                       ["--tenant", tenant_id, "--all", "--lessons-dir", str(lessons)])


def _code(got: P.CliResult) -> object:
    """The exit status the operator would see: `main`'s return, or the `SystemExit`'s code
    (`sys.exit("message")` carries the message)."""
    return got.raised.code if got.raised is not None else got.rc  # type: ignore[union-attr]


def _ok(got: P.CliResult) -> bool:
    return _code(got) == 0


def _refused(got: P.CliResult) -> bool:
    """Exited non-zero: a non-zero return, or `sys.exit` with a message or a non-zero code."""
    return _code(got) not in (0, None)


def _shown(got: P.CliResult) -> str:
    return f"rc={_code(got)!r}\nstdout: {got.out[-800:]}\nsaid: {got.said[-800:]}"


# ==========================================================================================
# Scenes — real tenants and real entries on the real filesystem.
# ==========================================================================================

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
    """Two UUID runs in `runs` with their sidecars: one loaded lesson L (a report and a
    `lessons_loaded` row, so the tracer prints its row), the other carries a STAGED sidecar
    too (the sidecar clause takes it; it must stay)."""
    loaded = S.make_run(runs, sidecars=True)
    (loaded / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (loaded / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": LESSON, "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")
    other = S.make_run(runs)
    H.plant_sidecars(runs, other.name, staged=True)
    return frozenset({loaded.name, other.name})


def _scene(data_root: Path, where: Path, *, tenant_id: str = T, old_root: bool = True) -> Scene:
    """`tenant_id` set up under `data_root` (the real `accept_tenant`), its `<T>/runs` holding
    two UUID runs with their sidecars and then every pre-#1187 entry
    (`plant_old_natural_entries`), plus an old episodes root at `<where>/old-episodes` shaped
    like the dev box's two (`plant_old_episodes_root`; planted only with `old_root`)."""
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
    """The entries of `tree` whose top-level name is one of `names` (the entries those
    top-level entries hold included)."""
    return {rel: v for rel, v in tree.items() if Path(rel).parts[0] in names}


def _world(*roots: Path) -> dict[str, dict[str, Any]]:
    """Every root's tree, by root: the "nothing changed" observation."""
    return {str(r): S.tree(r) for r in roots}


def _names(folder: Path) -> frozenset[str]:
    return frozenset(os.listdir(folder)) if folder.is_dir() else frozenset()


def _full(sc: Scene) -> list[str]:
    return ["--tenant", T, "--old-episodes-root", str(sc.old_root)]


def _inodes(sc: Scene) -> dict[str, dict[str, tuple[int, int]]]:
    """The scene's entries' `(st_dev, st_ino)` before the command, by where each must END:
    the old natural entries (bound for `runs-legacy/`), the old episodes (bound for
    `episodes-legacy/`), and the UUID runs with their sidecars (staying in `<T>/runs`)."""
    return {"runs_legacy": S.identities(sc.runs, sc.old),
            "episodes_legacy": S.identities(sc.old_root, sc.old_episodes),
            "runs": S.identities(sc.runs, sc.stay)}


def _assert_renamed(sc: Scene, before: dict[str, dict[str, tuple[int, int]]]) -> None:
    """Flow 6 step 4 / decision 7 / S-move (adversary F3): every planned entry was moved by
    ONE rename — it, and every entry inside it, keeps its `(st_dev, st_ino)` in its
    destination folder (a copy, even byte-identical, makes new inodes) — and nothing that
    stays was rewritten in place."""
    after = {"runs_legacy": S.identities(sc.runs_legacy),
             "episodes_legacy": S.identities(sc.episodes_legacy),
             "runs": S.identities(sc.runs)}
    for where, was in before.items():
        moved = {rel for rel in was if after[where].get(rel) != was[rel]}
        assert not moved, (f"{len(moved)} entr(ies) bound for {where} are not the entries that "
                           f"were planted (copied, not renamed): {sorted(moved)[:6]}")


# ==========================================================================================
# O6 / declared changes 6 and 7 — before the command, the listing refuses an old entry and
# the refusal names the command.
# ==========================================================================================

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
    """#1187 declared change 6 (`_tenant.json` is neither written nor needed) and O10: the
    positive control of every refusal below, on its own. `<T>/runs` holding only UUID run
    folders and their sidecars (a staged one included) and NO `_tenant.json`: `runs.all_runs()`
    answers exactly those runs, and the tracer prints L's row. RED at base (a): the listing
    judges the container's record first and refuses its absence (`TenantRecordCorrupt`)."""
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
    """#1187 declared change 6. `runs.all_runs()` over a container holding UUID runs, their
    sidecars and ONE pre-#1187 entry raises `RunRefused` whose message names that entry and
    `defender/ops/retire_legacy_runs.py` (Flow 7). Positive control, same call: with the entry
    moved out, the listing answers exactly the UUID runs (no `_tenant.json` needed).
    RED at base: `tenant_record` lists (the record is accepted, (c)); every other kind is refused
    as `TenantRefused` for the MISSING record before the entry is judged, a message that does not
    name the command (c)."""
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
    """#1187 declared change 7. `trace_lesson.py --tenant T --all` over a container holding a
    UUID run that loaded L and ONE pre-#1187 entry exits non-zero, prints no row, and its
    refusal names that entry and `defender/ops/retire_legacy_runs.py` (O6: the tracer surfaces
    the listing's refusal verbatim and stops). Positive control, same command: with the entry
    moved out, it prints L's row. RED at base as the listing test above: `tenant_record` traces
    (c); every other kind stops on the missing record, not naming the command (c)."""
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
    """#1187 declared changes 6 and 7, the dev box's real shape (R2-18: the playground container
    holds `_tenant.json`, old runs and their sidecars, and no `_episodes`, whose own refusal the
    per-kind tests above pin): `<T>/runs` holding `_tenant.json` naming T, old minted and pinned
    runs and an old run's sidecars beside the UUID runs. The tracer exits non-zero, prints no
    row, and names the command. RED at base (c): every one of those entries is accepted today
    (the record names T, both old ids pass today's grammar), so the tracer prints L's row."""
    sc = _scene(data_root, tmp_path, old_root=False)
    shutil.rmtree(sc.runs / "_episodes")

    got = _trace(T, sc.lessons)
    assert _refused(got), f"the tracer served a pre-#1187 container: {_shown(got)}"
    assert got.out == "", f"the tracer printed rows before stopping: {got.out!r}"
    assert S.COMMAND in got.said, f"the refusal does not name the command: {got.said!r}"


# ==========================================================================================
# O5 / Flow 6 — the command moves old entries aside, intact, and the tenant is served after.
# ==========================================================================================

def test_1187_o5_the_command_moves_every_old_entry_aside_intact_and_the_tracer_then_serves(
        data_root, tmp_path):
    """#1187 O5, Flow 6 steps 1, 4 and 5 (decision 4: old episodes go to the tenant named).
    `retire_legacy_runs --tenant T --old-episodes-root R`, over the dev box's shape:
    - exits 0;
    - `<T>/runs` keeps exactly the UUID runs and their sidecars (a staged one included),
      byte for byte;
    - `<T>/runs-legacy/` holds exactly every other entry (old runs, their sidecars,
      `_tenant.json`, `_episodes`), byte for byte, under the same names;
    - `<T>/episodes-legacy/` holds exactly R's entries, byte for byte; R is left, emptied;
    - nothing is deleted (the union of the trees is the tree before);
    - nothing is copied (adversary F3): every moved entry, and every entry inside it, keeps its
      `(st_dev, st_ino)` — only a rename does; a copy-then-delete makes new inodes behind
      identical bytes — and every entry that stays keeps its own;
    - stdout names each entry moved;
    - before it, the tracer refuses naming the command (O6); after it, it prints L's row.
    RED at base (a): `defender.ops` does not exist."""
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
    """#1187 O5 through the repository's own listing: after the command, `runs.all_runs()`
    answers exactly the planted UUID runs. RED at base (a): `defender.ops` does not exist."""
    sc = _scene(data_root, tmp_path)
    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    t = S.tenant(data_root, T)
    assert sorted(str(r.id) for r in t.runs_repository().all_runs()) == sorted(sc.uuid_runs)


def test_1187_o5_without_an_old_episodes_root_only_the_natural_entries_move(
        data_root, tmp_path, monkeypatch):
    """#1187 Flow 6, O9: with no `--old-episodes-root`, the command moves the natural entries
    and nothing else. An old episodes root exists and the retired `DEFENDER_EPISODES_BASE`
    names it: the command reads no environment for it, so it stays untouched and
    `<T>/episodes-legacy/` holds nothing. RED at base (a): `defender.ops` does not exist."""
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
    """#1187 Flow 6 step 1 (recheck S4): an `--old-episodes-root` that does not exist is an
    empty move set, not a refusal: exit 0, the natural entries still move, the folder is not
    created, and `<T>/episodes-legacy/` holds nothing. RED at base (a): `defender.ops` does not
    exist."""
    sc = _scene(data_root, tmp_path, old_root=False)
    gone = tmp_path / "no-such-episodes-root"

    got = _retire("--tenant", T, "--old-episodes-root", str(gone))
    assert _ok(got), _shown(got)
    assert _names(sc.runs_legacy) == sc.old
    assert not os.path.lexists(gone), "the absent old episodes root was created"
    assert S.tree(sc.episodes_legacy) == {}


def test_1187_o5_the_named_old_episodes_root_is_held_following_its_spelling(
        data_root, tmp_path):
    """#1187 Flow 6 step 1 and S-move: the operator names the old episodes root, "so it is held
    following its spelling, as configuration" — a root named through a link is served: its
    entries move, intact; the link itself stays. (The no-follow rule judges the ENTRIES of the
    move set, pinned by the S-move cases below.) RED at base (a): `defender.ops` does not
    exist."""
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
    """#1187 Flow 6 step 1: "a re-run after the operator has deleted the emptied root still
    succeeds" — exit 0, and nothing changes. RED at base (a): `defender.ops` does not exist."""
    sc = _scene(data_root, tmp_path)
    first = _retire(*_full(sc))
    assert _ok(first), _shown(first)
    sc.old_root.rmdir()
    after_first = _world(data_root)

    again = _retire(*_full(sc))
    assert _ok(again), _shown(again)
    assert _world(data_root) == after_first, "the re-run changed something"


def test_1187_o5_a_second_run_changes_nothing(data_root, tmp_path):
    """#1187 O5 ("a second run of the command changes anything" is its failing) and Flow 6
    step 5: the second run of the same command exits 0 and leaves the data root and the old
    episodes root byte-identical. RED at base (a): `defender.ops` does not exist."""
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
    """#1187 Flow 6 step 6: each rename is atomic, so a crash leaves some entries moved and the
    rest not; the re-run finishes the rest. An entry already in a legacy folder (absent from its
    source) is NOT a taken destination name. End state: exactly the clean run's (every entry
    intact in its place, each the very entry planted: renamed, never copied — F3). RED at base
    (a): `defender.ops` does not exist."""
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
    """#1187 R3 (owner, 2026-10-15): the command has NO pending-curation refusal. With a
    curation request queued through the real writer (`enqueue_curation`) naming an old run of
    T, the command still exits 0 and moves that run; the queue is not touched (the deploy note,
    not the command, deals with it). RED at base (a): `defender.ops` does not exist."""
    from defender.tests import _state1135

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
    """#1187 decision 4 and N13: every entry of the old episodes root moves into the tenant the
    operator names, with no per-episode tenant check — one old episode's arm container even
    carries a `_tenant.json` naming ANOTHER tenant (U), and it still moves, bytes intact. S-move:
    nothing of U's (its own old entries included) moves or changes. RED at base (a):
    `defender.ops` does not exist."""
    sc = _scene(data_root, tmp_path / "t")
    other = _scene(data_root, tmp_path / "u", tenant_id=U, old_root=False)
    H.plant_tenant_record(sc.old_root / sorted(sc.old_episodes)[0] / "runs", U)
    episodes_before = S.tree(sc.old_root)
    other_before = S.tree(other.tenant_dir)

    got = _retire(*_full(sc))
    assert _ok(got), _shown(got)
    assert S.tree(sc.episodes_legacy) == episodes_before
    assert S.tree(other.tenant_dir) == other_before, f"tenant {U}'s tree changed"


# ==========================================================================================
# S-move — refuse before ANY move. Each refusal: non-zero exit, every tree byte-identical,
# the refusal names what it found. Positive control: the operator's fix, then the same command
# moves.
# ==========================================================================================

def _link_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    """A link in `<T>/runs` with an old-looking name, pointing at a folder outside (it sorts
    LAST, after entries a check-as-you-go command would already have moved)."""
    (outside / "target").mkdir()
    (outside / "target" / "kept.txt").write_text("outside\n", encoding="utf-8")
    link = sc.runs / "zz-old-link"
    os.symlink(outside / "target", link)
    return link, "link"


def _uuid_named_link_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    """A link NAMED like a UUID run: not a run folder (judged from its directory entry), so it is
    in the move set, and a link there refuses — a name-only classifier would keep it."""
    target = S.make_run(outside / "elsewhere")
    link = sc.runs / S.new_id()
    os.symlink(target, link)
    return link, "link"


def _fifo_in_runs(sc: Scene, outside: Path) -> tuple[Path, str]:
    return H.make_fifo(sc.runs / "zz-old-fifo"), "special"


def _link_in_old_root(sc: Scene, outside: Path) -> tuple[Path, str]:
    """The operator's `latest` shortcut in the old episodes root (R2-17), pointing at a sibling.
    The old episodes move after every natural entry, so a command that checked as it went would
    have moved all of `<T>/runs` by now."""
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
    """#1187 S-move, Flow 6 step 2: an entry of the move set that is a link (a link to a folder,
    a link named like a UUID run, the operator's `latest` link in the old episodes root) or
    anything but a regular file or directory (a FIFO) refuses the whole command before anything
    moves: non-zero exit, the data root, the old episodes root and the link's target
    byte-identical, the refusal naming the entry — and, for a link, the operator's step of
    removing it by hand (`rm` the link). Positive control: the operator removes it, and the same
    command moves everything. RED at base (a): `defender.ops` does not exist."""
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
    """#1187 S-move, Flow 6 step 2: `<T>/runs-legacy` or `<T>/episodes-legacy` existing as a
    link (to a real folder, or dangling) or as a regular file refuses before anything moves:
    non-zero exit, every tree byte-identical (the link's target folder included: nothing went
    THROUGH the link), the refusal naming the destination. Positive control: the operator
    removes it, and the same command moves everything (creating the folder). RED at base (a):
    `defender.ops` does not exist."""
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
    """An EMPTY folder at an old run's name: a rename between handles would silently replace it
    (R2-22)."""
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
    """A DANGLING link at an old sidecar's name, aimed at a file outside `<T>` that does not
    exist (deck #1042 replay, adversary F4): the name is taken — a link is an entry — though
    `os.path.exists` follows it and answers False. A copy writes the sidecar's bytes THROUGH it
    to the outside path; a rename replaces the link. Either breaks "its name must be absent"."""
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
    """A DANGLING link at an old run FOLDER's name (a folder copied through it would land
    outside `<T>`)."""
    sc.runs_legacy.mkdir()
    taken = sc.runs_legacy / S.OLD_PINNED_ID
    os.symlink(outside / "no-such-folder", taken)
    return taken


def _link_to_a_folder_at_old_episode(sc: Scene, outside: Path) -> Path:
    """A link at the last old episode's name in `episodes-legacy/`, to a real folder outside
    `<T>` (nothing may be written into it)."""
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
    """#1187 S-move, Flow 6 step 2 (review D3): a planned entry whose name is already taken in
    its destination folder refuses the whole command before anything moves — the move is
    non-replacing only because of this plan-time check (R2-22: a rename replaces an existing
    file or empty folder). A link is an entry, so a link at the name — dangling, or aimed at a
    file or folder outside `<T>` — takes it as much as a file does (adversary F4: a check that
    follows the link, `os.path.exists`, calls a dangling one free). Non-zero exit, every tree
    byte-identical — the planted entry keeps its own bytes, a planted link stays a link with its
    own target, and nothing appears at, or is written into, the outside path it names — the
    refusal naming the taken name. Positive control: the operator removes the planted entry;
    the same command adopts the existing legacy folder and moves everything. RED at base (a):
    `defender.ops` does not exist."""
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
    """#1187 N15 with S-move's destination check: after the command moved `_tenant.json`, a
    checkout still on pre-#1187 code writes a fresh one into `<T>/runs`. The next run of the
    command refuses (the name is taken in `runs-legacy/`), naming it, and changes nothing — the
    record already moved keeps its bytes. RED at base (a): `defender.ops` does not exist."""
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
    """#1187 S-move, Flow 6 step 1: the command lists `<T>/runs` off the held `<T>`, never
    following a link. With `<T>/runs` a link to a folder holding the old entries, it refuses:
    non-zero exit, the link's target and every other tree byte-identical. Positive control: the
    real folder put back, the same command moves. RED at base (a): `defender.ops` does not
    exist."""
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
    """#1187 S-move, Flow 6 step 1 ("Hold `<data root>/<T>` no-follow"): the command never
    follows a link at `<T>` itself (adversary F5: reached as `<data root>/T` by path, a link
    there makes the command move the entries of whatever folder it names). `<data root>/T` is a
    link —
    - `another_tenants_folder`: to U's real tenant folder, holding U's old entries — so a
      followed link moves U's entries under T's name;
    - `a_folder_outside_the_data_root`: to T's own real folder, set aside outside the data
      root.
    `--tenant T` exits non-zero and every tree — the data root, the link's target, the old
    episodes root — is byte-identical, the link still a link. Positive control, same command:
    the real folder in place (U asked for by its own name; T's own folder put back) moves its
    old entries. RED at base (a): `defender.ops` does not exist."""
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
    """The `OTHER_MOUNT_ENV` folder, proved fit or skipped: same `st_dev` as the data root, and
    a rename from it into the data root fails with EXDEV (two mounts of one filesystem)."""
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
    """#1187 Flow 6 step 2, last clause (adversary F6; an unseamed rule the handoff left to the
    implementation stage): "Two mount points of one filesystem can still give `EXDEV` at rename
    time. That refuses with both paths named, and a re-run is safe." The old episodes root sits
    on a second mount of the data root's filesystem, so the plan-time `st_dev` check passes and
    the rename fails. The command exits non-zero, its refusal names the old episode's path and
    its destination under `<T>`, and nothing is copied or lost: every old episode is in exactly
    one place (its source or `episodes-legacy/`), every byte intact. A re-run under the same
    mounts refuses again and changes nothing. RUNS ONLY where `DEFENDER_TEST_SAME_FS_OTHER_MOUNT`
    names such a folder (CI must provide the bind mount; this container cannot mount); the
    positive control (the same root on the data root's own mount moves) is
    `test_1187_s_move_an_old_episodes_root_on_another_filesystem_refuses_before_any_move
    [same_filesystem]`. RED at base (a): `defender.ops` does not exist."""
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
    """#1187 S-move, Flow 6 step 2 (review U3): the command only renames, so a source on another
    filesystem than `<T>` (compared by `st_dev` at plan time) refuses before anything moves —
    non-zero exit, every tree byte-identical, the refusal naming the old episodes root. The
    other filesystem is `/dev/shm` (tmpfs); the case skips where that is not a filesystem of its
    own beside the data root. Positive control, same command: the same root on the data root's
    filesystem moves. RED at base (a): `defender.ops` does not exist."""
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


# ==========================================================================================
# N9 — the help states the precondition; the command is the path the refusal names.
# ==========================================================================================

def test_1187_n9_the_help_states_that_no_run_fork_or_drain_may_be_in_flight(data_root):
    """#1187 N9: the command does not detect a run, fork or drain in flight; it states the rule
    in its help. `--help` exits 0 and its text names forks and drains (the words a statement of
    "no run, fork or drain on the data root while it runs" cannot avoid; "run" alone would be
    met by the command's own name). RED at base (a): `defender.ops` does not exist."""
    got = _retire("--help")
    assert _ok(got), _shown(got)
    text = " ".join(got.out.split()).casefold()
    for word in ("fork", "drain"):
        assert word in text, f"--help does not state the quiescence rule ({word!r}): {got.out!r}"


def test_1187_o6_the_path_the_refusal_names_runs_as_the_operators_command(data_root, tmp_path):
    """#1187 O6 + Flow 6 as the operator runs it: `python <checkout>/defender/ops/
    retire_legacy_runs.py --tenant T --old-episodes-root R` — the exact path every listing
    refusal names — as a real process under the configured data root, exits 0 and moves the old
    entries (its `__main__` block wired to `main`). RED at base (a): no such file."""
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
