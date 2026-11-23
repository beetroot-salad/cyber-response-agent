"""#1618 flow 8 / K7: one host-side sweep over `run-knowledge/`, `drafts/` and `.repo-scratch/`; live owners are never swept."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K


def _roots(t) -> dict[str, Path]:
    # FORCED: a `.repo-scratch/` entry is `<tenant id>` + `.owner-<pid>-<start>-<tag>` (`owned_temporary`'s names, via `A.named`)
    return {"run-knowledge": A.run_copies(t), "drafts": K.tenant_root(t) / "drafts",
            "repo-scratch": K.tenant_root(t).parent / ".repo-scratch"}


def _entry(t, root: str, mark: tuple[int, str] | None, *, by_name: bool) -> Path:
    base = _roots(t)[root]
    stem = {"run-knowledge": f".building-{uuid.uuid4()}", "drafts": ".building-b", "repo-scratch": t.tenant_id}[root]
    if by_name:
        assert mark is not None
        return A.plant(base / A.named(stem, *mark), pid=mark[0], start=mark[1], by_name=True)
    name = str(uuid.uuid4()) if root == "run-knowledge" else (f"b-{uuid.uuid4().hex[:6]}" if root == "drafts" else f"{t.tenant_id}-{uuid.uuid4().hex[:6]}")
    return A.plant(base / name, pid=mark[0], start=mark[1])


@pytest.mark.parametrize("how", ["owner-file", "name-only"])
def test_a17_a_sweep_removes_dead_owners_in_all_three_roots_and_keeps_live_ones(t, how):
    """Dead owners' entries go, a live other process's and this process's stay, in each root (K7, F8)."""
    other = A.live_child()
    try:
        live_other = (other.pid, A.process_start(other.pid))
        mine = (os.getpid(), A.process_start(os.getpid()))
        dead, kept = {}, {}
        for root in _roots(t):
            dead[root] = _entry(t, root, A.dead_mark(), by_name=how == "name-only")
            kept[root + "-other"] = _entry(t, root, live_other, by_name=how == "name-only")
            kept[root + "-mine"] = _entry(t, root, mine, by_name=how == "name-only")
        K.sweep(t)
        assert [r for r, p in dead.items() if os.path.lexists(p)] == [], "a dead owner's entry was not swept"
        assert [r for r, p in kept.items() if not p.is_dir()] == [], "a live owner's entry was swept"
        other.kill()
        other.wait()
        K.sweep(t)
        assert not any(os.path.lexists(p) for r, p in kept.items() if r.endswith("-other")), "control: the killed owner's entries go"
        assert all(p.is_dir() for r, p in kept.items() if r.endswith("-mine"))
    finally:
        other.kill()


def test_a17_the_start_of_the_fetch_sweeps_too(t):
    """`fetch_copy` sweeps dead owners at its start and leaves a live one (K7, F8)."""
    dead = _entry(t, "repo-scratch", A.dead_mark(), by_name=True)
    live = _entry(t, "run-knowledge", (os.getpid(), A.process_start(os.getpid())), by_name=False)
    dest = K.owned_dest(A.run_copies(t))
    assert K.fetch_copy(t, dest) == t.origin_main()
    assert not os.path.lexists(dead)
    assert live.is_dir()


def _wrong_start(start: str) -> str:
    """A start time no process with that pid has now: the pid recycled for another process (K7)."""
    return str(int(start) + 1)


@pytest.mark.parametrize("how", ["owner-file", "name-only"])
def test_1618_k7_an_owner_naming_a_live_pid_with_another_start_time_is_dead_and_swept(t, how):
    """An entry whose owner is a live pid with a start time that pid does not have is a recycled pid: its owner is gone, so
    the sweep removes it, in each root; control: the same pid with its real start time is kept (K7, F8)."""
    mine = (os.getpid(), A.process_start(os.getpid()))
    recycled = (mine[0], _wrong_start(mine[1]))
    assert A.process_start(recycled[0]) is not None, "premise: the recorded pid is a live process"
    swept, kept = {}, {}
    for root in _roots(t):
        swept[root] = _entry(t, root, recycled, by_name=how == "name-only")
        kept[root] = _entry(t, root, mine, by_name=how == "name-only")
    K.sweep(t)
    assert [r for r, p in swept.items() if os.path.lexists(p)] == [], "a recycled pid's entry was kept as live"
    assert [r for r, p in kept.items() if not p.is_dir()] == [], "control: the live owner's entry was swept"


def _deep_entry(base: Path, name: str, mark: tuple[int, str], *, folders: int = 40, files: int = 8) -> Path:
    """A dead owner's entry holding `folders` x `files` files in nested folders: a sweep takes long enough to overlap."""
    entry = A.plant(base / name, pid=mark[0], start=mark[1])
    for i in range(folders):
        sub = entry / "stage" / "agent" / f"lessons-{i}" / "deeper"
        sub.mkdir(parents=True)
        for j in range(files):
            (sub / f"lesson-{j}.md").write_text(f"{i}-{j}\n", encoding="utf-8")
    return entry


def test_1618_k7_concurrent_sweeps_of_the_same_dead_entries_all_succeed_and_keep_every_live_entry_whole(t):
    """Several host processes sweep at once (every fetch and batch start begins with a sweep, K2): each sweep of the same
    dead owners' entries succeeds, however the others remove them under it; every dead entry is gone and every live owner's
    entry is kept byte for byte, in each root (K7, F8; no lock, K1)."""
    import threading

    mine = (os.getpid(), A.process_start(os.getpid()))
    roots = _roots(t)
    live = {root: _entry(t, root, mine, by_name=False) for root in roots}
    for root, entry in live.items():
        (entry / "stage" / "agent" / "kept.md").write_text(f"kept in {root}\n", encoding="utf-8")
    before = {root: K.tree_bytes(entry) for root, entry in live.items()}
    stems = {"run-knowledge": lambda: str(uuid.uuid4()), "drafts": lambda: f"b-{uuid.uuid4().hex[:6]}",
             "repo-scratch": lambda: f"{t.tenant_id}-{uuid.uuid4().hex[:6]}"}
    sweepers, rounds = 8, 6
    faults: list[str] = []
    for _round in range(rounds):
        dead = [_deep_entry(roots[root], stems[root](), A.dead_mark()) for root in roots]
        barrier = threading.Barrier(sweepers)

        def sweeper() -> None:
            barrier.wait()
            try:
                K.sweep(t)
            except BaseException as raised:  # noqa: BLE001 — every fault of a concurrent sweep is the finding
                faults.append(f"{type(raised).__name__}: {raised}")

        threads = [threading.Thread(target=sweeper) for _ in range(sweepers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        assert not any(thread.is_alive() for thread in threads), "a sweep never returned"
        assert faults == [], f"a concurrent sweep failed: {faults[:3]}"
        assert [p for p in dead if os.path.lexists(p)] == [], "a dead owner's entry outlived the sweeps"
    assert {root: K.tree_bytes(entry) for root, entry in live.items()} == before, "a live owner's entry lost files"
