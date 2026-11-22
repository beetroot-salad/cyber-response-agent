"""#1618 flow 8 / K7: one host-side sweep over `run-knowledge/`, `drafts/` and `.repo-scratch/`; live owners are never swept."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K


def _roots(t) -> dict[str, Path]:
    # FORCED: a `.repo-scratch/` entry is `<tenant id>` + `.owner-<pid>-<start>-<tag>` (owned_temporary's grammar)
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
