"""#1108 P4 O-PIN (held-out side): `evaluations/held_out` pins every fixture to one commit.

Design (O-PIN): "`evaluations/held_out` pins every fixture to one commit (comparability)";
O11: "Subprocess launchers (e2e, `held_out`) use O-PIN" (`run.py --knowledge-commit <sha>`).
Orchestrator decision OD10: held_out resolves `current` ONCE, when the index is created, and
records it with the index; every launch of that index pins to it, even after `current` moves.
How the commit is recorded in F is not designed, so these tests observe it only through what
each launch starts.

Entry surface: `evaluations.held_out.main(["launch", slug, "--tenant", T, "--index", F,
"--fixtures-dir", D], spawn=)` with its existing `spawn=` seam (records argv; runs nothing).
The tenant is the P4 fixture tenant published for real (`p4_tenant`).
"""
from __future__ import annotations

import re
from pathlib import Path

from ._support import export_dir

PIN = "--knowledge-commit"
_SHA = re.compile(r"\A[0-9a-f]{40}([0-9a-f]{24})?\Z")
SLUGS = ("p4-held-out-one", "p4-held-out-two")


class RecordingSpawn:
    """`held_out`'s `spawn(argv, *, env=None) -> int` seam: records each argv, runs nothing."""

    def __init__(self) -> None:
        self.argvs: list[list[str]] = []

    def __call__(self, argv, *, env=None) -> int:
        self.argvs.append([str(a) for a in argv])
        return 0


def _fixtures(root: Path) -> Path:
    for slug in SLUGS:
        (root / slug).mkdir(parents=True)
        (root / slug / "alert.json").write_text('{"alert": "held-out"}\n', encoding="utf-8")
        (root / slug / "ground_truth.yaml").write_text(
            "held_out: true\ndisposition: benign\n", encoding="utf-8")
    return root


def _launch(t, slug: str, index: Path, fixtures: Path, spawn: RecordingSpawn) -> object:
    from evaluations import held_out

    try:
        return held_out.main(["launch", slug, "--tenant", t.tenant_id, "--index", str(index),
                              "--fixtures-dir", str(fixtures)], spawn=spawn)
    except SystemExit as stop:
        return stop.code


def _pins(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, tok in enumerate(argv[:-1]) if tok == PIN]


def _assert_pinned_to_an_export(t, argv: list[str]) -> str:
    pins = _pins(argv)
    assert len(pins) == 1, f"held_out started an unpinned (or doubly pinned) run.py: {argv}"
    assert _SHA.match(pins[0]), f"the pin is not a commit id: {pins[0]!r}"
    assert export_dir(t.tenant, pins[0]).is_dir(), (
        f"the pin {pins[0]} names no export of the tenant (a pinned run reads an export)")
    return pins[0]


def _fresh_index(tmp_path: Path, name: str) -> Path:
    index = tmp_path / name / "held-out-index.jsonl"
    index.parent.mkdir()
    return index


def test_od10_the_first_launch_pins_to_current_at_index_creation(p4_tenant, tmp_path):
    """OD10: the launch that creates the index starts `run.py --knowledge-commit <current>` —
    exactly one pin, naming the export `current` names at that moment."""
    t = p4_tenant
    spawn = RecordingSpawn()
    fixtures = _fixtures(tmp_path / "fixtures")
    index = _fresh_index(tmp_path, "eval")

    rc = _launch(t, SLUGS[0], index, fixtures, spawn)

    assert rc in (0, None), f"the held-out launch failed (exit {rc!r})"
    assert len(spawn.argvs) == 1, spawn.argvs
    assert _assert_pinned_to_an_export(t, spawn.argvs[0]) == t.commit, (
        "the first launch did not pin to the commit `current` named at index creation")


def test_od10_every_launch_of_an_index_pins_to_its_commit_after_current_moves(p4_tenant, tmp_path):
    """OD10 (comparability): a merged PR published between two launches into one index moves
    `current`, yet the second launch pins to the commit recorded at index creation. Positive
    control on the same channel: a NEW index created after the publish pins to the new
    `current` — so the pin follows the index, not a constant."""
    t = p4_tenant
    spawn = RecordingSpawn()
    fixtures = _fixtures(tmp_path / "fixtures")
    index = _fresh_index(tmp_path, "eval")

    _launch(t, SLUGS[0], index, fixtures, spawn)
    later = t.merge({"agent/lessons/merged-mid-evaluation.md": "a lesson merged mid-run\n"})
    assert t.publish().commit == later
    _launch(t, SLUGS[1], index, fixtures, spawn)
    fresh = _fresh_index(tmp_path, "eval-after-publish")
    _launch(t, SLUGS[0], fresh, fixtures, spawn)

    assert len(spawn.argvs) == 3, spawn.argvs
    pins = [_assert_pinned_to_an_export(t, argv) for argv in spawn.argvs]
    assert pins[:2] == [t.commit, t.commit], (
        f"launches of one index ran on different knowledge commits: {pins[:2]}")
    assert pins[2] == later, (
        f"control: an index created after the publish did not pin to the new current: {pins[2]}")
