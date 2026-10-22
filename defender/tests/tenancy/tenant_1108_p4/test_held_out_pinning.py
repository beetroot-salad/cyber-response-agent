"""#1108 P4 O-PIN (held-out side): `evaluations/held_out` pins every fixture to one commit.

Design (O-PIN): "`evaluations/held_out` pins every fixture to one commit (comparability)";
O11: "Subprocess launchers (e2e, `held_out`) use O-PIN" (`run.py --knowledge-commit <sha>`).

WHAT IS NOT DESIGNED (reported, not frozen): where the one commit comes from — e.g. (a) the
launch resolves `current` once and records it with the index so later launches into the same
index reuse it, or (b) the operator names it (`held_out.py launch ... --knowledge-commit S`).
These tests therefore drive the plain launch (`held_out.main(["launch", slug, "--tenant", T,
"--index", F, "--fixtures-dir", D], spawn=)`) and assert only what holds under either answer:
  - a launch never starts an UNPINNED `run.py`: it either starts `run.py` with exactly one
    `--knowledge-commit <sha>` naming one of the tenant's exports, or refuses having started
    nothing;
  - launches into one index that do start runs pin them all to the same commit, even when a
    publish moves `current` between them.
Once the source is decided, the orchestrator should strengthen them (under (a): both launches
start and the pin is the first launch's `current`; under (b): the given sha is passed through).

Entry surface: `evaluations.held_out.main` with its existing `spawn=` seam (records argv; runs
nothing). The tenant is the P4 fixture tenant published for real (`p4_tenant`).
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


def test_o_pin_held_out_never_starts_an_unpinned_run(p4_tenant, tmp_path):
    """O-PIN / O11: a held-out launch either starts `run.py` pinned to one of the tenant's
    exports, or refuses having started nothing — it never starts a run that would publish and
    read whatever `main` holds at that moment."""
    t = p4_tenant
    spawn = RecordingSpawn()
    fixtures = _fixtures(tmp_path / "fixtures")
    index = tmp_path / "eval" / "held-out-index.jsonl"
    index.parent.mkdir()

    rc = _launch(t, SLUGS[0], index, fixtures, spawn)

    if not spawn.argvs:
        assert rc not in (0, None), "held_out started nothing yet reported success"
        return
    for argv in spawn.argvs:
        _assert_pinned_to_an_export(t, argv)


def test_o_pin_held_out_pins_every_fixture_of_one_index_to_one_commit(p4_tenant, tmp_path):
    """O-PIN (comparability): two fixtures launched into one index, with a merged PR published
    between them (so `current` moves), run on the same knowledge commit."""
    t = p4_tenant
    spawn = RecordingSpawn()
    fixtures = _fixtures(tmp_path / "fixtures")
    index = tmp_path / "eval" / "held-out-index.jsonl"
    index.parent.mkdir()

    _launch(t, SLUGS[0], index, fixtures, spawn)
    later = t.merge({"agent/lessons/merged-mid-evaluation.md": "a lesson merged mid-run\n"})
    assert t.publish().commit == later
    _launch(t, SLUGS[1], index, fixtures, spawn)

    pins = {_assert_pinned_to_an_export(t, argv) for argv in spawn.argvs}
    assert len(pins) <= 1, (
        f"fixtures of one held-out index ran on different knowledge commits: {sorted(pins)}")
