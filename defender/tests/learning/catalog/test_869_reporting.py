"""#869: a dropped row is reported, never silently absorbed, and takes a fate of its own.

The mixed pitfalls tick runs over a batch draft (`_curator1134.draft_lane`) with adapters in a product checkout; what landed is
read from the batch branch (`agent/...`).

#1278: the file queue's consumed ledger and graveyard are gone (design r8 Schema "Retired files"); the tick reports into the
claim's `outcomes` and `on_curated` (D1/D9): a taught row is committed (it stays in its batch for the merge), a row naming an
undeclared system is skipped, naming it, at once, and a row with no id is dead.

Retired from this file: `test_a_membership_refusal_is_terminal_and_leaves_a_re_drivable_record` (a refused request moved to
`author-queue/failed/` with its record, once: the folder, the `failed` record and the re-drive are gone with the file queue;
that a failing request is not retried without bound is `test_loop.py::test_lead_author_drain_bounds_the_retries_of_a_failing_request`).
"""
from __future__ import annotations

from pathlib import Path

from defender.learning.store import Outcome
from defender.tests.support.learning.core._declared870 import Claim, tick
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.runtime.engine._declared869 import (
    Spawn,
    agent_marker_file,
    pitfall_row,
    seed_agent_files,
    seed_product,
    write,
)


def _mixed_batch(tmp_path: Path, monkeypatch, *, name: str = "repo"):
    """Two `elastic` rows, one undeclared `elastik` row, and a curator edit that makes a real
    commit: only a batch that commits gives the dropped row a sha it could wrongly inherit (an
    all-dropped batch's sha is `None`)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    product = seed_product(tmp_path, adapters=("elastic",), name=f"product-{name}")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product,
                        files=seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=()))
    claim = Claim()
    claim.add(pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic"), pitfall_row("r:l-002:0", "elastik"))
    spawn = Spawn(lambda root: write(
        agent_marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ), root=lane.root)
    return lane, claim, spawn


def test_a_dropped_row_is_never_labelled_committed(tmp_path, monkeypatch):
    """Of three rows, the two taught are reported committed (with the tick's commit) and the undeclared one is not."""
    lane, claim, spawn = _mixed_batch(tmp_path, monkeypatch)
    assert tick(lane, spawn, claim) == 0

    assert "agent/skills/elastic/execution.md" in lane.landed()
    assert claim.committed == {"r:l-000:0", "r:l-001:0"}, f"the committed set is {claim.committed}"
    [disposition] = claim.curated
    assert disposition.sha, "the committed rows carry no commit"
    assert ("pitfall", "r:l-002:0") not in {(k, i) for k, i in claim.outcomes if i in claim.committed}


def test_a_dropped_row_takes_a_terminal_undeclared_category(tmp_path, monkeypatch):
    """The row naming an undeclared system is skipped at once, naming the system; the taught rows take no fate yet (they
    stay in the batch until the merge)."""
    lane, claim, spawn = _mixed_batch(tmp_path, monkeypatch, name="undeclared")
    assert tick(lane, spawn, claim) == 0

    assert claim.outcomes == {("pitfall", "r:l-002:0"): Outcome.skipped("undeclared-system:elastik")}, (
        f"the dropped row's fate is {claim.outcomes}")
    assert "agent/skills/elastic/execution.md" in lane.landed()
