"""#870: three ways to leave the queue uncurated, told apart.

The one lane tick here runs over a batch draft (`_curator1134.draft_lane`)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.systems.verbs import is_system_name
from defender.tests.support.learning.core._declared870 import (
    PITFALLS_SECTION,
    Spawn,
    consumed_by_id,
    graveyard_by_id,
    pitfall_row,
)
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.runtime.engine._declared869 import write_adapter
from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

#: The tenant's learned-SQL-pitfalls add-on (the fixture's committed copy).
ADDON = FIXTURE_AGENT / "skills" / "gather" / "defender-sql.pitfalls.md"


def _curate_execution_md(system: str):
    """`_declared870.curate_execution_md` at the draft's spelling: one bullet in
    `agent/skills/<system>/execution.md` under the root the spawn is handed."""

    def _edit(root: Path) -> None:
        C.put(root / "agent" / "skills" / system / "execution.md",
              f"# {system}\n\n{PITFALLS_SECTION}\n\n- use the key, not the id\n")

    return _edit


@pytest.fixture
def paths(tmp_path: Path) -> LoopPaths:
    """State only — `_graveyard_dropped_rows` writes beside the queue and reads no tree."""
    return LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")


def _reason(paths, row: dict) -> str:
    """Retire one row through the real appender and classifier and read back the reason it filed
    under. Read with `.get`, so an unfiled row fails the caller's comparison, not a `KeyError` here.
    """
    persist.append_pitfalls([row], state=_state1135.state_for_paths(paths))
    rows = persist.read_pitfalls(_state1135.state_for_paths(paths))
    pitfalls_curator._graveyard_dropped_rows(_state1135.state_for_paths(paths), rows, [row["pitfall_id"]])
    entry = graveyard_by_id(paths).get(row["pitfall_id"], {})
    return str(entry.get("deadletter_reason"))


def test_a_systemless_row_retires_as_no_system(paths):
    assert _reason(paths, pitfall_row("r:l-000:0", "")) == "no-system"


def test_a_malformed_name_retires_as_malformed_system(paths, tmp_path, monkeypatch):
    for i, malformed in enumerate(("../evil", "a\\b", ".hidden", "a\x00b")):
        assert is_system_name(malformed) is False, malformed
        assert _reason(paths, pitfall_row(f"m:l-00{i}:0", malformed)) == "malformed-system"

    # Whitespace is stripped before the shape check, so this row is `no-system` under either
    # alphabet; the probe only keeps that traceable.
    assert is_system_name("   ") is False, "the name alphabet admits whitespace"
    assert _reason(paths, pitfall_row("w:l-000:0", "   ")) == "no-system"

    # Outside the alphabet: two homoglyphs, and the uppercase spelling #914 moved out.
    for i, outside in enumerate(("\u0435lastic", "\uff45lastic", "Elastic")):
        assert is_system_name(outside) is False, (
            f"the name alphabet admits {outside!r}, so it reads as an onboarding miss, "
            f"not as attacker-shaped"
        )
        assert _reason(paths, pitfall_row(f"u:l-00{i}:0", outside)) == "malformed-system"

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    # The lane writes a batch draft carrying the declared system's marker and the pitfalls
    # add-on; adapters stay in the product checkout.
    product = tmp_path / "product"
    write_adapter(product, "elastic")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files={
        "skills/elastic/execution.md": "# execution\n",
        "skills/gather/defender-sql.pitfalls.md": ADDON.read_text(encoding="utf-8"),
    })
    inert = LoopPaths(repo_root=product, state_dir=tmp_path / "state-inert")
    idless = {k: v for k, v in pitfall_row("x:l-000:0", "elastic").items() if k != "pitfall_id"}
    persist.append_pitfalls([idless, pitfall_row("k:l-000:0", "elastic")], state=_state1135.state_for_paths(inert))
    assert len(persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(inert)))) == 2, (
        "an id-less row stopped counting toward the threshold arithmetic"
    )

    # The spawn's `repo_root` is the draft root.
    assert pitfalls_curator.run_pitfalls(
        paths=inert, invoke=Spawn(_curate_execution_md("elastic")), trees=C.draft_trees(lane),
        batch=lane.batch,
    ) == 0
    survivors = persist.read_pitfalls(_state1135.state_for_paths(inert))
    assert [r.get("pitfall_id") for r in survivors] == [None], (
        "the id-less row no longer survives the tick untouched (recorded, not demanded: "
        "changing it is a decision, not a fix)"
    )
    assert "k:l-000:0" in consumed_by_id(inert)
    assert graveyard_by_id(inert) == {}


def test_an_undeclared_name_retires_naming_itself(paths):
    assert _reason(paths, pitfall_row("r:l-001:0", "newsys")) == "undeclared-system:newsys"
    assert _reason(paths, pitfall_row("r:l-002:0", "alsomissing")) == (
        "undeclared-system:alsomissing"
    ), "the one false string all three classes shared survived"
