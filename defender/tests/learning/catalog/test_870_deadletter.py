"""#870: three ways to leave the queue uncurated, told apart.

#1278: the graveyard and its `deadletter_reason` are gone (design r8 Schema "Retired files"); a row nothing can teach takes its
own terminal fate from the tick (D9): skipped, the reason naming the class (no system, a malformed name, or the undeclared
system by name), and a row with no id is dead. The one lane tick here runs over a batch draft (`_curator1134.draft_lane`)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.store import Outcome
from defender.systems.verbs import is_system_name
from defender.tests.support.learning.core._declared870 import PITFALLS_SECTION, Claim, Spawn, pitfall_row, tick
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
def lane(tmp_path: Path, monkeypatch):
    """A batch draft of the tenant declaring `elastic` (a marker and an adapter), over a product checkout."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    product = tmp_path / "product"
    write_adapter(product, "elastic")
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files={
        "skills/elastic/execution.md": "# execution\n",
        "skills/gather/defender-sql.pitfalls.md": ADDON.read_text(encoding="utf-8"),
    })


def _fate(lane, row: dict):
    """Run one real tick over a claim holding only `row` and read the fate the dropped row took (`None` if it took none, so
    an undecided row fails the caller's comparison, not a `KeyError` here)."""
    claim = Claim()
    claim.add(row)
    assert tick(lane, Spawn(None), claim) == 0
    return claim.outcomes.get(("pitfall", row["pitfall_id"]))


def test_a_systemless_row_retires_as_no_system(lane):
    assert _fate(lane, pitfall_row("r:l-000:0", "")) == Outcome.skipped("no-system")


def test_a_malformed_name_retires_as_malformed_system(lane):
    for i, malformed in enumerate(("../evil", "a\\b", ".hidden", "a\x00b")):
        assert is_system_name(malformed) is False, malformed
        assert _fate(lane, pitfall_row(f"m:l-00{i}:0", malformed)) == Outcome.skipped("malformed-system")

    # Whitespace is stripped before the shape check, so this row is `no-system` under either
    # alphabet; the probe only keeps that traceable.
    assert is_system_name("   ") is False, "the name alphabet admits whitespace"
    assert _fate(lane, pitfall_row("w:l-000:0", "   ")) == Outcome.skipped("no-system")

    # Outside the alphabet: two homoglyphs, and the uppercase spelling #914 moved out.
    for i, outside in enumerate(("\u0435lastic", "\uff45lastic", "Elastic")):
        assert is_system_name(outside) is False, (
            f"the name alphabet admits {outside!r}, so it reads as an onboarding miss, "
            f"not as attacker-shaped"
        )
        assert _fate(lane, pitfall_row(f"u:l-00{i}:0", outside)) == Outcome.skipped("malformed-system")


def test_a_row_with_no_id_is_dead_at_once_and_does_not_hold_back_the_taught_one(lane):
    """An id-less row cannot be addressed: it is dead, and the keyed row beside it is taught and reported committed."""
    idless = {k: v for k, v in pitfall_row("x:l-000:0", "elastic").items() if k != "pitfall_id"}
    keyed = pitfall_row("k:l-000:0", "elastic")
    claim = Claim()
    claim.items = lambda: [("pitfall", "k:l-000:0", keyed), ("pitfall", "digest-key", idless)]  # the store keys an id-less row by its digest

    assert tick(lane, Spawn(_curate_execution_md("elastic"), root=Path(lane.batch.draft_root)), claim) == 0

    assert claim.committed == {"k:l-000:0"}
    assert claim.outcomes == {("pitfall", "digest-key"): Outcome.dead("row carries no value under 'pitfall_id'")}


def test_an_undeclared_name_retires_naming_itself(lane):
    assert _fate(lane, pitfall_row("r:l-001:0", "newsys")) == Outcome.skipped("undeclared-system:newsys")
    assert _fate(lane, pitfall_row("r:l-002:0", "alsomissing")) == Outcome.skipped(
        "undeclared-system:alsomissing"), "the one false string all three classes shared survived"
