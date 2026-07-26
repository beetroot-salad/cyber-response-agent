"""Integration tests for the compaction glue that survives in runtime/driver.py.

#705 replaced the live per-loop compaction mechanism (`driver._compact_messages`,
`driver._frontier_index`, a sentinel scan through `investigation.md` text) with the
store-backed `selection.fold`/`selection.render` — the fold boundary is now a store
query, not a text scan (see `tests/test_selection_705.py`). What remains local to
`driver.py` is the flag reader and the (unrelated) gather-summary pointer helper.
"""

from __future__ import annotations

from defender.runtime import driver


def test_summary_pointers_lists_persisted_summaries(tmp_path):
    d = tmp_path / "gather_summaries"
    d.mkdir()
    (d / "l-001.md").write_text("x")
    (d / "l-002.md").write_text("y")
    ptrs = driver._summary_pointers(tmp_path)
    assert set(ptrs) == {"l-001", "l-002"}
    assert ptrs["l-001"].endswith("gather_summaries/l-001.md")


def test_compaction_flag_default_off(monkeypatch):
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    assert driver._compaction_enabled() is False
    monkeypatch.setenv("DEFENDER_COMPACTION", "on")
    assert driver._compaction_enabled() is True
    monkeypatch.setenv("DEFENDER_COMPACTION", "0")
    assert driver._compaction_enabled() is False
