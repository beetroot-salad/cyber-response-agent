"""Integration tests for the compaction glue that survives in runtime/driver.py."""

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


