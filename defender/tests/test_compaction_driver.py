"""Integration tests for the live compaction glue in runtime/driver.py.

These cover the riskiest seam — that a compacted history (synthetic frontier +
tail) survives the dump → compact → re-validate round-trip as real PydanticAI
message objects — without a live agent run or any API call. The pure
freeze/reuse logic is covered in test_compaction.py.
"""

from __future__ import annotations

from pydantic_ai.messages import ModelMessagesTypeAdapter

from defender.runtime import driver


def _msgs(n: int) -> list:
    """n alternating request/response ModelMessage objects (request first)."""
    dicts = []
    for i in range(n):
        if i % 2 == 0:
            dicts.append({"kind": "request",
                          "parts": [{"part_kind": "user-prompt", "content": f"u{i} " * 40}]})
        else:
            dicts.append({"kind": "response",
                          "parts": [{"part_kind": "text", "content": f"a{i} " * 40}]})
    return ModelMessagesTypeAdapter.validate_python(dicts)


LOOP1 = ("```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
         "l-001|1|raw-auth|v-001|h-001|elastic|w\n```\n")
LOOP2 = ("```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
         "l-001|1|raw-auth|v-001|h-001|elastic|w\n"
         "l-005|2|cmdb-ip|v-006|h-002|cmdb|w\n```\n")


def test_freeze_roundtrips_to_valid_messages(tmp_path):
    (tmp_path / "investigation.md").write_text(LOOP2)
    messages = _msgs(5)  # ends on a request → loop-2 boundary
    holder: dict = {"state": None}
    out = driver._compact_messages(messages, tmp_path, holder)

    assert holder["state"] is not None
    assert holder["state"].frozen_through == 1
    assert len(out) < len(messages)            # compacted
    # the result must be real, re-dumpable message objects (the round-trip risk)
    redump = ModelMessagesTypeAdapter.dump_python(out, mode="json")
    assert redump[0]["parts"][0]["part_kind"] == "user-prompt"   # orientation kept
    assert "```invlang" in redump[1]["parts"][0]["content"]      # synthetic frontier


def test_passthrough_returns_original_objects(tmp_path):
    (tmp_path / "investigation.md").write_text(LOOP1)  # loop 1 → nothing to fold
    messages = _msgs(5)
    holder: dict = {"state": None}
    out = driver._compact_messages(messages, tmp_path, holder)
    assert out is messages          # untouched, no round-trip
    assert holder["state"] is None


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
