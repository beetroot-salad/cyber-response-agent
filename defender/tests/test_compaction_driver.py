"""Integration tests for the live compaction glue in runtime/driver.py.

Cover the riskiest seam — a compacted history (synthetic frontier + tail)
surviving the dump → compact → re-validate round-trip as real PydanticAI message
objects — without a live agent run. The pure freeze/reuse + fold-boundary logic
is covered in test_compaction.py.
"""

from __future__ import annotations

from pydantic_ai.messages import ModelMessagesTypeAdapter

from defender.runtime import driver


def _msgs(n: int) -> list:
    """n alternating request/response ModelMessage objects, large enough to fold."""
    dicts = []
    for i in range(n):
        if i % 2 == 0:
            dicts.append({"kind": "request",
                          "parts": [{"part_kind": "user-prompt", "content": f"u{i} " * 400}]})
        else:
            dicts.append({"kind": "response",
                          "parts": [{"part_kind": "text", "content": f"a{i} " * 400}]})
    return ModelMessagesTypeAdapter.validate_python(dicts)


_LH = ":L findings [id|loop|name|target|tests|system|window]"
_OBS1 = (":E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
         "e-001|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success")

# loop 1 planned, no results → nothing safe to fold
UNRESOLVED1 = f"```invlang\n{_LH}\nl-001|1|raw-auth|v-001|h-001|elastic|w\n```\n"
# loop 1 resolved + loop 2 just planned (active, unresolved) → fold loop 1 only
RESOLVED1_PLAN2 = (
    f"```invlang\n{_LH}\nl-001|1|raw-auth|v-001|h-001|elastic|w\n\n{_OBS1}\n```\n\n"
    f"```invlang\n{_LH}\nl-005|2|cmdb-ip|v-006|h-002|cmdb|w\n```\n"
)


def test_freeze_roundtrips_to_valid_messages(tmp_path):
    (tmp_path / "investigation.md").write_text(RESOLVED1_PLAN2)
    messages = _msgs(5)
    holder: dict = {"state": None}
    out = driver._compact_messages(messages, tmp_path, holder)

    assert holder["state"] is not None
    assert holder["state"].frozen_through == 1
    assert len(out) < len(messages)
    redump = ModelMessagesTypeAdapter.dump_python(out, mode="json")
    assert redump[0]["parts"][0]["part_kind"] == "user-prompt"   # orientation kept
    frontier = redump[1]["parts"][0]["content"]
    assert "```invlang" in frontier and "l-001" in frontier      # settled loop in
    assert "l-005" not in frontier                               # active loop OUT


def test_passthrough_returns_original_objects(tmp_path):
    (tmp_path / "investigation.md").write_text(UNRESOLVED1)
    messages = _msgs(5)
    holder: dict = {"state": None}
    out = driver._compact_messages(messages, tmp_path, holder)
    assert out is messages
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
