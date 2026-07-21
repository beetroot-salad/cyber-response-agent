"""Integration tests for the live compaction glue in runtime/driver.py.

Cover the riskiest seams without a live agent run: (1) a compacted history
round-trips to valid PydanticAI message objects, and (2) — the regression for
the 2nd-A/B bug — the live tail GROWS under PydanticAI's history-processor
*accumulation* (it feeds our output back, so a stateless marker-based processor
is required; a stateful index into a growing canonical went flat and looped).
"""

from __future__ import annotations

from pydantic_ai.messages import ModelMessagesTypeAdapter

from defender.runtime import compaction, driver


def _msgs(n: int, start: int = 0) -> list:
    """n alternating request/response ModelMessage objects, large enough to fold.
    `start` offsets the content so successive batches differ (and never contain
    the frontier sentinel)."""
    dicts = []
    for i in range(start, start + n):
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
UNRESOLVED1 = f"```invlang\n{_LH}\nl-001|1|raw-auth|v-001|h-001|elastic|w\n```\n"
RESOLVED1_PLAN2 = (
    f"```invlang\n{_LH}\nl-001|1|raw-auth|v-001|h-001|elastic|w\n\n{_OBS1}\n```\n\n"
    f"```invlang\n:T close\nloop 1\n```\n\n"
    f"```invlang\n{_LH}\nl-005|2|cmdb-ip|v-006|h-002|cmdb|w\n```\n"
)


def test_freeze_roundtrips_to_valid_messages(tmp_path):
    (tmp_path / "investigation.md").write_text(RESOLVED1_PLAN2)
    messages = _msgs(6)
    out = driver._compact_messages(messages, tmp_path)

    assert len(out) < len(messages)
    redump = ModelMessagesTypeAdapter.dump_python(out, mode="json")
    assert redump[0]["parts"][0]["part_kind"] == "user-prompt"
    frontier = redump[1]["parts"][0]["content"]
    assert compaction.FRONTIER_SENTINEL in frontier
    assert "l-001" in frontier
    assert "l-005" not in frontier


def test_passthrough_returns_original_objects(tmp_path):
    (tmp_path / "investigation.md").write_text(UNRESOLVED1)
    messages = _msgs(6)
    assert driver._compact_messages(messages, tmp_path) is messages


def test_tail_grows_under_pydanticai_accumulation(tmp_path):
    """Regression for the 2nd-A/B bug. PydanticAI feeds the processor's OUTPUT
    back plus new turns; simulate that and assert the live tail accumulates
    instead of staying flat (flat == the agent loses memory and loops)."""
    (tmp_path / "investigation.md").write_text(RESOLVED1_PLAN2)
    H = _msgs(6)
    lengths = []
    for turn in range(5):
        out = driver._compact_messages(H, tmp_path)
        lengths.append(len(out))
        H = list(out) + _msgs(2, start=100 + turn * 2)

    assert lengths[0] == 2
    assert lengths == sorted(lengths)
    assert lengths[-1] > lengths[0]
    def _frontier_text(h):
        return ModelMessagesTypeAdapter.dump_python(
            driver._compact_messages(h, tmp_path), mode="json")[1]["parts"][0]["content"]
    assert _frontier_text(H) == _frontier_text(H)


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
