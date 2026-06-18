"""Unit tests for the pure per-loop compaction core (runtime/compaction.py).

These pin the behaviour the offline dry-run and (later) the live hook rely on:
loop detection off the invlang frontier, freeze-per-loop transitions, the
orphaned-pair / no-saving fallbacks, and the size + reconstruction helpers.
No I/O, no PydanticAI — everything operates on the message-dump dict form.
"""

from __future__ import annotations

from defender.runtime import compaction as C


# --- fixtures: minimal invlang frontier documents ------------------------

def _frontier(*rows: str) -> str:
    header = ":L findings [id|loop|name|target|tests|system|window]"
    return "```invlang\n" + header + "\n" + "\n".join(rows) + "\n```\n"


LOOP1 = _frontier("l-001|1|raw-auth|v-001|h-001|elastic|w")
LOOP2 = _frontier(
    "l-001|1|raw-auth|v-001|h-001|elastic|w",
    "l-005|2|cmdb-ip|v-006|h-002|cmdb|w",
)


def _req(content: str = "x") -> dict:
    return {"kind": "request", "parts": [{"part_kind": "user-prompt", "content": content}]}


def _resp(content: str = "y") -> dict:
    return {"kind": "response", "parts": [{"part_kind": "text", "content": content}]}


# --- detect_loop ----------------------------------------------------------

def test_detect_loop_single():
    assert C.detect_loop(LOOP1) == 1


def test_detect_loop_takes_max():
    assert C.detect_loop(LOOP2) == 2


def test_detect_loop_empty_is_none():
    assert C.detect_loop("") is None


def test_detect_loop_garbage_is_none():
    assert C.detect_loop("just some prose, no invlang here") is None


# --- compact: passthrough / freeze / reuse --------------------------------

def test_loop1_passes_through():
    history = [_req("orientation" * 50), _resp(), _req()]
    step = C.compact(history, LOOP1, None)
    assert step.action == "passthrough"
    assert step.history is history  # unchanged identity
    assert step.state is None


def test_freezes_at_loop2_boundary():
    # 5 real messages, ending on the request where loop 2 first appears.
    history = [_req("orientation" * 80), _resp("a" * 80), _req("b" * 80),
               _resp("c" * 80), _req("d" * 80)]
    step = C.compact(history, LOOP2, None)
    assert step.action == "froze"
    assert step.loop == 2
    assert step.state is not None
    assert step.state.frozen_through == 1          # folded loop 1, loop 2 active
    assert step.state.freeze_index == len(history)  # absorbed everything so far
    # prefix = orientation (verbatim) + synthetic frontier; tail empty at freeze
    assert len(step.history) == 2
    assert step.history[0] is history[0]            # orientation kept verbatim
    assert "```invlang" in step.history[1]["parts"][0]["content"]
    assert C.history_chars(step.history) < C.history_chars(history)


def test_reuses_within_frozen_loop():
    history = [_req("orientation" * 80), _resp("a" * 80), _req("b" * 80),
               _resp("c" * 80), _req("d" * 80)]
    frozen = C.compact(history, LOOP2, None).state
    # advance: a response then another request, still loop 2
    history = history + [_resp("e" * 80), _req("f" * 80)]
    step = C.compact(history, LOOP2, frozen)
    assert step.action == "reused"
    assert step.state is frozen                      # prefix held byte-stable
    # prefix (2) + live tail starting at the response that followed the freeze
    assert len(step.history) == 4
    assert step.history[2] is history[5]             # tail opens on the response
    assert step.history[2]["kind"] == "response"


def test_prefix_is_byte_stable_across_a_loop():
    history = [_req("orientation" * 80), _resp("a" * 80), _req("b" * 80),
               _resp("c" * 80), _req("d" * 80)]
    frozen = C.compact(history, LOOP2, None).state
    a = C.compact(history + [_resp("e"), _req("f")], LOOP2, frozen).history[1]
    b = C.compact(history + [_resp("e"), _req("f"), _resp("g"), _req("h")], LOOP2, frozen).history[1]
    assert a == b  # same frontier message → cache stays warm within the loop


# --- compact: fallbacks ---------------------------------------------------

def test_fallback_when_cut_not_on_boundary():
    # A frozen state whose freeze_index lands on a *request* would orphan a
    # tool-return in the tail — compact must bail to the full history.
    history = [_req("orientation" * 80), _resp("a" * 80), _req("b" * 80),
               _resp("c" * 80), _req("d" * 80)]
    bad = C.FrozenState(prefix=(history[0], C.render_frontier_message(LOOP2)),
                        freeze_index=2, frozen_through=1)
    # history[2] is a request → tail would open on a request
    assert history[2]["kind"] == "request"
    step = C.compact(history, LOOP2, bad)
    assert step.action == "fallback"
    assert step.reason == "cut-not-on-boundary"
    assert step.history is history


def test_loop_undetermined_passes_through_without_state():
    history = [_req("orientation" * 50)]
    step = C.compact(history, "", None)
    assert step.action == "passthrough"
    assert step.reason == "loop-undetermined"


# --- size + reconstruction helpers ----------------------------------------

def test_payload_chars_counts_text_and_tool_args():
    msg = {"parts": [
        {"part_kind": "user-prompt", "content": "abcd"},
        {"part_kind": "tool-call", "tool_name": "bash", "args": {"command": "ls"}},
    ]}
    # "abcd" (4) + "bash" (4) + json.dumps({"command":"ls"}) (20)
    assert C.payload_chars(msg) == 4 + 4 + len('{"command": "ls"}')


def test_apply_writes_write_then_edit():
    text = ""
    text = C.apply_writes(text, {"parts": [
        {"part_kind": "tool-call", "tool_name": "write_file",
         "args": {"path": "/run/investigation.md", "content": "alpha"}}]})
    assert text == "alpha"
    text = C.apply_writes(text, {"parts": [
        {"part_kind": "tool-call", "tool_name": "edit_file",
         "args": {"path": "/run/investigation.md", "old_string": "alpha", "new_string": "beta"}}]})
    assert text == "beta"


def test_apply_writes_ignores_other_files():
    text = C.apply_writes("keep", {"parts": [
        {"part_kind": "tool-call", "tool_name": "write_file",
         "args": {"path": "/run/report.md", "content": "wipe"}}]})
    assert text == "keep"
