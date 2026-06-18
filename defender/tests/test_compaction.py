"""Unit tests for the pure per-loop compaction core (runtime/compaction.py).

Pins the behaviour the offline dry-run and the live hook rely on: loop detection,
the *resolved* fold boundary (fold only loops below the active one — the N=1 fix),
the frontier trimming that keeps the active loop out of the frozen snapshot,
freeze/reuse transitions, the fallbacks, and the size + reconstruction helpers.
No I/O, no PydanticAI — everything operates on the message-dump dict form.
"""

from __future__ import annotations

from defender.runtime import compaction as C


# --- fixtures: realistic multi-fence invlang frontiers --------------------

_LH = ":L findings [id|loop|name|target|tests|system|window]"


def _block(*rows: str) -> str:
    return "```invlang\n" + "\n".join(rows) + "\n```"


def _obs(lead: str) -> str:
    return (f":E {lead}.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
            f"e-{lead.split('-')[1]}|attempted_auth|v-003|v-001|"
            "2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success")


# loop 1 planned but no results yet → nothing safe to fold
UNRESOLVED1 = _block(_LH, "l-001|1|raw-auth|v-001|h-001|elastic|w")
# loop 1 resolved (has an observation) + loop 2 just planned (unresolved)
RESOLVED1_PLAN2 = "\n\n".join([
    _block(_LH, "l-001|1|raw-auth|v-001|h-001|elastic|w", "", _obs("l-001")),
    _block(_LH, "l-005|2|cmdb-ip|v-006|h-002|cmdb|w"),
])
# both loops resolved
RESOLVED2 = "\n\n".join([
    _block(_LH, "l-001|1|raw-auth|v-001|h-001|elastic|w", "", _obs("l-001")),
    _block(_LH, "l-005|2|cmdb-ip|v-006|h-002|cmdb|w", "", _obs("l-005")),
])

# simple frontiers for detect_loop (max :L loop, ignores resolution)
LOOP1 = _block(_LH, "l-001|1|raw-auth|v-001|h-001|elastic|w")
LOOP2 = _block(_LH, "l-001|1|raw-auth|v-001|h-001|elastic|w",
               "l-005|2|cmdb-ip|v-006|h-002|cmdb|w")


def _req(tag: str = "u", n: int = 600) -> dict:
    return {"kind": "request", "parts": [{"part_kind": "user-prompt", "content": (tag + " ") * n}]}


def _resp(tag: str = "a", n: int = 600) -> dict:
    return {"kind": "response", "parts": [{"part_kind": "text", "content": (tag + " ") * n}]}


def _history(n: int = 5) -> list:
    """n alternating request/response messages, large enough that folding saves."""
    return [_req() if i % 2 == 0 else _resp() for i in range(n)]


# --- detect_loop (unchanged: highest planned loop) ------------------------

def test_detect_loop_single():
    assert C.detect_loop(LOOP1) == 1


def test_detect_loop_takes_max():
    assert C.detect_loop(LOOP2) == 2


def test_detect_loop_empty_is_none():
    assert C.detect_loop("") is None


# --- fold_boundary (the resolved-boundary fix) ----------------------------

def test_fold_boundary_unresolved_loop1_is_zero():
    assert C.fold_boundary(UNRESOLVED1) == 0   # nothing safe to fold yet


def test_fold_boundary_folds_below_active_loop():
    # loop 1 resolved, loop 2 active/unresolved → fold loop 1 only
    assert C.fold_boundary(RESOLVED1_PLAN2) == 1


def test_fold_boundary_folds_active_loop_once_resolved():
    assert C.fold_boundary(RESOLVED2) == 2


def test_fold_boundary_empty_is_zero():
    assert C.fold_boundary("") == 0


def test_frontier_through_excludes_active_loop():
    ft = C._frontier_through(RESOLVED1_PLAN2, 1)
    assert "l-001" in ft        # settled loop kept
    assert "l-005" not in ft    # active loop's plan row excluded


# --- compact: passthrough / freeze / reuse --------------------------------

def test_passes_through_until_a_loop_resolves():
    history = _history()
    step = C.compact(history, UNRESOLVED1, None)
    assert step.action == "passthrough"
    assert step.history is history
    assert step.state is None


def test_freezes_at_resolved_boundary_excluding_active_loop():
    history = _history()
    step = C.compact(history, RESOLVED1_PLAN2, None)
    assert step.action == "froze"
    assert step.loop == 2                      # active (planned) loop
    assert step.state.frozen_through == 1      # only the resolved loop folded
    assert step.state.freeze_index == len(history)
    assert len(step.history) == 2              # orientation + frontier; tail empty
    frontier = step.history[1]["parts"][0]["content"]
    assert "l-001" in frontier                 # settled lead present
    assert "l-005" not in frontier             # active loop kept OUT of the snapshot
    assert C.history_chars(step.history) < C.history_chars(history)


def test_reuses_within_frozen_loop():
    history = _history()
    frozen = C.compact(history, RESOLVED1_PLAN2, None).state
    history = history + [_resp(), _req()]      # active loop proceeds in the tail
    step = C.compact(history, RESOLVED1_PLAN2, frozen)
    assert step.action == "reused"
    assert step.state is frozen
    assert step.history[2] is history[5]       # tail opens on the response
    assert step.history[2]["kind"] == "response"


def test_refreezes_when_next_loop_resolves():
    history = _history()
    frozen = C.compact(history, RESOLVED1_PLAN2, None).state
    history = history + [_resp(), _req()]
    step = C.compact(history, RESOLVED2, frozen)  # loop 2 now resolved
    assert step.action == "froze"
    assert step.state.frozen_through == 2
    assert step.state is not frozen


def test_prefix_is_byte_stable_across_a_loop():
    history = _history()
    frozen = C.compact(history, RESOLVED1_PLAN2, None).state
    a = C.compact(history + [_resp(), _req()], RESOLVED1_PLAN2, frozen).history[1]
    b = C.compact(history + [_resp(), _req(), _resp(), _req()], RESOLVED1_PLAN2, frozen).history[1]
    assert a == b


# --- compact: fallbacks ---------------------------------------------------

def test_fallback_when_cut_not_on_boundary():
    history = _history()
    bad = C.FrozenState(prefix=(history[0], C.render_frontier_message(RESOLVED1_PLAN2)),
                        freeze_index=2, frozen_through=1)
    assert history[2]["kind"] == "request"     # tail would open on a request
    step = C.compact(history, RESOLVED1_PLAN2, bad)
    assert step.action == "fallback"
    assert step.reason == "cut-not-on-boundary"
    assert step.history is history


def test_loop_undetermined_passes_through_without_state():
    step = C.compact(_history(1), "", None)
    assert step.action == "passthrough"


# --- size + reconstruction helpers ----------------------------------------

def test_payload_chars_counts_text_and_tool_args():
    msg = {"parts": [
        {"part_kind": "user-prompt", "content": "abcd"},
        {"part_kind": "tool-call", "tool_name": "bash", "args": {"command": "ls"}},
    ]}
    assert C.payload_chars(msg) == 4 + 4 + len('{"command": "ls"}')


def test_apply_writes_write_then_edit():
    text = C.apply_writes("", {"parts": [
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
