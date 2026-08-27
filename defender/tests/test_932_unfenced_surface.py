"""#932 — a block written outside a ```invlang fence is invisible, not merely unchecked.

`INVLANG_FENCE_RE` matches ```invlang ... ``` pairs and the tokenizer reads only what those
pairs enclose, so rows written outside one never become records. Every hypothesis-side rule
then passes on an empty companion, and `_check_append_only` — which counts fence pairs and
refuses a DECREASE — sees none, because the write added no pair rather than removing one.

The shape that cost a run (`live-867-old`): fence opens at `## ORIENT`, closes after the
prologue, prose follows, and `## PLAN` continues with `:H` blocks without reopening. The
document reads correctly to a human and parses to nothing.

Each block below pairs the violation with a LIVENESS CONTROL — the same bytes, fenced —
so a check that stopped running fails here rather than passing vacuously.
"""

from __future__ import annotations

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang import _walkers
from defender.skills.invlang.validate import validate_companion

_PROLOGUE_ROWS = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring/internal/known-corp|172.18.0.15|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|
"""

_PLAN_ROWS = """\
:H hypothesize.hypotheses \
[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.refuts [id|refutes|claim]
r1|p1|"failures are evenly spaced"
"""

#: The baseline every case appends to: prologue fenced and closed, then prose.
_ORIENT_ONLY = f"```invlang\n{_PROLOGUE_ROWS}```\n\nTriage question: is the burst automated?\n"

#: The bug — `## PLAN` and its rows continue after the closed fence, never reopening one.
_UNFENCED_PLAN = f"{_ORIENT_ONLY}\n## PLAN\n\n{_PLAN_ROWS}"

#: The same bytes, fenced. This is the repair the diagnostic asks for.
_FENCED_PLAN = f"{_ORIENT_ONLY}\n## PLAN\n\n```invlang\n{_PLAN_ROWS}```\n"


def _surface_errors(proposed: str, current: str | None = None) -> list[str]:
    return [e for e in validate_companion(proposed, current) if "non-invlang surface" in e]


def test_unfenced_plan_is_refused_against_its_real_baseline() -> None:
    """The append that produced the bug: ORIENT is on disk, this write adds PLAN unfenced."""
    errors = _surface_errors(_UNFENCED_PLAN, _ORIENT_ONLY)
    assert len(errors) == 1
    # The count is what makes the message actionable — every header the write orphaned, not
    # just the first one the scan reached.
    assert "adds 3 block header(s)" in errors[0]
    assert ":H hypothesize.hypotheses" in errors[0]


def test_fenced_plan_is_accepted_and_actually_parses() -> None:
    """LIVENESS CONTROL. Same rows, one fence, and the hypothesis reaches the companion —
    which is the point: acceptance alone would also be satisfied by parsing nothing."""
    assert _surface_errors(_FENCED_PLAN, _ORIENT_ONLY) == []
    companion, _ = parse_dense_companion(_FENCED_PLAN)
    assert sorted(_walkers.all_hypotheses(companion)) == ["h-001"]


def test_unfenced_rows_reach_no_rule_at_all() -> None:
    """Why this is a surface rule and not a per-rule fix. With the PLAN unfenced the
    companion holds no hypothesis, so no hypothesis-side rule has anything to refuse — the
    document is not failing them, it is invisible to them."""
    companion, _ = parse_dense_companion(_UNFENCED_PLAN)
    assert _walkers.all_hypotheses(companion) == {}


def test_a_first_write_has_no_baseline_to_grandfather() -> None:
    """No `current_text` means every unfenced header is introduced by this write."""
    assert len(_surface_errors(_UNFENCED_PLAN)) == 1


def test_committed_unfenced_rows_do_not_wedge_the_next_write() -> None:
    """`investigation.md` is append-only, so bytes already committed unfenced cannot be
    fenced after the fact. Refusing the whole document for them would deny every later write
    with no repair available — the wedge the v2.22 delta closed on rules #6 and #17. The rule
    is scoped to what THIS write introduces, so a clean append onto a broken file lands."""
    followup = (
        f"{_UNFENCED_PLAN}\n```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|burst-cadence|v-001|h-001|elastic|±10m\n```\n"
    )
    assert _surface_errors(followup, _UNFENCED_PLAN) == []


def test_fix_row_style_rewrite_adds_no_header_and_is_not_refused() -> None:
    """The count comparison has to survive a write that is not a pure append. `fix_row`
    rewrites a row in place; it introduces no header, so the counts match and nothing fires."""
    rewritten = _UNFENCED_PLAN.replace(
        '"failures arrive in bursts"', '"failures arrive in bursts within 10s"'
    )
    assert rewritten != _UNFENCED_PLAN
    assert _surface_errors(rewritten, _UNFENCED_PLAN) == []


def test_a_model_cut_off_mid_block_is_not_refused() -> None:
    """The other way a fence goes wrong, and it stays accepted. An unterminated trailing
    ```invlang is a write that stopped mid-block: the next append closes it and the rows
    parse. `test_frontier_recall_919` fixes that shape as accepted-by-design. Only rows
    orphaned AFTER a closed fence are refused, because no later append can reach back and
    wrap bytes already committed."""
    truncated = f"{_ORIENT_ONLY}\n```invlang\n:H hypothesize.hypotheses [id|name|attached_to"
    assert _surface_errors(truncated, _ORIENT_ONLY) == []


def test_the_continuation_that_closes_a_truncated_block_lands() -> None:
    """LIVENESS CONTROL for the exemption: the append that finishes the block is accepted
    too, so the exemption buys the shape it claims to and not just silence."""
    truncated = f"{_ORIENT_ONLY}\n```invlang\n"
    completed = truncated + _PLAN_ROWS + "```\n"
    assert _surface_errors(completed, truncated) == []
    companion, _ = parse_dense_companion(completed)
    assert sorted(_walkers.all_hypotheses(companion)) == ["h-001"]


def test_yaml_fence_still_refused() -> None:
    """The loud half of the same family, unchanged."""
    errors = _surface_errors("```yaml\nhypothesize:\n  hypotheses: []\n```\n")
    assert len(errors) == 1
    assert "```yaml/```yml" in errors[0]
