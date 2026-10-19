"""One node-axis walk (validate.iter_vertex_cells) under both the benign gate and the frontier, and the document frontier."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

pytest.importorskip("pydantic_ai")

from defender._artifact_schema import validate_investigation  # noqa: E402
from defender.skills.invlang.frontier import (  # noqa: E402
    derive_frontier,
    frontier_from_text,
)
from defender.skills.invlang.parser import parse_dense_companion  # noqa: E402
from defender.skills.invlang.validate import (  # noqa: E402
    CELL_EMPTY,
    CELL_HELD,
    CELL_OPEN,
    _check_benign_open_slots,
    diagnose,
    effective_vertex_state,
    is_ident_open,
    iter_vertex_cells,
)
from defender.tests._invlang_warn_836 import (  # noqa: E402
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
)


EDGE_BLOCK = """
```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed
```
"""

BLANK_IDENT_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-008|process|nc||image=/usr/bin/nc
```
"""

OPEN_CLASS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|??|nc[pid=4242]|image=/usr/bin/nc
```
"""
CLOSE_CLASS_ROW = "l-001|v-006|class|nc"

#: A refinement naming the EDGE. The gate blocks on it; the frontier cannot key on it.
EDGE_TARGET_DOC = PROLOGUE + EDGE_BLOCK + attr_block("l-001|e-001|attrs.auth_method|??")

#: Open at block 2, closed at block 3.
REFINED_DOC = PROLOGUE + OPEN_CLASS_BLOCK + attr_block(CLOSE_CLASS_ROW)

_FIXTURE_DOCS = {
    "edge target": EDGE_TARGET_DOC,
    "blank ident": PROLOGUE + BLANK_IDENT_BLOCK,
    "refined": REFINED_DOC,
}


def _cells(doc: str, *, include_ident: bool = True):
    body, _warnings = parse_dense_companion(doc)
    return list(iter_vertex_cells(body, include_ident=include_ident))


def _frontier(doc: str):
    body, _warnings = parse_dense_companion(doc)
    return derive_frontier(body)


# the shared walk


def test_a_blank_cell_is_neither_open_nor_held():
    """CLAIM: cells are three-state, and the third state is not a rounding error."""
    doc = _FIXTURE_DOCS["blank ident"]
    by_slot = {c.slot: c for c in _cells(doc) if c.vertex_id == "v-008"}

    assert by_slot["ident"].state == CELL_EMPTY
    assert not by_slot["ident"].is_open
    assert not by_slot["ident"].is_held
    assert by_slot["class"].state == CELL_HELD
    assert by_slot["attrs.image"].state == CELL_HELD

    f = _frontier(doc)
    assert not [s for s in f.slots if s.vertex_id == "v-008"]
    assert {h.slot for h in f.held if h.vertex_id == "v-008"} == {"class", "attrs.image"}


def test_include_ident_is_the_gates_divergence_made_a_parameter():
    """CLAIM: the ident asymmetry is one flag on one walk, and still asymmetric."""
    doc = _FIXTURE_DOCS["blank ident"]
    assert not [c for c in _cells(doc, include_ident=False) if c.slot == "ident"]
    assert [c for c in _cells(doc, include_ident=True) if c.slot == "ident"]

    open_ident = PROLOGUE + """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-009|identity|user/known-corp|??|
```
"""
    body, _warnings = parse_dense_companion(open_ident)
    assert _check_benign_open_slots(body) == [], "the shared walk leaked ident into the gate"
    assert validate_investigation(open_ident + CONCLUDE_BENIGN, None) is None
    assert [s.slot for s in derive_frontier(body).slots] == ["ident"]


def test_the_open_cells_are_exactly_what_the_gate_refuses_on():
    """CLAIM: the gate blocks on the open cells and on nothing else — one message per cell."""
    doc = PROLOGUE + OPEN_CLASS_BLOCK + BLANK_IDENT_BLOCK
    body, _warnings = parse_dense_companion(doc)
    open_ids = [c.vertex_id for c in iter_vertex_cells(body, include_ident=False) if c.is_open]
    errors = _check_benign_open_slots(body)
    assert open_ids == ["v-006"]
    assert len(errors) == len(open_ids)
    assert "v-006" in errors[0]
    assert all(c.state in (CELL_OPEN, CELL_HELD, CELL_EMPTY)
               for c in iter_vertex_cells(body, include_ident=True))


def test_the_document_frontier_tracks_open_and_resolved_slots():
    opened = frontier_from_text(PROLOGUE + OPEN_CLASS_BLOCK)
    closed = frontier_from_text(REFINED_DOC)
    assert [(s.vertex_id, s.slot) for s in opened.slots] == [("v-006", "class")]
    assert closed.slots == ()
    assert ("v-006", "class") in [(h.vertex_id, h.slot) for h in closed.held]


def test_prose_between_blocks_cannot_change_the_document_frontier():
    prosed = (PROLOGUE + "\n\nWorking hypothesis: the source IP is a scanner.\n\n"
              + OPEN_CLASS_BLOCK + "\n\nStill unresolved.\n\n" + attr_block(CLOSE_CLASS_ROW))
    assert frontier_from_text(prosed) == frontier_from_text(REFINED_DOC)


def test_the_recall_fast_path_sees_a_delimiter_that_straddles_the_seam(tmp_path):
    """CLAIM: `_frontier_recall`'s no-new-fence fast path cannot skip an append that MOVED the
    frontier, when the closing delimiter STRADDLES the join."""
    from defender.runtime.tools import _frontier_recall
    from defender.skills.invlang.frontier import frontier_from_text
    from defender.tests._lessons_corpus import _main_deps, _write_lesson

    deps, _run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir(parents=True, exist_ok=True)
    _write_lesson(corpus, "straddle-probe", nodes=("type: compute, slot: class",))

    before = ("```invlang\n"
              ":V prologue.vertices [id|type|class|ident|attrs?]\n"
              "v-001|compute|??|x|\n"
              "``")
    after = before + "`"

    # The fixture has to actually move, or a returned "" proves nothing about the gate.
    assert frontier_from_text(before).is_empty(), "fixture: the truncated fence must parse to nothing"
    assert frontier_from_text(after).slots, "fixture: the completed fence must open a slot"

    assert _frontier_recall(deps, before, after), (
        "the fast path skipped an append whose trailing backtick closed a fence"
    )


def _reobservation_doc(*rows: str) -> str:
    """`v-001` declared in the prologue and re-declared once per lead — one `:V` row each."""
    leads = "\n".join(
        f"l-{i:03d}|{i}|reobserve|v-001||cmdb|n/a" for i in range(1, len(rows))
    )
    blocks = [
        "```invlang\n:V prologue.vertices [id|type|class|ident|attrs?]\n" + rows[0]
        + ("\n\n:L findings [id|loop|name|target|tests|system|window]\n" + leads if leads else "")
        + "\n```"
    ]
    blocks += [
        f"```invlang\n:V l-{i:03d}.observations.vertices "
        f"[id|type|class|ident|attrs?]\n{row}\n```"
        for i, row in enumerate(rows[1:], start=1)
    ]
    return "\n\n".join(blocks) + "\n"


def _reobserved(*rows: str) -> dict:
    """The folded state of `v-001` over `_reobservation_doc`, fixture hygiene asserted."""
    doc = _reobservation_doc(*rows)
    assert diagnose(doc) == [], f"fixture carries a diagnostic:\n{doc}"
    body, _warnings = parse_dense_companion(doc)
    return effective_vertex_state(body)["v-001"]


def test_a_candidate_set_ident_is_open_and_a_later_concrete_name_supersedes_it():
    """CLAIM: `ident` reads the SAME two open markers every other cell does."""
    assert is_ident_open("{dev-ws-1, dev-ws-2}"), "a candidate-set ident read as settled"
    assert is_ident_open("{dev-ws-1"), "an unterminated candidate set read as settled"

    row = "v-001|compute|ip-only/internet/novel|{ident}|"
    assert _reobserved(
        row.format(ident="??"), row.format(ident="{dev-ws-1, dev-ws-2}"),
    )["identifier"] == "{dev-ws-1, dev-ws-2}", "the candidate set did not supersede `??`"
    assert _reobserved(
        row.format(ident="??"),
        row.format(ident="{dev-ws-1, dev-ws-2}"),
        row.format(ident="dev-ws-1"),
    )["identifier"] == "dev-ws-1", "the run named the host and the fold kept the candidate set"


def test_a_blank_cell_takes_a_later_value_that_is_itself_still_partly_open():
    """CLAIM: the blank arm keys on what is HELD, not on what is arriving."""
    partly_open = _reobserved(
        "v-001|process|bash||kind=child", "v-001|process|bash|bash[pid=??]|",
    )
    assert partly_open["identifier"] == "bash[pid=??]", "a blank ident refused a partial name"

    blank_class = _reobserved(
        "v-001|compute|||knowledge=partial",
        "v-001|compute|bastion/internal/known-corp|jump-box-1|",
    )
    assert blank_class["classification"] == "bastion/internal/known-corp", (
        "a blank class cell refused the class a later observation supplied"
    )


def test_a_blank_class_still_refuses_an_open_one_so_the_benign_gate_cannot_move():
    """CLAIM: the class arm supersedes toward SETTLED only — the direction the gate cares about."""
    doc_rows = ("v-001|compute|||knowledge=partial", "v-001|compute|??/??/??|jump-box-1|")
    assert _reobserved(*doc_rows)["classification"] == "", (
        "an unresolved class superseded a blank one and can now block a benign close"
    )

    body, _warnings = parse_dense_companion(_reobservation_doc(*doc_rows))
    assert _check_benign_open_slots(body) == []
