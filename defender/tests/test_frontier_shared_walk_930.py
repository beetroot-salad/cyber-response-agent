"""#919 / PR-930 — one node-axis walk under both readers, and the frontier at block N.

Two changes, one theme: the frontier stops being a second opinion about the document.

**The shared walk.** `validate.iter_vertex_cells` is now THE node-axis walk. The
benign-disposition gate (`_check_benign_open_slots`) and lesson retrieval
(`frontier._node_state`) both read it, where before they were two loops over
`effective_vertex_state` that agreed only by inspection. The contract axis had already been
collapsed this way (`_open_contracts` calls `outstanding_authz_contracts`); this is the other
half.

The point is NOT that the two readers now behave identically — they must not, and #836 decided
why. It is that their two documented divergences become explicit knobs rather than two
implementations free to drift:

  * `include_ident` — a parameter. The gate passes False (an `ident=??` must not block a benign
    close, #836 N3); retrieval passes True.
  * the edge-targeted refinement — NOT a parameter. The walk reports those cells because the
    gate blocks on them; `_node_state` drops them because an `OpenSlot` needs a vertex type an
    `:E` row has not got. Both halves are pinned below, from both sides, because a future
    "cleanup" that moves either one is exactly the regression this file exists to catch.

**`frontier_at(text, n)`.** The retrieval key a lesson should carry is the frontier at the
moment the pitfall was live, not at the moment the run closed. Measured on the runs in hand, a
terminal document holds ~2 open slots against ~21 held facts while the same document a few
blocks earlier holds 6 against 7 — the first is barely a key. Under the turn-N branch
(`docs/learning-architecture-redesign.md`) a finding is born at a branch point, and this is how
that state is read back.

`n` counts ```invlang FENCES, not messages, because the frontier only moves when a block lands.
That makes the index coarse, and the coarseness is reported rather than hidden: an out-of-range
`n` snaps and `snapped` says so, because a curator handed the terminal frontier for a block that
does not exist has been handed the one state that keys nothing.

Out of scope here: the curator-facing verb that maps a run's message index onto a fence index
(that needs the run's trace, which is `learning/`'s business, not invlang's), and any change to
what `_frontier_recall` emits at runtime.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

pytest.importorskip("pydantic_ai")

from defender._artifact_schema import validate_investigation  # noqa: E402
from defender.skills.invlang import frontier as frontier_mod  # noqa: E402
from defender.skills.invlang.frontier import (  # noqa: E402
    derive_frontier,
    frontier_at,
)
from defender.skills.invlang.parser import parse_dense_companion  # noqa: E402
from defender.skills.invlang.validate import (  # noqa: E402
    CELL_EMPTY,
    CELL_HELD,
    CELL_OPEN,
    _check_benign_open_slots,
    diagnose,
    iter_vertex_cells,
)
from defender.tests._invlang_warn_836 import (  # noqa: E402
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
)

# --------------------------------------------------------------------------- #
# fixtures
#
# Every document below was EXECUTED against the real `diagnose` while this file was written and
# carries ZERO diagnostics; `test_the_fixture_documents_carry_no_invlang_fault` re-asserts it on
# every run. An empty frontier is the honest answer for an unparseable document, so a fixture
# that quietly failed to parse would let a do-nothing implementation pass half this file.
# --------------------------------------------------------------------------- #

#: One observed edge, so a `:R attr_updates` row has a legal EDGE target to name. `diagnose`
#: accepts a refinement targeting `e-001` (`_check_attr_update_targets`), which is the whole
#: reason the divergence below exists rather than being a parse error nobody has to decide.
EDGE_BLOCK = """
```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed
```
"""

#: A `process` vertex whose IDENT CELL IS BLANK — not `??`, absent. The three-state fixture:
#: `''` is neither a question the run has open nor a fact it holds, and an implementation that
#: classified cells with one bool would have to call it one or the other.
BLANK_IDENT_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-008|process|nc||image=/usr/bin/nc
```
"""

#: A `process` vertex with an open CLASS cell, and the refinement that closes it. Together they
#: are the prefix/terminal contrast `frontier_at` exists for: open at one block index, settled
#: at the next.
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


def test_the_fixture_documents_carry_no_invlang_fault():
    """Fixture hygiene: every document above parses clean, so a failure below is the code."""
    for name, doc in _FIXTURE_DOCS.items():
        assert diagnose(doc) == [], f"fixture {name!r} carries a diagnostic"


# --------------------------------------------------------------------------- #
# the shared walk
# --------------------------------------------------------------------------- #

def test_the_gate_and_the_frontier_read_one_walk():
    """CLAIM: both readers CALL `iter_vertex_cells` rather than re-deriving the node axis.

    Structural, and deliberately so. Every behavioral assertion in this file would still pass
    against two loops that happen to agree today — which is the state PR-930 replaced, and the
    state they drifted out of twice already. The thing being protected is that there is one
    definition, so it is the thing asserted."""
    for reader in (_check_benign_open_slots, frontier_mod._node_state):
        src = inspect.getsource(reader)
        assert "iter_vertex_cells" in src, (
            f"{reader.__qualname__} no longer reads the shared walk"
        )
        assert "effective_vertex_state(" not in src, (
            f"{reader.__qualname__} re-derives the fold instead of reading the shared walk"
        )


def test_a_blank_cell_is_neither_open_nor_held():
    """CLAIM: cells are three-state, and the third state is not a rounding error.

    `is_unresolved("")` is False by design (`_apply_attr_updates` records why: a blank value
    cell must never read as a RESOLUTION), so a two-state classifier has to call an absent
    identifier something. Calling it held would report every cell a vertex never carried as a
    fact the run KNOWS, and `HeldFact` is retrieval input — `observed_nodes` selectors would
    start matching on emptiness."""
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
    """CLAIM: the ident asymmetry is one flag on one walk, and still asymmetric.

    #836 N3 routes `ident` to its own top-level slot precisely so an unresolved identifier does
    not block a benign close; #919 wants it because an unpinned identifier is the most
    retrieval-worthy open slot there is. Both readings survive the merge, and the flag is where
    the disagreement now lives."""
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


def test_an_edge_targeted_refinement_blocks_the_gate_and_is_dropped_by_the_frontier():
    """CLAIM: the second divergence is unchanged, and it is a `_node_state` filter — not a knob.

    A `:R attr_updates` row may legally name an `:E` id. The gate blocks on the resulting open
    cell and must keep doing so, so the shared walk has to REPORT it; the frontier drops it
    because an `OpenSlot` carries a vertex `type` for a selector to match and an edge has none.
    So an authz question opened on an edge attribute recalls nothing — a known limitation, and
    the reason the filter cannot be pushed down into the walk where it would silently narrow
    the gate."""
    doc = _FIXTURE_DOCS["edge target"]
    body, _warnings = parse_dense_companion(doc)

    assert [(c.vertex_id, c.slot) for c in iter_vertex_cells(body, include_ident=False)
            if c.is_open] == [("e-001", "attrs.auth_method")], "the walk stopped reporting it"

    blocked = _check_benign_open_slots(body)
    assert len(blocked) == 1
    assert "e-001" in blocked[0]
    assert "benign blocked" in (validate_investigation(doc + CONCLUDE_BENIGN, None) or "")

    assert derive_frontier(body).slots == (), "an edge cell reached the retrieval key"


def test_the_walk_reports_cells_in_document_order_class_ident_attrs():
    """CLAIM: order is part of the contract, because both readers spend it.

    The gate's diagnostics are read in emission order by an operator, and `_node_state` builds
    two ordered lists a ranking later walks. A walk that reordered cells would leave every
    membership assertion in this file green and still change what a human sees first."""
    doc = PROLOGUE + BLANK_IDENT_BLOCK
    assert [(c.vertex_id, c.slot) for c in _cells(doc)] == [
        ("v-001", "class"), ("v-001", "ident"), ("v-001", "attrs.kind"),
        ("v-002", "class"), ("v-002", "ident"),
        ("v-008", "class"), ("v-008", "ident"), ("v-008", "attrs.image"),
    ]


def test_the_open_cells_are_exactly_what_the_gate_refuses_on():
    """CLAIM: the gate blocks on the open cells and on nothing else — one message per cell.

    The join this pins is the one a refactor breaks silently: a gate that filtered on its own
    predicate rather than on `cell.is_open` would pass every other test here."""
    doc = PROLOGUE + OPEN_CLASS_BLOCK + BLANK_IDENT_BLOCK
    body, _warnings = parse_dense_companion(doc)
    open_ids = [c.vertex_id for c in iter_vertex_cells(body, include_ident=False) if c.is_open]
    errors = _check_benign_open_slots(body)
    assert open_ids == ["v-006"]
    assert len(errors) == len(open_ids)
    assert "v-006" in errors[0]
    assert all(c.state in (CELL_OPEN, CELL_HELD, CELL_EMPTY)
               for c in iter_vertex_cells(body, include_ident=True))


# --------------------------------------------------------------------------- #
# frontier_at
# --------------------------------------------------------------------------- #

def test_the_prefix_frontier_is_where_the_key_lives():
    """CLAIM: the motivating contrast — a slot open at one block index and gone at the next.

    This is the whole argument for indexing at all. `REFINED_DOC` closes `v-006`'s class in its
    third block, so the terminal frontier a finding-time dump would capture has nothing to key
    on, while the frontier one block earlier carries the open class the lesson is about."""
    at_open = frontier_at(REFINED_DOC, 2)
    at_closed = frontier_at(REFINED_DOC, 3)

    assert [(s.vertex_id, s.slot) for s in at_open.frontier.slots] == [("v-006", "class")]
    assert at_closed.frontier.slots == ()
    assert ("v-006", "class") in [(h.vertex_id, h.slot) for h in at_closed.frontier.held]


def test_the_terminal_index_is_the_whole_document():
    """CLAIM: `frontier_at` at `total` is `derive_frontier` over the full parse — the prefix
    machinery adds an index, it does not add a second reading of the document."""
    total = frontier_at(REFINED_DOC, 0).total
    assert total == 3
    body, _warnings = parse_dense_companion(REFINED_DOC)
    assert frontier_at(REFINED_DOC, total).frontier == derive_frontier(body)


def test_index_zero_is_the_empty_frontier():
    """CLAIM: before any block landed, nothing is open and nothing is held. Not an error —
    it is the state a run starts in, and the honest answer for a document with no fences."""
    assert frontier_at(REFINED_DOC, 0).frontier.is_empty()

    fenceless = frontier_at("prose, and no invlang anywhere", 2)
    assert fenceless.total == 0
    assert fenceless.n == 0
    assert fenceless.frontier.is_empty()


@pytest.mark.parametrize(("requested", "expected"), [(99, 3), (4, 3), (-5, 0)])
def test_an_out_of_range_index_snaps_and_says_so(requested, expected):
    """CLAIM: out-of-range clamps, and the result reports that it did.

    The failure to avoid is silent, not loud. A curator who asks for block 12 of a 3-block
    document and is quietly handed the terminal frontier gets the one state that keys nothing,
    with no signal distinguishing it from a real answer — so `requested` is carried alongside
    `n` and `snapped` is their disagreement."""
    result = frontier_at(REFINED_DOC, requested)
    assert result.n == expected
    assert result.requested == requested
    assert result.snapped is True
    assert frontier_at(REFINED_DOC, 3).snapped is False


def test_prose_between_blocks_cannot_change_the_answer():
    """CLAIM: the prefix is rebuilt from fence bodies, so analyst prose between two blocks is
    inert. `parse_dense_companion` already ignores it; this pins that `frontier_at` does not
    reintroduce a dependency on it by slicing the raw text instead."""
    prosed = (PROLOGUE + "\n\nWorking hypothesis: the source IP is a scanner.\n\n"
              + OPEN_CLASS_BLOCK + "\n\nStill unresolved.\n\n" + attr_block(CLOSE_CLASS_ROW))
    for n in range(0, 4):
        assert frontier_at(prosed, n).frontier == frontier_at(REFINED_DOC, n).frontier


def test_the_recall_fast_path_sees_a_delimiter_that_straddles_the_seam():
    """CLAIM: `_frontier_recall`'s no-new-fence fast path cannot skip an append that MOVED the
    frontier.

    The gate exists because `parse_dense_companion` reads only ```invlang fences, so an append
    adding no delimiter cannot change the parse. That is true of the appended TEXT and false of
    the appended SLICE: a document ending in a truncated ``` and an append supplying the last
    backtick closes a fence whose slice holds no delimiter at all. Pinned with the real
    predicate rather than by driving the tool, because the bug is the window, not the plumbing."""
    from defender.skills.invlang.frontier import frontier_from_text

    before = ("```invlang\n"
              ":V prologue.vertices [id|type|class|ident|attrs?]\n"
              "v-001|compute|??|x|\n"
              "``")
    after = before + "`"
    assert frontier_from_text(before) != frontier_from_text(after), "fixture stopped moving"

    skips = bool(before) and after.startswith(before) and "```" not in after[max(0, len(before) - 2):]
    assert not skips, "the fast path skipped an append that closed a fence"


def test_frontier_at_never_raises():
    """CLAIM: it inherits `frontier_from_text`'s guarantee. Its callers run against documents a
    model is still writing, and a half-written block must not turn into a failed tool call on a
    write that already landed."""
    for text in ("", "```invlang\n:V bogus [nope\n|||||\n```", "```invlang\n```"):
        result = frontier_at(text, 1)
        assert result.frontier.is_empty()
