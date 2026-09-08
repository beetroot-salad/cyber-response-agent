"""#986 M3 — the container-identity lesson must reach a record that carries a container ID.

O4 (operator): `defender/lessons/container-identity-gap-not-terminal.md` can reach a run whose
record carries a container id and no container name. Observed failing today: frontier replay
against the baseline record returns the lesson absent from the pushed set.

The lesson-side reason, from the design's own probes:

  * `_best_match` (`scripts/lessons/lessons_frontier.py:472`) pairs `frontier_nodes` with the
    frontier's OPEN slots and `observed_nodes` with its SETTLED cells (C7);
  * `is_ident_open("soc-playground")` is `False` (C6) — a concrete ident is never an open slot;
  * the lesson's only selector is `frontier_nodes: [{type: compute, slot: ident}]`, so once
    the prologue names any host the lesson is on the wrong lane and cannot fire.

M3 keeps that selector and adds three `observed_nodes` selectors for the settled cells the
census (C8) found the container id in: `{type: process, slot: attrs.container}`,
`{type: compute, slot: attrs.container}`, `{type: compute, slot: attrs.container_id}`.

WHAT THIS FILE DRIVES, AND WHAT THAT DOES AND DOES NOT PROVE.

  * The lesson under test is the REAL shipped corpus file — `defender/lessons/`, not a
    `_write_lesson` fixture — because O4 is about whether the artefact in the tree can reach a
    real-shaped document, which a fixture lesson written to suit the assertion cannot answer.
    (`test_frontier_recall_919.py::test_the_shipped_corpus_reaches_the_motivating_investigation`
    is the same idiom, one lesson over.)
  * The DOCUMENTS are hand-built here, not replayed. `.defender-runs/` is gitignored and does
    not exist in a fresh checkout, so the nine runs are not available as checked-in fixtures.
    Each fixture below is one census row's shape written by hand, carrying exactly the one cell
    under test, and `test_the_fixture_documents_carry_no_invlang_fault` re-asserts on every run
    that all of them still parse and validate clean — an empty frontier is the correct answer
    for a malformed document, so a fixture that quietly stopped parsing would make every
    negative half of this file pass against a do-nothing implementation.
  * `source_signature` IS NOT GATING ON THIS LANE and these tests therefore say nothing about
    it. `match_lessons` takes a frontier and a corpus and never reads `source_signature`; the
    signature grep is the OTHER retrieval (`runtime/orient.py:101`, `defender-lessons
    "source_signature:.*<rule.id>"`), which runs once at PLAN time. This lesson declares
    `source_signature: [v2-falco-suspicious-network-tool]` while #986's alert is
    `v2-off-hours-sudo`, so the PLAN-time lane cannot reach it on this alert and M3 does not
    change that. What is pinned here is the frontier lane only — which is the lane O4 names
    ("frontier replay ... absent from the pushed set").

Nothing here asserts the lesson's frontmatter has a field. A selector is a claim about which
documents the lesson reaches, so every test below asks `match_lessons` for the answer.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))

pytest.importorskip("pydantic_ai")

#: The shipped corpus, and the lesson in it this file is about.
CORPUS = DEFENDER / "lessons"
LESSON = "container-identity-gap-not-terminal"

#: Wider than the shipped `top_k` (3), for the two NEGATIVES and the O5 regression only. A
#: negative asserted at `top_k=3` would also pass when the lesson matched and was merely
#: out-ranked, which is not the claim; and the regression's claim is that the existing selector
#: still FIRES, which must not turn red the day a sixteenth lesson out-ranks it.
ALL_HITS = 99


# drivers — imported inside the bodies so this file collects on a tree without the M3 edit


def _frontier(text: str):
    from defender.skills.invlang.frontier import frontier_from_text

    return frontier_from_text(text)


def _recall(text: str, *, top_k: int | None = None) -> list[str]:
    from defender.scripts.lessons import lessons_frontier

    kw = {} if top_k is None else {"top_k": top_k}
    return [h.name for h in lessons_frontier.match_lessons(_frontier(text), CORPUS, **kw)]


def _doc(*vertex_rows: str) -> str:
    """One invlang companion: the given `:V` rows plus a lead, and nothing else open.

    The lead block is there so the document is a plausible record rather than a bare vertex
    table; it contributes nothing to the node axis."""
    return (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        + "\n".join(vertex_rows)
        + "\n\n:L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-host-lookup|v-001||cmdb|n/a\n"
        "```\n"
    )


#: The alerted Docker host and the privileged identity, as ORIENT honestly wrote them: the
#: alert envelope names only `soc-playground` (C1), so the host's `ident` is SETTLED and every
#: fixture below inherits that fact. This is the whole reason the shipped `frontier_nodes`
#: selector is dark on these records.
HOST = "v-001|compute|container-host/internal/known-corp|soc-playground|os=linux"
ROOT = "v-002|identity|user/known-corp|root|uid=0"

#: Census C8's three settled shapes, one document each, each carrying the container id in
#: exactly ONE cell — so a partial M3 (one selector of the three) fails on the other two.
PROCESS_ATTR = _doc(HOST, ROOT, "v-003|process|bash|bash[pid=4242]|container=e5b0213bd690")
HOST_ATTR = _doc(
    "v-001|compute|container-host/internal/known-corp|soc-playground|os=linux;container=e5b0213bd690",
    ROOT,
)
HOST_ID_ATTR = _doc(
    "v-001|compute|container-host/internal/known-corp|soc-playground|"
    "os=linux;container_id=e5b0213bd690",
    ROOT,
)

#: The CEILING (t1, t2, t7): the container is a fully attributed second vertex whose OWN
#: `ident` is the container id. Nothing on the record spells `container` as an attribute name,
#: and the ident is settled, so neither lane has a cell to key on.
IDENT_IS_THE_ID = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|e5b0213bd690|kind=container"
)
#: The ceiling document's paired positive: the same record, plus the census cell M3 covers.
IDENT_IS_THE_ID_PLUS_ATTR = _doc(
    HOST,
    ROOT,
    "v-005|compute|database-server/internal/novel|e5b0213bd690|kind=container;container_id=e5b0213bd690",
)

#: t5/t8's shape: the resolved NAME parked in an attribute. O4 is about a record carrying a
#: container id and NO container name, and M3's selector list stops at the three id-bearing
#: cells, so this document is out of scope for the lesson.
NAME_ATTR = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|db-1|kind=container;container_name=db-1"
)
#: Its paired positive: the same record once an id-bearing cell is present too.
NAME_ATTR_PLUS_ID = _doc(
    HOST,
    ROOT,
    "v-005|compute|database-server/internal/novel|db-1|"
    "kind=container;container_name=db-1;container=e5b0213bd690",
)

#: The shape the SHIPPED selector is right for and must keep reaching (O5): a container
#: declared with an open ident.
OPEN_CONTAINER_IDENT = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|??|kind=container"
)

_FIXTURES = {
    "process attrs.container": PROCESS_ATTR,
    "compute attrs.container": HOST_ATTR,
    "compute attrs.container_id": HOST_ID_ATTR,
    "ident is the id": IDENT_IS_THE_ID,
    "ident is the id + attr": IDENT_IS_THE_ID_PLUS_ATTR,
    "attrs.container_name": NAME_ATTR,
    "attrs.container_name + id": NAME_ATTR_PLUS_ID,
    "open container ident": OPEN_CONTAINER_IDENT,
}


def test_the_fixture_documents_carry_no_invlang_fault():
    """Guards every document in this file.

    Each was EXECUTED against the real `diagnose` while this file was written and carried zero
    diagnostics. Re-asserted here because a fixture that stopped parsing derives an EMPTY
    frontier, and an empty frontier retrieves nothing — which would green both negatives and
    the ceiling test against an implementation that does nothing at all. The non-empty check is
    the second half of the same guard."""
    from defender.skills.invlang.validate import diagnose

    for label, doc in _FIXTURES.items():
        assert diagnose(doc, None) == [], f"{label}: fixture is not a clean invlang document"
        f = _frontier(doc)
        assert not f.is_empty(), f"{label}: fixture derives an empty frontier"


# O4 — the three settled cells the census found the container id in


@pytest.mark.parametrize(
    "label",
    ["process attrs.container", "compute attrs.container", "compute attrs.container_id"],
)
def test_the_shipped_lesson_reaches_a_record_carrying_the_container_id(label):
    """CLAIM: on a record whose only trace of the container is a settled id cell, the shipped
    container-identity lesson is in the pushed set.

    Asserted at the SHIPPED `top_k` (3), not at a widened one, because O4's failing observation
    is stated in those terms: "the lesson absent from the pushed set". Parametrised over the
    three cells separately so an M3 that adds one selector of three is caught on the other two —
    one document per cell, each carrying exactly that cell and no other container trace."""
    assert LESSON in _recall(_FIXTURES[label]), (
        f"{label}: the container-identity lesson is not retrieved on a record that carries the "
        "container id in this cell"
    )


# the recorded bound, and the shape M3 deliberately does not cover


def test_the_container_id_written_as_the_vertexs_own_ident_is_still_not_reached():
    """CLAIM: a record that spells the container id as the container vertex's OWN `ident` does
    not retrieve the lesson, even after M3.

    THIS IS A RECORDED BOUND, NOT A DEFECT. The design states it: t1, t2 and t7 wrote the id
    that way and "are not reached, because the matcher cannot express 'ident looks like an id'".
    A settled ident is invisible to `frontier_nodes` (C6) and `observed_nodes` has no selector
    that could tell `e5b0213bd690` from `db-1` in an `ident` cell — a `{type: compute, slot:
    ident}` observed selector would fire on every named host in every record ever written.

    Pinned so nobody later reads M3 as covering more than it does, and asserted at `top_k=99`
    so it is about the lesson not MATCHING rather than about it being out-ranked. The paired
    positive is the same record with one census cell added, which must retrieve — without it
    this test would also pass on a corpus where the lesson was deleted."""
    assert LESSON not in _recall(IDENT_IS_THE_ID, top_k=ALL_HITS), (
        "the selector-only fix reached the ident shape — either a selector now matches every "
        "named host, or this recorded ceiling has been closed and this test needs rewriting "
        "against whatever closed it"
    )
    assert LESSON in _recall(IDENT_IS_THE_ID_PLUS_ATTR), (
        "positive control on the same record: adding the census cell must retrieve the lesson"
    )


def test_a_resolved_container_name_in_an_attribute_does_not_by_itself_retrieve_the_lesson():
    """CLAIM: `attrs.container_name` (t5, t8) is not one of M3's selectors.

    O4 names "a record that carries a container id and NO container name", and M3 enumerates
    exactly three cells, all of which hold an ID. A record whose attribute already holds the
    resolved NAME has answered the question this lesson asks, and a fourth selector for it would
    push the lesson at runs that do not need it.

    This pins the design's enumeration. If a later decision adds a `container_name` selector,
    this test is the place that records the change — it is not load-bearing on the mechanism.
    Paired with the same record once an id cell is present, so it cannot pass by the lesson
    being unreachable in general."""
    assert LESSON not in _recall(NAME_ATTR, top_k=ALL_HITS), (
        "an attribute holding the resolved NAME retrieved the identity-gap lesson"
    )
    assert LESSON in _recall(NAME_ATTR_PLUS_ID), (
        "positive control on the same record: the id-bearing cell must retrieve the lesson"
    )


# O5 — the selector M3 keeps


def test_the_shipped_open_ident_selector_still_fires():
    """CLAIM (O5): M3 ADDS a lane; it does not move the lesson off the one it has.

    `frontier_nodes: [{type: compute, slot: ident}]` is right for a container declared with an
    unresolved ident, and that shape is the one the lesson was authored from. An M3 that
    replaced the selector rather than adding to it would pass every O4 test above and silently
    lose this.

    GREEN TODAY, deliberately — this is the regression half of the spec, and O5's whole content
    is that nothing already working goes red. Driven at `top_k=99` because the claim is that the
    selector MATCHES, which must not become a claim about how it ranks against a corpus that
    keeps growing."""
    assert LESSON in _recall(OPEN_CONTAINER_IDENT, top_k=ALL_HITS), (
        "the open-ident selector no longer reaches a container declared with an unresolved ident"
    )
