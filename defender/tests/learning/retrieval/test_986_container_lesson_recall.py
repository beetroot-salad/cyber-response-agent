"""The shipped container-identity lesson reaches records carrying a container id (frontier lane)."""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[3]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))


from defender.tests.support.shared._pre_p4_shipped import LESSONS as SHIPPED_LESSONS  # noqa: E402

#: The shipped corpus, and the lesson in it this file is about. #1108 P4 (O1, O-U5): lessons
#: are tenant knowledge and the product tree ships none; the corpus this repo shipped before P4
#: is kept byte for byte as a test fixture, so the recall engine is still pinned against it.
CORPUS = SHIPPED_LESSONS
LESSON = "container-identity-gap-not-terminal"

ALL_HITS = 99


# drivers — imported inside the bodies so this file collects on a tree without the M3 edit


def _frontier(text: str):
    from defender.skills.invlang.frontier import frontier_from_text

    return frontier_from_text(text)


@lru_cache(maxsize=1)
def _lessons() -> tuple:
    """The REAL shipped corpus, parsed ONCE for this module."""
    from defender.knowledge._corpus import iter_lessons

    return tuple(iter_lessons(CORPUS))


def _recall(text: str, *, top_k: int | None = None) -> list[str]:
    from defender.investigation.lessons_engine import lessons_frontier

    kw = {} if top_k is None else {"top_k": top_k}
    return [
        h.name
        for h in lessons_frontier.match_loaded(_frontier(text), list(_lessons()), **kw)
    ]


def _doc(*vertex_rows: str) -> str:
    """One invlang companion: the given `:V` rows plus a lead, and nothing else open."""
    return (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        + "\n".join(vertex_rows)
        + "\n\n:L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-host-lookup|v-001||cmdb|n/a\n"
        "```\n"
    )


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

IDENT_IS_THE_ID = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|e5b0213bd690|kind=container"
)
#: The ceiling document's paired positive: the same record, plus the census cell M3 covers.
IDENT_IS_THE_ID_PLUS_ATTR = _doc(
    HOST,
    ROOT,
    "v-005|compute|database-server/internal/novel|e5b0213bd690|kind=container;container_id=e5b0213bd690",
)

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
    """Guards every document in this file."""
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
    """CLAIM: on a record whose only trace of the container is a settled id cell, the shipped container-identity..."""
    assert LESSON in _recall(_FIXTURES[label]), (
        f"{label}: the container-identity lesson is not retrieved on a record that carries the "
        "container id in this cell"
    )


# the recorded bound, and the shape M3 deliberately does not cover


def test_the_container_id_written_as_the_vertexs_own_ident_is_still_not_reached():
    """CLAIM: a record that spells the container id as the container vertex's OWN `ident` does not retrieve the..."""
    assert LESSON not in _recall(IDENT_IS_THE_ID, top_k=ALL_HITS), (
        "the selector-only fix reached the ident shape — either a selector now matches every "
        "named host, or this recorded ceiling has been closed and this test needs rewriting "
        "against whatever closed it"
    )
    assert LESSON in _recall(IDENT_IS_THE_ID_PLUS_ATTR), (
        "positive control on the same record: adding the census cell must retrieve the lesson"
    )


def test_a_resolved_container_name_in_an_attribute_does_not_by_itself_retrieve_the_lesson():
    """CLAIM: `attrs.container_name` (t5, t8) is not one of M3's selectors."""
    assert LESSON not in _recall(NAME_ATTR, top_k=ALL_HITS), (
        "an attribute holding the resolved NAME retrieved the identity-gap lesson"
    )
    assert LESSON in _recall(NAME_ATTR_PLUS_ID), (
        "positive control on the same record: the id-bearing cell must retrieve the lesson"
    )


# O5 — the selector M3 keeps


def test_the_shipped_open_ident_selector_still_fires():
    """CLAIM (O5): M3 ADDS a lane; it does not move the lesson off the one it has."""
    assert LESSON in _recall(OPEN_CONTAINER_IDENT, top_k=ALL_HITS), (
        "the open-ident selector no longer reaches a container declared with an unresolved ident"
    )


# ADVERSARY-CLOSED (#986 red-team pass). Below this line: holes where an edit to the shipped
# lesson greened everything above while changing what the lesson is or where it can be reached.


PROCESS_ATTR_OTHER_CLASS = _doc(
    HOST, ROOT, "v-003|process|sudo|sudo[pid=4242]|container=e5b0213bd690"
)
_FIXTURES["process attrs.container, other class"] = PROCESS_ATTR_OTHER_CLASS


def test_the_process_selector_is_not_scoped_to_one_process_class():
    """CLAIM: the process selector fires on the CELL, whatever the process is."""
    assert LESSON in _recall(PROCESS_ATTR_OTHER_CLASS), (
        "the lesson missed a container id on a `sudo` process while reaching the same cell on "
        "a `bash` one — the selector is scoped to a class M3 does not name"
    )


def _lesson():
    """The shipped lesson as PRODUCTION reads it."""
    return next(le for le in _lessons() if le.path.stem == LESSON)


