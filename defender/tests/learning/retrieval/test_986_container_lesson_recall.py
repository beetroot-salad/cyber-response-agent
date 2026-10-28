"""The shipped container-identity lesson reaches records carrying a container id (frontier lane)."""
from __future__ import annotations

from functools import lru_cache

import pytest

from defender.investigation.lessons_engine import lessons_frontier
from defender.knowledge._corpus import iter_lessons
from defender.skills.invlang.frontier import frontier_from_text
from defender.skills.invlang.validate import diagnose
from defender.tests.support.shared._pre_p4_shipped import LESSONS as SHIPPED_LESSONS  # noqa: E402

#: The corpus shipped before P4, kept byte for byte as a fixture (the product tree ships no
#: lessons), and the lesson in it this file is about.
CORPUS = SHIPPED_LESSONS
LESSON = "container-identity-gap-not-terminal"

ALL_HITS = 99


# drivers


@lru_cache(maxsize=1)
def _lessons() -> tuple:
    """The real shipped corpus, parsed once for this module."""
    return tuple(iter_lessons(CORPUS))


def _recall(text: str, *, top_k: int | None = None) -> list[str]:
    kw = {} if top_k is None else {"top_k": top_k}
    return [
        h.name
        for h in lessons_frontier.match_loaded(frontier_from_text(text), list(_lessons()), **kw)
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

#: The three settled shapes, each carrying the container id in exactly one cell, so a fix that
#: covers one selector of the three fails on the other two.
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
#: The same cell on another process class.
PROCESS_ATTR_OTHER_CLASS = _doc(
    HOST, ROOT, "v-003|process|sudo|sudo[pid=4242]|container=e5b0213bd690"
)

IDENT_IS_THE_ID = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|e5b0213bd690|kind=container"
)
#: The ceiling document's paired positive: the same record plus a covered cell.
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

#: The shape the original selector is right for and must keep reaching: a container declared
#: with an open ident.
OPEN_CONTAINER_IDENT = _doc(
    HOST, ROOT, "v-005|compute|database-server/internal/novel|??|kind=container"
)

_FIXTURES = {
    "process attrs.container": PROCESS_ATTR,
    "process attrs.container, other class": PROCESS_ATTR_OTHER_CLASS,
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
    for label, doc in _FIXTURES.items():
        assert diagnose(doc, None) == [], f"{label}: fixture is not a clean invlang document"
        f = frontier_from_text(doc)
        assert not f.is_empty(), f"{label}: fixture derives an empty frontier"


# the settled cells that carry the container id


@pytest.mark.parametrize(
    "label",
    ["process attrs.container", "compute attrs.container", "compute attrs.container_id",
     "process attrs.container, other class"],  # last: the selector is not scoped to `bash`
)
def test_the_shipped_lesson_reaches_a_record_carrying_the_container_id(label):
    assert LESSON in _recall(_FIXTURES[label]), (
        f"{label}: the container-identity lesson is not retrieved on a record that carries the "
        "container id in this cell"
    )


# the recorded bound: shapes the selectors deliberately do not cover


def test_the_container_id_written_as_the_vertexs_own_ident_is_still_not_reached():
    assert LESSON not in _recall(IDENT_IS_THE_ID, top_k=ALL_HITS), (
        "the ident shape was reached: a selector matches every named host, or this recorded "
        "ceiling has closed"
    )
    assert LESSON in _recall(IDENT_IS_THE_ID_PLUS_ATTR), (
        "positive control on the same record: adding the census cell must retrieve the lesson"
    )


def test_a_resolved_container_name_in_an_attribute_does_not_by_itself_retrieve_the_lesson():
    assert LESSON not in _recall(NAME_ATTR, top_k=ALL_HITS), (
        "an attribute holding the resolved NAME retrieved the identity-gap lesson"
    )
    assert LESSON in _recall(NAME_ATTR_PLUS_ID), (
        "positive control on the same record: the id-bearing cell must retrieve the lesson"
    )


# the original selector still fires


def test_the_shipped_open_ident_selector_still_fires():
    """The new selectors add a lane; they do not move the lesson off the one it had."""
    assert LESSON in _recall(OPEN_CONTAINER_IDENT, top_k=ALL_HITS), (
        "the open-ident selector no longer reaches a container declared with an unresolved ident"
    )
