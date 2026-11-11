"""#1278 r8 "Not stored": a PR's review and comment text is read live and handed to the curator, and persisted nowhere in
`learning.*`. Every feedback path is scanned after, for every text source it reads."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.core._feedback1278 import FeedbackCurator, make_scene, opened, tick
from defender.tests.support.learning.core._store1278 import lesson_citing
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_delivery._support import close_on_remote, comment_row, review_row
from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME

pytestmark = pytest.mark.postgres

WORDS = "zq-review-words-8f31"

#: Where review text can come from, as the forge serves it (id offsets keep rows distinct).
SOURCES = {
    "request-changes-review-body": lambda: ([review_row(801, "owner", "REQUEST_CHANGES", body=WORDS)], []),
    "comment-review-body": lambda: ([review_row(802, "owner", "COMMENT", body=WORDS)], []),
    "approval-review-body": lambda: ([review_row(803, "owner", "APPROVED", body=WORDS)], []),
    "plain-comment": lambda: ([], [comment_row(804, "analyst", WORDS)]),
}
#: Every path that reads feedback: (closes the PR first, curator authors something, sources it applies to).
#: An open PR is acted on only by a live changes-requested review (H7); the other sources are no feedback there.
PATHS = {
    "closed-then-replaced": (True, True, tuple(SOURCES)),
    "closed-then-replacement-commits-nothing": (True, False, tuple(SOURCES)),
    "open-with-live-changes-requested": (False, True, ("request-changes-review-body",)),
}
CELLS = [(path, source) for path, (_c, _a, sources) in PATHS.items() for source in sources]


@pytest.fixture
def world(p4_tenant, migrated_database, monkeypatch, tmp_path):  # noqa: F811 — the imported fixture
    scene = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    scene.t.forge.scopes = {"write:repository", "read:issue"}
    return scene


@pytest.mark.parametrize(("path", "source"), CELLS, ids=[f"{p}--{s}" for p, s in CELLS])
def test_review_text_is_never_stored_whichever_path_reads_it_from_whichever_source(world, caplog, path, source):
    """After the ticks, no `learning.*` row holds the words, though the curator was handed them. (r8 Not stored)"""
    closes, authors, _sources = PATHS[path]
    w = world
    w.seed("f1")
    files = {f"lessons/{LESSON_NAME}": lesson_citing("f1")}
    writer = FeedbackCurator(files)
    _batch, branch, number = opened(w, writer, caplog)
    w.t.forge.reviews[number], w.t.forge.comments[number] = SOURCES[source]()
    if closes:
        close_on_remote(w.t.p3, branch)
    curator = FeedbackCurator(files) if authors else FeedbackCurator()
    tick(w, curator)
    tick(w, curator)

    stored = w.stored_text()
    assert WORDS not in stored, f"review text from {source} was stored on the {path} path"
    assert WORDS in curator.seen_text(), "control: the words reached the curator, so the scan could have found them"
