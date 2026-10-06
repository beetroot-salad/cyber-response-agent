"""#1217 — a queries-table payload sidecar is never written past `_io.READ_LIMIT`.

A host process writes `gather_raw/<lead>/<seq>.json`, so the box's `--ulimit fsize` (#1198) does
not bound it, and every reader of a sidecar refuses a file over `READ_LIMIT`. The one writer,
`record_query.persist_payload`, refuses instead: it writes nothing and returns `None`, the shape
it already returns for any failed write, which every reader of `payload_path` handles.

The bash tool is not a source: its only queries-row writer records an empty payload, so box
stdout never reaches a sidecar and has no test here.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import READ_LIMIT, read_bytes_capped  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, LEAD, q, run_gather  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402

pytestmark = pytest.mark.e2e

#: Two bytes in UTF-8, one character: a payload of these is over the cap in bytes while its
#: character count is not, so a writer measuring `len(text)` lets it through.
WIDE = "é"


def test_persist_payload_refuses_a_payload_one_byte_over_the_read_limit(tmp_path):
    text = WIDE * (READ_LIMIT // 2) + "x"
    assert len(text) <= READ_LIMIT < len(text.encode("utf-8"))

    rel = record_query.persist_payload(tmp_path, LEAD, 0, text)

    assert rel is None
    assert not (tmp_path / "gather_raw" / LEAD / "0.json").exists()


def test_persist_payload_writes_a_payload_of_exactly_the_read_limit_and_it_reads_back(tmp_path):
    """The boundary the reader draws: `READ_LIMIT` bytes is readable, so it is written."""
    text = WIDE * (READ_LIMIT // 2)
    assert len(text.encode("utf-8")) == READ_LIMIT

    rel = record_query.persist_payload(tmp_path, LEAD, 0, text)

    assert rel is not None
    assert read_bytes_capped(tmp_path / rel) == text.encode("utf-8")


def test_an_oversized_adapter_response_leaves_no_sidecar(tmp_path):
    """Driven through a real run: the query tool records the row, with no sidecar and no
    `raw payload:` pointer to a file that is not there."""
    def query(ctx: VerbContext, *, native_query: str) -> dict:
        return {"blob": "x" * (READ_LIMIT + 1)}

    r = run_gather(tmp_path, verbs=FakeVerbs({"elastic": {"query": query}}), turns=[
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ])

    row = r.row()
    assert row["exit_code"] == 0
    assert row["payload_path"] is None
    assert not (r.run_dir / "gather_raw" / LEAD / "0.json").exists()
    assert "[record_query] raw payload:" not in r.gather_saw
