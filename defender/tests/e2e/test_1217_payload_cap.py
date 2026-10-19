from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import READ_LIMIT, read_bytes_capped  # noqa: E402
from defender.runtime import record_query  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, LEAD, q, run_gather  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402

pytestmark = pytest.mark.e2e

#: Two bytes in UTF-8, one character: a payload of these is over the cap in bytes while its
#: character count is not, so a writer measuring `len(text)` lets it through.
WIDE = "é"


def test_persist_payload_refuses_a_payload_one_byte_over_the_read_limit(tmp_path):
    text = WIDE * (READ_LIMIT // 2) + "x"
    assert len(text) <= READ_LIMIT < len(text.encode("utf-8"))
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()

    rel = record_query.persist_payload(_writer_run_1165(run_dir), LEAD, 0, text)

    assert rel is None
    assert not (run_dir / "gather_raw" / LEAD / "0.json").exists()


def test_persist_payload_writes_a_payload_of_exactly_the_read_limit_and_it_reads_back(tmp_path):
    """The boundary the reader draws: `READ_LIMIT` bytes is readable, so it is written."""
    text = WIDE * (READ_LIMIT // 2)
    assert len(text.encode("utf-8")) == READ_LIMIT
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = tmp_path / fixture_uuid("run")
    run_dir.mkdir()

    rel = record_query.persist_payload(_writer_run_1165(run_dir), LEAD, 0, text)

    assert rel is not None
    assert read_bytes_capped(run_dir / rel) == text.encode("utf-8")


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
