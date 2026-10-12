"""#1235 round 3: one backend call is one row, on lead-0's capped path too.

`_CallLedger.call`'s capped branch is `try: envelope = fn(); _record_manual_row(exit 0)
... except BaseException: _record_manual_row(exit 2)`. Under round 3 the first append records
the success row in the state and THEN its view write raises; the catch-all treats that OSError as
the call's own fault and records a second row (exit 2, unmapped fault) for the same call.
The rule: a refused view write is not the call's fault; the call's row is the one it earned."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests.e2e import _lead_zero_808 as LZ  # noqa: E402


def test_a_capped_call_whose_view_write_is_refused_is_recorded_once(tmp_path):
    down = TransportFault("docker exec failed")
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    seen: dict = {}

    def answer(name, params):
        table = RunPaths(seen["run_dir"]).executed_queries
        table.unlink(missing_ok=True)
        table.symlink_to(outside)
        return LZ.envelope([], index=params.get("index"))

    def before(run_dir):
        seen["run_dir"] = run_dir

    try:
        res = LZ.run(tmp_path, run_id="adv3-capped", shell=down, answer=answer, before=before)
        state = res.state
        outcome = "run completed"
    except OSError as e:
        state = None
        outcome = f"run raised {e!r}"
    calls = []
    print("OUTCOME", outcome)
    if state is not None:
        rows = state.lead_rows("l-000")
        calls = [(r["seq"], r["verb"], r["exit_code"]) for r in rows]
        print("ROWS", calls)
        verbs = [c.verb for c in res.rec.calls]
        print("VERB CALLS", verbs)
    assert outside.read_bytes() == b""
    query_rows = [c for c in calls if c[1] == "query"]
    assert len(query_rows) == 1, f"one capped call, rows: {calls}"
