"""Hermetic in-process gather test (slice 2): the nested gather agent runs
an adapter through its gated bash tool, the harness captures it transparently
(queries table + payload), and a summary comes back — all against the STUB_*
sandbox, no live data source.

Spawns a real model → `llm`-marked (CI skips with `-m "not llm"`) and skipped
without ANTHROPIC_API_KEY. The deterministic pieces (capture, claim, gate) are
covered by test_gather_capture.py / test_permission.py.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

pytest.importorskip("pydantic_ai")

from defender.runtime import driver, observe, tools  # noqa: E402

_GI = _DEFENDER / "tests" / "gather_invocation"

pytestmark = [
    pytest.mark.llm,
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="needs first-party ANTHROPIC_API_KEY (PydanticAI engine)",
    ),
]


def _build_sandbox(tmp_path: Path, fixture: str) -> tuple[Path, Path, dict, Path]:
    """A defender sandbox whose adapters are the test stubs: bin/ shims (resolved
    by run_env's PATH) exec `$DEFENDER_DIR/scripts/tools/<sys>_cli.py`, which here
    are the stub CLIs reading STUB_*_PAYLOAD. Mirrors the retained gather_invocation
    fixtures/stubs, plus bin/ (the in-process run_env points PATH at $DEFENDER_DIR/bin)."""
    fx = _GI / "fixtures" / fixture
    params = json.loads((fx / "dispatch.json").read_text())
    system = params["system"]
    sb = tmp_path / "sandbox"
    (sb / "skills" / "gather").mkdir(parents=True)
    (sb / "skills" / system).mkdir(parents=True)
    (sb / "scripts" / "tools").mkdir(parents=True)
    (sb / "bin").mkdir()
    # Copy the gather skill surface (SKILL.md — production — plus
    # failure-modes.md and any on-demand sub-files) so the gather agent resolves
    # its instructions in the sandbox.
    for md in (_DEFENDER / "skills" / "gather").glob("*.md"):
        shutil.copy(md, sb / "skills" / "gather" / md.name)
    shutil.copy(fx / "system_skill.md", sb / "skills" / system / "SKILL.md")
    for stub in (_GI / "stubs").glob("*.py"):
        d = sb / "scripts" / "tools" / stub.name
        shutil.copy(stub, d)
        d.chmod(0o755)
    for shim in (_DEFENDER / "bin").glob("defender-*"):
        d = sb / "bin" / shim.name
        shutil.copy(shim, d)
        d.chmod(0o755)
    run_dir = sb / "runs" / "gtest"
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(fx / "alert.json", run_dir / "alert.json")
    return sb, run_dir, params, fx


def test_gather_dispatch_via_tool(tmp_path, monkeypatch):
    """The full dispatch composition (`_run_gather`, the body of the `gather` tool)
    over the single-agent gather (#340): claim the lead → run the nested
    gather agent → it runs the adapter (captured under its lead_id) →
    untrusted-wrap → reuse rejection. Drives it directly so it always dispatches
    (no dependence on the main model gathering)."""
    from pydantic_ai.exceptions import ModelRetry

    sb, run_dir, params, fx = _build_sandbox(tmp_path, "V2_sparse_in_band")
    monkeypatch.setenv("STUB_ELASTIC_PAYLOAD", str(fx / "elastic_payload.json"))
    lead_id, system = "l-007", params["system"]
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    deps = tools.RunDeps(run_dir=run_dir, defender_dir=sb, run_id="gtest", salt="sALt", is_main_session=True)

    def factory(agent_id):
        return driver.build_gather_agent(sb, logger, agent_id)

    out = asyncio.run(tools._run_gather(
        deps, factory, driver.GATHER_REQUEST_LIMIT,
        lead_id, system, params["goal"], params["what_to_summarize"],
    ))
    logger.close()

    # Claim wrote the leads table; the gather agent's adapter call was captured under
    # its lead_id, with a query_id (the model's --query-id tag, or the
    # {system}.{verb} default — either way the queries-table row is keyed to it).
    assert (run_dir / "gather_raw" / f"{lead_id}.lead.json").is_file()
    rows = [json.loads(x) for x in (run_dir / "executed_queries.jsonl").read_text().splitlines() if x.strip()]
    assert rows and rows[0]["lead_id"] == lead_id
    assert rows[0]["query_id"].startswith(f"{system}.")
    # The gather logs under a single gather: instance (Sonnet by default).
    recs = [json.loads(x) for x in (run_dir / "llm_requests.jsonl").read_text().splitlines() if x.strip()]
    aids = {r["agent_id"] for r in recs}
    assert aids and all(a.startswith("gather:") for a in aids)
    # Return is untrusted-wrapped (salted tag) with no raw-path leak.
    assert "untrusted" in out and "sALt" in out and "gather_raw" not in out

    # A reused lead_id is rejected with ModelRetry (bounces the defender to PLAN).
    with pytest.raises(ModelRetry):
        asyncio.run(tools._run_gather(
            deps, factory, driver.GATHER_REQUEST_LIMIT,
            lead_id, system, params["goal"], params["what_to_summarize"],
        ))
