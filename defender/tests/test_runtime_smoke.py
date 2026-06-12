"""End-to-end smoke test for the PydanticAI runtime driver (slice 1).

Runs one real investigation through the driver on a monitor-case fixture and
asserts the artifact contract: a valid-invlang investigation.md, a report.md
with a disposition, and a tool_trace.jsonl result event. Spawns a real model
request, so it's marked `llm` (CI skips with `-m "not llm"`) and skips when no
ANTHROPIC_API_KEY is set.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import sys
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_DEFENDER))

from runtime import driver  # noqa: E402
from defender.skills.invlang.validate import validate_companion  # noqa: E402

FIXTURE = _DEFENDER / "fixtures" / "gtest-01-auth" / "alert.json"

pytestmark = [
    pytest.mark.llm,
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="needs first-party ANTHROPIC_API_KEY (PydanticAI engine)",
    ),
]


def _materialize(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(FIXTURE, run_dir / "alert.json")
    (run_dir / "meta.json").write_text(json.dumps({"run_id": "smoke", "salt": secrets.token_hex(8)}))
    return run_dir


def test_runtime_smoke(tmp_path):
    run_dir = _materialize(tmp_path)
    salt = json.loads((run_dir / "meta.json").read_text())["salt"]

    asyncio.run(driver.run_investigation(
        alert_path=run_dir / "alert.json",
        run_dir=run_dir,
        run_id="smoke",
        defender_dir=_DEFENDER,
        salt=salt,
    ))

    inv = run_dir / "investigation.md"
    rep = run_dir / "report.md"
    assert inv.is_file(), "investigation.md was not written"
    assert rep.is_file(), "report.md was not written"

    # investigation.md is valid invlang (the gate would have blocked an invalid
    # write, but re-validate the final artifact directly).
    assert validate_companion(inv.read_text(), None) == []

    # report.md carries a disposition from the closed enum.
    body = rep.read_text()
    assert any(f"disposition: {d}" in body for d in ("benign", "inconclusive", "malicious"))

    # tool_trace.jsonl has a result event with usage (the run_stats / Phase-B hook).
    events = [json.loads(line) for line in (run_dir / "tool_trace.jsonl").read_text().splitlines() if line.strip()]
    result_evs = [e for e in events if e.get("type") == "result"]
    assert result_evs and "usage" in result_evs[-1]
