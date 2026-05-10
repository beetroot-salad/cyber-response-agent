#!/usr/bin/env python3
"""Invoke the hypothesize subagent against each synthetic fixture and capture
output to disk. Uses the shared _subagent wrapper so the pipeline matches
production exactly (model, plugin loading, session mapping, audit log).

Usage:
    soc-agent/.venv/bin/python3 docs/experiments/hypothesize-stress-test/run.py
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SOC_AGENT_ROOT = REPO_ROOT / "soc-agent"
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._subagent import invoke_subagent  # noqa: E402


FIXTURE_DIRS = [
    REPO_ROOT / "docs/experiments/hypothesize-stress-test/fixture-1-legitimacy-axis",
    REPO_ROOT / "docs/experiments/hypothesize-stress-test/fixture-2-compound-pressure",
    REPO_ROOT / "docs/experiments/hypothesize-stress-test/fixture-3-subsequent-event",
]


def prepare_run_dir(fixture: Path, outputs_root: Path) -> Path:
    """Copy fixture alert + investigation into a fresh run dir. The handler's
    subagent invocation expects {run_dir}/alert.json + {run_dir}/investigation.md."""
    run_dir = outputs_root / f"run-{fixture.name}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    shutil.copy(fixture / "alert.json", run_dir / "alert.json")
    shutil.copy(fixture / "investigation.md", run_dir / "investigation.md")
    return run_dir


def main() -> int:
    outputs_root = REPO_ROOT / "docs/experiments/hypothesize-stress-test/outputs"
    outputs_root.mkdir(exist_ok=True)

    # The shared wrapper reads these env vars to wire session→run mapping
    # and audit logging. Signature id matches the rule in each fixture's alert.
    signature_by_fixture = {
        "fixture-1-legitimacy-axis": "wazuh-rule-5710",
        "fixture-2-compound-pressure": "wazuh-rule-100001",
        "fixture-3-subsequent-event": "wazuh-rule-5710",
    }

    results = []
    for fixture in FIXTURE_DIRS:
        signature_id = signature_by_fixture[fixture.name]
        run_dir = prepare_run_dir(fixture, outputs_root)

        os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
        os.environ["SOC_AGENT_SIGNATURE_ID"] = signature_id

        prompt = "\n".join([
            f"run_dir={run_dir}",
            f"signature_id={signature_id}",
            "loop_n=1",
        ])

        print(f"\n=== Running {fixture.name} (signature {signature_id}) ===",
              flush=True)
        try:
            stdout = invoke_subagent("hypothesize", prompt, timeout=300)
        except Exception as exc:
            stdout = f"<INVOCATION ERROR: {exc}>"

        output_path = run_dir / "subagent_output.md"
        output_path.write_text(stdout)
        print(f"  → wrote {output_path}")
        results.append((fixture.name, output_path, len(stdout)))

    print("\n=== Summary ===")
    for name, path, chars in results:
        print(f"  {name}: {chars} chars → {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
