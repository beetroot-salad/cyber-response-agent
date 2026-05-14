#!/usr/bin/env python3
"""Arm B harness: run a customization fixture through Haiku and capture output.

Usage:
  harness.py <fixture-path> [--trial N] [--out-dir DIR]

Output: writes runs/<fixture-id>__trial-<N>.json with prompt, raw output, and metadata.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
LEADS_DIR = Path("/workspace/soc-agent/knowledge/common-investigation/leads")
PROMPT_PATH = ROOT / "variants" / "customization_prompt.md"

CLAUDE_ARGV = ["claude", "-p", "--model", "haiku", "--output-format", "text"]
TIMEOUT_S = 180


def load_seed(seed_name: str) -> tuple[str, str]:
    """Return (definition_md, template_md) for a seed name."""
    defn = (LEADS_DIR / seed_name / "definition.md").read_text()
    template = (LEADS_DIR / seed_name / "templates" / "wazuh.md").read_text()
    return defn, template


def build_prompt(fixture: dict) -> str:
    template = PROMPT_PATH.read_text()
    defn, tpl = load_seed(fixture["seed_name"])
    return (
        template
        .replace("{definition_md}", defn)
        .replace("{template_md}", tpl)
        .replace("{alert_excerpt}", json.dumps(fixture["alert_excerpt"], indent=2))
        .replace("{adaptation_note}", fixture["adaptation_note"])
    )


def invoke_haiku(prompt: str) -> tuple[str, int, float]:
    t0 = time.time()
    try:
        result = subprocess.run(
            CLAUDE_ARGV,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )
        return result.stdout, result.returncode, time.time() - t0
    except subprocess.TimeoutExpired:
        return f"<TIMEOUT after {TIMEOUT_S}s>", 124, time.time() - t0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("fixture", type=Path)
    p.add_argument("--trial", type=int, default=1)
    p.add_argument("--out-dir", type=Path, default=ROOT / "runs")
    args = p.parse_args()

    fixture = json.loads(args.fixture.read_text())
    prompt = build_prompt(fixture)
    stdout, rc, elapsed = invoke_haiku(prompt)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{fixture['id']}__trial-{args.trial:02d}.json"
    out.write_text(json.dumps({
        "fixture_id": fixture["id"],
        "category": fixture["category"],
        "trial": args.trial,
        "elapsed_s": round(elapsed, 2),
        "returncode": rc,
        "stdout": stdout,
        "reference_query": fixture["reference_query"],
        "rubric": fixture["rubric"],
    }, indent=2))
    print(f"wrote {out.name} (rc={rc}, {elapsed:.1f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
