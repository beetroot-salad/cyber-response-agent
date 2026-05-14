#!/usr/bin/env python3
"""Arm A harness: NL-goal -> seed selection across catalog sizes.

Usage:
  arm_a_harness.py <fixture> --catalog-size N [--trial N] [--out-dir DIR]

Catalog sizes: 8 (real only), 58 (real + first 50 distractors by sorted name),
158 (real + first 150 distractors), or any explicit N.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
REAL_LEADS_DIR = Path("/workspace/soc-agent/knowledge/common-investigation/leads")
DISTRACTORS_DIR = ROOT / "fixtures" / "distractors"
PROMPT_PATH = ROOT / "variants" / "selection_prompt.md"

CLAUDE_ARGV = ["claude", "-p", "--model", "haiku", "--output-format", "text"]
TIMEOUT_S = 180

REAL_LEAD_NAMES = [
    "ad-hoc",
    "authentication-history",
    "correlated-endpoint-events",
    "data-source-debug",
    "network-analysis",
    "process-lineage",
    "source-reputation",
    "user-analysis",
]


def parse_lead_manifest_entry(definition_path: Path) -> tuple[str, str, str]:
    """Return (name, tags, one_line_goal)."""
    text = definition_path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError(f"no frontmatter: {definition_path}")
    fm_body, rest = m.group(1), m.group(2)

    name_m = re.search(r"^name:\s*(\S+)", fm_body, re.MULTILINE)
    tags_m = re.search(r"^data_tags:\s*(.+)", fm_body, re.MULTILINE)
    name = name_m.group(1) if name_m else definition_path.parent.name
    tags = tags_m.group(1).strip() if tags_m else "[]"

    goal_m = re.search(r"##\s*Goal\s*\n+(.+?)(?=\n##|\Z)", rest, re.DOTALL)
    if not goal_m:
        goal_line = ""
    else:
        goal_text = goal_m.group(1).strip()
        first_para = goal_text.split("\n\n")[0]
        goal_line = " ".join(line.strip() for line in first_para.splitlines())

    return name, tags, goal_line


def build_catalog_manifest(catalog_size: int) -> tuple[str, list[str]]:
    """Return (manifest_text, included_lead_names)."""
    entries = []
    included = []

    for name in REAL_LEAD_NAMES:
        defn = REAL_LEADS_DIR / name / "definition.md"
        if not defn.exists():
            continue
        n, tags, goal = parse_lead_manifest_entry(defn)
        entries.append((n, tags, goal))
        included.append(n)

    needed_distractors = max(0, catalog_size - len(entries))
    if needed_distractors > 0:
        distractor_paths = sorted(DISTRACTORS_DIR.glob("*/definition.md"))
        for defn in distractor_paths[:needed_distractors]:
            n, tags, goal = parse_lead_manifest_entry(defn)
            entries.append((n, tags, goal))
            included.append(n)

    rng_seed = 1337
    import random as _random
    rng = _random.Random(rng_seed)
    shuffled = entries[:]
    rng.shuffle(shuffled)

    lines = [f"`{n}` | {tags} | {goal}" for n, tags, goal in shuffled]
    return "\n".join(lines), included


def build_prompt(fixture: dict, catalog_manifest: str) -> str:
    template = PROMPT_PATH.read_text()
    return (
        template
        .replace("{nl_goal}", fixture["nl_goal"])
        .replace("{catalog_manifest}", catalog_manifest)
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
    p.add_argument("--catalog-size", type=int, required=True)
    p.add_argument("--trial", type=int, default=1)
    p.add_argument("--out-dir", type=Path, default=ROOT / "runs_arm_a")
    args = p.parse_args()

    fixture = json.loads(args.fixture.read_text())
    manifest, included = build_catalog_manifest(args.catalog_size)
    prompt = build_prompt(fixture, manifest)
    stdout, rc, elapsed = invoke_haiku(prompt)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"{fixture['id']}__N{args.catalog_size:03d}__trial-{args.trial:02d}.json"
    out.write_text(json.dumps({
        "fixture_id": fixture["id"],
        "class": fixture["class"],
        "catalog_size": args.catalog_size,
        "actual_catalog_size": len(included),
        "trial": args.trial,
        "elapsed_s": round(elapsed, 2),
        "returncode": rc,
        "stdout": stdout,
        "correct_leads": fixture["correct_leads"],
    }, indent=2))
    print(f"wrote {out.name} (rc={rc}, {elapsed:.1f}s, N={len(included)})",
          file=sys.stderr)


if __name__ == "__main__":
    main()
