#!/usr/bin/env python3
"""Stage real-03-low-shell-100001 as a stress fixture and generate
actor_story.md + projected_telemetry.yaml. The judge stress harness
then re-judges this fixture N times per variant.

Heavier than rerun-100001-envelope-split: 3 lead positions (vs 2),
10 gather_raw files (vs ~5), 155-line investigation (vs ~85), with
multiple sub-shard queries (0b/0c/0d, 1b) showing real fan-out.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

EXP = Path(__file__).resolve().parent
SRC = Path("/workspace/defender/run-transcripts/real-03-low-shell-100001")
DST = EXP / "fixtures" / "stress-real-03"
LOOP_PY = Path("/workspace/defender/learning/loop.py")

sys.path.insert(0, str(LOOP_PY.parent))
import loop  # type: ignore


def stage() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    for name in ("alert.json", "investigation.md", "lead_sequence.yaml"):
        shutil.copy2(SRC / name, DST / name)
    # report.md needs frontmatter for loop helpers — defender from this
    # transcript era predates the schema. Inject minimum required fields.
    report_orig = (SRC / "report.md").read_text()
    fm = (
        "---\n"
        "case_id: stress-real-03\n"
        "disposition: benign\n"
        "confidence: high\n"
        "matched_archetype: routine-container-exec\n"
        "---\n\n"
    )
    (DST / "report.md").write_text(fm + report_orig)
    gather_src = SRC / "gather_raw"
    gather_dst = DST / "gather_raw"
    if gather_dst.exists():
        shutil.rmtree(gather_dst)
    shutil.copytree(gather_src, gather_dst)
    print(f"staged {DST}")


def run_actor_oracle() -> None:
    # actor_input via project script
    actor_input = DST / "actor_input.yaml"
    cmd = [
        sys.executable,
        "/workspace/defender/scripts/project_lead_sequence.py",
        str(DST),
        "--actor-out",
        str(actor_input),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"project failed: {r.stderr}")
    print(r.stdout.strip())

    print("[stress] invoking actor (sonnet)…", file=sys.stderr)
    actor_story = loop.invoke_actor(DST / "alert.json", actor_input, DST)
    (DST / "actor_story.md").write_text(actor_story)
    print(f"actor_story: {len(actor_story)} bytes", file=sys.stderr)

    if loop.is_skip_story(actor_story):
        raise SystemExit("actor emitted SKIP — pick a different fixture")

    print("[stress] invoking oracle (sonnet)…", file=sys.stderr)
    lead_seq_text = (DST / "lead_sequence.yaml").read_text()
    exemplars = loop.assemble_exemplar_bundle(DST, lead_seq_text)
    oracle_yaml = loop.invoke_oracle(
        DST / "alert.json",
        DST / "actor_story.md",
        DST / "lead_sequence.yaml",
        exemplars,
    )
    stripped = loop.strip_yaml_fence(oracle_yaml)
    (DST / "projected_telemetry.yaml").write_text(stripped)
    if stripped != oracle_yaml:
        (DST / "projected_telemetry.raw.txt").write_text(oracle_yaml)
    print(f"projected_telemetry: {len(stripped)} bytes", file=sys.stderr)


if __name__ == "__main__":
    stage()
    run_actor_oracle()
