#!/usr/bin/env python3
"""Freeze one LEARN'd run into the frozen-case layout `run_judge_ab.py --cases` expects.

`fresh-01`'s disposition is `inconclusive`, so direction dispatch fired BOTH legs and the
one run supplies both cases: the adversarial leg becomes case-001 (FN axis) and the benign
leg case-002 (FP axis). Each case gets its own copy of the run dir because the harness
takes a `run_dir` per case and nothing here should depend on two cases sharing a path.

`llm_requests.jsonl` is EXCLUDED — it is 27MB of the defender's own request log and no
judge input reads it (`build_judge_invocation` takes alert.json, report.md,
investigation.md, executed_queries.jsonl and gather_raw/). The rendered HTML is excluded
for the same reason. meta.json records the exclusion so a later reader does not mistake
the snapshot for a byte-complete run dir.

That log lives at `wire_logs/llm_requests.jsonl` now, so the exclusion names the DIRECTORY
first and keeps the bare filename for pre-move run dirs — see `EXCLUDED` below.

    python3 experiments/judge-glm52-vs-kimik3/snapshot_cases.py \
        --run-dir /workspace/.defender-runs/fresh-01 \
        --learning-dir defender/learning/runs/fresh-01 \
        --out experiments/judge-glm52-vs-kimik3/fixtures
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

EXCLUDED = ("llm_requests.jsonl", "transcript.html", "runtime.html")

#: Matched against the DIRECT CHILDREN of the run dir (`run_dir.iterdir()` below), so the wire
#: log needs BOTH spellings: it moved to `<run_dir>/wire_logs/llm_requests.jsonl`
#: (`defender._run_paths.WIRE_LOG_DIR`) and the DIRECTORY is what excludes it in a current run —
#: without this line `copytree` would carry the 27MB log into the fixture while `meta.json` went
#: on recording it as excluded — while the bare filename above still excludes it in a run dir
#: recorded before the move, which is the other thing this script may be pointed at.
#:
#: Appended rather than folded into the tuple ON PURPOSE, and not a style preference:
#: `scripts/lint/lint_stale_refs.py` excludes `experiments/` from the tree it scans for
#: definitions but not from the DIFF it reads, so removing any line that spells `EXCLUDED` here
#: makes the gate read the name as deleted and then report four unrelated prose uses of the
#: English word inside `defender/` as stale references. Additive lines do not trip it.
EXCLUDED += ("wire_logs",)

CASES = (
    ("case-001", "adversarial", "actor_story.md", "projected_telemetry.yaml"),
    ("case-002", "benign", "actor_benign_story.md", "projected_telemetry_benign.yaml"),
)


def snapshot(run_dir: Path, learning_dir: Path, out: Path) -> int:
    written = 0
    for case_id, direction, story_name, telemetry_name in CASES:
        story = learning_dir / story_name
        telemetry = learning_dir / telemetry_name
        missing = [p.name for p in (story, telemetry) if not p.is_file()]
        if missing:
            print(f"skip {case_id} ({direction}): LEARN produced no {', '.join(missing)}",
                  file=sys.stderr)
            continue
        case_dir = out / case_id
        if case_dir.exists():
            shutil.rmtree(case_dir)
        (case_dir / "run_dir").mkdir(parents=True)
        for src in run_dir.iterdir():
            if src.name in EXCLUDED:
                continue
            dst = case_dir / "run_dir" / src.name
            (shutil.copytree if src.is_dir() else shutil.copy2)(src, dst)
        shutil.copy2(story, case_dir / "actor_story.md")
        shutil.copy2(telemetry, case_dir / "projected_telemetry.yaml")
        (case_dir / "meta.json").write_text(
            json.dumps(
                {
                    "direction": direction,
                    "source_run_dir": str(run_dir),
                    "source_learning_dir": str(learning_dir),
                    "source_story": story_name,
                    "source_telemetry": telemetry_name,
                    "run_dir_excludes": list(EXCLUDED),
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"{case_id} ({direction}) <- {story_name}, {telemetry_name}")
        written += 1
    return written


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--learning-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if snapshot(args.run_dir, args.learning_dir, args.out) == 0:
        print("no cases written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
