#!/usr/bin/env python3
"""Bad-lesson-only verification-check runner. N=3 reps per (lesson, check).

Invokes Haiku via the same pattern as soc-agent/hooks/scripts/judge_runner.py.
Writes raw outputs + verdicts to runs/, then aggregates to results/summary.md.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path("/workspace/tasks-scratch/defender-author-verification")
TRANSCRIPTS = Path("/workspace/defender/run-transcripts")

BAD_LESSONS = {
    "L1-bad-T3-zero-success-spray.md":   ("real-01-low-monitoring-probe",  "BENIGN"),
    "L2-bad-T2-burst-escalate.md":        ("real-02-low-bait-monitoring-burst", "BENIGN"),
    "L3-bad-T2-pname-null-escalate.md":   ("real-03-low-shell-100001",      "BENIGN"),
    "L4-bad-T4-high-entropy-c2.md":       ("real-04-low-dns-100110",        "ESCALATE"),
}
GOOD_LESSONS = {
    "L5-good-monitoring-username-fingerprint.md":      ("real-01-low-monitoring-probe",  "BENIGN"),
    "L6-good-burst-not-disqualifying-monitoring.md":   ("real-02-low-bait-monitoring-burst", "BENIGN"),
    "L7-good-container-shell-baseline-first.md":       ("real-03-low-shell-100001",      "BENIGN"),
    "L8-good-multi-domain-rotation-ratio.md":          ("real-04-low-dns-100110",        "ESCALATE"),
}
CASE_BY_LESSON = {**BAD_LESSONS, **GOOD_LESSONS}

CHECKS = ["forward", "reverse", "regression"]
N_REPS = 3
MODEL = "haiku"
TIMEOUT = 180

CLAUDE_ARGV = ["claude", "-p", "--model", MODEL, "--output-format", "text"]


def load_transcript(case_dir: str) -> str:
    inv = (TRANSCRIPTS / case_dir / "investigation.md").read_text()
    rep = (TRANSCRIPTS / case_dir / "report.md").read_text()
    return f"{inv}\n\n--- REPORT ---\n\n{rep}"


def load_lesson(name: str) -> str:
    return (ROOT / "lessons" / name).read_text()


def build_prompt(check: str, lesson: str, transcript: str, disposition: str) -> str:
    template = (ROOT / "prompts" / f"{check}.md").read_text()
    return template.format(transcript=transcript, lesson=lesson, disposition=disposition)


VERDICT_RE = re.compile(r"VERDICT:\s*(GOOD|BAD)", re.IGNORECASE)


def parse_verdict(stdout: str) -> str:
    matches = VERDICT_RE.findall(stdout)
    if not matches:
        return "UNPARSEABLE"
    return matches[-1].upper()


def invoke(prompt: str) -> tuple[str, int]:
    try:
        r = subprocess.run(
            CLAUDE_ARGV, input=prompt, capture_output=True, text=True, timeout=TIMEOUT
        )
        return r.stdout, r.returncode
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {TIMEOUT}s", 1
    except FileNotFoundError:
        return "claude CLI not found", 1


def run_one(lesson_name: str, check: str, rep: int) -> dict:
    case_dir, disposition = CASE_BY_LESSON[lesson_name]
    transcript = load_transcript(case_dir)
    lesson = load_lesson(lesson_name)
    prompt = build_prompt(check, lesson, transcript, disposition)
    t0 = time.monotonic()
    stdout, rc = invoke(prompt)
    dur = time.monotonic() - t0
    verdict = parse_verdict(stdout)
    out_dir = ROOT / "runs" / check / lesson_name.replace(".md", "")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"rep-{rep}.json"
    record = {
        "lesson": lesson_name,
        "check": check,
        "rep": rep,
        "verdict": verdict,
        "rc": rc,
        "duration_s": round(dur, 1),
        "stdout": stdout,
    }
    out_path.write_text(json.dumps(record, indent=2))
    print(f"[{check}/{lesson_name}/rep-{rep}] verdict={verdict} rc={rc} dur={dur:.1f}s", flush=True)
    return record


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "bad":
        lessons = BAD_LESSONS
    elif which == "good":
        lessons = GOOD_LESSONS
    else:
        lessons = CASE_BY_LESSON

    jobs = [
        (lesson, check, rep)
        for lesson in lessons
        for check in CHECKS
        for rep in range(1, N_REPS + 1)
    ]
    print(f"Launching {len(jobs)} Haiku calls ({len(lessons)} lessons x 3 checks x 3 reps)...", flush=True)
    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(run_one, *j) for j in jobs]
        for f in as_completed(futures):
            records.append(f.result())

    # Aggregate
    by_key: dict[tuple[str, str], list[str]] = {}
    for r in records:
        by_key.setdefault((r["lesson"], r["check"]), []).append(r["verdict"])

    lines = [f"# N=3 results — set={which}\n"]
    lines.append("For each (lesson, check, rep), verdict is the model's GOOD/BAD on the lesson.\n")
    lines.append("- On BAD lessons: BAD verdict = caught (TN); GOOD verdict = missed (FN).")
    lines.append("- On GOOD lessons: GOOD verdict = correctly accepted (TP); BAD verdict = false-positive (FP).\n")
    lines.append("| Lesson | Check | Reps (verdicts) |")
    lines.append("|---|---|---|")
    for lesson in lessons:
        for check in CHECKS:
            verdicts = by_key.get((lesson, check), [])
            lines.append(f"| {lesson} | {check} | {','.join(verdicts)} |")

    summary = "\n".join(lines) + "\n"
    out_name = f"{which}-summary.md"
    (ROOT / "results" / out_name).write_text(summary)
    print("\n" + summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
