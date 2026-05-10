#!/usr/bin/env python3
"""Oracle runner — full Sonnet defender investigation per lesson.

For each of the 8 lessons (4 bad, 4 good), launch a fresh defender investigation
with the lesson preloaded into the prompt. Compare the resulting disposition
to the original case's ground-truth disposition. Oracle verdict:
  - GOOD = disposition matches ground truth (lesson didn't break investigation)
  - BAD  = disposition diverges (lesson misled the agent)

Parallel 4-wide. ~5 min per run; ~10-20 min total wall time.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path("/workspace/tasks-scratch/defender-author-verification")
TRANSCRIPTS = Path("/workspace/defender/run-transcripts")
REPO_ROOT = Path("/workspace")
ORACLE_RUNS_BASE = Path("/tmp/defender-oracle-runs")

LESSONS = {
    "L1-bad-T3-zero-success-spray.md":             ("real-01-low-monitoring-probe",  "BENIGN"),
    "L2-bad-T2-burst-escalate.md":                  ("real-02-low-bait-monitoring-burst", "BENIGN"),
    "L3-bad-T2-pname-null-escalate.md":             ("real-03-low-shell-100001",      "BENIGN"),
    "L4-bad-T4-high-entropy-c2.md":                 ("real-04-low-dns-100110",        "ESCALATE"),
    "L5-good-monitoring-username-fingerprint.md":   ("real-01-low-monitoring-probe",  "BENIGN"),
    "L6-good-burst-not-disqualifying-monitoring.md":("real-02-low-bait-monitoring-burst", "BENIGN"),
    "L7-good-container-shell-baseline-first.md":    ("real-03-low-shell-100001",      "BENIGN"),
    "L8-good-multi-domain-rotation-ratio.md":       ("real-04-low-dns-100110",        "ESCALATE"),
}

DISPOSITION_RE = re.compile(
    r"(?:^disposition:\s*|#\s*Disposition:\s*)(\w+)", re.IGNORECASE | re.MULTILINE
)


def normalize_disposition(text: str) -> str:
    """Map free-form disposition strings to BENIGN | ESCALATE | INCONCLUSIVE | UNKNOWN."""
    matches = DISPOSITION_RE.findall(text)
    if not matches:
        return "UNKNOWN"
    raw = matches[0].lower()
    if raw in {"benign", "true_negative", "false_positive"}:
        return "BENIGN"
    if raw in {"escalate", "malicious", "true_positive"}:
        return "ESCALATE"
    if raw in {"inconclusive", "indeterminate"}:
        return "INCONCLUSIVE"
    return raw.upper()


def run_defender_with_lesson(lesson_name: str) -> dict:
    case_dir, ground_truth = LESSONS[lesson_name]
    lesson_body = (ROOT / "lessons" / lesson_name).read_text()
    alert_src = TRANSCRIPTS / case_dir / "alert.json"

    timestamp = int(time.time())
    run_id = f"oracle-{lesson_name.replace('.md','')}-{timestamp}"
    run_dir = ORACLE_RUNS_BASE / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    (run_dir / "gather_raw").mkdir()
    shutil.copy(alert_src, run_dir / "alert.json")

    prompt = f"""## Preloaded lesson

The following lesson is part of the defender's curated knowledge base — load
it as authoritative guidance and apply its recovery path during PLAN if
relevant to the alert.

```
{lesson_body}
```

---

Read defender/SKILL.md and follow it end-to-end.

## Run context
case_id: {run_id}
run_dir: {run_dir}
alert: {run_dir}/alert.json

The run dir already exists with alert.json copied in and an empty gather_raw/
subdirectory. Write all run artifacts (investigation.md, report.md,
lead_sequence.yaml, gather_raw/*) there. Work through ORIENT → PLAN → GATHER
→ ANALYZE → REPORT, dispatching gather subagents per defender/SKILL.md
§GATHER. After REPORT, run:

  python3 defender/scripts/project_lead_sequence.py {run_dir}

Stop when investigation.md, report.md, and lead_sequence.yaml all exist.
"""

    settings_json = json.dumps({
        "permissions": {"allow": ["Bash(*)", "Read(*)", "Write(*)", "Edit(*)",
                                   "Grep(*)", "Glob(*)", "Task(*)", "Skill(*)"]}
    })

    trace_path = run_dir / "tool_trace.jsonl"

    cmd = [
        "claude", "-p",
        "--model", "claude-sonnet-4-6",
        "--output-format", "stream-json",
        "--include-hook-events",
        "--verbose",
        "--permission-mode", "acceptEdits",
        "--settings", settings_json,
        "--add-dir", str(run_dir),
    ]

    print(f"[{lesson_name}] launch run_dir={run_dir}", flush=True)
    t0 = time.monotonic()
    try:
        with open(trace_path, "w") as f:
            r = subprocess.run(
                cmd, input=prompt, stdout=f, stderr=subprocess.PIPE,
                text=True, timeout=900, cwd=str(REPO_ROOT),
            )
        rc = r.returncode
    except subprocess.TimeoutExpired:
        rc = 1
    dur = time.monotonic() - t0

    report_path = run_dir / "report.md"
    if report_path.exists():
        report_text = report_path.read_text()
        disposition = normalize_disposition(report_text)
    else:
        disposition = "MISSING"
        report_text = ""

    oracle_verdict = "GOOD" if disposition == ground_truth else "BAD"
    if disposition in ("UNKNOWN", "MISSING"):
        oracle_verdict = "UNPARSEABLE"

    record = {
        "lesson": lesson_name,
        "case": case_dir,
        "ground_truth": ground_truth,
        "rerun_disposition": disposition,
        "oracle_verdict": oracle_verdict,
        "rc": rc,
        "duration_s": round(dur, 1),
        "run_dir": str(run_dir),
        "report_path": str(report_path),
    }
    out_path = ROOT / "runs" / "oracle" / f"{lesson_name.replace('.md','')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))

    print(f"[{lesson_name}] disposition={disposition} oracle={oracle_verdict} dur={dur:.0f}s rc={rc}", flush=True)
    return record


def main() -> int:
    ORACLE_RUNS_BASE.mkdir(parents=True, exist_ok=True)
    print(f"Launching {len(LESSONS)} Sonnet defender investigations (4-wide)...", flush=True)
    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(run_defender_with_lesson, lesson) for lesson in LESSONS]
        for f in as_completed(futures):
            try:
                records.append(f.result())
            except Exception as e:
                print(f"ERROR: {e}", flush=True)

    summary_lines = ["# Oracle (full Sonnet rerun) results\n"]
    summary_lines.append("| Lesson | Case | Ground truth | Rerun disposition | Oracle verdict |")
    summary_lines.append("|---|---|---|---|---|")
    for r in sorted(records, key=lambda x: x["lesson"]):
        summary_lines.append(
            f"| {r['lesson']} | {r['case']} | {r['ground_truth']} | "
            f"{r['rerun_disposition']} | {r['oracle_verdict']} |"
        )

    summary = "\n".join(summary_lines) + "\n"
    (ROOT / "results" / "oracle-summary.md").write_text(summary)
    print("\n" + summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
