#!/usr/bin/env python3
"""Replay each arm from arm-A's post-ORIENT anchor — PLAN only.

Per (arm, case): materializes a fresh run dir, pre-populates
investigation.md with anchors/<case>/investigation.md, applies the
arm overlay (a/b/c/d.md from the parent advisory-ab/ dir), and
prompts the agent to author only PLAN (:H + :L) before stopping.

Metrics captured per run (results/<ts>/<arm>-<case>.json):
    leads_authored: list of {id, name, target, tests, system, ...}
    advisory_calls: list of {kind: bash|task, args/prompt, response_excerpt,
                              wall_clock_s, subagent_tokens_in/out, cost_usd}
    plan_turn_cost_usd: total run cost (= PLAN turn since we stopped)
    plan_turn_wall_clock_s
    plan_turn_input_tokens, plan_turn_output_tokens
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent                       # .../plan_only
AB_DIR = HERE.parent                                          # .../advisory-ab
REPO_ROOT = AB_DIR.parents[1]                                 # repo root
DEFENDER_DIR = REPO_ROOT / "defender"
ANCHORS_DIR = HERE / "anchors"
FIXTURES_DIR = AB_DIR / "fixtures"
ARMS_DIR = AB_DIR / "arms"
RESULTS_DIR = HERE / "results"

ARMS = ["a", "b", "c", "d", "e", "bf", "cf", "df"]
CASES = ["POS-1", "NEG-1"]

REPLAY_PROMPT = """## Run context
case_id: {run_id}
run_dir: {run_dir}
alert: {run_dir}/alert.json

`investigation.md` has been pre-populated with the `## ORIENT`
section already authored. You are joining this investigation
mid-flight at the start of PLAN. Do not edit ORIENT; do not
re-author `:V` / `:E`.

Read defender/SKILL.md.

**Scope for this run: PLAN ONLY.** Append a `## PLAN (loop 1)`
section to `investigation.md` with the `:H hypothesize.hypotheses`
block and the `:L findings` block per defender/SKILL.md §PLAN. Then
**STOP**. Do NOT:
- Dispatch the gather subagent (no `Task` to gather)
- Author `:R` / `:T` / `## ANALYZE` / `## REPORT`
- Write `report.md`

You MAY do whatever PLAN requires per the arm-specific extension
below (reading lessons, querying advisory, etc.) before authoring
`:H` / `:L`. Stop immediately after the final Write/Edit that lands
`:L findings`.

{arm_section}
"""

ARM_OVERLAY_HEADER = (
    "## Arm-specific PLAN extension\n\n"
    "The following extends defender/SKILL.md §PLAN for this run. "
    "Apply it wherever it conflicts with the SKILL.\n\n"
)


def arm_overlay(arm: str) -> str:
    path = ARMS_DIR / f"{arm}.md"
    body = path.read_text().strip()
    if not body or body.startswith("<!--"):
        return ""
    return ARM_OVERLAY_HEADER + body + "\n"


def materialize_run_dir(arm: str, case_id: str) -> Path:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"plan-only-{arm}-{case_id.lower()}-{ts}"
    run_dir = Path("/tmp/defender-runs") / run_id
    (run_dir / "gather_raw").mkdir(parents=True)

    # Seed alert.json from the fixture.
    alert_src = FIXTURES_DIR / case_id / "alert.json"
    shutil.copy(alert_src, run_dir / "alert.json")

    # Pre-populate investigation.md from the anchor.
    anchor_inv = ANCHORS_DIR / case_id / "investigation.md"
    if not anchor_inv.is_file():
        sys.exit(f"missing anchor for {case_id}: {anchor_inv} — run capture.py first")
    shutil.copy(anchor_inv, run_dir / "investigation.md")
    return run_dir


def spawn_replay(arm: str, case_id: str, results_dir: Path) -> dict:
    run_dir = materialize_run_dir(arm, case_id)

    sys.path.insert(0, str(DEFENDER_DIR))
    try:
        import run as defender_run  # type: ignore
    finally:
        sys.path.pop(0)

    settings_path = defender_run.build_settings_file()
    # Inject experiment-local Bash patterns so the agent can call the
    # fake/NL wrapper scripts under acceptEdits without permission prompts.
    settings_path = _augment_settings(settings_path)
    prompt = REPLAY_PROMPT.format(
        run_id=run_dir.name,
        run_dir=run_dir,
        arm_section=arm_overlay(arm),
    )
    model = defender_run.DEFAULT_MODEL

    print(f"[replay] {arm}/{case_id}: run_dir={run_dir}", file=sys.stderr)
    t0 = time.monotonic()
    rc = defender_run.spawn_claude(prompt, run_dir, settings_path, model, effort=None)
    wall = time.monotonic() - t0

    metrics = extract_metrics(arm, case_id, run_dir, rc, wall)
    out = results_dir / f"{arm}-{case_id}.json"
    out.write_text(json.dumps(metrics, indent=2))
    print(f"[replay] {arm}/{case_id}: leads={len(metrics['leads_authored'])} "
          f"advisory={len(metrics['advisory_calls'])} "
          f"cost=${metrics['plan_turn_cost_usd']} "
          f"wall={metrics['plan_turn_wall_clock_s']}s rc={rc}", file=sys.stderr)
    return metrics


_LEAD_RE = re.compile(r"^(l-\d+)\|(\d+)\|([^|]+)\|(.*)$")


def parse_leads(inv_text: str) -> list[dict]:
    """Pick out :L findings rows that the replay agent authored.

    The anchor only contains ORIENT, so any l-\\d+ row in the post-run
    investigation.md was authored by the replay arm. Schema rows
    starting with `[id|loop|...]` are excluded by the leading l-\\d+
    pattern. The rest of the row is captured raw — the agent uses
    different column counts depending on whether `mode?` and other
    optional columns are present.
    """
    leads = []
    for ln in inv_text.splitlines():
        m = _LEAD_RE.match(ln.rstrip())
        if not m:
            continue
        rest = m.group(4).split("|")
        leads.append({
            "id": m.group(1),
            "loop": int(m.group(2)),
            "name": m.group(3).strip(),
            "row": ln.rstrip(),
            "fields": [f.strip() for f in rest],
        })
    return leads


def extract_metrics(arm: str, case_id: str, run_dir: Path, rc: int, wall: float) -> dict:
    inv = (run_dir / "investigation.md").read_text() if (run_dir / "investigation.md").is_file() else ""
    leads = parse_leads(inv)

    trace_path = run_dir / "tool_trace.jsonl"
    events: list[dict] = []
    if trace_path.is_file():
        for line in trace_path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    # Cost + tokens for the outer (main-agent) run. The 'result' events
    # roll up usage cumulatively per claude -p invocation. With one
    # subagent dispatch, the subagent emits its own 'result' too. We
    # want both: total_cost includes everything, subagent_cost is
    # broken out for the advisory call.
    main_cost, main_in, main_out = 0.0, 0, 0
    sub_cost, sub_in, sub_out = 0.0, 0, 0
    for ev in events:
        if ev.get("type") != "result":
            continue
        usage = ev.get("usage", {}) or {}
        cost = float(ev.get("total_cost_usd", 0) or 0)
        is_subagent = bool(ev.get("parent_tool_use_id"))
        if is_subagent:
            sub_cost += cost
            sub_in += usage.get("input_tokens", 0) or 0
            sub_out += usage.get("output_tokens", 0) or 0
        else:
            main_cost += cost
            main_in += usage.get("input_tokens", 0) or 0
            main_out += usage.get("output_tokens", 0) or 0

    # Advisory call detection — Bash with `invlang.cli ... advisory`,
    # or Task whose prompt references defender/skills/advisory.
    advisory_calls: list[dict] = []
    # Build tool_use_id → tool_result lookup so we can excerpt
    # responses and compute (best-effort) wall clock from event order.
    tool_results: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "user":
            continue
        for c in ev.get("message", {}).get("content", []) or []:
            if c.get("type") != "tool_result":
                continue
            tid = c.get("tool_use_id")
            if tid:
                tool_results[tid] = c

    # Walk events in order, pair tool_use → tool_result, compute the
    # gap in events (cheap proxy for "did anything else happen between
    # dispatch and response"). True wall clock isn't in the trace, so
    # we report subagent cost as the cost signal for B.
    for i, ev in enumerate(events):
        if ev.get("type") != "assistant" or ev.get("parent_tool_use_id"):
            continue
        for c in ev.get("message", {}).get("content", []) or []:
            if c.get("type") != "tool_use":
                continue
            name = c.get("name", "")
            payload = c.get("input", {}) or {}
            is_adv = False
            kind = None
            if name == "Bash":
                cmd = str(payload.get("command", ""))
                if "invlang.cli" in cmd and " advisory" in cmd:
                    is_adv = True
                    kind = "bash"
                elif "fake_advisory.py" in cmd:
                    is_adv = True
                    kind = "bash-fake"
                elif "advisory_nl.py" in cmd:
                    is_adv = True
                    kind = "bash-nl"
            elif name in ("Task", "Agent"):
                prompt = str(payload.get("prompt", ""))
                subagent_type = str(payload.get("subagent_type", ""))
                if "defender/skills/advisory" in prompt or subagent_type == "advisory":
                    is_adv = True
                    kind = "task"
            if not is_adv:
                continue
            tid = c.get("id")
            res = tool_results.get(tid, {})
            res_content = res.get("content", "")
            if isinstance(res_content, list):
                res_text = "\n".join(
                    part.get("text", "") for part in res_content if isinstance(part, dict)
                )
            else:
                res_text = str(res_content)
            advisory_calls.append({
                "kind": kind,
                "tool_use_id": tid,
                "args": payload,
                "response_excerpt": res_text[:1200],
                "response_len_chars": len(res_text),
                "event_gap": _event_gap(events, i, tid),
            })

    return {
        "arm": arm,
        "case_id": case_id,
        "run_dir": str(run_dir),
        "rc": rc,
        "plan_turn_wall_clock_s": round(wall, 2),
        "plan_turn_cost_usd": round(main_cost + sub_cost, 4),
        "main_agent_cost_usd": round(main_cost, 4),
        "main_input_tokens": main_in,
        "main_output_tokens": main_out,
        "subagent_cost_usd": round(sub_cost, 4),
        "subagent_input_tokens": sub_in,
        "subagent_output_tokens": sub_out,
        "leads_authored": leads,
        "advisory_calls": advisory_calls,
    }


EXTRA_BASH_PATTERNS = [
    "Bash(python3 experiments/advisory-ab/plan_only/advisory_nl.py *)",
    "Bash(python3 experiments/advisory-ab/plan_only/fake_advisory.py *)",
]


def _augment_settings(settings_path: Path) -> Path:
    data = json.loads(settings_path.read_text())
    allow = data.setdefault("permissions", {}).setdefault("allow", [])
    for pat in EXTRA_BASH_PATTERNS:
        if pat not in allow:
            allow.append(pat)
    settings_path.write_text(json.dumps(data, indent=2))
    return settings_path


def _event_gap(events: list[dict], use_idx: int, tool_use_id: str | None) -> int:
    if not tool_use_id:
        return -1
    for j in range(use_idx + 1, len(events)):
        ev = events[j]
        if ev.get("type") != "user":
            continue
        for c in ev.get("message", {}).get("content", []) or []:
            if c.get("type") == "tool_result" and c.get("tool_use_id") == tool_use_id:
                return j - use_idx
    return -1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--arm", choices=ARMS)
    p.add_argument("--case", choices=CASES)
    p.add_argument("--all", action="store_true")
    p.add_argument("--results-dir", default=None)
    ns = p.parse_args(argv)

    if not ns.all and not (ns.arm and ns.case):
        p.error("provide --arm and --case, or --all")

    if ns.results_dir:
        results_dir = Path(ns.results_dir)
    else:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results_dir = RESULTS_DIR / ts
    results_dir.mkdir(parents=True, exist_ok=True)
    print(f"[replay] results_dir={results_dir}", file=sys.stderr)

    if ns.all:
        for c in CASES:
            for a in ARMS:
                spawn_replay(a, c, results_dir)
    else:
        spawn_replay(ns.arm, ns.case, results_dir)

    print(f"[replay] done — results in {results_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
