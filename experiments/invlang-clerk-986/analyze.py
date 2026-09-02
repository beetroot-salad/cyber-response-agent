#!/usr/bin/env python3
"""Score the clerk-split trials: cost by role, who absorbed the validator, disposition vs label.

    analyze.py score  [--manifest runs/manifest.jsonl] [--out results/final.jsonl]
    analyze.py judge  --fixture F1-off-hours-sudo [--cap 15] [--out results/judge.jsonl]

`score` is deterministic and reads only run dirs. `judge` is the blinded pairwise comparison
(claude -p, both orders) and costs money; run it after `score` says the arms are comparable.

Accounting rules that matter (learned on the nine prior runs):
  * `wire_logs/llm_requests.jsonl` snapshots the WHOLE conversation on every request, so a
    retry-prompt is counted once per tool_call_id, never per record it appears in.
  * A MAIN turn is a "repair turn" when the request record immediately before it carries a
    retry-prompt for the write verb (`append_block` in arm A, `record` in arm C).
  * Clerk-side refusals never reach the wire as retry-prompts: they are in `clerk_trace.jsonl`,
    one line per `record` call, written by the experimental tool.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from itertools import product
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from defender.scripts.pricing import usage_cost  # noqa: E402

RUNS_BASE = Path(os.environ.get("DEFENDER_RUNS_BASE", "/workspace/.defender-runs"))
WRITE_VERBS = {"append_block", "record"}
JUDGE_MODEL = "claude-opus-5"


# ----------------------------------------------------------------------------- per-run facts

def _wire(run_dir: Path) -> list[dict]:
    p = run_dir / "wire_logs" / "llm_requests.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.sort(key=lambda r: (r.get("agent_id", ""), r.get("seq", 0)))
    return out


def _role(agent_id: str) -> str:
    for prefix in ("main", "gather", "clerk", "review"):
        if agent_id == prefix or agent_id.startswith(prefix + ":"):
            return prefix
    return "other"


def cost_by_role(recs: list[dict]) -> dict:
    tok = defaultdict(lambda: defaultdict(int))
    cost = defaultdict(float)
    calls = defaultdict(int)
    unknown_models: set[str] = set()
    for r in recs:
        if r.get("kind") != "response":
            continue
        role = _role(r.get("agent_id", ""))
        u = r.get("usage") or {}
        model = r.get("model") or ""
        calls[role] += 1
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
            tok[role][k] += u.get(k, 0)
        try:
            cost[role] += usage_cost(model, u)
        except Exception:  # noqa: BLE001 — an unpriced model must not zero the whole run silently
            unknown_models.add(model)
    return {
        "cost": {k: round(v, 4) for k, v in cost.items()},
        "cost_total": round(sum(cost.values()), 4),
        "calls": dict(calls),
        "tokens": {k: dict(v) for k, v in tok.items()},
        "unpriced_models": sorted(unknown_models),
    }


def main_refusals(recs: list[dict]) -> dict:
    """Refusals MAIN itself absorbed, and the turns it spent answering them."""
    main = [r for r in recs if r.get("agent_id") == "main"]
    seen: set[str] = set()
    refused = 0
    refused_texts: list[str] = []
    repair_turns = 0
    repair_out = 0
    prev = None
    for r in main:
        parts = (r.get("message") or {}).get("parts", [])
        if r.get("kind") == "request":
            for p in parts:
                if p.get("part_kind") == "retry-prompt" and p.get("tool_name") in WRITE_VERBS:
                    tid = p.get("tool_call_id") or json.dumps(p.get("content"))[:80]
                    if tid not in seen:
                        seen.add(tid)
                        refused += 1
                        refused_texts.append(str(p.get("content"))[:300])
        else:
            trig = prev if prev and prev.get("kind") == "request" else None
            if trig and any(
                p.get("part_kind") == "retry-prompt" and p.get("tool_name") in WRITE_VERBS
                for p in (trig.get("message") or {}).get("parts", [])
            ):
                repair_turns += 1
                repair_out += (r.get("usage") or {}).get("output_tokens", 0)
        prev = r
    return {
        "main_write_refusals": refused,
        "main_repair_turns": repair_turns,
        "main_repair_output_tokens": repair_out,
        "main_refusal_samples": refused_texts[:3],
    }


def clerk_trace(run_dir: Path) -> dict:
    p = run_dir / "clerk_trace.jsonl"
    if not p.exists():
        return {"clerk_calls": 0}
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return {
        "clerk_calls": len(rows),
        "clerk_rounds": sum(int(r.get("rounds", 1)) for r in rows),
        "clerk_refusals": sum(len(r.get("refusals", [])) for r in rows),
        "clerk_giveups": sum(1 for r in rows if not r.get("committed", True)),
        "clerk_gaps": sum(len(r.get("gaps", [])) for r in rows),
        "clerk_gap_samples": [g for r in rows for g in r.get("gaps", [])][:5],
        "clerk_prose_chars": sum(int(r.get("prose_chars", 0)) for r in rows),
        "clerk_rows_chars": sum(int(r.get("rows_chars", 0)) for r in rows),
    }


def disposition(run_dir: Path) -> str | None:
    p = run_dir / "report.md"
    if not p.exists():
        return None
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()[:12]:
        if line.startswith("disposition:"):
            return line.split(":", 1)[1].strip()
    return None


def wall_minutes(run_dir: Path) -> float | None:
    try:
        started = json.loads((run_dir / "budget.json").read_text())["started_at"]
        s = datetime.fromisoformat(started)
        if s.tzinfo is None:
            s = s.replace(tzinfo=timezone.utc)
        end_src = run_dir / "report.md"
        if not end_src.exists():
            end_src = run_dir / "investigation.md"
        e = datetime.fromtimestamp(end_src.stat().st_mtime, tz=timezone.utc)
        return round((e - s).total_seconds() / 60, 1)
    except Exception:  # noqa: BLE001
        return None


def record_validates(run_dir: Path) -> int | None:
    """Count of validator findings on the final document (R1). None if it cannot be read."""
    p = run_dir / "investigation.md"
    if not p.exists():
        return None
    try:
        from defender.skills.invlang.validate import validate_companion
        return len(validate_companion(p.read_text(encoding="utf-8")))
    except Exception as e:  # noqa: BLE001
        print(f"warn: validator failed on {run_dir.name}: {e!r}", file=sys.stderr)
        return None


def score_run(entry: dict) -> dict:
    run_dir = RUNS_BASE / entry["run_id"]
    recs = _wire(run_dir)
    main_resp = [r for r in recs if r.get("agent_id") == "main" and r.get("kind") == "response"]
    disp = disposition(run_dir)
    out = {
        **{k: entry.get(k) for k in ("run_id", "arm", "fixture", "label", "clerk_model", "exit")},
        "concluded": disp is not None,
        "disposition": disp,
        "correct": (disp == entry.get("label")) if entry.get("label") else None,
        "wall_min": wall_minutes(run_dir),
        "main_turns": len(main_resp),
        "main_output_tokens": sum((r.get("usage") or {}).get("output_tokens", 0) for r in main_resp),
        "validator_findings_at_end": record_validates(run_dir),
        **cost_by_role(recs),
        **main_refusals(recs),
        **clerk_trace(run_dir),
    }
    return out


# ----------------------------------------------------------------------------- aggregation

def _mean(xs: list) -> float | None:
    xs = [x for x in xs if isinstance(x, (int, float))]
    return round(sum(xs) / len(xs), 3) if xs else None


def summarize(rows: list[dict]) -> str:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["fixture"], r["arm"])].append(r)
    cols = [
        ("n", lambda g: len(g)),
        ("concluded", lambda g: sum(1 for r in g if r["concluded"])),
        ("correct", lambda g: sum(1 for r in g if r["correct"])),
        ("$total", lambda g: _mean([r["cost_total"] for r in g])),
        ("$main", lambda g: _mean([r["cost"].get("main", 0) for r in g])),
        ("$clerk", lambda g: _mean([r["cost"].get("clerk", 0) for r in g])),
        ("$gather", lambda g: _mean([r["cost"].get("gather", 0) for r in g])),
        ("main_out_tok", lambda g: _mean([r["main_output_tokens"] for r in g])),
        ("main_turns", lambda g: _mean([r["main_turns"] for r in g])),
        ("main_refused", lambda g: _mean([r["main_write_refusals"] for r in g])),
        ("main_repair_turns", lambda g: _mean([r["main_repair_turns"] for r in g])),
        ("clerk_calls", lambda g: _mean([r["clerk_calls"] for r in g])),
        ("clerk_refusals", lambda g: _mean([r.get("clerk_refusals", 0) for r in g])),
        ("clerk_giveups", lambda g: _mean([r.get("clerk_giveups", 0) for r in g])),
        ("clerk_gaps", lambda g: _mean([r.get("clerk_gaps", 0) for r in g])),
        ("findings_at_end", lambda g: _mean([r["validator_findings_at_end"] for r in g])),
        ("wall_min", lambda g: _mean([r["wall_min"] for r in g])),
    ]
    lines = []
    header = f"{'fixture':22s} {'arm':3s} " + " ".join(f"{c:>17s}" for c, _ in cols)
    lines.append(header)
    for (fix, arm), g in sorted(groups.items()):
        lines.append(f"{fix:22s} {arm:3s} " + " ".join(f"{str(f(g)):>17s}" for _, f in cols))
    dispositions = defaultdict(lambda: defaultdict(int))
    for r in rows:
        dispositions[(r["fixture"], r["arm"])][r["disposition"] or "none"] += 1
    lines.append("")
    for k, d in sorted(dispositions.items()):
        lines.append(f"{k[0]:22s} {k[1]:3s} dispositions: {dict(d)}")
    return "\n".join(lines)


def cmd_score(args: argparse.Namespace) -> int:
    entries = [json.loads(l) for l in Path(args.manifest).read_text().splitlines() if l.strip()]
    if args.only:
        entries = [e for e in entries if e["run_id"] in set(args.only)]
    rows = [score_run(e) for e in entries]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    print(summarize(rows))
    unpriced = sorted({m for r in rows for m in r["unpriced_models"]})
    if unpriced:
        print(f"\nWARNING: unpriced models (cost under-counted): {unpriced}")
    return 0


# ----------------------------------------------------------------------------- pairwise judge

JUDGE_RUBRIC = """\
You are comparing two runs of an automated alert-triage agent on the SAME alert. You will see
each run's investigation document and its closing report, labelled X and Y. You do not know
how either was produced; judge only what is on the page.

Decide which run's CLOSING CLAIM is better earned, on these questions:
1. Is the disposition's rationale supported by evidence the run's own leads actually gathered
   (quoted results, not assertions)?
2. Were the leads discriminating — did each one test something that could have changed the
   verdict — rather than confirmatory or redundant?
3. Is the closing claim scoped to the entity the run actually investigated, and are the open
   questions it names the ones that are genuinely open?
4. Does the record carry what the prose asserts, so a reader could audit the verdict from the
   rows alone?

Reply with ONE JSON object and nothing else:
{"winner": "X" | "Y" | "tie", "margin": "clear" | "slight", "reasons": "<three sentences max>"}
"""


def _doc(run_id: str) -> str:
    d = RUNS_BASE / run_id
    inv = (d / "investigation.md").read_text(encoding="utf-8", errors="replace") if (d / "investigation.md").exists() else "(missing)"
    rep = (d / "report.md").read_text(encoding="utf-8", errors="replace") if (d / "report.md").exists() else "(no report — the run did not close)"
    return f"--- investigation.md ---\n{inv}\n\n--- report.md ---\n{rep}\n"


def _judge_once(x: str, y: str) -> dict:
    prompt = f"{JUDGE_RUBRIC}\n\n=== RUN X ===\n{_doc(x)}\n\n=== RUN Y ===\n{_doc(y)}\n"
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    proc = subprocess.run(  # noqa: S603
        ["claude", "-p", "--model", JUDGE_MODEL], input=prompt, capture_output=True,
        text=True, env=env, timeout=1800, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude -p failed: {proc.stderr[-500:]}")
    return _parse_verdict(proc.stdout)


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _parse_verdict(text: str) -> dict:
    """The judge's JSON object, tolerant only of formatting: a fence, prose around the object,
    a trailing comma. A reply with no readable object is recorded as an unparsed tie rather
    than ending the pass — one bad reply must not discard the pairs already judged."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1].rsplit("```", 1)[0]
    m = re.search(r"\{.*\}", t, re.S)
    if m:
        try:
            return json.loads(_TRAILING_COMMA.sub(r"\1", m.group(0)))
        except json.JSONDecodeError:
            pass
    return {"winner": "tie", "margin": "unparsed", "reasons": t[:300]}


def cmd_judge(args: argparse.Namespace) -> int:
    entries = [json.loads(l) for l in Path(args.manifest).read_text().splitlines() if l.strip()]
    left, right = args.arms
    a = [e["run_id"] for e in entries if e["fixture"] == args.fixture and e["arm"] == left]
    c = [e["run_id"] for e in entries if e["fixture"] == args.fixture and e["arm"] == right]
    pairs = list(product(a, c))[: args.cap]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tally = defaultdict(int)
    with out.open("a", encoding="utf-8") as fh:
        for ra, rc in pairs:
            v1 = _judge_once(ra, rc)          # X=A, Y=C
            v2 = _judge_once(rc, ra)          # X=C, Y=A
            pref1 = {"X": left, "Y": right}.get(v1.get("winner"), "tie")
            pref2 = {"X": right, "Y": left}.get(v2.get("winner"), "tie")
            verdict = pref1 if pref1 == pref2 else "tie"   # order-flip counts as a tie
            tally[verdict] += 1
            row = {"fixture": args.fixture, left: ra, right: rc, "A": ra, "C": rc, "arms": [left, right],
                   "order1": v1, "order2": v2, "verdict": verdict}
            fh.write(json.dumps(row) + "\n")
            print(f"{ra} vs {rc}: {verdict}  ({pref1}/{pref2})")
    n = sum(tally.values())
    print(f"\n{args.fixture} {left} vs {right}: n={n} pairs  {right} preferred {tally[right]}/{n}  {left} preferred {tally[left]}/{n}  tie {tally['tie']}/{n}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score")
    s.add_argument("--manifest", default=str(HERE / "runs" / "manifest.jsonl"))
    s.add_argument("--out", default=str(HERE / "results" / "final.jsonl"))
    s.add_argument("--only", nargs="*", help="run ids to restrict to")
    s.set_defaults(fn=cmd_score)
    j = sub.add_parser("judge")
    j.add_argument("--manifest", default=str(HERE / "runs" / "manifest.jsonl"))
    j.add_argument("--fixture", required=True)
    j.add_argument("--cap", type=int, default=15)
    j.add_argument("--arms", nargs=2, default=["A", "C"], metavar=("LEFT", "RIGHT"))
    j.add_argument("--out", default=str(HERE / "results" / "judge.jsonl"))
    j.set_defaults(fn=cmd_judge)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
