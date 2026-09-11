#!/usr/bin/env python3
"""gather-flash-port analysis — one row per GATHER DISPATCH, aggregated per (arm, fixture).

A dispatch is a lead the gather subagent actually ran a model for (≥1 `gather:<lead>` call in
the wire log). The harness's own model-less ancestor query (`l-000`) is not one.

Per dispatch
  * completed        — gather_summaries/<lead>.md exists AND is a summary, not the harness's
                       "hit its request limit / dead end / ended abnormally" stand-in (the tool
                       writes those to the same file so MAIN sees something); `terminated` names
                       which
  * fidelity         — an LLM judge (claude-opus-5 via `claude -p`, blind to arm) scores each
                       `what_to_summarize` dimension exact | wrong | dropped against every tool
                       return gather itself saw (wire log), and lists `unsupported` measurements
                       the summary states that no return contains. Cached under results/extractions/.
  * requests, retries (retry-prompt parts fed back), queries, query_errors
  * cost (defender.scripts.pricing), cached share, reasoning tokens
  * wall (first→last gather response), and how many sibling dispatches overlapped it
Per run
  * dispatches, disposition vs label, concluded, review outcome, whole-run $ by role

Rank by per-dispatch mean with n as support. Never count-weighted.

Usage:
    python3 analyze.py                 # everything under runs/ named in manifest.jsonl
    python3 analyze.py --no-judge      # skip the LLM pass (reliability + cost only)
    python3 analyze.py --runs a b c    # a subset
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

_EXP = Path(__file__).resolve().parent
RUNS = _EXP / "runs"
RESULTS = _EXP / "results"
EXTRACTIONS = RESULTS / "extractions"
JUDGE_MODEL = "claude-opus-5"
SEEN_CAP = 120_000  # bytes of tool-return text the judge sees per dispatch

sys.path.insert(0, str(_EXP.parents[1]))  # the `defender` package is <repo>/defender
from defender.scripts.pricing import usage_cost  # noqa: E402

_JUDGE = """You score a security 'gather' summary against what the gather subagent actually saw.
The subagent was asked to report specific measurements (the DIMENSIONS below) over systems of
record; WHAT GATHER SAW is every tool return it received — query results, file reads, adapter
error text, corrections — in order, so it is the ground truth. Classify each dimension:
  exact   — the summary addresses it and every value it gives is supported by the payloads
            (formatting/precision differences are fine; a count you can verify from the rows
            and that matches is exact; an honest "0 / none found" is exact when the payloads
            are empty for it)
  wrong   — the summary addresses it but a value contradicts the payloads (a count that is
            off, an under-reported cardinality, a wrong timestamp/host/user)
  dropped — the summary does not address it at all
Then list UNSUPPORTED claims: any specific measurement (a number, an entity name, a timestamp)
the summary asserts as observed that appears in no tool return. An error message or HTTP
status the tool returned counts as seen. Do not list interpretation, caveats, or the
subagent's own reasoning about what a result means — only concrete values presented as
measured. Be strict about 'wrong' and about 'unsupported'; be lenient about wording. If a
return was truncated (marked [TRUNCATED]) and a value could plausibly sit in the cut part,
count it exact, not unsupported.

Return ONLY a JSON object:
{"dims": {"<dimension text, verbatim>": {"status": "exact|wrong|dropped", "note": "<short>"}},
 "unsupported": ["<claim>", ...]}
"""


# ---------------------------------------------------------------- extraction per dispatch

def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _wire(run_dir: Path) -> list[dict]:
    p = run_dir / "wire_logs" / "llm_requests.jsonl"
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.open(encoding="utf-8") if line.strip()]


def _queries(run_dir: Path) -> dict[str, list[dict]]:
    out = defaultdict(list)
    p = run_dir / "executed_queries.jsonl"
    if p.is_file():
        for line in p.open(encoding="utf-8"):
            if line.strip():
                q = json.loads(line)
                out[q["lead_id"]].append(q)
    return out


_TERMINATORS = (
    ("request_limit", "hit its request limit"),
    ("dead_end", "hit a dead end"),
    ("abnormal", "ended abnormally"),
)


def _terminated(summary_p: Path) -> str | None:
    """Which harness stand-in the summary file is, or None for a real summary. The tool writes
    `gather for <lead> <terminator text>...` as the whole output of a dispatch it cut short."""
    if not summary_p.is_file():
        return "missing"
    head = summary_p.read_text(encoding="utf-8", errors="replace")[:600]
    for name, needle in _TERMINATORS:
        if needle in head:
            return name
    return None


def dispatches(run_dir: Path) -> list[dict]:
    """One row per lead that saw ≥1 gather model call."""
    wire = _wire(run_dir)
    by_lead: dict[str, dict] = defaultdict(lambda: {
        "requests": 0, "retry_ids": set(), "cost": 0.0, "in": 0, "cr": 0, "out": 0, "reason": 0,
        "first": None, "last": None, "models": set(), "finish": None,
    })
    for rec in wire:
        aid = rec.get("agent_id", "")
        if not aid.startswith("gather:"):
            continue
        lid = aid.split(":", 1)[1]
        a = by_lead[lid]
        msg = rec.get("message", {})
        if rec["kind"] == "request":
            # Every request carries the whole history, so a retry-prompt part recurs in each
            # later request of the dispatch; count each distinct one once.
            for p in msg.get("parts", []):
                if p.get("part_kind") == "retry-prompt":
                    a["retry_ids"].add((p.get("tool_call_id"), p.get("timestamp"), str(p.get("content"))[:120]))
        elif rec["kind"] == "response":
            a["requests"] += 1
            u = rec.get("usage") or {}
            a["cost"] += usage_cost(rec.get("model", ""), u)
            a["in"] += u.get("input_tokens", 0)
            a["cr"] += u.get("cache_read_input_tokens", 0)
            a["out"] += u.get("output_tokens", 0)
            a["reason"] += ((msg.get("usage") or {}).get("details") or {}).get("reasoning_tokens", 0)
            a["models"].add(rec.get("model", ""))
            a["finish"] = msg.get("finish_reason")
            ts = msg.get("timestamp")
            if ts:
                t = _ts(ts)
                dur = rec.get("duration_ms") or 0
                start = datetime.fromtimestamp(t.timestamp() - dur / 1000, tz=t.tzinfo)
                a["first"] = start if a["first"] is None or start < a["first"] else a["first"]
                a["last"] = t if a["last"] is None or t > a["last"] else a["last"]
    qs = _queries(run_dir)
    rows = []
    for lid, a in by_lead.items():
        if a["requests"] == 0:
            continue
        lead = {}
        lp = run_dir / "gather_raw" / f"{lid}.lead.json"
        if lp.is_file():
            lead = json.loads(lp.read_text(encoding="utf-8"))
        summary_p = run_dir / "gather_summaries" / f"{lid}.md"
        terminated = _terminated(summary_p)
        q = qs.get(lid, [])
        rows.append({
            "run_id": run_dir.name, "lead": lid,
            "provenance": lead.get("provenance"),
            "goal": lead.get("goal", ""),
            "dims": list(lead.get("what_to_summarize", [])),
            "completed": summary_p.is_file() and terminated is None,
            "terminated": terminated,
            "finish": a["finish"],
            "requests": a["requests"], "retries": len(a["retry_ids"]),
            "queries": len(q), "query_errors": sum(1 for x in q if x.get("exit_code")),
            "cost": round(a["cost"], 5),
            "in_tokens": a["in"], "cache_read": a["cr"], "out_tokens": a["out"],
            "reasoning_tokens": a["reason"],
            "cached_share": (a["cr"] / (a["in"] + a["cr"])) if (a["in"] + a["cr"]) else 0.0,
            "wall_s": (a["last"] - a["first"]).total_seconds() if a["first"] and a["last"] else None,
            "first": a["first"].isoformat() if a["first"] else None,
            "last": a["last"].isoformat() if a["last"] else None,
            "models": sorted(a["models"]),
        })
    # overlap: how many sibling dispatches were live at this one's midpoint
    for r in rows:
        if not r["first"]:
            r["overlap"] = 0
            continue
        mid = _ts(r["first"]) + (_ts(r["last"]) - _ts(r["first"])) / 2
        r["overlap"] = sum(
            1 for o in rows if o is not r and o["first"] and _ts(o["first"]) <= mid <= _ts(o["last"])
        )
    return sorted(rows, key=lambda r: r["lead"])


# ---------------------------------------------------------------- judge

def _seen_text(run_dir: Path, lid: str) -> str:
    """Everything the gather model was shown for this dispatch: every tool return and every
    correction, in first-seen order. The wire log writes one record per history message per
    turn, so the same part recurs; it is kept once by (kind, tool_call_id). This — not the
    saved payload files — is the ground truth: an adapter's error text (an HTTP 404 body) is
    something gather read and may legitimately report, and it is in no payload file."""
    seen: dict[tuple, dict] = {}
    for rec in _wire(run_dir):
        if rec.get("agent_id") != f"gather:{lid}" or rec.get("kind") != "request":
            continue
        for part in rec.get("message", {}).get("parts", []):
            kind = part.get("part_kind")
            if kind not in ("tool-return", "retry-prompt"):
                continue
            key = (kind, part.get("tool_call_id"), part.get("timestamp"))
            if key not in seen:
                seen[key] = part
    if not seen:
        return "(nothing returned to the model)"
    parts = list(seen.values())
    per = max(SEEN_CAP // len(parts), 1500)
    chunks = []
    for i, part in enumerate(parts):
        c = part.get("content")
        t = c if isinstance(c, str) else json.dumps(c)
        if len(t) > per:
            t = t[:per] + "\n[TRUNCATED]"
        label = "correction" if part.get("part_kind") == "retry-prompt" else f"tool {part.get('tool_name')}"
        chunks.append(f"--- return {i} ({label}) ---\n{t}")
    return "\n".join(chunks)


def _queries_text(run_dir: Path, lid: str) -> str:
    return "\n".join(
        f"{q['seq']}: {q.get('raw_command','')}  (exit={q.get('exit_code')}, payload={q.get('payload_path')})"
        for q in _queries(run_dir).get(lid, [])
    ) or "(none)"


def _parse(text: str) -> dict | None:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1].rsplit("```", 1)[0]
    m = re.search(r"\{.*\}", t, re.S)
    if not m:
        return None
    try:
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", m.group(0)))
    except json.JSONDecodeError:
        return None


def judge(run_dir: Path, row: dict) -> dict | None:
    if not row["completed"] or not row["dims"]:
        return None
    cache = EXTRACTIONS / run_dir.name / f"{row['lead']}.json"
    if cache.is_file():
        return json.loads(cache.read_text(encoding="utf-8"))
    summary = (run_dir / "gather_summaries" / f"{row['lead']}.md").read_text(encoding="utf-8")
    dims = "\n".join(f"- {d}" for d in row["dims"])
    prompt = (
        f"{_JUDGE}\n\n=== GOAL ===\n{row['goal']}\n\n=== DIMENSIONS ===\n{dims}\n\n"
        f"=== QUERIES RUN ===\n{_queries_text(run_dir, row['lead'])}\n\n"
        f"=== WHAT GATHER SAW (tool returns, in order) ===\n{_seen_text(run_dir, row['lead'])}\n\n=== SUMMARY ===\n{summary}\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    proc = subprocess.run(  # noqa: S603
        ["claude", "-p", "--model", JUDGE_MODEL], input=prompt, capture_output=True,
        text=True, env=env, timeout=1800, check=False,
    )
    if proc.returncode != 0:
        print(f"  judge failed {run_dir.name}/{row['lead']}: {proc.stderr[-300:]}", file=sys.stderr)
        return None
    verdict = _parse(proc.stdout)
    if verdict is None:
        print(f"  judge unparsed {run_dir.name}/{row['lead']}", file=sys.stderr)
        return None
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(verdict, indent=1), encoding="utf-8")
    return verdict


def score(row: dict, verdict: dict | None) -> None:
    n = len(row["dims"])
    if verdict is None or n == 0:
        row.update(exact=None, wrong=None, dropped=None, unsupported=None, error_rate=None)
        return
    statuses = [v.get("status") for v in verdict.get("dims", {}).values()]
    # the judge may re-key dimensions; count what it returned, bounded by what was asked
    wrong = min(statuses.count("wrong"), n)
    dropped = min(statuses.count("dropped"), n)
    exact = max(0, min(statuses.count("exact"), n - wrong - dropped))
    unsup = len(verdict.get("unsupported") or [])
    row.update(exact=exact, wrong=wrong, dropped=dropped, unsupported=unsup,
               error_rate=min(1.0, (wrong + dropped + unsup) / n))


# ---------------------------------------------------------------- run level

def run_row(run_dir: Path, meta: dict, drows: list[dict]) -> dict:
    fm = {}
    rp = run_dir / "report.md"
    if rp.is_file():
        head = rp.read_text(encoding="utf-8").split("---")
        if len(head) >= 3:
            for line in head[1].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fm[k.strip()] = v.strip()
    by_role = defaultdict(float)
    for rec in _wire(run_dir):
        if rec["kind"] == "response":
            by_role[rec["agent_id"].split(":")[0]] += usage_cost(rec.get("model", ""), rec.get("usage") or {})
    return {
        "run_id": run_dir.name, "arm": meta.get("arm"), "fixture": meta.get("fixture"),
        "label": meta.get("label"), "exit": meta.get("exit"),
        "concluded": rp.is_file(), "disposition": fm.get("disposition"),
        "correct": (fm.get("disposition") == meta.get("label")) if meta.get("label") else None,
        "review_outcome": fm.get("outcome"),
        "dispatches": len(drows),
        "cost_main": round(by_role.get("main", 0.0), 4),
        "cost_gather": round(by_role.get("gather", 0.0), 4),
        "cost_review": round(by_role.get("review", 0.0), 4),
        "cost_total": round(sum(by_role.values()), 4),
        "gather_models": sorted({m for r in drows for m in r["models"]}),
    }


# ---------------------------------------------------------------- aggregate

def _mean(xs):
    xs = [x for x in xs if x is not None]
    return (sum(xs) / len(xs)) if xs else None


def _f(x, fmt="{:.2f}"):
    return "—" if x is None else fmt.format(x)


def table(drows: list[dict], rrows: list[dict]) -> str:
    arm_of = {r["run_id"]: (r["arm"], r["fixture"]) for r in rrows}
    groups = defaultdict(list)
    for d in drows:
        groups[arm_of.get(d["run_id"], ("?", "?"))].append(d)
    out = ["| arm | fixture | n disp | completed | exact | error rate | unsupported/disp | reqs | retries | queries | q-err | $/disp | cached | reasoning tok | wall s | overlap |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for (arm, fx), g in sorted(groups.items()):
        judged = [d for d in g if d.get("error_rate") is not None]
        out.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            arm, fx, len(g),
            _f(_mean([d["completed"] for d in g]), "{:.0%}"),
            _f(_mean([d["exact"] / len(d["dims"]) for d in judged if d["dims"]]), "{:.0%}") + f" (n={len(judged)})",
            _f(_mean([d["error_rate"] for d in judged]), "{:.0%}"),
            _f(_mean([d["unsupported"] for d in judged])),
            _f(_mean([d["requests"] for d in g]), "{:.1f}"),
            _f(_mean([d["retries"] for d in g]), "{:.1f}"),
            _f(_mean([d["queries"] for d in g]), "{:.1f}"),
            _f(_mean([d["query_errors"] for d in g]), "{:.1f}"),
            _f(_mean([d["cost"] for d in g]), "{:.4f}"),
            _f(_mean([d["cached_share"] for d in g]), "{:.0%}"),
            _f(_mean([d["reasoning_tokens"] for d in g]), "{:.0f}"),
            _f(_mean([d["wall_s"] for d in g]), "{:.0f}"),
            _f(_mean([d["overlap"] for d in g]), "{:.1f}"),
        ))
    out.append("")
    out.append("| arm | fixture | runs | concluded | correct vs label | dispatches/run | $ gather/run | $ main/run | $ total/run |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    rg = defaultdict(list)
    for r in rrows:
        rg[(r["arm"], r["fixture"])].append(r)
    for (arm, fx), g in sorted(rg.items()):
        out.append("| {} | {} | {} | {}/{} | {}/{} | {} | {} | {} | {} |".format(
            arm, fx, len(g), sum(1 for r in g if r["concluded"]), len(g),
            sum(1 for r in g if r["correct"]), sum(1 for r in g if r["correct"] is not None),
            _f(_mean([r["dispatches"] for r in g]), "{:.1f}"),
            _f(_mean([r["cost_gather"] for r in g]), "{:.3f}"),
            _f(_mean([r["cost_main"] for r in g]), "{:.3f}"),
            _f(_mean([r["cost_total"] for r in g]), "{:.3f}"),
        ))
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-judge", action="store_true")
    ap.add_argument("--runs", nargs="*", default=None)
    ap.add_argument("--out", default=None, help="write the table to results/<out>.md")
    args = ap.parse_args()

    manifest = {}
    mp = RUNS / "manifest.jsonl"
    if mp.is_file():
        for line in mp.open(encoding="utf-8"):
            if line.strip():
                m = json.loads(line)
                manifest[m["run_id"]] = m
    run_ids = args.runs or sorted(r for r, m in manifest.items() if not m.get("excluded"))
    drows, rrows = [], []
    for rid in run_ids:
        rd = RUNS / rid
        if not rd.is_dir():
            print(f"  missing run dir {rid}", file=sys.stderr)
            continue
        ds = dispatches(rd)
        for d in ds:
            score(d, None if args.no_judge else judge(rd, d))
        drows.extend(ds)
        rrows.append(run_row(rd, manifest.get(rid, {"arm": "?", "fixture": "?"}), ds))

    RESULTS.mkdir(exist_ok=True)
    with (RESULTS / "dispatches.jsonl").open("w", encoding="utf-8") as f:
        for d in drows:
            f.write(json.dumps(d) + "\n")
    with (RESULTS / "runs.jsonl").open("w", encoding="utf-8") as f:
        for r in rrows:
            f.write(json.dumps(r) + "\n")
    t = table(drows, rrows)
    print(t)
    if args.out:
        (RESULTS / f"{args.out}.md").write_text(t + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
