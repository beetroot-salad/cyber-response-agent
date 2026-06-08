#!/usr/bin/env python3
"""Aggregate effort-tradeoff runs: cost / time / quality per (fixture, effort).

Reads each run's:
  - tool_trace.jsonl `result` event  -> total_cost_usd, output_tokens, cache, duration_ms, num_turns
  - assistant content blocks          -> orchestrator thinking vs text chars (where output went)
  - report.md frontmatter             -> disposition, confidence
  - investigation.md conclude         -> matched_archetype
  - results/run_manifest.jsonl        -> harness wall-clock, rc

Ground truth: malicious fixture must NOT be benign (no false negative);
benign fixture must be benign (no over-escalation).
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path

EXP = Path("/workspace/experiments/effort-tradeoff")
MANIFEST = EXP / "results" / "run_manifest.jsonl"

# Ground truth turned out subtler than benign/malicious (see plan.md + results).
# `mal` fixture is a detection FP: a failed dev.dana invalid-user spray joined by
# host.name to an UNRELATED authorized sre.chen login. Correct handling = decompose
# + ground the authorized leg + flag the spray as a companion concern. `ben` is
# routine sre baseline. So we don't binary-score disposition; we capture it plus
# whether the run retained the key nuances (spray flagged; authorization grounded).
SPRAY_RE = re.compile(r"spray|companion|separate investigation|office-ws-1|invalid user|warrant", re.I)
AUTHZ_RE = re.compile(r"authorized|iam-policy|trust edge|approved-source|bastion|sre\.chen", re.I)


def parse_result_and_thinking(trace: Path) -> dict:
    result = None
    think = text = 0
    for line in trace.open():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "result":
            result = e.get("usage", {}) | {
                "duration_ms": e.get("duration_ms"),
                "num_turns": e.get("num_turns"),
                "total_cost_usd": e.get("total_cost_usd"),
            }
        elif e.get("type") == "assistant":
            for c in (e.get("message", {}).get("content") or []):
                if c.get("type") == "thinking":
                    think += len(c.get("thinking", ""))
                elif c.get("type") == "text":
                    text += len(c.get("text", ""))
    return {"result": result, "think_chars": think, "text_chars": text}


def frontmatter(md: Path) -> dict:
    if not md.exists():
        return {}
    m = re.match(r"^---\n(.*?)\n---", md.read_text(), re.S)
    out = {}
    if m:
        for ln in m.group(1).splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                out[k.strip()] = v.strip()
    return out


def archetype(inv: Path) -> str | None:
    if not inv.exists():
        return None
    m = re.search(r"matched_archetype\s+(\S+)", inv.read_text())
    return m.group(1) if m else None


def nuance_flags(rd: Path) -> dict:
    """Heuristic reasoning-quality signals from report.md + investigation.md."""
    text = ""
    for fn in ("report.md", "investigation.md"):
        p = rd / fn
        if p.exists():
            text += p.read_text()
    return {
        "spray_flagged": bool(SPRAY_RE.search(text)),
        "authz_grounded": bool(AUTHZ_RE.search(text)),
    }


def main() -> None:
    rows = []
    for ln in MANIFEST.read_text().splitlines():
        if not ln.strip():
            continue
        man = json.loads(ln)
        rd = Path(man["run_dir"])
        trace = rd / "tool_trace.jsonl"
        info = parse_result_and_thinking(trace) if trace.exists() else {"result": None, "think_chars": 0, "text_chars": 0}
        r = info["result"] or {}
        fm = frontmatter(rd / "report.md")
        disp = fm.get("disposition")
        nf = nuance_flags(rd)
        row = {
            "run_id": man["run_id"], "effort": man["effort"], "fixture": man["fixture"],
            "rc": man["rc"],
            "cost_usd": r.get("total_cost_usd"),
            "out_tok": r.get("output_tokens"),
            "cache_read": r.get("cache_read_input_tokens"),
            "cache_create": r.get("cache_creation_input_tokens"),
            "dur_s": round(r["duration_ms"] / 1000, 1) if r.get("duration_ms") else None,
            "turns": r.get("num_turns"),
            "think_chars": info["think_chars"], "text_chars": info["text_chars"],
            "think_pct": round(100 * info["think_chars"] / max(info["think_chars"] + info["text_chars"], 1), 1),
            "disposition": disp, "confidence": fm.get("confidence"),
            "archetype": archetype(rd / "investigation.md"),
            "spray_flag": nf["spray_flagged"], "authz": nf["authz_grounded"],
        }
        rows.append(row)

    # table
    cols = ["run_id", "effort", "fixture", "rc", "cost_usd", "out_tok", "cache_read",
            "dur_s", "turns", "think_pct", "disposition", "confidence", "spray_flag", "authz"]
    w = {c: max(len(c), *(len(str(r.get(c))) for r in rows)) for c in cols} if rows else {}
    print("  ".join(c.ljust(w[c]) for c in cols))
    for r in sorted(rows, key=lambda x: (x["fixture"], ["low", "medium", "high"].index(x["effort"]))):
        print("  ".join(str(r.get(c)).ljust(w[c]) for c in cols))

    # per-effort means (support n shown) — propagation + tradeoff view
    print("\n# per-effort means (n = support)")
    for eff in ["low", "medium", "high"]:
        sub = [r for r in rows if r["effort"] == eff and r["cost_usd"] is not None]
        if not sub:
            continue
        n = len(sub)
        mc = sum(r["cost_usd"] for r in sub) / n
        md = sum(r["dur_s"] for r in sub if r["dur_s"]) / n
        mo = sum(r["out_tok"] for r in sub) / n
        print(f"  {eff:6} n={n}  cost=${mc:.2f}  dur={md:.0f}s  out_tok={mo:.0f}")

    Path(EXP / "results" / "metrics.json").write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {EXP/'results'/'metrics.json'}")


if __name__ == "__main__":
    main()
