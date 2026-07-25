#!/usr/bin/env python3
"""Score oracle projection vs. actual telemetry, in the oracle's own 4-way
vocabulary. Scores at the PER-QUERY grain (where the category is well-defined)
and then aggregates to the lead, because a lead can bundle queries whose
envelopes fall in different categories — the reason l-002 / l-006 looked like
oracle "misses" under the earlier lead-grain scorer.

Category (per query's actual result, as a signed diff over baseline):
  +event  event-stream query whose window overlaps the attack AND whose rows
          carry the attack signature (failures in-window / attacker src / canary)
  +noise  event-stream query returning baseline-shaped routine only (no attack
          delta) — e.g. the source's historical logins to other hosts
  0       state/lookup query (returns current config, no event stream), OR an
          event query whose window/filter the attack never touched (empty delta)
  -event  (never expected here) an event query that SHOULD carry the attack but
          came back empty — a real miss

The oracle emits ONE category per LEAD. The truthful lead category is the
"strongest" of its queries: +event > +noise > 0. Divergence is reported with
the per-query breakdown that explains it.

Actuals are read OFFLINE from the run's captured payloads (gather_raw/) +
executed_queries.jsonl — no live ES needed (the env is levered down). The
distinguishability of the attack rows from baseline was measured live before
teardown and is recorded below with provenance; pass --live to re-measure when
the env is up.

Usage: analyze.py <projection.yaml> <run_dir> [--live]
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

# Attack ground truth (attacks/runs/ssh-brute-force-canary-42-e7d87435/meta.json).
ATTACK_START = "2026-07-25T07:45:35Z"
ATTACK_END = "2026-07-25T07:48:40Z"
ATTACK_SRC = "172.18.0.15"
CANARY = ("canary-1", "172.18.0.9")

# Distinguishability, measured live on 2026-07-25 before teardown (see
# results/findings.md). canary-1 sshd failures from 172.18.0.15:
#   attack window = 96 ; C1-today-pre = 0 ; C2 -14d = 0 ; C3 -21d = 0
# => the attack rows are absent from every shape-matched control window, so an
#    in-window failure row is a genuine +event delta, not baseline coincidence.
RECORDED_DISTINGUISHABILITY = {"attack": 96, "C1-today-pre": 0, "C2-14d": 0, "C3-21d": 0}

STATE_SYSTEMS = {"cmdb", "identity", "threat-intel", "change-mgmt"}
_ISO = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"


def _to_epoch(iso: str) -> float:
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", iso)
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    # crude ordinal ok for same-year comparisons
    return ((((y * 366 + mo * 31 + d) * 24 + h) * 60 + mi) * 60) + s


ATK_S, ATK_E = _to_epoch(ATTACK_START), _to_epoch(ATTACK_END)


def query_window(params: dict) -> tuple[str, str] | None:
    """Extract (start, end) from an ES|QL body, or None for state queries /
    all-time queries with no @timestamp bound."""
    q = params.get("query")
    if not isinstance(q, str):
        return None
    m = re.search(rf'@timestamp >= "({_ISO})" AND @timestamp < "({_ISO})"', q)
    return (m.group(1), m.group(2)) if m else None


def window_overlaps_attack(win: tuple[str, str] | None) -> bool:
    if win is None:
        return True  # all-time / unbounded → includes the attack instant
    s, e = _to_epoch(win[0]), _to_epoch(win[1])
    return s < ATK_E and e > ATK_S


def load_rows(run_dir: Path, lead_id: str, seq: int) -> list:
    f = run_dir / "gather_raw" / lead_id / f"{seq}.json"
    if not f.is_file():
        return []
    try:
        doc = json.loads(f.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if isinstance(doc, dict) and isinstance(doc.get("values"), list):
        return doc["values"]
    return doc if isinstance(doc, list) else []


def row_has_attack_signature(rows: list) -> bool:
    """A row is attack-attributable if it shows in-window failures or names the
    attacker src / canary. Robust to GROUP BY dropping the source.ip column: any
    failure count > 0 whose first/last_seen lands in the attack window is the
    burst (these queries already filter source.ip == attacker)."""
    for r in rows:
        if not isinstance(r, dict):
            blob = json.dumps(r)
            if ATTACK_SRC in blob or CANARY[1] in blob:
                return True
            continue
        blob = json.dumps(r)
        failed = r.get("failed") or r.get("failed_count") or r.get("total_failed") or 0
        fseen = r.get("first_seen") or r.get("last_seen") or r.get("@timestamp")
        in_win = isinstance(fseen, str) and ATK_S <= _to_epoch(fseen) <= ATK_E + 5
        if isinstance(failed, (int, float)) and failed > 0 and in_win:
            return True
        if (ATTACK_SRC in blob or CANARY[1] in blob) and ("fail" in blob.lower() or in_win):
            return True
    return False


def rows_have_baseline_routine(rows: list) -> bool:
    """Non-attack event rows = the source's historical routine (e.g. accepted
    logins to other hosts, outside the attack window)."""
    for r in rows:
        if not isinstance(r, dict):
            continue
        accepted = r.get("accepted") or 0
        fseen = r.get("first_seen") or r.get("@timestamp")
        out_win = isinstance(fseen, str) and _to_epoch(fseen) < ATK_S - 60
        if isinstance(accepted, (int, float)) and accepted > 0 and out_win:
            return True
    return False


def classify_query(system: str, query_id: str, params: dict, rows: list) -> tuple[str, str]:
    if system in STATE_SYSTEMS:
        return "0", "state/lookup — current config, no event stream"
    win = query_window(params)
    overlaps = window_overlaps_attack(win)
    if query_id.endswith("detection-alerts"):
        return ("+event" if rows else "0",
                "success-after-failure alert present" if rows else "no such alert (0 rows)")
    if overlaps and row_has_attack_signature(rows):
        return "+event", "in-window failure burst / attacker src present"
    if rows_have_baseline_routine(rows):
        return "+noise", "source's historical routine (out-of-window, accepted)"
    if not rows:
        return "0", "empty (attack never touched this window/filter)"
    return "0", "rows present but no attack delta"


RANK = {"-event": 3, "+event": 2, "+noise": 1, "0": 0}


def predicted_category(events: list) -> str:
    if not events:
        return "0"
    markers = [e for e in events if isinstance(e, str)]
    if markers:
        return "-noise" if any(m.strip().startswith("<suppressed") for m in markers) else "+noise"
    return "+event"


def maybe_live_distinguishability() -> dict:
    def cnt(start, end):
        body = {"size": 0, "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": start, "lt": end}}},
            {"term": {"host.name": "canary-1"}}, {"term": {"process.name": "sshd"}},
            {"term": {"event.outcome": "failure"}}, {"term": {"source.ip": ATTACK_SRC}}]}}}
        out = subprocess.run(["/workspace/infra/bin/es.sh", "/logs-system.auth-*/_search",
                              "-H", "Content-Type: application/json", "-d", json.dumps(body)],
                             capture_output=True, text=True, timeout=90)
        return json.loads(out.stdout)["hits"]["total"]["value"]
    return {"attack": cnt("2026-07-25T07:45:00Z", "2026-07-25T07:50:00Z"),
            "C1-today-pre": cnt("2026-07-25T06:00:00Z", "2026-07-25T07:44:00Z"),
            "C2-14d": cnt("2026-07-11T07:30:00Z", "2026-07-11T08:30:00Z"),
            "C3-21d": cnt("2026-07-04T07:30:00Z", "2026-07-04T08:30:00Z")}


def main() -> None:
    projection = yaml.safe_load(Path(sys.argv[1]).read_text())
    run_dir = Path(sys.argv[2])
    live = "--live" in sys.argv[3:]
    preds = {p["lead_id"]: p["events"] for p in projection["projections"]}

    dist = maybe_live_distinguishability() if live else RECORDED_DISTINGUISHABILITY
    print("== distinguishability (canary-1 failures from %s) %s ==" %
          (ATTACK_SRC, "[live]" if live else "[recorded pre-teardown]"))
    for k, v in dist.items():
        print(f"  {k:<13} : {v}")
    print(f"  => attack rows off-baseline: {dist['attack'] > 0 and max(v for k, v in dist.items() if k != 'attack') == 0}\n")

    # group executed queries by lead
    byq: dict[str, list] = {}
    for line in (run_dir / "executed_queries.jsonl").read_text().splitlines():
        r = json.loads(line)
        byq.setdefault(r["lead_id"], []).append(r)

    print("== per-query actual categories → aggregated lead truth vs oracle ==")
    agree = diverge = 0
    for lead_id in sorted(preds):
        qs = sorted(byq.get(lead_id, []), key=lambda r: r["seq"])
        per_q = []
        for r in qs:
            rows = load_rows(run_dir, lead_id, r["seq"])
            cat, why = classify_query(r["system"], r["query_id"], r["params"], rows)
            per_q.append((r["seq"], r["query_id"], cat, why))
        actual = max((c for _, _, c, _ in per_q), key=lambda c: RANK[c], default="0")
        pred = predicted_category(preds[lead_id])
        ok = pred == actual
        agree += ok
        diverge += not ok
        heterogeneous = len({c for _, _, c, _ in per_q}) > 1
        flag = "MATCH" if ok else "DIVERGE"
        het = "  (heterogeneous lead)" if heterogeneous else ""
        print(f"\n  {lead_id}  pred={pred:<7} actual={actual:<7} {flag}{het}")
        for seq, qid, cat, why in per_q:
            print(f"      seq{seq} {qid:<32} {cat:<7} {why}")

    print(f"\n  lead-level category agreement: {agree}/{agree+diverge}")

    print("\n== field grounding (+event leads) — concrete values only ==")
    for lead_id in ("l-001", "l-004"):
        evs = [e for e in preds.get(lead_id, []) if isinstance(e, dict)]
        concrete = [(k, v) for e in evs[:1] for k, v in e.items() if not str(v).startswith("<")]
        print(f"  {lead_id}: " + ", ".join(f"{k}={v}" for k, v in concrete))


if __name__ == "__main__":
    main()
