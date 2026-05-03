#!/usr/bin/env python3
"""
Mechanical replacement for the `ticket-context` subagent.

Dispatches parallel wazuh_cli.py queries for the alert's Key Observables + the
same-signature query, then clusters returned alerts into `repeats` (all observables
match) and `related` (shares >=1 observable, grouped by distinct shared-dimension set).
Emits the YAML schema documented in soc-agent/agents/ticket-context.md.

Inputs: --run-dir (has alert.json), --signature-id (for field-quirks.md).
Output: fenced YAML block on stdout, matching the subagent's contract.
Debug trace is written to stderr (prefix `[ticket_context]`).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, UTC
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WAZUH_CLI = REPO_ROOT / "scripts" / "tools" / "wazuh_cli.py"
CLUSTER_COMPRESSION_THRESHOLD = 20
HIGH_VOLUME_THRESHOLD = 100


def _dbg(msg: str) -> None:
    print(f"[ticket_context] {msg}", file=sys.stderr, flush=True)


def parse_key_observables(field_quirks_path: Path) -> list[dict]:
    """Parse the `| Observable | JSON path | ... |` markdown table from field-quirks.md.

    Returns a list of {name, json_path} entries preserving table order. Raises if
    the table is missing or empty — fail-fast per repo convention.
    """
    text = field_quirks_path.read_text()
    m = re.search(
        r"^## Key observables\s*\n\n(\|[^\n]*\|\s*\n)+",
        text,
        re.MULTILINE,
    )
    if not m:
        raise RuntimeError(f"No ## Key observables table found in {field_quirks_path}")
    lines = [ln.strip() for ln in m.group(0).splitlines() if ln.startswith("|")]
    if len(lines) < 3:
        raise RuntimeError(f"Key observables table in {field_quirks_path} has no data rows")
    observables = []
    for ln in lines[2:]:  # skip header + separator
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) < 2 or not cells[0] or not cells[1]:
            continue
        json_path = cells[1].strip("` ")
        observables.append({"name": cells[0], "json_path": json_path})
    if not observables:
        raise RuntimeError(f"No observables parsed from {field_quirks_path}")
    return observables


def extract_json_path(obj: dict, dotted_path: str):
    """Walk a dotted JSON path through a nested dict. Returns value or None."""
    cur = obj
    for part in dotted_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _scalar(v):
    """Coerce an observable value to a YAML/hash-safe scalar string, or None."""
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return str(v)
    # Lists/dicts: stringify deterministically so clustering keys stay hashable.
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_query(query: str, start: str, end: str, run_dir: str) -> tuple[str, list[dict], str | None]:
    """Run one wazuh_cli query; return (query, results_list, error). Always --raw."""
    cmd = [
        sys.executable,
        str(WAZUH_CLI),
        "query",
        "--query",
        query,
        "--start",
        start,
        "--end",
        end,
        "--limit",
        "10000",
        "--raw",
        "--run-dir",
        run_dir,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return query, [], "timeout after 60s"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()[-1][:200]
        return query, [], f"rc={proc.returncode}: {err}"
    # --run-dir wraps output in salted tags: <run-<salt>-siem-data> ... </run-<salt>-siem-data>
    text = proc.stdout.strip()
    m = re.search(r"<run-[a-f0-9]+-siem-data>\s*(.*?)\s*</run-[a-f0-9]+-siem-data>", text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    try:
        items = json.loads(text) if text else []
    except json.JSONDecodeError as exc:
        return query, [], f"json-decode: {exc}"
    if not isinstance(items, list):
        return query, [], "non-list JSON result"
    return query, items, None


def extract_observables_from_event(event: dict, observables: list[dict]) -> dict:
    """Pull the values of each Key Observable from a returned event, coerced to scalar strings."""
    return {obs["json_path"]: _scalar(extract_json_path(event, obs["json_path"])) for obs in observables}


def cluster_events(
    all_events: dict[str, dict],
    current_obs: dict,
    observables: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Group dedup'd events into repeats + related clusters per ticket-context.md."""
    repeats_events: list[dict] = []
    # related groups keyed by frozenset((dim, value), ...) of shared dimensions
    related_groups: dict[frozenset, list[dict]] = {}

    key_paths = [o["json_path"] for o in observables if o["name"].lower() != "timestamp"]

    for alert_id, ev in all_events.items():
        event_obs = extract_observables_from_event(ev, observables)
        # Which key dims (excluding timestamp) match the current alert?
        shared = {
            kp: current_obs[kp]
            for kp in key_paths
            if event_obs.get(kp) == current_obs.get(kp) and current_obs.get(kp) is not None
        }
        if len(shared) == len(key_paths):
            # All key observables match -> repeat
            repeats_events.append(ev)
        elif shared:
            key = frozenset(shared.items())
            related_groups.setdefault(key, []).append(ev)

    return _summarize_repeats(repeats_events), _summarize_related(related_groups)


def _event_ts(ev: dict) -> str:
    return ev.get("timestamp") or extract_json_path(ev, "timestamp") or ""


def _event_rule(ev: dict) -> str | None:
    return str(extract_json_path(ev, "rule.id") or "") or None


def _event_rule_desc(ev: dict) -> str | None:
    return extract_json_path(ev, "rule.description") or extract_json_path(ev, "data.rule.name")


def _summarize_repeats(events: list[dict]) -> list[dict]:
    if not events:
        return []
    events.sort(key=_event_ts)
    ids = [ev.get("id") for ev in events if ev.get("id")]
    rules = sorted({_event_rule(ev) for ev in events if _event_rule(ev)})
    cluster = {
        "count": len(events),
        "first_seen": _event_ts(events[0]),
        "last_seen": _event_ts(events[-1]),
        "signatures": rules,
    }
    if len(events) > CLUSTER_COMPRESSION_THRESHOLD:
        cluster["compressed"] = True
    else:
        cluster["alert_ids"] = ids
    return [cluster]


def _summarize_related(groups: dict[frozenset, list[dict]]) -> list[dict]:
    out = []
    for shared_set, events in groups.items():
        events.sort(key=_event_ts)
        shared = dict(shared_set)
        rules_sorted: list[str] = []
        rule_descs: dict[str, str] = {}
        for ev in events:
            rid = _event_rule(ev)
            if rid and rid not in rules_sorted:
                rules_sorted.append(rid)
                desc = _event_rule_desc(ev)
                if desc:
                    rule_descs[rid] = desc
        cluster = {
            "shared": shared,
            "count": len(events),
            "first_seen": _event_ts(events[0]),
            "last_seen": _event_ts(events[-1]),
            "signatures": rules_sorted,
        }
        if rule_descs:
            cluster["signatures_detail"] = rule_descs
        if len(events) > CLUSTER_COMPRESSION_THRESHOLD:
            cluster["compressed"] = True
        else:
            ids = [ev.get("id") for ev in events if ev.get("id")]
            cluster["alert_ids"] = ids
        out.append(cluster)
    # Stable sort: descending count, then by shared-dims cardinality desc
    out.sort(key=lambda c: (-c["count"], -len(c["shared"])))
    return out


def compute_high_volume(all_events: dict[str, dict], observables: list[dict]) -> list[dict]:
    """Flag any observable value that accumulates >100 alerts across queries."""
    from collections import defaultdict

    counts: dict[tuple[str, str], set[str]] = defaultdict(set)  # (dim, val) -> rule-id set
    totals: dict[tuple[str, str], int] = defaultdict(int)
    for ev in all_events.values():
        rid = _event_rule(ev)
        for obs in observables:
            if obs["name"].lower() == "timestamp":
                continue
            val = _scalar(extract_json_path(ev, obs["json_path"]))
            if val is None:
                continue
            key = (obs["json_path"], val)
            totals[key] += 1
            if rid:
                counts[key].add(rid)
    out = []
    for key, total in totals.items():
        if total > HIGH_VOLUME_THRESHOLD:
            dim, val = key
            out.append({
                "dimension": dim,
                "value": val,
                "total_count": total,
                "signature_count": len(counts[key]),
            })
    out.sort(key=lambda x: -x["total_count"])
    return out


def emit_yaml(data: dict) -> str:
    """Render the ticket_context payload as a fenced YAML block.

    Uses PyYAML's safe_dump so untrusted alert-derived strings are escaped
    correctly. Insertion order is preserved (sort_keys=False); the schema
    contract is {entities, high_volume_dimensions, repeats, related, [queries_failed|partial]}.
    """
    payload: dict = {
        "entities": data["entities"],
        "high_volume_dimensions": data["high_volume_dimensions"],
        "repeats": data["repeats"],
        "related": data["related"],
    }
    if data.get("queries_failed"):
        payload["queries_failed"] = data["queries_failed"]
    if data.get("queries_partial"):
        payload["queries_partial"] = data["queries_partial"]

    body = yaml.safe_dump(
        {"ticket_context": payload},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=10000,
    )
    return f"```yaml\n{body}```"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else "")
    p.add_argument("--run-dir", required=True, help="Investigation run directory with alert.json")
    p.add_argument("--signature-id", required=True, help="Full signature_id (e.g. wazuh-rule-5710)")
    p.add_argument("--window", default="4h", help="Lookback window ending at alert timestamp (default 4h)")
    args = p.parse_args(argv)

    sys.path.insert(0, str(REPO_ROOT))
    from hooks.scripts.run_context import is_safe_id  # noqa: E402

    if not is_safe_id(args.signature_id):
        print(f"error: invalid signature_id: {args.signature_id!r}", file=sys.stderr)
        return 2

    run_dir = Path(args.run_dir)
    alert_path = run_dir / "alert.json"
    field_quirks_path = REPO_ROOT / "knowledge" / "signatures" / args.signature_id / "field-quirks.md"

    _dbg(f"run_dir={run_dir} signature_id={args.signature_id} window={args.window}")
    _dbg(f"alert={alert_path} field_quirks={field_quirks_path}")

    alert = json.loads(alert_path.read_text())
    observables = parse_key_observables(field_quirks_path)
    _dbg(f"parsed {len(observables)} key observables: {[o['name'] for o in observables]}")

    # Extract current observable values from alert (scalar-coerced for consistency)
    current_obs = {obs["json_path"]: _scalar(extract_json_path(alert, obs["json_path"])) for obs in observables}
    _dbg(f"current_obs={current_obs}")

    alert_ts = extract_json_path(alert, "timestamp") or alert.get("@timestamp")
    if not alert_ts:
        print("error: no timestamp on alert", file=sys.stderr)
        return 2

    # Compute window
    end_dt = datetime.fromisoformat(alert_ts.replace("Z", "+00:00"))
    unit = args.window[-1]
    amount = int(args.window[:-1])
    delta = {"h": timedelta(hours=amount), "m": timedelta(minutes=amount), "d": timedelta(days=amount)}[unit]
    start_dt = end_dt - delta
    start = iso_utc(start_dt)
    end = iso_utc(end_dt)
    _dbg(f"time window: start={start} end={end}")

    # Build queries: per-observable (exclude timestamp) + same-signature
    rule_id = str(extract_json_path(alert, "rule.id") or "")
    queries: list[tuple[str, str]] = []  # (label, query)
    for obs in observables:
        if obs["name"].lower() == "timestamp":
            continue
        val = current_obs[obs["json_path"]]
        if val is None:
            continue
        queries.append((obs["json_path"], f"{obs['json_path']}:{json.dumps(val)}"))
    if rule_id:
        queries.append(("same-signature", f"rule.id:{rule_id}"))
    _dbg(f"dispatching {len(queries)} queries: {[label for label, _ in queries]}")

    # Parallel dispatch
    all_events: dict[str, dict] = {}
    failed_labels: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, len(queries))) as ex:
        futures = {ex.submit(run_query, q, start, end, str(run_dir)): label for label, q in queries}
        for fut in as_completed(futures):
            label = futures[fut]
            _, items, err = fut.result()
            if err:
                _dbg(f"query[{label}] FAILED: {err}")
                failed_labels.append(f"{label}({err})")
                continue
            new_ids = 0
            for ev in items:
                eid = ev.get("id")
                if eid and eid not in all_events:
                    all_events[eid] = ev
                    new_ids += 1
            _dbg(f"query[{label}] returned {len(items)} events ({new_ids} new; dedup total={len(all_events)})")

    if not all_events and failed_labels:
        reason = f"all queries failed: {'; '.join(failed_labels)}"
        _dbg(f"emitting queries_failed: {reason}")
        out = {
            "entities": {o["json_path"]: current_obs.get(o["json_path"], "") for o in observables},
            "high_volume_dimensions": [],
            "repeats": [],
            "related": [],
            "queries_failed": reason,
        }
        print(emit_yaml(out))
        return 0

    repeats, related = cluster_events(all_events, current_obs, observables)
    high_vol = compute_high_volume(all_events, observables)
    _dbg(f"clusters: repeats={len(repeats)} related_groups={len(related)} high_volume={len(high_vol)}")

    out = {
        "entities": {o["json_path"]: current_obs.get(o["json_path"], "") for o in observables},
        "high_volume_dimensions": high_vol,
        "repeats": repeats,
        "related": related,
    }
    if failed_labels:
        out["queries_partial"] = "; ".join(failed_labels)
        _dbg(f"partial failures: {out['queries_partial']}")

    print(emit_yaml(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
