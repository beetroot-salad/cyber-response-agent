#!/usr/bin/env python3
"""Project a raw v2 detection alert (kibana.alert.* envelope) into the
normalized defender fixture shape that run.py / the agent consumes.

Resolves ancestor EVENT docs (the underlying auth.log events that carry the
real source IP / actor / target host) by _id so the fixture is self-describing.

Usage:
    project_alert.py <raw_alert.json> <out_fixture.json>

<raw_alert.json> is a single hit _source dict (as emitted by
elastic_cli.py alerts --raw, picking one hit).
"""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path

DEFENDER = Path("/workspace/defender-v2-tree/defender")
ELASTIC_CLI = DEFENDER / "scripts" / "tools" / "elastic_cli.py"
PY = DEFENDER / ".venv" / "bin" / "python3"


def fetch_event(doc_id: str, index: str) -> dict | None:
    """Resolve one ancestor event doc by _id from its datastream index."""
    # ancestor index is a concrete .ds-… backing index; query its datastream pattern
    pattern = "logs-system.auth-*" if "system.auth" in index else index
    out = subprocess.run(
        [str(PY), str(ELASTIC_CLI), "query", f'_id:"{doc_id}"',
         "--index", pattern, "--limit", "1", "--raw"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(f"  [warn] ancestor {doc_id[:12]} fetch rc={out.returncode}: {out.stderr[:160]}", file=sys.stderr)
        return None
    try:
        d = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    hits = d.get("hits") if isinstance(d, dict) else d
    if hits:
        h = hits[0]
        return h.get("_source") or h
    return None


def project(s: dict) -> dict:
    rule_get = lambda k, d=None: s.get(f"kibana.alert.rule.{k}", d)
    params = rule_get("parameters", {}) or {}
    ancestors = s.get("kibana.alert.ancestors", []) or []
    resolved = []
    for a in ancestors:
        if a.get("type") != "event":
            continue
        ev = fetch_event(a["id"], a.get("index", ""))
        resolved.append(ev if ev is not None else {"_unresolved_id": a["id"], "index": a.get("index")})

    return {
        "alert_id": s.get("kibana.alert.uuid"),
        "alert_timestamp": s.get("@timestamp") or s.get("kibana.alert.original_time"),
        "rule": {
            "id": rule_get("rule_id"),
            "name": rule_get("name"),
            "type": rule_get("type"),
            "severity": rule_get("severity"),
            "risk_score": rule_get("risk_score"),
            "tags": rule_get("tags", []),
            "description": rule_get("description"),
            "language": params.get("language"),
            "query": params.get("query"),
            "index": params.get("index"),
        },
        "reason": s.get("kibana.alert.reason"),
        "host": s.get("host"),
        "process": s.get("process"),
        "event": s.get("event"),
        "ancestor_events": resolved,
        "signal_index": ".internal.alerts-security.alerts-default-*",
    }


def main() -> None:
    raw = json.loads(Path(sys.argv[1]).read_text())
    s = raw.get("_source") or raw
    fixture = project(s)
    Path(sys.argv[2]).write_text(json.dumps(fixture, indent=2))
    n_anc = len(fixture["ancestor_events"])
    print(f"wrote {sys.argv[2]}  alert_id={fixture['alert_id'][:16]}…  "
          f"rule={fixture['rule']['name']}  ancestors={n_anc}")
    print(f"  reason: {fixture['reason'][:140]}")


if __name__ == "__main__":
    main()
