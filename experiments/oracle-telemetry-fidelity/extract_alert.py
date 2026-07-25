#!/usr/bin/env python3
"""Project a live v2 detection alert into the committed defender fixture shape.

Shape is taken from `defender/fixtures/v2-cross-tier-ssh-pivot/alert.json` — the
shape-current v2 input — NOT from experiments/effort-tradeoff/project_alert.py,
whose paths (`/workspace/defender-v2-tree`, `scripts/tools/elastic_cli.py`) no
longer exist and which resolves ancestors into full docs the committed fixture
keeps as bare references.

Transport is `infra/bin/es.sh` (docker exec curl inside the ES container), the
same seam the elastic adapter uses.

Usage: extract_alert.py <rule_id> <since-iso> <out.json>
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ES_SH = Path("/workspace/infra/bin/es.sh")
ALERTS = "/.internal.alerts-security.alerts-default-*/_search"


def es(path: str, body: dict) -> dict:
    out = subprocess.run(
        [str(ES_SH), path, "-H", "Content-Type: application/json", "-d", json.dumps(body)],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        sys.exit(f"es.sh rc={out.returncode}: {out.stderr[:400]}")
    return json.loads(out.stdout)


def project(s: dict) -> dict:
    def rule_get(k, d=None):
        return s.get(f"kibana.alert.rule.{k}", d)

    def entity(name: str) -> dict:
        """Alert docs carry both nested (`host: {name}`) and flat-dotted
        (`host.name`) forms depending on rule type; the threshold rule uses the
        flat form, so read both or the entity silently comes back null."""
        nested = s.get(name)
        if isinstance(nested, dict) and nested.get("name") is not None:
            return nested
        return {"name": s.get(f"{name}.name")}

    params = rule_get("parameters", {}) or {}
    fixture = {
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
        },
        "reason": s.get("kibana.alert.reason"),
        "host": entity("host"),
        "user": entity("user"),
        "ancestor_events": s.get("kibana.alert.ancestors", []) or [],
        "signal_index": ".internal.alerts-security.alerts-default-*",
    }
    # A threshold rule's evidence IS its grouping + count; the committed EQL
    # fixture has no slot for it because EQL alerts carry none. Dropping it would
    # hand the defender a less faithful alert than the one that actually fired.
    if (tr := s.get("kibana.alert.threshold_result")) is not None:
        fixture["threshold_result"] = tr
    return fixture


def main() -> None:
    rule_id, since, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    resp = es(ALERTS, {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.rule.rule_id": rule_id}},
            {"range": {"@timestamp": {"gte": since}}},
        ]}},
    })
    hits = resp["hits"]["hits"]
    if not hits:
        sys.exit(f"no alert for rule_id={rule_id} since {since}")
    fixture = project(hits[0]["_source"])
    Path(out_path).write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"  alert_id  : {fixture['alert_id']}")
    print(f"  timestamp : {fixture['alert_timestamp']}")
    print(f"  rule      : {fixture['rule']['name']} ({fixture['rule']['type']})")
    print(f"  reason    : {fixture['reason']}")
    print(f"  host/user : {fixture['host']} / {fixture['user']}")
    print(f"  ancestors : {len(fixture['ancestor_events'])}")


if __name__ == "__main__":
    main()
