#!/usr/bin/env python3
"""Mint a defender alert.json from a live playground detection alert.

`defender/run.py` takes an alert.json fixture; the playground's detection engine writes
Kibana-shaped docs to .alerts-security.alerts-default. This maps one to the other so a
FRESH alert (fired minutes ago by playground-v2/attacks/runner.py) can be investigated,
rather than replaying a checked-in fixture.

Field mapping is derived from defender/fixtures/v2-sshd-success-after-failures/alert.json.

  ./mint_alert.py --rule-name "v2 sshd failed-auth burst" --out <dir>/alert.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ES_QUERY = r'''docker exec elasticsearch sh -c 'curl -s -m 20 -k -u elastic:$ELASTIC_PASSWORD \
  "https://localhost:9200/.alerts-security.alerts-default/_search?size=%(size)d" \
  -H "Content-Type: application/json" -d %(body)s' '''


def es_search(body: dict, size: int = 1) -> dict:
    payload = json.dumps(json.dumps(body))  # shell-safe single JSON arg
    cmd = ES_QUERY % {"size": size, "body": payload}
    out = subprocess.check_output(
        ["ssh", "-F", "/workspace/.ssh/config", "-o", "BatchMode=yes",
         "soc-playground", cmd],
        text=True, timeout=90,
    )
    return json.loads(out)


def _nest(src: dict, prefix: str) -> dict:
    """Rebuild a nested dict from flattened dotted keys.

    Detection-engine docs store `host.name` as a literal top-level key rather than a
    nested `host` object, so `src.get("host")` misses. Accept either shape.
    """
    if isinstance(src.get(prefix), dict):
        return src[prefix]
    out: dict = {}
    for k, v in src.items():
        if not k.startswith(prefix + "."):
            continue
        cur = out
        parts = k[len(prefix) + 1:].split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def mint(src: dict, index: str) -> dict:
    g = src.get
    rule = {
        "id": g("kibana.alert.rule.rule_id") or g("kibana.alert.rule.uuid") or "",
        "name": g("kibana.alert.rule.name") or "",
        "type": g("kibana.alert.rule.type") or "",
        "severity": g("kibana.alert.severity") or "",
        "risk_score": g("kibana.alert.risk_score") or 0,
        "tags": g("kibana.alert.rule.tags") or [],
        "description": g("kibana.alert.rule.description") or "",
        "language": (g("kibana.alert.rule.parameters") or {}).get("language", ""),
        "query": (g("kibana.alert.rule.parameters") or {}).get("query", ""),
    }
    return {
        "alert_id": g("kibana.alert.uuid") or "",
        "alert_timestamp": g("@timestamp") or "",
        "rule": rule,
        "reason": g("kibana.alert.reason") or "",
        "host": _nest(src, "host"),
        "user": _nest(src, "user"),
        "ancestor_events": g("kibana.alert.ancestors") or [],
        "signal_index": index,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rule-name", required=True)
    p.add_argument("--host", default=None, help="filter on host.name")
    p.add_argument("--within", default="30m")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)

    must = [
        {"term": {"kibana.alert.rule.name": a.rule_name}},
        {"range": {"@timestamp": {"gte": f"now-{a.within}"}}},
    ]
    if a.host:
        must.append({"term": {"host.name": a.host}})
    res = es_search({"query": {"bool": {"must": must}},
                     "sort": [{"@timestamp": "desc"}]})
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        print(f"no alert matching {a.rule_name!r} within {a.within}", file=sys.stderr)
        return 1
    hit = hits[0]
    alert = mint(hit["_source"], hit["_index"])
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(alert, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {a.out}")
    print(f"  rule : {alert['rule']['name']}  ({alert['rule']['type']}, "
          f"{alert['rule']['severity']})")
    print(f"  when : {alert['alert_timestamp']}")
    print(f"  host : {(alert['host'] or {}).get('name')}   user: "
          f"{(alert['user'] or {}).get('name')}")
    print(f"  ancestors: {len(alert['ancestor_events'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
