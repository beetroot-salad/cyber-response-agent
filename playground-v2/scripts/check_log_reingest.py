#!/usr/bin/env python3
"""Live check: restarting a role host must not re-ship log lines it already shipped.

Restarts one role host container, waits for its agent to settle, then counts documents from
that host that Elasticsearch ingested after the restart but whose `@timestamp` is older than
the restart by more than `--slack`. Anything above zero is a re-read of an already-shipped
file. Exit 0 = clean, 1 = re-ingestion seen, 2 = the check could not run.

    python3 scripts/check_log_reingest.py web-2 [--settle 150] [--slack 600]

Disturbs the live stack (one container restart), so it is a manual check, never part of a
suite.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import time
from pathlib import Path

ES_SH = Path(__file__).resolve().parents[1] / "infra" / "bin" / "es.sh"
CONTEXT = "soc-playground"
# The host-side streams a role host ships from its own /var/log.
INDICES = "logs-system.auth-*,logs-system.syslog-*,logs-nginx.*-*,logs-postgresql.log-*"


def _es(path: str, body: dict) -> dict:
    out = subprocess.run(
        [str(ES_SH), path, "-H", "Content-Type: application/json", "-d", json.dumps(body)],
        capture_output=True, text=True, check=True, timeout=180,
    ).stdout
    return json.loads(out)


def _var_log_device(host: str) -> str:
    return subprocess.run(
        ["docker", "--context", CONTEXT, "exec", host, "stat", "-c", "%d", "/var/log"],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout.strip()


def _reshipped(host: str, restarted_at: dt.datetime, slack_s: int) -> dict:
    older_than = restarted_at - dt.timedelta(seconds=slack_s)
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"term": {"host.name": host}},
            {"range": {"event.ingested": {"gte": restarted_at.isoformat()}}},
            {"range": {"@timestamp": {"lt": older_than.isoformat()}}},
        ]}},
        "aggs": {"file": {"terms": {"field": "log.file.path", "size": 20}}},
    }
    resp = _es(f"/{INDICES}/_search", body)
    return {
        "count": resp["hits"]["total"]["value"],
        "files": {b["key"]: b["doc_count"] for b in resp["aggregations"]["file"]["buckets"]},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host")
    ap.add_argument("--settle", type=int, default=150, help="seconds to wait after restart")
    ap.add_argument("--slack", type=int, default=600,
                    help="a line dated within this many seconds before the restart is not counted")
    args = ap.parse_args()

    try:
        before = _var_log_device(args.host)
        restarted_at = dt.datetime.now(dt.UTC).replace(microsecond=0)
        subprocess.run(["docker", "--context", CONTEXT, "restart", args.host],
                       capture_output=True, text=True, check=True, timeout=120)
        after = _var_log_device(args.host)
        time.sleep(args.settle)
        found = _reshipped(args.host, restarted_at, args.slack)
    except (subprocess.SubprocessError, OSError, KeyError, ValueError) as exc:
        print(f"check could not run: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({"host": args.host, "restarted_at": restarted_at.isoformat(),
                      "var_log_device": {"before": before, "after": after}, **found}, indent=2))
    return 1 if found["count"] else 0


if __name__ == "__main__":
    sys.exit(main())
