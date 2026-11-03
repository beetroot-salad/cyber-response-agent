"""Alert → ticket watcher (#1400): opens each new alert's ticket in the playground ticket-server.

Stands in for the customer's alert automation. Every POLL_SECONDS it reads the security alerts
written since its cursor and posts them to the ticket-server's `POST /hooks/kibana-alerts`, which
opens one ticket per alert keyed by `kibana.alert.uuid` and ignores an alert it already has.

Why polling and not a Kibana rule action: Kibana's webhook connector needs a Gold licence and this
stack runs Basic, so the action is accepted and then skipped on every fire.

The cursor is the newest alert `@timestamp` seen. Each poll re-reads OVERLAP_SECONDS before it, so
an alert indexed a little after a newer one is not missed; the hook makes the re-sends no-ops. A
failed page leaves the cursor where it was, so the next poll retries it. On start the cursor is
LOOKBACK_SECONDS back. Standard library only.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

ALERTS_INDEX = ".alerts-security.alerts-default"
PAGE_SIZE = 500

Fetch = Callable[[dict], list]   # search body -> hits
Post = Callable[[list], None]    # alerts -> None; raises when the ticket-server refused them


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def search_body(since: datetime, after: Optional[list] = None) -> dict:
    body = {
        "size": PAGE_SIZE,
        "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
        "query": {"range": {"@timestamp": {"gte": _iso(since)}}},
    }
    if after is not None:
        body["search_after"] = after
    return body


def as_alert(hit: dict) -> dict:
    """The alert as the hook reads it: its stored fields, plus the document id."""
    return {**hit.get("_source", {}), "_id": hit.get("_id")}


def poll_once(cursor: datetime, overlap: timedelta, fetch: Fetch, post: Post) -> datetime:
    """Send every alert from `cursor - overlap` on; return the new cursor.

    A page is posted before the cursor moves past it, so an exception from `fetch` or `post`
    leaves the cursor at the last page that landed.
    """
    since, after = cursor - overlap, None
    while True:
        hits = fetch(search_body(since, after))
        if not hits:
            return cursor
        post([as_alert(h) for h in hits])
        newest = max((_parse(h["_source"]["@timestamp"]) for h in hits
                      if isinstance(h.get("_source", {}).get("@timestamp"), str)), default=cursor)
        cursor = max(cursor, newest)
        if len(hits) < PAGE_SIZE:
            return cursor
        after = hits[-1].get("sort")


# --- the real transport ----------------------------------------------------------------------

def _es_fetch(url: str, user: str, password: str, ca: str) -> Fetch:
    ctx = ssl.create_default_context(cafile=ca)
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def fetch(body: dict) -> list:
        req = urllib.request.Request(
            f"{url}/{ALERTS_INDEX}/_search?ignore_unavailable=true",
            data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": auth},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.load(resp).get("hits", {}).get("hits", [])

    return fetch


def _hook_post(url: str) -> Post:
    def post(alerts: list) -> None:
        req = urllib.request.Request(
            url, data=json.dumps({"alerts": alerts}).encode(), method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.load(resp)
        if result.get("created"):
            print(f"opened {len(result['created'])} ticket(s): {', '.join(result['created'])}",
                  flush=True)

    return post


def main() -> None:
    env = os.environ
    fetch = _es_fetch(env.get("WATCHER_ES_URL", "https://elasticsearch:9200"),
                      env.get("WATCHER_ES_USER", "alert-ticket-watcher"),
                      env["WATCHER_ES_PASSWORD"],
                      env.get("WATCHER_ES_CA", "/certs/ca/ca.crt"))
    post = _hook_post(env.get("WATCHER_HOOK_URL", "http://ticket-server:8080/hooks/kibana-alerts"))
    poll = float(env.get("WATCHER_POLL_SECONDS", "30"))
    overlap = timedelta(seconds=float(env.get("WATCHER_OVERLAP_SECONDS", "120")))
    cursor = datetime.now(timezone.utc) - timedelta(
        seconds=float(env.get("WATCHER_LOOKBACK_SECONDS", "86400")))
    print(f"watching {ALERTS_INDEX} from {_iso(cursor)} every {poll:g}s", flush=True)
    while True:
        try:
            cursor = poll_once(cursor, overlap, fetch, post)
        except Exception as exc:  # keep polling; the cursor did not move past the failure
            print(f"poll failed, will retry: {type(exc).__name__}: {exc}", file=sys.stderr,
                  flush=True)
        time.sleep(poll)


if __name__ == "__main__":
    main()
