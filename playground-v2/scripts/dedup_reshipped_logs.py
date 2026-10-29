#!/usr/bin/env python3
"""Remove the copies of log lines a role host re-shipped, keeping the first copy of each line.

Until role hosts kept /var/log on a named volume (see compose.yml), every container restart
gave /var/log a new device number, and the agent re-read every log file from line one. The
streams it ships from /var/log hold each such line several times. This rebuilds one stream
with one copy per line and swaps it in.

A line is (host.name, log.file.path, log.offset, @timestamp, message): the same file, place
in the file, and parsed time. `message` is absent in some streams (nginx) and then left out.
`@timestamp` keeps two different lines apart when a rotated file restarts at offset 0. A copy
whose fields differ at all is kept, so a mistake keeps too much, never too little.

The first-ingested copy is the one kept: the rebuild reads the old indices hour by hour of
`event.ingested`, oldest first, into an index whose `_id` is the line's fingerprint, so a
later copy of a line already written is refused. `event.ingested` and every other field are
carried over unchanged (the integration pipelines, which would restamp `event.ingested`, do
not run).

    python3 scripts/dedup_reshipped_logs.py build  system.syslog   # roll over, rebuild (resumable)
    python3 scripts/dedup_reshipped_logs.py verify system.syslog   # counts, per day, sample check
    python3 scripts/dedup_reshipped_logs.py swap   system.syslog   # rebuilt index replaces the old ones
    python3 scripts/dedup_reshipped_logs.py drop   system.syslog   # delete the detached old indices

`swap` leaves the old indices in place, outside the stream; only `drop` deletes anything.
Disturbs the live stack, so it is a manual tool, never part of a suite.
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
PIPELINE = "playground-dedup-line-key"
KEY_FIELDS = ["host.name", "log.file.path", "log.offset", "@timestamp", "message"]
HOUR_MS = 3600 * 1000
# An hour with fewer old docs than this is rebuilt in one blocking call; a bigger one runs as a
# task that is polled, so no single HTTP call outlives its timeout.
SYNC_MAX = 200_000
# Progress is recorded every this many hours; a resumed build redoes at most this many.
SAVE_EVERY = 24


def _es(method: str, path: str, body: dict | None = None, ok404: bool = False) -> dict:
    args = [str(ES_SH), path, "-X", method]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    out = subprocess.run(args, capture_output=True, text=True, check=True, timeout=600).stdout
    resp = json.loads(out) if out.strip() else {}
    if isinstance(resp, dict) and "error" in resp and not (ok404 and resp.get("status") == 404):
        raise RuntimeError(f"{method} {path}: {json.dumps(resp['error'])[:600]}")
    return resp


def _stream(dataset: str) -> str:
    return f"logs-{dataset}-default"


def _dest(dataset: str) -> str:
    return f"dedup-logs-{dataset}-default"


def _meta(dataset: str) -> dict | None:
    resp = _es("GET", f"/{_dest(dataset)}/_mapping", ok404=True)
    if "error" in resp:
        return None
    return next(iter(resp.values()))["mappings"].get("_meta", {}).get("dedup")


def _put_meta(dataset: str, meta: dict) -> None:
    _es("PUT", f"/{_dest(dataset)}/_mapping", {"_meta": {"dedup": meta}})


def _ensure_pipeline() -> None:
    _es("PUT", f"/_ingest/pipeline/{PIPELINE}", {
        "description": "Sets _id to a fingerprint of the log line (dedup_reshipped_logs.py).",
        "processors": [
            {"fingerprint": {"fields": KEY_FIELDS, "target_field": "_line_key",
                             "method": "SHA-256", "ignore_missing": True}},
            {"set": {"field": "_id", "copy_from": "_line_key"}},
            {"remove": {"field": "_line_key"}},
        ],
    })


def _create_dest(dataset: str, sources: list[str]) -> None:
    sim = _es("POST", f"/_index_template/_simulate_index/{_stream(dataset)}")["template"]
    index = dict(sim["settings"]["index"])
    # `logsdb` holds private settings ES derives itself and refuses to have set.
    for key in ("default_pipeline", "final_pipeline", "routing", "number_of_replicas", "logsdb"):
        index.pop(key, None)
    index.update({"hidden": True, "number_of_replicas": 0, "refresh_interval": "-1"})
    mappings = {k: v for k, v in sim["mappings"].items() if k != "_data_stream_timestamp"}
    mappings["_meta"] = {"dedup": {"sources": sources, "done_until": None,
                                   "created": 0, "conflicts": 0}}
    _es("PUT", f"/{_dest(dataset)}", {"settings": {"index": index}, "mappings": mappings})


def _hours(sources: list[str]) -> list[tuple[int, int]]:
    resp = _es("POST", f"/{','.join(sources)}/_search", {
        "size": 0,
        "aggs": {"h": {"date_histogram": {"field": "event.ingested", "fixed_interval": "1h",
                                          "min_doc_count": 1}}},
    })
    return [(b["key"], b["doc_count"]) for b in resp["aggregations"]["h"]["buckets"]]


def _reindex_hour(dataset: str, sources: list[str], start_ms: int, docs: int) -> tuple[int, int]:
    body = {
        "conflicts": "proceed",
        "source": {"index": sources, "size": 5000,
                   "query": {"range": {"event.ingested": {
                       "gte": start_ms, "lt": start_ms + HOUR_MS, "format": "epoch_millis"}}}},
        "dest": {"index": _dest(dataset), "op_type": "create", "pipeline": PIPELINE},
    }
    if docs < SYNC_MAX:
        status = {"response": _es("POST", "/_reindex", body)}
    else:
        task = _es("POST", "/_reindex?wait_for_completion=false", body)["task"]
        while not (status := _es("GET", f"/_tasks/{task}")).get("completed"):
            time.sleep(5)
    resp = status.get("response") or {}
    if status.get("error") or resp.get("failures"):
        raise RuntimeError(f"reindex of hour {start_ms} failed: "
                           f"{json.dumps(status.get('error') or resp['failures'])[:600]}")
    return resp["created"], resp["version_conflicts"]


def build(dataset: str) -> int:
    _ensure_pipeline()
    meta = _meta(dataset)
    if meta is None:
        # Roll over first so the current write index, which holds lines re-shipped before the
        # fix, becomes one of the old indices this rebuild replaces.
        _es("POST", f"/{_stream(dataset)}/_rollover")
        info = _es("GET", f"/_data_stream/{_stream(dataset)}")["data_streams"][0]
        sources = [i["index_name"] for i in info["indices"][:-1]]
        _create_dest(dataset, sources)
        meta = _meta(dataset)
        print(f"rolled over; rebuilding {len(sources)} indices into {_dest(dataset)}")
    sources = meta["sources"]
    hours = [(h, d) for h, d in _hours(sources)
             if meta["done_until"] is None or h > meta["done_until"]]
    print(f"{len(hours)} ingest hours to go", flush=True)
    for n, (hour, docs) in enumerate(hours, 1):
        created, conflicts = _reindex_hour(dataset, sources, hour, docs)
        meta.update(done_until=hour, created=meta["created"] + created,
                    conflicts=meta["conflicts"] + conflicts)
        if n % SAVE_EVERY == 0 or n == len(hours) or docs >= SYNC_MAX:
            _put_meta(dataset, meta)
        if n % 100 == 0 or n == len(hours) or created + conflicts > 100_000:
            when = dt.datetime.fromtimestamp(hour / 1000, dt.UTC).strftime("%Y-%m-%d %H:00")
            print(f"[{n}/{len(hours)}] {when} kept {meta['created']} "
                  f"dropped {meta['conflicts']}", flush=True)
    _es("POST", f"/{_dest(dataset)}/_refresh")
    return 0


def _count(index: str, body: dict | None = None) -> int:
    return _es("POST", f"/{index}/_count", body or {"query": {"match_all": {}}})["count"]


def _days(index: str) -> dict[str, int]:
    resp = _es("POST", f"/{index}/_search", {"size": 0, "aggs": {"d": {"date_histogram": {
        "field": "@timestamp", "calendar_interval": "1d", "min_doc_count": 1}}}})
    return {b["key_as_string"][:10]: b["doc_count"] for b in resp["aggregations"]["d"]["buckets"]}


def _key_query(src: dict) -> dict:
    filters = []
    for field in KEY_FIELDS:
        value = src
        for part in field.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is None:
            filters.append({"bool": {"must_not": {"exists": {"field": field}}}})
        elif field == "message":
            filters.append({"match_phrase": {field: value}})
        else:
            filters.append({"term": {field: value}})
    return {"bool": {"filter": filters}}


def verify(dataset: str, samples: int) -> int:
    meta = _meta(dataset)
    if meta is None:
        print("no rebuild found; run build first", file=sys.stderr)
        return 2
    sources, dest = ",".join(meta["sources"]), _dest(dataset)
    _es("POST", f"/{dest}/_refresh")
    problems = []
    src_total, dest_total = _count(sources), _count(dest)
    if meta["created"] + meta["conflicts"] != src_total:
        problems.append(f"read {meta['created'] + meta['conflicts']} of {src_total} old docs")
    # A resumed build counts the docs it wrote before stopping as refused, so the rebuilt
    # index can hold more than `created`, never fewer.
    if dest_total < meta["created"]:
        problems.append(f"rebuilt index holds {dest_total}, build wrote {meta['created']}")
    src_days, dest_days = _days(sources), _days(dest)
    print(f"old {src_total}  rebuilt {dest_total}  dropped {src_total - dest_total} "
          f"({(src_total - dest_total) / max(src_total, 1):.1%})")
    for day in sorted(src_days):
        kept = dest_days.get(day, 0)
        if not kept or kept > src_days[day]:
            problems.append(f"{day}: old {src_days[day]} rebuilt {kept}")
    # Every rebuilt doc is byte-identical to the earliest-ingested old copy of its line.
    hits = _es("POST", f"/{dest}/_search", {"size": samples, "query": {"function_score": {
        "random_score": {"seed": 7, "field": "_seq_no"}}}})["hits"]["hits"]
    for hit in hits:
        copies = _es("POST", f"/{sources}/_search", {
            "size": 100, "query": _key_query(hit["_source"]),
            "sort": [{"event.ingested": "asc"}]})["hits"]["hits"]
        if not copies or copies[0]["_source"] != hit["_source"]:
            problems.append(f"{hit['_id']}: not the earliest old copy ({len(copies)} copies)")
    print(f"checked {len(hits)} sampled lines against their old copies")
    for p in problems[:40]:
        print("PROBLEM", p)
    return 1 if problems else 0


def swap(dataset: str) -> int:
    meta = _meta(dataset)
    if meta is None:
        print("no rebuild found; run build first", file=sys.stderr)
        return 2
    dest = _dest(dataset)
    _es("PUT", f"/{dest}/_settings", {"index": {"refresh_interval": None}})
    actions = [{"remove_backing_index": {"data_stream": _stream(dataset), "index": i}}
               for i in meta["sources"]]
    actions.insert(0, {"add_backing_index": {"data_stream": _stream(dataset), "index": dest}})
    _es("POST", "/_data_stream/_modify", {"actions": actions})
    print(f"{dest} now serves {_stream(dataset)}; old indices detached: {meta['sources']}")
    return 0


def drop(dataset: str) -> int:
    meta = _meta(dataset)
    info = _es("GET", f"/_data_stream/{_stream(dataset)}")["data_streams"][0]
    if meta is None or _dest(dataset) not in {i["index_name"] for i in info["indices"]}:
        print("rebuilt index is not serving the stream; run swap first", file=sys.stderr)
        return 2
    _es("DELETE", f"/{','.join(meta['sources'])}")
    print(f"deleted {meta['sources']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=["build", "verify", "swap", "drop"])
    ap.add_argument("dataset", help="e.g. system.syslog, system.auth, nginx.access, postgresql.log")
    ap.add_argument("--samples", type=int, default=200, help="verify: lines to check")
    args = ap.parse_args()
    try:
        if args.step == "build":
            return build(args.dataset)
        if args.step == "verify":
            return verify(args.dataset, args.samples)
        return {"swap": swap, "drop": drop}[args.step](args.dataset)
    except (subprocess.SubprocessError, OSError, RuntimeError, KeyError, ValueError) as exc:
        print(f"{args.step} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
