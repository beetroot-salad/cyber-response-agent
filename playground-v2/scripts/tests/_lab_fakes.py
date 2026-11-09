"""Fakes that record lab operations and inject inputs and failures. None of them implements policy.

One `Journal` is shared by every fake in a test, so order across the lock store, the clock, the
Elasticsearch seam and the lab operations is read from a single list of `(op, detail)` entries.

Owner: the lab-core author (make-a-case, launcher). Other modules may import and ADD fakes in
their own files, never edit this one. Names kept stable from the sketch: Journal, FakeLockStore,
FakeClock, FakeES, sha, canonical_digest, instant, seconds. Added (r6.4.1):

* `RULES_PART`: the name of the detection-rules part in a freeze's `parts` (A5).
* `FakeCluster(FakeES)`: a frozen Elasticsearch that HOLDS documents, so a test reads the end
  state (`cluster.indices`, `.pipelines`, `.repos`, `.ilm`, `.lifecycle_off`, `.mutations`).
  Supported: snapshot GET/PUT/restore, `_ilm/stop`, per-stream lifecycle DELETE, index DELETE and
  `_close`, `_count`, `_search` (match_all/term/terms/range/exists/ids/bool; size/from only),
  `_delete_by_query`, `_reindex` (pipeline, version_type external, op_type create), ingest
  pipelines (`drop` with the data-drop Painless condition, `rename`, `remove`), `_cat/indices`,
  `_cluster/health`. Anything else raises NotImplementedError so a gap is loud, not silent.
  Data-stream membership is by backing-index name only (deferred verification item 7).
* `World`: the documents a snapshot holds (auth, syslog, nginx events; alerts with ancestry).
* `LabOps`: the lab operations seam both make-a-case and the launcher drive.
* `LabRig`: a freeze + parts + case dir + cluster + ops wired together on a tmp path.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

RULES_PART = "detection-rules.tar"


class Journal(list):
    def ops(self) -> list[str]:
        return [op for op, _ in self]

    def first(self, op: str) -> int:
        return self.ops().index(op)

    def last(self, op: str) -> int:
        return len(self) - 1 - self.ops()[::-1].index(op)


class FakeLockStore:
    """The lab-side record store `chaos.lock` drives: three primitives, nothing more."""

    def __init__(self, journal: Journal) -> None:
        self.journal = journal
        self.records: dict[str, str] = {}
        self._mutex = threading.Lock()

    def create_exclusive(self, name: str, record: str) -> bool:
        with self._mutex:
            self.journal.append(("lock.create", name))
            if name in self.records:
                return False
            self.records[name] = record
            return True

    def read(self, name: str) -> str | None:
        self.journal.append(("lock.read", name))
        return self.records.get(name)

    def delete(self, name: str) -> None:
        self.journal.append(("lock.delete", name))
        self.records.pop(name, None)


class FakeClock:
    """`now()` advances one second per call; `sleep_until` jumps to the moment it is given.
    `last` is the latest reading handed out."""

    def __init__(self, journal: Journal, start: datetime) -> None:
        self.journal, self.last = journal, start

    def now(self) -> datetime:
        self.last = self.last + timedelta(seconds=1)
        return self.last

    def sleep(self, seconds: float) -> None:
        self.journal.append(("clock.sleep", seconds))
        self.last = self.last + timedelta(seconds=seconds)

    def sleep_until(self, moment: Any) -> None:
        moment = instant(moment)
        self.journal.append(("clock.sleep_until", moment))
        self.last = max(self.last, moment)


class FakeES:
    """The chaos seam's `es_request(method, path, body=None)` shape (chaos/seam.py), recording.

    `answers` maps `(METHOD, /path-without-query)` (leading slash either way) to a payload or to `fn(body) -> payload`;
    then `route(method, path, body)`; anything unanswered returns `{}` (ES's acknowledged shape is not what a test reads).
    `fail(method, path, body) -> bool` raises `RuntimeError` for a request a test faults."""

    def __init__(self, journal: Journal, answers: dict | None = None,
                 fail: Callable[[str, str, Any], bool] | None = None,
                 route: Callable[[str, str, Any], Any] | None = None) -> None:
        self.journal, self.answers, self.fail = journal, dict(answers or {}), fail
        self.route = route
        self.requests: list[tuple[str, str, Any]] = []

    def es_request(self, method: str, path: str, body: Any = None) -> Any:
        path = path if path.startswith("/") else "/" + path  # one spelling for every reader below
        self.requests.append((method, path, body))
        self.journal.append(("es", (method, path)))
        if self.fail is not None and self.fail(method, path, body):
            raise RuntimeError(f"{method} {path} failed")
        key = (method, path.split("?", 1)[0])
        if key in self.answers:
            answer = self.answers[key]
            return answer(body) if callable(answer) else answer
        return self.route(method, key[1], body) if self.route is not None else {}

    def matching(self, method: str, needle: str) -> list[tuple[str, str, Any]]:
        return [r for r in self.requests if r[0] == method and needle in r[1]]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(doc: Any) -> str:
    """r6.1's canonical-JSON sha256 (sorted keys, compact separators, ASCII-escaped)."""
    return sha(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())


def instant(value: Any) -> datetime:
    """A timestamp however it is spelled, as an aware datetime (spelling is the builder's)."""
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def seconds(value: Any) -> float:
    """A duration however it is spelled (timedelta, number of seconds)."""
    return value.total_seconds() if isinstance(value, timedelta) else float(value)


# -- a frozen Elasticsearch that holds documents -------------------------------------------------

class FakeGap(AssertionError):
    """A request the fake does not model. Raised loudly; `LabRig.launch` also fails on any."""


def _values(obj: Any, path: str) -> list:
    """Every value at a dotted `path` in a document whose keys may themselves be dotted."""
    if isinstance(obj, list):
        return [v for item in obj for v in _values(item, path)]
    if not isinstance(obj, dict):
        return []
    found: list = []
    for key, value in obj.items():
        if key == path:
            found.extend(value if isinstance(value, list) else [value])
        elif path.startswith(key + "."):
            found.extend(_values(value, path[len(key) + 1:]))
    return found


def _ordered(a: Any, b: Any) -> tuple[Any, Any]:
    try:
        return instant(a), instant(b)
    except (ValueError, TypeError):
        return a, b


def _matches(query: dict | None, source: dict, doc_id: str) -> bool:
    if not query or "match_all" in query:
        return True
    (kind, arg), = query.items()
    if kind == "bool":
        def clause(name):
            got = arg.get(name, [])
            return got if isinstance(got, list) else [got]

        must = clause("must") + clause("filter")
        should = clause("should")
        ok = (all(_matches(q, source, doc_id) for q in must)
              and not any(_matches(q, source, doc_id) for q in clause("must_not")))
        return ok and (bool(must) or not should or any(_matches(q, source, doc_id) for q in should))
    if kind == "term":
        (field, want), = arg.items()
        want = want.get("value") if isinstance(want, dict) else want
        return any(str(v) == str(want) for v in _values(source, field))
    if kind == "terms":
        (field, wants), = arg.items()
        return any(str(v) in {str(w) for w in wants} for v in _values(source, field))
    if kind == "ids":
        return doc_id in arg["values"]
    if kind == "exists":
        return bool(_values(source, arg["field"]))
    if kind == "range":
        (field, bounds), = arg.items()
        tests = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
                 "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b}
        for value in _values(source, field):
            if all(tests[op](*_ordered(value, bound)) for op, bound in bounds.items() if op in tests):
                return True
        return False
    raise FakeGap(f"query kind {kind!r}")


def _java_hash(text: str) -> int:
    h = 0
    for ch in text:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return h - (1 << 32) if h & 0x80000000 else h


_DROP_IF = re.compile(r"ctx\.message != null && \(\(ctx\.message \+ '(.*)'\)\.hashCode\(\) "
                      r"& 0x7fffffff\) % 100 < (\d+)$")


def run_processors(processors: list[dict], source: dict) -> dict | None:
    """What an ingest pipeline made of `processors` does to one flat document; None = dropped.
    The oracle for "exactly what the verbatim processor outputs" (drop, rename, remove)."""
    doc = copy.deepcopy(source)
    for processor in processors:
        (kind, spec), = processor.items()
        if kind == "drop":
            m = _DROP_IF.match(spec.get("if", ""))
            if m is None:
                raise FakeGap(f"drop condition {spec!r}")
            if "message" in doc and (_java_hash(str(doc["message"]) + m.group(1)) & 0x7FFFFFFF) % 100 < int(m.group(2)):
                return None
        elif kind in ("rename", "remove"):
            field = spec["field"]
            keys = [k for k in doc if k == field or k.startswith(field + ".")]
            if not keys and not spec.get("ignore_missing"):
                raise RuntimeError(f"field [{field}] not present")
            for key in keys:
                value = doc.pop(key)
                if kind == "rename":
                    doc[spec["target_field"] + key[len(field):]] = value
        else:
            raise FakeGap(f"processor {kind!r}")
    return doc


class FakeCluster(FakeES):
    """A frozen cluster. `content` is what the snapshot holds: `{index: {id: {"_source", "_version"}}}`;
    `streams` maps a backing index to its data stream's name (membership by name only).
    `observe()` is called at every mutating request and its result kept in `mutations`, so a test
    reads, e.g., what the copy-state marker said at that moment. `health_status` is what
    `_cluster/health` answers."""

    def __init__(self, journal: Journal, *, repo: str, snapshot: str, snapshot_uuid: str,
                 content: dict, streams: dict[str, str],
                 fail: Callable[[str, str, Any], bool] | None = None,
                 observe: Callable[[], Any] | None = None) -> None:
        super().__init__(journal, fail=fail, route=self._dispatch)
        self.repo, self.snapshot, self.snapshot_uuid = repo, snapshot, snapshot_uuid
        self.content, self.stream_of, self.observe = content, dict(streams), observe
        self.indices: dict[str, dict] = {}
        self.repos: dict[str, Any] = {}
        self.pipelines: dict[str, dict] = {}
        self.ilm, self.lifecycle_off, self.health_status = "RUNNING", set(), "green"
        self.mutations: list[dict] = []
        self.restores = 0
        self.unsupported: list[str] = []
        self._uuids = 0

    # -- state helpers a test reads -----------------------------------------------------------

    def state(self) -> dict[str, dict[str, tuple[int, dict]]]:
        """`{index: {id: (version, source)}}` of every index."""
        return {n: {i: (d["_version"], d["_source"]) for i, d in ix["docs"].items()}
                for n, ix in self.indices.items()}

    def put(self, name: str, doc_id: str, source: dict, version: int = 1) -> None:
        self._index(name)["docs"][doc_id] = {"_source": copy.deepcopy(source), "_version": version}

    def _index(self, name: str) -> dict:
        if name not in self.indices:
            self._uuids += 1
            self.indices[name] = {"uuid": f"uuid-{name}-{self._uuids}", "docs": {}, "closed": False}
        return self.indices[name]

    def _note(self, kind: str, target: str) -> None:
        self.mutations.append({"kind": kind, "target": target, "ilm": self.ilm,
                               "lifecycle_off": set(self.lifecycle_off),
                               "streams": {s for n, s in self.stream_of.items() if n in self.indices},
                               "observed": self.observe() if self.observe else None})

    def _expand(self, expr: str, *, streams: bool = True, closed: bool = False) -> list[str]:
        names: list[str] = []
        for part in expr.split(","):
            for name, ix in self.indices.items():
                hit = fnmatch.fnmatchcase(name, part) or (
                    streams and name in self.stream_of and fnmatch.fnmatchcase(self.stream_of[name], part))
                if hit and name not in names and (closed or not ix["closed"]):
                    names.append(name)
            if not names and not any(c in part for c in "*?") and part not in self.indices:
                raise RuntimeError(f"index_not_found_exception: no such index [{part}]")
        return names

    # -- routing -----------------------------------------------------------------------------------

    def _dispatch(self, method: str, path: str, body: Any) -> Any:
        seg = path.strip("/").split("/")
        ack = {"acknowledged": True}
        try:
            if seg[0] == "_snapshot":
                return self._snapshots(method, seg, body)
            if path == "/_ilm/stop":
                self.ilm = "STOPPED"
                return ack
            if path == "/_ilm/status":
                return {"operation_mode": self.ilm}
            if seg[0] == "_data_stream" and seg[-1] == "_lifecycle" and method == "DELETE":
                self.lifecycle_off.add(seg[1])
                return ack
            if path == "/_cluster/health":
                n = sum(1 for ix in self.indices.values() if not ix["closed"])
                return {"status": self.health_status, "active_primary_shards": n,
                        "unassigned_shards": 0 if self.health_status == "green" else 1}
            if seg[0] == "_cat" and seg[1] == "indices":
                names = self._expand(seg[2], closed=True) if len(seg) > 2 else list(self.indices)
                return [{"index": n, "uuid": self.indices[n]["uuid"], "health": self.health_status,
                         "status": "close" if self.indices[n]["closed"] else "open",
                         "docs.count": str(len(self.indices[n]["docs"]))} for n in names]
            if path == "/_reindex":
                return self._reindex(body)
            if seg[0] == "_ingest" and seg[1] == "pipeline":
                return self._pipeline(method, seg[2] if len(seg) > 2 else None, body)
            if any(s in path for s in ("/_refresh", "/_flush", "/_settings", "/_security", "/_cluster/settings")):
                return ack
            if method == "DELETE" and len(seg) == 1:
                names = self._expand(seg[0], streams=False, closed=True)
                self._note("delete-index", seg[0])
                for n in names:
                    del self.indices[n]
                return ack
            if method == "PUT" and len(seg) == 1:
                if seg[0] in self.indices:
                    raise RuntimeError(f"resource_already_exists_exception [{seg[0]}]")
                self._index(seg[0])
                return ack
            if len(seg) == 2 and seg[1] == "_close":
                for n in self._expand(seg[0], streams=False):
                    self.indices[n]["closed"] = True
                return ack
            if len(seg) == 2 and seg[1] == "_count":
                return {"count": sum(len(self.indices[n]["docs"]) for n in self._expand(seg[0]))}
            if len(seg) == 2 and seg[1] == "_search":
                return self._search(seg[0], body or {})
            if len(seg) == 2 and seg[1] == "_delete_by_query":
                return self._delete_by_query(seg[0], body or {})
        except FakeGap as gap:
            self.unsupported.append(str(gap))
            raise
        self.unsupported.append(f"{method} {path}")
        raise FakeGap(f"{method} {path}")

    def _snapshots(self, method: str, seg: list[str], body: Any) -> Any:
        repo = seg[1]
        if len(seg) == 2 and method in ("PUT", "POST"):
            self.repos[repo] = body or {}
            return {"acknowledged": True}
        if repo not in self.repos:
            raise RuntimeError(f"repository_missing_exception [{repo}]")
        snap = seg[2]
        if len(seg) == 3 and method == "GET":
            if (repo, snap) != (self.repo, self.snapshot):
                raise RuntimeError(f"snapshot_missing_exception [{repo}:{snap}]")
            return {"snapshots": [{"snapshot": snap, "uuid": self.snapshot_uuid, "state": "SUCCESS",
                                   "indices": list(self.content)}]}
        if len(seg) == 3 and method in ("PUT", "POST"):
            if (self.repos[repo].get("settings") or {}).get("readonly") or self.repos[repo].get("readonly"):
                raise RuntimeError(f"repository_exception: [{repo}] cannot create snapshot in a readonly repository")
            return {"accepted": True}
        if len(seg) == 4 and seg[3] == "_restore":
            return self._restore(body or {})
        raise FakeGap(f"snapshot request {method} /{'/'.join(seg)}")

    def _restore(self, body: dict) -> Any:
        wanted = body.get("indices")
        names = list(self.content)
        if wanted:
            parts = wanted.split(",") if isinstance(wanted, str) else list(wanted)
            names = [n for n in names if any(fnmatch.fnmatchcase(n, p) for p in parts)]
        self._note("restore", ",".join(names))
        for n in names:
            if n in self.indices and not self.indices[n]["closed"]:
                raise RuntimeError(f"snapshot_restore_exception: cannot restore index [{n}] because an "
                                   "open index with same name already exists in the cluster")
        for n in names:
            self.indices.pop(n, None)
            self._index(n)["docs"] = copy.deepcopy(self.content[n])
        self.restores += 1
        return {"snapshot": {"snapshot": self.snapshot, "indices": names,
                             "shards": {"total": len(names), "failed": 0, "successful": len(names)}}}

    def _search(self, expr: str, body: dict) -> Any:
        hits = []
        for n in self._expand(expr):
            for i, d in sorted(self.indices[n]["docs"].items()):
                if _matches(body.get("query"), d["_source"], i):
                    hits.append({"_index": n, "_id": i, "_version": d["_version"],
                                 "_source": copy.deepcopy(d["_source"])})
        start = int(body.get("from", 0))
        page = hits[start:start + int(body.get("size", 10))]
        return {"hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": page}}

    def _delete_by_query(self, expr: str, body: dict) -> Any:
        self._note("delete_by_query", expr)
        deleted = 0
        for n in self._expand(expr):
            docs = self.indices[n]["docs"]
            for i in [i for i, d in docs.items() if _matches(body.get("query"), d["_source"], i)]:
                del docs[i]
                deleted += 1
        return {"deleted": deleted, "total": deleted, "version_conflicts": 0, "failures": []}

    def _pipeline(self, method: str, name: str | None, body: Any) -> Any:
        if method == "PUT":
            self.pipelines[name] = body or {}
            return {"acknowledged": True}
        if method == "DELETE":
            if name not in self.pipelines:
                raise RuntimeError(f"resource_not_found_exception pipeline [{name}]")
            del self.pipelines[name]
            return {"acknowledged": True}
        if method == "GET":
            return {n: p for n, p in self.pipelines.items() if name in (None, n)}
        raise FakeGap(f"pipeline {method}")

    def _reindex(self, body: dict) -> Any:
        source, dest = body["source"], body["dest"]
        if body.get("script") or source.get("script"):
            raise FakeGap("reindex script")
        sources = source["index"] if isinstance(source["index"], str) else ",".join(source["index"])
        pipeline = dest.get("pipeline")
        processors = None
        if pipeline is not None:
            if pipeline not in self.pipelines:
                raise RuntimeError(f"pipeline with id [{pipeline}] does not exist")
            processors = self.pipelines[pipeline].get("processors", [])
        self._note("reindex", f"{sources}->{dest['index']}")
        total = created = 0
        for n in self._expand(sources):
            if n == dest["index"]:
                raise RuntimeError("reindex cannot write into an index its reading from")
            for i, d in sorted(self.indices[n]["docs"].items()):
                if not _matches(source.get("query"), d["_source"], i):
                    continue
                total += 1
                out = d["_source"] if processors is None else run_processors(processors, d["_source"])
                if out is None:
                    continue
                target = self._index(dest["index"])["docs"]
                existing = target.get(i)
                external = dest.get("version_type") == "external"
                if (dest.get("op_type") == "create" and existing) or (
                        external and existing and existing["_version"] >= d["_version"]):
                    raise RuntimeError(f"version_conflict_engine_exception [{i}]")
                version = d["_version"] if external else (existing["_version"] + 1 if existing else 1)
                target[i] = {"_source": copy.deepcopy(out), "_version": version}
                created += 1
        return {"total": total, "created": created, "updated": 0, "deleted": 0,
                "version_conflicts": 0, "failures": []}


# -- the world a snapshot holds ---------------------------------------------------------------------

T = "2026-10-20T09:00:00Z"
SPAN_START = "2026-10-20T07:00:00Z"
FREEZE_ID, SLUG = "f-2026-10-20", "m05-off-hours-sudo"
REPO, SNAP, SNAP_UUID = "frozen-cases", "f-2026-10-20", "dGhlLXNuYXBzaG90LXV1aWQ"
EVENTS, ALERTS_PATTERN = "logs-*", ".internal.alerts-security.alerts-default-*"
AUTH = ".ds-logs-system.auth-default-2026.10.01-000004"
SYSLOG = ".ds-logs-system.syslog-default-2026.10.01-000004"
NGINX = ".ds-logs-nginx.access-default-2026.10.01-000002"
ALERTS = ".internal.alerts-security.alerts-default-000001"
STREAMS = {AUTH: "logs-system.auth-default", SYSLOG: "logs-system.syslog-default",
           NGINX: "logs-nginx.access-default"}
_BASE = datetime(2026, 10, 20, 4, 0, tzinfo=UTC)

# Events: auth every 10 min from 04:00 (auth-00..35: 05 after T, 13 in the span [07:00, T] with a
# document exactly on each bound); syslog every 12 min (syslog-00..29: 04 after T, 11 in the span,
# one on each bound); nginx every 30 min (nothing after T, 3 in the span).
AUTH_IN_SPAN = [f"auth-{i:02d}" for i in range(18, 31)]
AUTH_AFTER_T = [f"auth-{i:02d}" for i in range(31, 36)]
SYSLOG_IN_SPAN = [f"syslog-{j:02d}" for j in range(15, 26)]
SYSLOG_AFTER_T = [f"syslog-{j:02d}" for j in range(26, 30)]
DATA_DROP = {"kind": "data-drop", "dataset": "system.syslog", "stream": "logs-system.syslog-*",
             "pipeline": "logs-system.syslog@custom", "fields": [],
             "processor": {"drop": {"if": "ctx.message != null && ((ctx.message + '7').hashCode() "
                                          "& 0x7fffffff) % 100 < 25"}}}
SCHEMA_DRIFT = {"kind": "schema-drift", "dataset": "system.auth", "stream": "logs-system.auth-*",
                "pipeline": "logs-system.auth@custom", "fields": ["source.port", "source.port_no"],
                "processor": {"rename": {"field": "source.port", "target_field": "source.port_no",
                                         "ignore_missing": True, "ignore_failure": True}}}
CMDB_STALE = {"kind": "field-flip", "host": "web-1", "field": "owner",
              "old_value": "platform", "new_value": "payments"}
RULES = {"v2-sshd-failed-auth-burst.json": {
             "rule_id": "v2-sshd-failed-auth-burst", "type": "threshold", "index": ["logs-system.auth-*"],
             "query": "event.outcome:failure", "threshold": {"field": ["source.ip", "user.name"], "value": 5}},
         "v2-off-hours-sudo.json": {
             "rule_id": "v2-off-hours-sudo", "type": "query", "index": ["logs-system.auth-*"],
             "query": "process.name:sudo and event.outcome:success"}}


def _at(minutes: int) -> str:
    return (_BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def alert_doc(uuid: str, at: str, *, status: str = "open", ancestors: tuple = (), port: int | None = None) -> dict:
    doc = {"@timestamp": at, "kibana.alert.uuid": uuid, "kibana.alert.workflow_status": status,
           "kibana.alert.rule.name": "v2 off-hours sudo", "host.name": "web-1",
           "kibana.alert.original_time": at,
           "kibana.alert.ancestors": [{"id": i, "type": "event", "index": ix, "depth": 0}
                                      for i, ix in ancestors]}
    if port is not None:
        doc["source.port"] = port
    return doc


ALERT_DOCS = {a["kibana.alert.uuid"]: a for a in [
    alert_doc("young", "2026-10-20T08:10:00Z", ancestors=(("auth-25", AUTH),), port=40025),
    alert_doc("derived-in", "2026-10-20T08:30:00Z", ancestors=(("auth-27", AUTH),), port=40027),
    # in the span by its own time, but its source event (06:00) is before it: not derived from the span
    alert_doc("derived-pre", "2026-10-20T07:30:00Z", ancestors=(("auth-12", AUTH),), port=40012),
    # derived from a span event of another dataset that carries the renamed field too
    alert_doc("syslog-alert", "2026-10-20T08:00:00Z", ancestors=(("syslog-20", SYSLOG),), port=41000),
    alert_doc("edge", "2026-10-20T03:00:00Z"),                       # exactly max_age old
    alert_doc("at-T", T),
    alert_doc("old", "2026-10-20T02:59:59Z"),                        # older than max_age
    alert_doc("future", "2026-10-20T09:00:01Z"),                     # stamped after T
    alert_doc("live-run", "2026-10-20T08:20:00Z"),
    alert_doc("ticketed", "2026-10-20T08:35:00Z"),
    alert_doc("acknowledged", "2026-10-20T08:40:00Z", status="acknowledged"),
]}
ALERT_VERSIONS = {"young": 3, "derived-in": 2}      # alerts are updated by workflow: _version is not 1


def world_content() -> dict[str, dict[str, dict]]:
    """What the snapshot holds: `{index: {id: {"_source", "_version"}}}`, flat dotted keys."""
    def event(i, minute, dataset, message, **extra):
        return {"@timestamp": _at(minute), "message": message, "event.dataset": dataset, **extra}

    auth = {f"auth-{i:02d}": {"_source": event(i, 10 * i, "system.auth", f"auth event {i}",
                                                **{"user.name": f"user{i % 4}", "source.ip": f"10.0.0.{i}",
                                                   "source.port": 40000 + i}),
                              "_version": 2 if i == 20 else 1} for i in range(36)}
    syslog = {f"syslog-{j:02d}": {"_source": event(j, 12 * j, "system.syslog", f"syslog line {j}"),
                                  "_version": 1} for j in range(30)}
    nginx = {f"nginx-{k:02d}": {"_source": event(k, 30 * k, "nginx.access", f"GET /{k}"), "_version": 1}
             for k in range(10)}
    alerts = {f"id-{u}": {"_source": copy.deepcopy(a), "_version": ALERT_VERSIONS.get(u, 1)}
              for u, a in ALERT_DOCS.items()}
    return {AUTH: auth, SYSLOG: syslog, NGINX: nginx, ALERTS: alerts}


def expected_copy(kind: str) -> dict[str, dict[str, tuple[int, dict]]]:
    """The end state of the variant's copy, written out explicitly from the world constants:
    `none` = base overlay only; `drop` = + the data-drop mutation; `drift` = + the schema-drift one;
    `cmdb` = base overlay only (the CMDB flip lives in the stub store)."""
    state = {n: {i: (d["_version"], copy.deepcopy(d["_source"])) for i, d in docs.items()}
             for n, docs in world_content().items()}
    for docs in state.values():
        for i in [i for i, (_v, src) in docs.items() if instant(src["@timestamp"]) > instant(T)]:
            del docs[i]
    if kind == "drop":
        for i in SYSLOG_IN_SPAN:
            if run_processors([DATA_DROP["processor"]], state[SYSLOG][i][1]) is None:
                del state[SYSLOG][i]
    elif kind == "drift":
        def drift(source):
            source["source.port_no"] = source.pop("source.port")

        for i in AUTH_IN_SPAN:
            drift(state[AUTH][i][1])
        for u in ("young", "derived-in"):
            drift(state[ALERTS][f"id-{u}"][1])
    return state


def counts_of(state: dict) -> dict[str, int]:
    return {n: len(docs) for n, docs in state.items()}


# -- the lab operations seam -------------------------------------------------------------------------

FROZEN_PROXY_URL = "http://frozen-proxy.internal:8443"
LIVE_PROXY_URL = "http://credential-proxy:8443"


def stub_state(parts: dict[str, bytes], mutations: Any) -> str:
    """What the stub stores hold once loaded from `parts` with the case's resolved mutations."""
    return canonical_digest({"parts": {n: sha(b) for n, b in sorted(parts.items())},
                             "mutations": [m for m in (mutations or []) if m.get("kind") == "field-flip"]})


def content_of(state: dict, stubs: str) -> str:
    """The content digest the fake lab ops answers: every index's documents and the stub stores."""
    return canonical_digest({"es": {n: {i: [v, s] for i, (v, s) in sorted(docs.items())}
                                    for n, docs in sorted(state.items())}, "stubs": stubs})


class LabOps:
    """The lab operations both make-a-case and the launcher drive. Records; implements no policy.

    read_marker() -> dict | None; write_marker(marker); load_stubs(parts_dir_of_the_freeze, as_of, mutations);
    restart_node(clock_offset); start_proxy() -> url; content_digest() -> hex (needs stubs loaded
    since the last teardown); teardown(); and for make-a-case: snapshot_alerts(freeze_dir),
    live_run_alerts(), ticketed_alerts(), freeze_rules(freeze_dir) -> dir of rule JSON."""

    def __init__(self, rig: "LabRig") -> None:
        self.rig = rig
        self.marker: dict | None = None
        self.markers: list[dict] = []
        self.stubs: tuple | None = None
        self.stub_digest: str | None = None
        self.offset = self.offset_reading = None
        self.loads: list[tuple] = []
        self.proxy_up = False
        self.fail_at: str | None = None      # an op name that raises when called

    def _j(self, name: str, detail: Any = None) -> None:
        self.rig.journal.append((name, detail))
        if name == self.fail_at:
            raise RuntimeError(f"{name} failed")

    def read_marker(self):
        self._j("read_marker")
        return None if self.marker is None else copy.deepcopy(self.marker)

    def write_marker(self, marker):
        self.marker = copy.deepcopy(marker)
        self.markers.append(copy.deepcopy(marker))
        self._j("write_marker", copy.deepcopy(marker))

    def load_stubs(self, parts, as_of, mutations=None):
        self.stubs = (parts, as_of, mutations)
        self.loads.append(self.stubs)
        root = Path(parts)
        self.stub_digest = stub_state({p.name: p.read_bytes() for p in sorted(root.iterdir())
                                       if p.is_file() and p.name != RULES_PART}, mutations)
        self._j("load_stubs")

    def restart_node(self, clock_offset):
        self.offset, self.offset_reading = clock_offset, self.rig.clock.last
        self._j("restart_node", clock_offset)

    def start_proxy(self):
        self.proxy_up = True
        self._j("start_proxy")
        return FROZEN_PROXY_URL

    def content_digest(self):
        assert self.stub_digest is not None, "content digest asked before the stub stores were loaded"
        self._j("content_digest")
        return content_of(self.rig.cluster.state(), self.stub_digest)

    def teardown(self):
        self.rig.index_at_teardown = self.rig.index.read_text() if self.rig.index.exists() else ""
        self.rig.cluster_at_teardown = self.rig.cluster.state()
        self.stub_digest, self.proxy_up = None, False
        self._j("teardown")

    def snapshot_alerts(self, freeze_dir):
        return [copy.deepcopy(a) for a in ALERT_DOCS.values()]

    def live_run_alerts(self):
        return {"live-run"}

    def ticketed_alerts(self):
        return {"ticketed"}

    def freeze_rules(self, freeze_dir):
        return self.rig.rules_dir


# -- the rig ------------------------------------------------------------------------------------------

PARTS = {"stubs.tar": b"stub-dump-bytes", "proc-tree.txt": b"PID PPID\n1 0 init\n",
         RULES_PART: b"rules-as-of-T"}
ROW_KEYS = {"slug", "run_id", "binding", "verdict", "reason", "verified_at", "knowledge"}
RUN_ID = "5b0d1f2e-3c4d-4e5f-8a6b-7c8d9e0f1a2b"


def load_script(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LabRig:
    """A freeze, its parts, a case dir, an empty frozen cluster that can restore the freeze's
    snapshot, the lab ops and a lock store, on `tmp_path`. `overlay`/`kind` pick the variant for
    `write_expected_case`; `fail(method, path, body)` faults a cluster request."""

    def __init__(self, tmp_path: Path, *, fail: Callable | None = None, snapshot_uuid: str = SNAP_UUID,
                 rules: dict | None = None, run_rc: int = 0, run_out: str | None = None) -> None:
        self.tmp_path = tmp_path
        self.journal = Journal()
        self.store = FakeLockStore(self.journal)
        self.clock = FakeClock(self.journal, instant("2026-11-08T12:00:00Z"))
        self.ops = LabOps(self)
        self.cluster = FakeCluster(self.journal, repo=REPO, snapshot=SNAP, snapshot_uuid=snapshot_uuid,
                                   content=world_content(), streams=STREAMS, fail=fail,
                                   observe=lambda: copy.deepcopy(self.ops.marker))
        self.freezes = tmp_path / "held_out" / "freezes"
        self.freeze_dir = self.freezes / FREEZE_ID
        self.freeze_dir.mkdir(parents=True)
        self.freeze = {"T": T, "elastic": {"repository": REPO, "snapshot": SNAP, "uuid": SNAP_UUID,
                                           "indices": counts_of(world_content())},
                       "parts": {n: sha(b) for n, b in PARTS.items()}, "captured_by": "op"}
        (self.freeze_dir / "freeze.yaml").write_text(yaml.safe_dump(self.freeze))
        self.parts = tmp_path / "parts"
        (self.parts / FREEZE_ID).mkdir(parents=True)
        for n, b in PARTS.items():
            (self.parts / FREEZE_ID / n).write_bytes(b)
        self.rules_dir = tmp_path / "rules-at-T"
        self.rules_dir.mkdir()
        for name, rule in (rules or RULES).items():
            (self.rules_dir / name).write_text(json.dumps(rule))
        self.case_dir = tmp_path / "held_out" / SLUG
        self.case_dir.mkdir(parents=True)
        (self.case_dir / "ground_truth.yaml").write_text("held_out: true\ndisposition: benign\n")
        self.index = tmp_path / "ops" / "held-out-index.jsonl"
        self.index.parent.mkdir()
        self.run_rc = run_rc
        self.run_out = f"run_id={RUN_ID}\n" if run_out is None else run_out
        self.argv = self.env = None
        self.index_at_teardown: str | None = None
        self.cluster_at_teardown: dict | None = None
        self.run_hook: Callable[[], None] | None = None
        self.lock_in_run: bool | None = None

    @property
    def launch_module(self):
        return load_script("launch_1347", Path(__file__).resolve().parents[1] / "launch_frozen.py")

    @property
    def make_module(self):
        return load_script("make_case_1347", Path(__file__).resolve().parents[1] / "make_case.py")

    # -- cases --------------------------------------------------------------------------------------

    def write_expected_case(self, kind: str, *, alert_uuid: str = "young", confirmed: bool = True,
                            **over: Any) -> dict:
        """case.yaml (and alert.json) for variant `kind`, every recorded value derived from the
        explicit `expected_copy(kind)`, not from running anything."""
        mutations = {"none": None, "cmdb": [CMDB_STALE], "drop": [DATA_DROP], "drift": [SCHEMA_DRIFT]}[kind]
        overlay = None if mutations is None else {"mutations": mutations, "span_start": SPAN_START}
        state = expected_copy(kind)
        doc = state[ALERTS][f"id-{alert_uuid}"][1]
        (self.case_dir / "alert.json").write_text(json.dumps(doc))
        stubs = stub_state({n: b for n, b in PARTS.items() if n != RULES_PART}, mutations)
        case = {"freeze": FREEZE_ID, "alert": canonical_digest(doc), "age": 3000, "overlay": overlay,
                "counts": counts_of(state), "content": content_of(state, stubs),
                "confirmed": ({"by": "op", "at": "2026-10-21T10:00:00Z", "reference_run": "r0"}
                              if confirmed else None), **over}
        (self.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
        return case

    def case(self) -> dict:
        return yaml.safe_load((self.case_dir / "case.yaml").read_text())

    # -- the agent ----------------------------------------------------------------------------------

    def run_fn(self, argv, env):
        self.journal.append(("run", None))
        self.argv, self.env = list(argv), dict(env)
        self.lock_in_run = "frozen-engine" in self.store.records
        if self.run_hook is not None:
            self.run_hook()
        return self.run_rc, self.run_out, ""

    def launch(self, **kw):
        kw = {"knowledge": "abc1234", **kw}
        try:
            return self.launch_module.launch(
                self.case_dir, freezes_dir=self.freezes, patterns=[EVENTS, ALERTS_PATTERN],
                index=self.index, parts_dir=self.parts, lock_store=self.store, es=self.cluster,
                ops=self.ops, run_fn=self.run_fn, clock=self.clock,
                env={"PATH": "/usr/bin", "DEFENDER_CREDENTIAL_PROXY_URL": LIVE_PROXY_URL},
                tenant="tenant-1", **kw)
        finally:
            assert not self.cluster.unsupported, f"the fake cluster does not model: {self.cluster.unsupported}"

    def write_case(self, alert_uuid: str, overlay: dict | None, **kw):
        try:
            return self.make_module.write_case(
                self.case_dir, freeze_dir=self.freeze_dir, alert_uuid=alert_uuid, overlay=overlay,
                patterns=[EVENTS, ALERTS_PATTERN], parts_dir=self.parts, lock_store=self.store,
                es=self.cluster, ops=self.ops, clock=self.clock,
                profiles_dir=kw.pop("profiles_dir", None) or Path(__file__).resolve().parents[2] / "chaos" / "profiles",
                inventory=kw.pop("inventory", None) or yaml.safe_load(
                    (Path(__file__).resolve().parents[2] / "hosts" / "inventory.yaml").read_text()),
                **kw)
        finally:
            assert not self.cluster.unsupported, f"the fake cluster does not model: {self.cluster.unsupported}"

    # -- reading what happened ----------------------------------------------------------------------

    def rows(self) -> list[dict]:
        return [json.loads(x) for x in self.index.read_text().splitlines()] if self.index.exists() else []

    def binding(self) -> str:
        return canonical_digest([canonical_digest(self.freeze), canonical_digest(self.case())])

    def es_at(self, pred: Callable[[str, str], bool]) -> list[int]:
        return [i for i, (op, d) in enumerate(self.journal) if op == "es" and pred(*d)]
