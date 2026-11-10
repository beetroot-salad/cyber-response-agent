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
  `_close`, `_count`, `_search` (match_all/term/terms/range/exists/ids/bool; size/from/sort/search_after/version, also as URL params, any other search
  URL param is a FakeGap; sorting on `_id` is refused as ES 9 does;
  unsorted = a seeded shuffle that differs between calls; from+size <= 10 000; `_version` only with
  `"version": true`; the total stops at 10 000 unless `track_total_hits`),
  `_delete_by_query`, `_reindex` (pipeline, version_type external, op_type create), ingest
  pipelines (`drop` with the data-drop Painless condition, `rename`, `remove`), `_cat/indices`,
  `_cluster/health`. Anything else raises NotImplementedError so a gap is loud, not silent.
  Data-stream membership is by backing-index name only (deferred verification item 7).
* `World`: the documents a snapshot holds (auth, syslog, nginx events; alerts with ancestry).
* `LabRig`: a freeze + parts + case dir + cluster + the REAL lab layer wired together on a tmp path.

Added (r6.4.2, repairs after attack batch 1):

* `FaultJournal`: a journal that raises `InjectedStep` from `append` at the k-th STEP entry (every entry but
  the lock store's and the clock's), after recording it, so one mechanism faults docker calls, cluster
  requests and the agent run alike. `step_log` lists the steps of a run that was not faulted.
* `FakeCluster`: per-operation `latency` that moves the rig clock (a restore takes minutes; `search` too).
* `expected_variant(mutation, span_start)` and `LabRig.write_variant_case(...)`: the end state of a
  variant and its case.yaml, from the world constants and the verbatim-processor oracle.

r6.4.3 (C-rig): the hand-written stand-in for the lab layer (`LabOps`) is gone. `LabRig` builds the real
`lab_ops.LabOps` and fakes only its outer edge: docker (`_rig_docker.RigDocker`, container-state aware, with
volumes and the files the lab keeps in the engine) and the frozen cluster, which the lab layer reaches through
its real curl path (`FrozenEs`): the rig docker answers the in-container curl from `FakeCluster`, with curl's
own exit code and `000` while the node does not listen. A node's cluster state lives on its data volume
(`save_node_state`/`load_node_state`). `FakeLockStore.delete_if_held_by` and `race` model finding 9.
A case's `content` is the digest the real layer gives the expected state (`LabRig.expected_content`).

r6.4.4: `FakeCluster.wedged` (on the node's data volume: health answers red for good; a fresh node on a new volume
is healthy) and `FakeCluster.nested` (`{index: n}` hidden nested documents: `_cat/indices` `docs.count` counts
them, `_count` does not, as in Elasticsearch). `LabRig.dirty_marker()` writes a dirty marker as a crashed restore
leaves it.
"""
from __future__ import annotations

import copy
import fnmatch
import functools
import hashlib
import json
import random
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import yaml

RULES_PART = "detection-rules.tar"


class Journal(list):
    def ops(self) -> list[str]:
        return [op for op, _ in self]

    def first(self, op: str) -> int:
        return self.ops().index(op)

    def last(self, op: str) -> int:
        return len(self) - 1 - self.ops()[::-1].index(op)


class InjectedStep(RuntimeError):
    """What a `FaultJournal` trip raises; the rig docker never turns it into an HTTP answer."""


class FaultJournal(Journal):
    """A `Journal` that raises `RuntimeError` when the `trip_at`-th step is appended (1-based), after
    recording it. A step is every entry except the lock store's (`lock.*`) and the clock's (`clock.*`)
    and those whose op is in `skip`. `step_log` is every step seen, so a run that is not faulted shows
    the steps a faulted run can be cut at."""

    def __init__(self, trip_at: int | None = None, skip: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.trip_at, self.skip, self.step_log, self.tripped = trip_at, set(skip), [], None

    def append(self, entry) -> None:
        super().append(entry)
        op = entry[0]
        if op.startswith(("lock.", "clock.")) or op in self.skip:
            return
        self.step_log.append(entry)
        if self.trip_at is not None and len(self.step_log) == self.trip_at:
            self.tripped = entry
            raise InjectedStep(f"injected failure at step {self.trip_at}: {op}")


class FakeLockStore:
    """The lab-side record store `chaos.lock` drives: four primitives, nothing more. r6.4.3 finding 9 adds
    `delete_if_held_by(name, token) -> bool`: one engine-side step that deletes the record only if its token is
    `token` (True when it deleted).

    `race(name, fn)` models another operator acting between a holder's read and its delete: `fn()` runs once,
    right AFTER the next `read(name)` has answered, or right BEFORE the next delete of `name` (either primitive)
    is served, whichever comes first, so a delete always meets the state `fn` left."""

    def __init__(self, journal: Journal) -> None:
        self.journal = journal
        self.records: dict[str, str] = {}
        self._mutex = threading.Lock()
        self._races: dict[str, Callable[[], None]] = {}

    def race(self, name: str, fn: Callable[[], None]) -> None:
        self._races[name] = fn

    def _run_race(self, name: str) -> None:
        fn = self._races.pop(name, None)
        if fn is not None:
            fn()

    def create_exclusive(self, name: str, record: str) -> bool:
        with self._mutex:
            self.journal.append(("lock.create", name))
            if name in self.records:
                return False
            self.records[name] = record
            return True

    def read(self, name: str) -> str | None:
        self.journal.append(("lock.read", name))
        answer = self.records.get(name)
        self._run_race(name)
        return answer

    def delete(self, name: str) -> None:
        self._run_race(name)
        self.journal.append(("lock.delete", name))
        self.records.pop(name, None)

    def delete_if_held_by(self, name: str, token: str) -> bool:
        with self._mutex:
            self._run_race(name)
            self.journal.append(("lock.delete", name))
            record = self.records.get(name)
            try:
                held = json.loads(record).get("token") if record is not None else None
            except (ValueError, AttributeError):
                held = None
            if record is None or not isinstance(held, str) or held != token:
                return False
            del self.records[name]
            return True


class FakeClock:
    """`now()` advances `step` seconds per call (default one; 0 = a clock that only moves when it is
    slept or `advance`d, for exact-boundary tests); `sleep_until` jumps to the moment it is given.
    `last` is the latest reading handed out."""

    def __init__(self, journal: Journal, start: datetime, step: float = 1) -> None:
        self.journal, self.last, self.step = journal, start, step

    def now(self) -> datetime:
        self.last = self.last + timedelta(seconds=self.step)
        return self.last

    def advance(self, delta: timedelta) -> None:
        """Time passing while something works (not a sleep the code under test asked for)."""
        self.last = self.last + delta

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
        key = (method, path.split("?", 1)[0])
        if "?" in path and key[1].endswith("/_search"):
            body = self._with_search_params(body, path.split("?", 1)[1])     # real ES reads these from the URL too
        if self.fail is not None and self.fail(method, key[1], body):   # faults match and report on the query-stripped path
            raise RuntimeError(f"{method} {key[1]} failed")
        if key in self.answers:
            answer = self.answers[key]
            return answer(body) if callable(answer) else answer
        return self.route(method, key[1], body) if self.route is not None else {}

    SEARCH_URL_PARAMS = ("version", "size", "from", "track_total_hits", "sort", "expand_wildcards")

    def _with_search_params(self, body: Any, query: str) -> dict:
        """The body with the URL parameters Elasticsearch accepts for `_search` merged in (the URL wins, as
        in ES). A parameter the fake does not model is a gap: loud, never silently ignored."""
        merged = dict(body or {})
        for name, values in parse_qs(query, keep_blank_values=True).items():
            if name not in self.SEARCH_URL_PARAMS:
                gap = f"search URL parameter [{name}]"
                if isinstance(getattr(self, "unsupported", None), list):
                    self.unsupported.append(gap)
                raise FakeGap(gap)
            value = values[-1]
            if name == "expand_wildcards":
                # Which index states a pattern reaches (open, hidden, closed, all); the fake's patterns
                # reach every index it holds, as `all` would, so this changes nothing it models.
                continue
            if name in ("size", "from"):
                merged[name] = int(value)
            elif name in ("version", "track_total_hits"):
                merged[name] = {"true": True, "false": False}.get(value.lower(), None)
                if merged[name] is None:
                    merged[name] = int(value)
            else:    # sort=field:dir,field2
                merged[name] = [{f: d} if d else f for f, _, d in (part.partition(":") for part in value.split(","))]
        return merged

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
    `_cluster/health` answers. `down_requests` lists what was asked while the node's container did not run
    (the rig docker refuses the exec, as docker does). `up=False` makes a direct request raise.
    `latency` maps `restore` / `delete_by_query` / `reindex` to the time that request takes, moved
    onto `clock` once the request has done its work."""

    def __init__(self, journal: Journal, *, repo: str, snapshot: str, snapshot_uuid: str,
                 content: dict, streams: dict[str, str],
                 fail: Callable[[str, str, Any], bool] | None = None,
                 observe: Callable[[], Any] | None = None,
                 clock: "FakeClock | None" = None, latency: dict[str, timedelta] | None = None,
                 up: bool = True) -> None:
        super().__init__(journal, fail=fail, route=self._dispatch)
        self.repo, self.snapshot, self.snapshot_uuid = repo, snapshot, snapshot_uuid
        self.content, self.stream_of, self.observe = content, dict(streams), observe
        self.indices: dict[str, dict] = {}
        self.repos: dict[str, Any] = {}
        self.pipelines: dict[str, dict] = {}
        self.ilm, self.lifecycle_off, self.health_status = "RUNNING", set(), "green"
        # r6.4.4: the node's data never recovers (shards red for good, as after a restore that crashed); it lives on
        # the data volume, so a fresh node on a new volume is healthy again.
        self.wedged = False
        # r6.4.4: `{index: n}` hidden nested (Lucene) documents an index holds beside its top-level ones: ES's
        # `_cat/indices` `docs.count` counts them, `_count` does not. Part of the index mapping, so it comes with
        # whatever restores the index.
        self.nested: dict[str, int] = {}
        self.mutations: list[dict] = []
        self.restores = 0
        self.unsupported: list[str] = []
        self.clock, self.latency, self.up = clock, dict(latency or {}), up
        self.down_requests: list[str] = []
        self._uuids = 0
        self.uuid_served_step: int | None = None   # step number (FaultJournal.step_log) of the first snapshot read that served the UUID
        self._order = random.Random(1347)   # the order an unsorted search answers in

    def _took(self, kind: str) -> None:
        if self.clock is not None and kind in self.latency:
            self.clock.advance(self.latency[kind])

    # -- the node's data volume (the rig docker swaps it when a node starts on another volume) ----

    def save_node_state(self) -> dict:
        return copy.deepcopy({"indices": self.indices, "repos": self.repos, "pipelines": self.pipelines,
                              "ilm": self.ilm, "lifecycle_off": self.lifecycle_off, "wedged": self.wedged})

    def load_node_state(self, state: dict | None) -> None:
        """`None`: a node on a new, empty data volume."""
        state = copy.deepcopy(state) if state else {"indices": {}, "repos": {}, "pipelines": {},
                                                    "ilm": "RUNNING", "lifecycle_off": set()}
        self.indices, self.repos, self.pipelines = state["indices"], state["repos"], state["pipelines"]
        self.ilm, self.lifecycle_off = state["ilm"], state["lifecycle_off"]
        self.wedged = bool(state.get("wedged", False))

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
        if not self.up:
            self.down_requests.append(f"{method} {path}")
            raise RuntimeError(f"{method} {path}: the node's container is not running")
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
                status = "red" if self.wedged else self.health_status
                return {"status": status, "active_primary_shards": n,
                        "unassigned_shards": 0 if status == "green" else 1}
            if seg[0] == "_cat" and seg[1] == "indices":
                names = self._expand(seg[2], closed=True) if len(seg) > 2 else list(self.indices)
                return [{"index": n, "uuid": self.indices[n]["uuid"], "health": self.health_status,
                         "status": "close" if self.indices[n]["closed"] else "open",
                         "docs.count": str(len(self.indices[n]["docs"]) + self.nested.get(n, 0))} for n in names]
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
            if self.uuid_served_step is None:     # the only route that serves the UUID; the fake has no other
                self.uuid_served_step = len(getattr(self.journal, "step_log", ()))
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
            names = [n for n in names if any(
                fnmatch.fnmatchcase(n, p) or (n in self.stream_of and fnmatch.fnmatchcase(self.stream_of[n], p))
                for p in parts)]
        self._note("restore", ",".join(names))
        self.mutations[-1]["indices_before"] = sorted(self.indices)
        self.mutations[-1]["whole"] = names == list(self.content)
        for n in names:
            if n in self.indices and not self.indices[n]["closed"]:
                raise RuntimeError(f"snapshot_restore_exception: cannot restore index [{n}] because an "
                                   "open index with same name already exists in the cluster")
        for n in names:
            self.indices.pop(n, None)
            self._index(n)["docs"] = copy.deepcopy(self.content[n])
        self.restores += 1
        self._took("restore")
        return {"snapshot": {"snapshot": self.snapshot, "indices": names,
                             "shards": {"total": len(names), "failed": 0, "successful": len(names)}}}

    MAX_RESULT_WINDOW = 10_000      # index.max_result_window: from + size may not exceed it

    def _search(self, expr: str, body: dict) -> Any:
        """As Elasticsearch: no order without a `sort` (here a seeded shuffle that differs between
        calls), `from + size` capped at the result window, `_version` only with `"version": true`,
        and a total that stops counting at 10 000 unless `track_total_hits` asks for it."""
        self._took("search")
        start, size = int(body.get("from", 0)), int(body.get("size", 10))
        if start + size > self.MAX_RESULT_WINDOW:
            raise RuntimeError(
                "illegal_argument_exception: Result window is too large, from + size must be less than or "
                f"equal to: [{self.MAX_RESULT_WINDOW}] but was [{start + size}]. See the scroll api for a "
                "more efficient way to request large data sets.")
        sort = body.get("sort")
        keys = []
        for key in ([] if not sort else sort if isinstance(sort, list) else [sort]):
            field, spec = next(iter(key.items())) if isinstance(key, dict) else (key, "asc")
            if field == "_id":
                raise RuntimeError(
                    "illegal_argument_exception: Fielddata access on the _id field is disallowed, you can "
                    "re-enable it by updating the dynamic cluster setting: indices.id_field_data.enabled")
            keys.append((field, (spec.get("order") if isinstance(spec, dict) else spec) == "desc"))
        if body.get("search_after") is not None and (not keys or len(body["search_after"]) != len(keys)):
            raise RuntimeError("illegal_argument_exception: search_after has "
                               f"[{len(body['search_after'])}] values but sort has [{len(keys)}]")
        hits = []
        for n in self._expand(expr):
            docs = self.indices[n]["docs"]
            for i, d in (docs.items() if keys else sorted(docs.items())):
                if _matches(body.get("query"), d["_source"], i):
                    hit = {"_index": n, "_id": i, "_source": copy.deepcopy(d["_source"])}
                    if body.get("version"):
                        hit["_version"] = d["_version"]
                    hits.append(hit)
        if keys:
            for position, hit in enumerate(hits):    # `_doc` is index order (insertion), not id order
                hit["sort"] = [position if f == "_doc" else hit["_source"].get(f) for f, _ in keys]

            def compare(a, b):
                for (f, desc), x, y in zip(keys, a, b):
                    if x == y:
                        continue
                    if x is None or y is None:
                        return 1 if x is None else -1    # a missing value sorts last, whatever the direction
                    return (x > y) - (x < y) if not desc else (y > x) - (y < x)
                return 0
            hits.sort(key=functools.cmp_to_key(lambda h, g: compare(h["sort"], g["sort"])))
            if body.get("search_after") is not None:
                after = list(body["search_after"])
                hits = [h for h in hits if compare(after, h["sort"]) < 0]
        else:
            self._order.shuffle(hits)
        tracked = body.get("track_total_hits", self.MAX_RESULT_WINDOW)
        page = hits[start:start + size]
        if tracked is False:
            return {"hits": {"hits": page}}      # ES leaves the total out
        limit = None if tracked is True else int(tracked)
        capped = limit is not None and len(hits) > limit
        total = {"value": limit if capped else len(hits), "relation": "gte" if capped else "eq"}
        return {"hits": {"total": total, "hits": page}}

    def _delete_by_query(self, expr: str, body: dict) -> Any:
        self._note("delete_by_query", expr)
        deleted = 0
        for n in self._expand(expr):
            docs = self.indices[n]["docs"]
            for i in [i for i, d in docs.items() if _matches(body.get("query"), d["_source"], i)]:
                del docs[i]
                deleted += 1
        self._took("delete_by_query")
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
        self._took("reindex")
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


def expected_variant(mutation: dict | None, span_start: str = SPAN_START) -> dict:
    """The end state of the variant "base overlay + one stored-state mutation over [span_start, T]",
    for any span and any processor (`expected_copy` fixes the two committed ones). In-span documents
    of the mutation's dataset are exactly what the verbatim processor outputs (`run_processors`);
    a schema-drift also rewrites the alerts whose ancestry reaches such a document."""
    state = expected_copy("none")
    if mutation is None or mutation["kind"] not in ("data-drop", "schema-drift"):
        return state
    start, end, hit = instant(span_start), instant(T), set()
    for index, docs in state.items():
        if index == ALERTS:
            continue
        for doc_id, (version, source) in list(docs.items()):
            if source.get("event.dataset") == mutation["dataset"] and start <= instant(source["@timestamp"]) <= end:
                hit.add((index, doc_id))
                out = run_processors([mutation["processor"]], source)
                if out is None:
                    del docs[doc_id]
                else:
                    docs[doc_id] = (version, out)
    if mutation["kind"] == "schema-drift":
        for doc_id, (version, source) in list(state[ALERTS].items()):
            if any((a["index"], a["id"]) in hit for a in source["kibana.alert.ancestors"]):
                state[ALERTS][doc_id] = (version, run_processors([mutation["processor"]], source))
    return state


def nested_alert(doc: dict) -> dict:
    """The same alert with its `kibana.alert.*` fields nested (`{"kibana": {"alert": {...}}}`), as Kibana's own
    exports and some run records carry it (C-parse: every reader accepts both shapes)."""
    out: dict = {}
    for key, value in doc.items():
        if key.startswith("kibana.alert."):
            node = out.setdefault("kibana", {}).setdefault("alert", {})
            *parents, leaf = key[len("kibana.alert."):].split(".")
            for p in parents:
                node = node.setdefault(p, {})
            node[leaf] = copy.deepcopy(value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def config_env(events: str, alerts: str) -> str:
    """The lab tenant's `settings/systems/elastic/config.env`, in the shape the tenant fixture has
    (comments, double-quoted values)."""
    return ('# Elastic Stack deployment configuration (non-secret values only).\n\n'
            '# Default index patterns for the two surfaces the adapter exposes.\n'
            f'ELASTIC_EVENTS_INDEX="{events}"\nELASTIC_ALERTS_INDEX="{alerts}"\n')


# -- the lab's outer edge, as the real lab layer reaches it --------------------------------------------

LIVE_PROXY_URL = "http://credential-proxy:8443"
CONTEXT = "soc-playground"                      # the lab server's docker context (lab_ops' default)
DEPLOY = "deploy"                               # the deployment's own engine (the rig docker's name for no --context)
CERTS_VOLUME = "soc-playground_certs"           # the lab's certs volume (lab_ops' default)
STATE_VOLUME = "lab-engine-state"               # D25: the engine's state volume, where the copy-state marker lives
TENANT_HOSTS = ["elasticsearch", "soc-playground"]
FROZEN_ENDPOINT = "10.99.0.1:19200"
FROZEN_AUDIT, LIVE_AUDIT = "/audit/frozen-proxy.jsonl", "/audit/proxy.jsonl"
LAB_OPS = Path(__file__).resolve().parents[1] / "lab_ops.py"
# The live lab's always-on services a rig deploys, by container name, with the images compose.yml gives them: the
# live Elasticsearch (RHEL minimal: no `flock`) and the lab's DNS resolver (alpine/busybox: `flock` and `grep`).
# `chaos.lock`'s store lives in whichever one `chaos.lock.LOCK_CONTAINER` names (`lock_box`): a rig deploys the lab,
# never a container made to suit the lock store.
LIVE_ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:9.3.3"
LAB_IMAGES = {"elasticsearch": LIVE_ES_IMAGE, "unbound": "soc-playground/unbound:local"}


def deploy_lab_services(docker, *, cluster: Any = None, env: dict | None = None):
    """The live lab's services on the rig docker, running: the live Elasticsearch (answering from `cluster`, with
    `env`) and the DNS resolver. Returns the live Elasticsearch container."""
    es = docker.existing(CONTEXT, "elasticsearch", LAB_IMAGES["elasticsearch"], cluster=cluster, env=env)
    for name, image in LAB_IMAGES.items():
        if name != "elasticsearch":
            docker.existing(CONTEXT, name, image)
    return es


def lock_box(docker, lock_container: str):
    """The deployed lab container `chaos.lock.LOCK_CONTAINER` names, which holds the lock records."""
    box = docker.containers.get((CONTEXT, lock_container))
    assert box is not None, f"the lab deploys no container {lock_container!r} (chaos.lock.LOCK_CONTAINER)"
    return box


def tar_bytes(members: dict[str, bytes]) -> bytes:
    """A deterministic tar of `members` (mtime 0, sorted)."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def stub_dump(tickets: list[str] = ()) -> bytes:
    """A stub dump in the shape capture writes (`stubs.tar`: one seed file per stub)."""
    return tar_bytes({"stub-change-mgmt.yaml": b"- {id: CHG-1, status: approved}\n",
                      "stub-ticket-server.json": json.dumps([{"id": t} for t in tickets]).encode(),
                      "stub-threat-intel.json": b'[{"indicator": "203.0.113.9"}]',
                      "stub-cmdb-overlays.json": b"{}"})


def rules_tar(rules: dict) -> bytes:
    return tar_bytes({name: json.dumps(rule).encode() for name, rule in rules.items()})


PARTS = {"stubs.tar": stub_dump(), "proc-tree.txt": b"PID PPID\n1 0 init\n", RULES_PART: rules_tar(RULES)}
ROW_KEYS = {"slug", "run_id", "binding", "verdict", "reason", "verified_at", "knowledge"}
RUN_ID = "5b0d1f2e-3c4d-4e5f-8a6b-7c8d9e0f1a2b"


def load_script(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_clean_marker(marker: Any) -> bool:
    """A marker that says the copy may be reused (D25: anything else, or none, means "do not reuse")."""
    return isinstance(marker, dict) and marker.get("dirty") is False


# -- the rig ------------------------------------------------------------------------------------------


class LabRig:
    """A freeze, its parts, a case dir, the REAL lab layer (`lab_ops.LabOps`) and a lock store, on `tmp_path`
    (r6.4.3 C-rig). Only the lab layer's outer edge is faked:

    * docker, through `run=`: `_rig_docker.RigDocker` (`rig.docker`). The lab starts cold: no engine, no frozen
      node; deployed before the test are the live Elasticsearch (`elasticsearch` on the lab server, answering
      from `rig.live`, a cluster holding everything the snapshot holds), the live credential proxy
      (`response-credential-proxy` on the deployment) and the lab's certs volume;
    * the frozen cluster (`rig.cluster`, a `FakeCluster`), reached only through the real curl path
      (`ops.frozen_es()`, curl run inside the frozen node's container), never through `es=`;
    * the environment the lab layer reads (`V2_RUNS_DIR` holding `rig.live_runs`, `V2_FROZEN_PARTS_DIR` holding
      the freeze's parts and a second freeze's stub dump carrying `rig.tickets`, `V2_FROZEN_READONLY_PASSWORD` =
      `rig.password`); a source set to None is unset;
    * the lock store, the clock and the journal, as before.

    `fail(method, path, body)` faults a cluster request; `docker_fail` is a set of effects that fail at the
    docker edge (`node-start`, `stub-start`, `proxy-start`, `marker-write`); `boot_requests` is how many curls a
    freshly started node refuses before it listens. `patterns`, `extra_alerts`, `journal`, `latency` (per cluster
    request kind, `search` included) and `clock_step` as before."""

    def __init__(self, tmp_path: Path, *, fail: Callable | None = None, snapshot_uuid: str = SNAP_UUID,
                 rules: dict | None = None, run_rc: int = 0, run_out: str | None = None,
                 patterns: tuple[str, str] = (EVENTS, ALERTS_PATTERN), extra_alerts: dict | None = None,
                 journal: Journal | None = None, latency: dict | None = None, clock_step: float = 1,
                 boot_requests: int = 0, docker_fail: set | None = None) -> None:
        from _rig_docker import RigDocker

        self.tmp_path = tmp_path
        self.journal = Journal() if journal is None else journal
        self.store = FakeLockStore(self.journal)
        self.clock = FakeClock(self.journal, instant("2026-11-08T12:00:00Z"), clock_step)
        content = world_content()
        for uuid, doc in (extra_alerts or {}).items():
            content[ALERTS][f"id-{uuid}"] = {"_source": copy.deepcopy(doc), "_version": 1}
        self.cluster = FakeCluster(self.journal, repo=REPO, snapshot=SNAP, snapshot_uuid=snapshot_uuid,
                                   content=content, streams=STREAMS, fail=fail,
                                   observe=lambda: copy.deepcopy(self.marker()),
                                   clock=self.clock, latency=latency)
        self.live = FakeCluster(Journal(), repo=REPO, snapshot=SNAP, snapshot_uuid=snapshot_uuid,
                                content=content, streams=STREAMS)
        for name, docs in content.items():
            self.live._index(name)
            for doc_id, d in docs.items():
                self.live.put(name, doc_id, d["_source"], d["_version"])
        self.docker = RigDocker(journal=self.journal, clock=self.clock, cluster=self.cluster,
                                live_cluster=self.live, boot_requests=boot_requests, fail=docker_fail,
                                on_service_stop=self._seen, on_volume_rm=lambda: copy.deepcopy(self.marker()))
        self._deployed(self.docker)
        self.patterns = list(patterns)
        self.tenant_dir = tmp_path / "tenant"
        self.tenant_settings = self.tenant_dir / "settings"
        self.set_tenant_patterns(*patterns)
        self.freezes = tmp_path / "held_out" / "freezes"
        self.freeze_dir = self.freezes / FREEZE_ID
        self.freeze_dir.mkdir(parents=True)
        self.parts = tmp_path / "parts"
        (self.parts / FREEZE_ID).mkdir(parents=True)
        parts = {**PARTS, **({RULES_PART: rules_tar(rules)} if rules is not None else {})}
        for n, b in parts.items():
            (self.parts / FREEZE_ID / n).write_bytes(b)
        self.freeze = {"T": T, "patterns": list(patterns),
                       "elastic": {"repository": REPO, "snapshot": SNAP, "uuid": SNAP_UUID,
                                   "indices": counts_of(content)},
                       "parts": {n: sha(b) for n, b in parts.items()}, "captured_by": "op"}
        (self.freeze_dir / "freeze.yaml").write_text(yaml.safe_dump(self.freeze))
        self.case_dir = tmp_path / "held_out" / SLUG
        self.case_dir.mkdir(parents=True)
        (self.case_dir / "ground_truth.yaml").write_text("held_out: true\ndisposition: benign\n")
        self.index = tmp_path / "ops" / "held-out-index.jsonl"
        self.index.parent.mkdir()
        self.runs = tmp_path / "runs"
        self.run_rc = run_rc
        self.run_out = f"run_id={RUN_ID}\n" if run_out is None else run_out
        self.argv = self.env = None
        self.run_clock = None
        self.run_hook: Callable[[], None] | None = None
        self.lock_in_run: bool | None = None
        self._live_runs: set[str] | None = {"live-run"}
        self.nested_live_runs: set[str] = set()     # live runs whose alert.json is nested (`{"kibana": {"alert": ...}}`)
        self._tickets: set[str] | None = {"ticketed"}
        self._password = "pw-0"
        self.lab_module = load_script("lab_ops_1347", LAB_OPS)
        self.ops = self.lab_module.LabOps(run=self.docker, **self._ops_kw())
        self._sync_env()

    def _ops_kw(self) -> dict:
        return {"tenant_dir": self.tenant_dir, "tenant_hosts": TENANT_HOSTS, "frozen_endpoint": FROZEN_ENDPOINT,
                "audit_path": FROZEN_AUDIT, "live_audit_path": LIVE_AUDIT}

    @staticmethod
    def _deployed(docker) -> None:
        certs = docker.volume(CONTEXT, CERTS_VOLUME)
        certs.update({"elasticsearch/elasticsearch.crt": b"crt", "elasticsearch/elasticsearch.key": b"key",
                      "ca/ca.crt": b"ca"})
        deploy_lab_services(docker, cluster=docker.live_cluster, env={"ELASTIC_PASSWORD": "live-elastic"})
        docker.existing(DEPLOY, "response-credential-proxy", "credential-proxy",
                        mounts=[("/proxy", "store", ("vol", DEPLOY, "proxy-config", 0), True)])
        docker.stores[("vol", DEPLOY, "proxy-config", 0)] = {"config.json": b"{}"}

    def _seen(self) -> dict:
        return {"index": self.index.read_text() if self.index.is_file() else "",
                "cluster": self.cluster.state(), "locks": set(self.store.records)}

    # -- the environment the lab layer reads ---------------------------------------------------------

    @property
    def live_runs(self):
        return self._live_runs

    @live_runs.setter
    def live_runs(self, value):
        self._live_runs = None if value is None else set(value)
        self._sync_env()

    @property
    def tickets(self):
        return self._tickets

    @tickets.setter
    def tickets(self, value):
        self._tickets = None if value is None else set(value)
        self._sync_env()

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value
        self._sync_env()

    def _sync_env(self) -> None:
        import os
        import shutil
        shutil.rmtree(self.runs, ignore_errors=True)
        self.runs.mkdir()
        for uuid in sorted((self._live_runs or set()) | self.nested_live_runs):
            run = self.runs / f"run-{uuid}"
            run.mkdir()
            doc = {"kibana": {"alert": {"uuid": uuid}}} if uuid in self.nested_live_runs else {"kibana.alert.uuid": uuid}
            (run / "alert.json").write_text(json.dumps(doc))
        side = self.parts / "f-tickets"
        side.mkdir(exist_ok=True)
        (side / "stubs.tar").write_bytes(stub_dump(sorted(self._tickets or ())))
        for var, value in (("V2_RUNS_DIR", None if self._live_runs is None and not self.nested_live_runs else self.runs),
                           ("V2_FROZEN_PARTS_DIR", None if self._tickets is None else self.parts),
                           ("V2_FROZEN_READONLY_PASSWORD", self._password)):
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = str(value)

    def set_tenant_patterns(self, events: str, alerts: str) -> None:
        """What the lab tenant's settings say the agent's patterns are now (D24)."""
        path = self.tenant_settings / "systems" / "elastic" / "config.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config_env(events, alerts))

    @property
    def launch_module(self):
        return load_script("launch_1347", Path(__file__).resolve().parents[1] / "launch_frozen.py")

    @property
    def make_module(self):
        return load_script("make_case_1347", Path(__file__).resolve().parents[1] / "make_case.py")

    # -- what the lab holds now ---------------------------------------------------------------------

    def marker(self) -> Any:
        """The copy-state marker: the JSON object carrying `dirty` or `variant` in the engine's state
        volume (D25), or None when there is none. Two of them is a test failure."""
        sid = self.docker.volumes.get((CONTEXT, STATE_VOLUME))
        found = []
        for _key, data in sorted(self.docker.stores.get(sid, {}).items()) if sid else []:
            try:
                doc = json.loads(data)
            except ValueError:
                continue
            if isinstance(doc, dict) and {"dirty", "variant"} & set(doc):
                found.append(doc)
        assert len(found) <= 1, f"more than one copy-state marker in {STATE_VOLUME}: {found}"
        return found[0] if found else None

    def drop_marker(self) -> None:
        """An unknown copy state: the marker is gone (lost, or never written)."""
        sid = self.docker.volumes.get((CONTEXT, STATE_VOLUME))
        files = self.docker.stores.get(sid, {})
        for key in [k for k, d in files.items() if b'"dirty"' in d or b'"variant"' in d]:
            del files[key]

    def dirty_marker(self) -> None:
        """A copy nobody trusts, as a restore that crashed partway leaves it: the marker says dirty."""
        marker = self.marker() or {}
        self.drop_marker()
        self.ops.write_marker({"variant": marker.get("variant", "unknown"), "dirty": True})

    def node_running(self) -> bool:
        node = self.docker.node()
        return node is not None and node.state == "running"

    def stubs(self) -> dict[str, dict]:
        """`{stub: {"as_of", "overlays", "running"}}` of each stub container the lab started last."""
        out = {}
        for e in self.docker.of_kind("stub-start"):
            c = e["container"]
            out[c.name] = {"as_of": c.env.get("V2_STUB_AS_OF"), "running": c.state == "running",
                           "overlays": copy.deepcopy(self.docker.stub_state.get(c.id, {}).get("overlays", {}))}
        return out

    def proxy(self):
        """The frozen proxy container last started (the one running the product's proxy program), or None."""
        starts = self.docker.of_kind("proxy-start")
        return starts[-1]["container"] if starts else None

    def teardown_seen(self) -> dict | None:
        """What the index, the cluster and the lock store held at the last moment a frozen service (a stub,
        a frontend, the proxy) stopped: the teardown."""
        stops = self.docker.of_kind("service-stop")
        return stops[-1]["seen"] if stops else None

    def nothing_serving(self) -> list:
        """Frozen services still running (the proxy, the stubs, the frontends): empty after a teardown."""
        return [(c.scope, c.name) for c in self.docker.services()]

    def users(self) -> list[tuple]:
        """`(password, frozen proxy running)` at each read-only user creation in the frozen cluster."""
        return [((e["body"] or {}).get("password"), e["proxy_running"]) for e in self.docker.of_kind("curl")
                if e["method"] in ("PUT", "POST") and e["path"].split("?")[0].startswith("/_security/user/")]

    def certs_mounted(self, node) -> bool:
        """The node container reads the live node's certificate from the lab's certs volume."""
        certs = self.docker.volumes.get((CONTEXT, CERTS_VOLUME))
        for dst, *_ in node.mounts:
            store, _key, _ro = self.docker.resolve(node, dst)
            if store == certs:
                return True
        return False

    # -- cases --------------------------------------------------------------------------------------

    def expected_content(self, state: dict, mutations: Any) -> str:
        """The content digest the real lab layer gives a copy holding exactly `state` with the freeze's stubs
        loaded with `mutations`: a separate lab (its own docker and cluster, reached directly) runs the real
        `load_stubs` and `content_digest`. The oracle is the state; the digest is the layer's own function."""
        from _rig_docker import RigDocker
        cluster = FakeCluster(Journal(), repo=REPO, snapshot=SNAP, snapshot_uuid=SNAP_UUID, content={},
                              streams=STREAMS)
        for name, docs in state.items():
            cluster._index(name)
            for doc_id, (version, source) in docs.items():
                cluster.put(name, doc_id, source, version)
        docker = RigDocker(journal=Journal(), clock=FakeClock(Journal(), self.clock.last), live_cluster=self.live)
        self._deployed(docker)
        ops = self.lab_module.LabOps(run=docker, es=cluster, **self._ops_kw())
        ops.load_stubs(self.parts / FREEZE_ID, T, mutations or None)
        return ops.content_digest(list(self.patterns))

    def write_expected_case(self, kind: str, *, alert_uuid: str = "young", confirmed: bool = True,
                            **over: Any) -> dict:
        """case.yaml (and alert.json) for variant `kind`, every recorded value derived from the
        explicit `expected_copy(kind)`, not from running the code under test."""
        mutations = {"none": None, "cmdb": [CMDB_STALE], "drop": [DATA_DROP], "drift": [SCHEMA_DRIFT]}[kind]
        overlay = None if mutations is None else {"mutations": mutations, "span_start": SPAN_START}
        state = expected_copy(kind)
        doc = state[ALERTS][f"id-{alert_uuid}"][1]
        (self.case_dir / "alert.json").write_text(json.dumps(doc))
        case = {"freeze": FREEZE_ID, "alert": canonical_digest(doc), "age": 3000, "overlay": overlay,
                "counts": counts_of(state),
                "content": over.pop("content", None) or self.expected_content(state, mutations),
                "confirmed": ({"by": "op", "at": "2026-10-21T10:00:00Z", "reference_run": "r0"}
                              if confirmed else None), **over}
        (self.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
        return case

    def write_variant_case(self, mutation: dict | None, span_start: str = SPAN_START, *,
                           alert_uuid: str = "young", state: dict | None = None,
                           alert_json: dict | None = None, confirmed: bool = True, **over: Any) -> dict:
        """case.yaml and alert.json for the variant (one mutation over `span_start`..T, or none), every
        recorded value derived from `expected_variant` (or from `state`, when a test gives the copy
        it expects). `alert_json` is what alert.json holds when that is not the copy's alert."""
        mutations = None if mutation is None else [mutation]
        overlay = None if mutations is None else {"mutations": mutations, "span_start": span_start}
        state = expected_variant(mutation, span_start) if state is None else state
        doc = state[ALERTS][f"id-{alert_uuid}"][1]
        (self.case_dir / "alert.json").write_text(json.dumps(doc if alert_json is None else alert_json))
        case = {"freeze": FREEZE_ID, "alert": canonical_digest(doc), "age": 3000, "overlay": overlay,
                "counts": counts_of(state),
                "content": over.pop("content", None) or self.expected_content(state, mutations),
                "confirmed": ({"by": "op", "at": "2026-10-21T10:00:00Z", "reference_run": "r0"}
                              if confirmed else None), **over}
        (self.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
        return case

    def case(self) -> dict:
        return yaml.safe_load((self.case_dir / "case.yaml").read_text())

    # -- the agent ----------------------------------------------------------------------------------

    def run_fn(self, argv, env):
        self.journal.append(("run", None))
        self.run_clock = self.clock.last
        self.argv, self.env = list(argv), dict(env)
        self.lock_in_run = "frozen-engine" in self.store.records
        if self.run_hook is not None:
            self.run_hook()
        return self.run_rc, self.run_out, ""

    def _edges_modelled(self) -> None:
        """A request the fakes do not model fails the test as a gap IN THE FAKE (repair the fake: model it), not
        as a contract demand on how the lab does what the design leaves open."""
        assert not self.cluster.unsupported, f"the fake cluster does not model: {self.cluster.unsupported}"
        assert not self.docker.unmodelled, f"the rig docker does not model: {self.docker.unmodelled}"

    def launch(self, **kw):
        kw = {"knowledge": "abc1234", **kw}
        self._sync_env()
        try:
            return self.launch_module.launch(
                self.case_dir, freezes_dir=self.freezes, tenant_settings=self.tenant_settings,
                index=self.index, parts_dir=self.parts, lock_store=self.store, es=self.ops.frozen_es(),
                ops=self.ops, run_fn=self.run_fn, clock=self.clock,
                env={"PATH": "/usr/bin", "DEFENDER_CREDENTIAL_PROXY_URL": LIVE_PROXY_URL},
                tenant="tenant-1", **kw)
        finally:
            self._edges_modelled()

    def write_case(self, alert_uuid: str, overlay: dict | None, **kw):
        self._sync_env()
        try:
            return self.make_module.write_case(
                self.case_dir, freeze_dir=self.freeze_dir, alert_uuid=alert_uuid, overlay=overlay,
                tenant_settings=self.tenant_settings, parts_dir=self.parts, lock_store=self.store,
                es=self.ops.frozen_es(), ops=self.ops, clock=self.clock,
                profiles_dir=kw.pop("profiles_dir", None) or Path(__file__).resolve().parents[2] / "chaos" / "profiles",
                inventory=kw.pop("inventory", None) or yaml.safe_load(
                    (Path(__file__).resolve().parents[2] / "hosts" / "inventory.yaml").read_text()),
                **kw)
        finally:
            self._edges_modelled()

    # -- reading what happened ----------------------------------------------------------------------

    def rows(self) -> list[dict]:
        return [json.loads(x) for x in self.index.read_text().splitlines()] if self.index.exists() else []

    def binding(self) -> str:
        return canonical_digest([canonical_digest(self.freeze), canonical_digest(self.case())])

    def es_at(self, pred: Callable[[str, str], bool]) -> list[int]:
        return [i for i, (op, d) in enumerate(self.journal) if op == "es" and pred(*d)]

    def docker_at(self) -> list[int]:
        return [i for i, (op, _d) in enumerate(self.journal) if op == "docker"]
