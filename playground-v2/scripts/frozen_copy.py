"""Readying one variant's frozen copy (#1347 A1), shared by make-a-case and the launcher.

A variant is a freeze plus the overlay's Elasticsearch part. Readying it means: unless a clean
marker already says the copy is this variant, discard the node and its data and start a fresh one
(D25), register the snapshot repository read-only and check the snapshot's UUID, restore the whole
snapshot and apply the base overlay (delete everything stamped after T) and then each fault
overlay; record a clean marker. The marker (`{variant, dirty, tallies}`, on the engine's state
volume, outside the node's data) is written dirty before the node is discarded and clean after the
last change, so a crash leaves a copy nobody trusts; a dirty or unknown marker means a fresh node.

The index patterns come from the freeze (`patterns`, D24); `check_patterns` refuses a freeze whose
patterns differ from the lab tenant's current ones.

Every Elasticsearch call goes through `es.es_request(method, path, body=None)` (the chaos seam's
shape) and reaches the FROZEN cluster only. Overlays promise an end state: documents outside the
span are untouched, each in-span document is what the overlay's verbatim processor makes of it, and
keeps its `_id`, `_index` and `_version`.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ES_KINDS = ("data-drop", "schema-drift")
# Where a frozen cluster finds the snapshot repository (its `path.repo`).
REPO_LOCATION = "/lab/repo"
SCRATCH = "-overlay"          # suffix of the scratch index an overlay copies through
PIPELINE = "frozen-overlay"   # the temporary pipeline holding the processor verbatim
ANCESTORS = "kibana.alert.ancestors"
PAGE = 1000
RESTORE_WAIT_S, HEALTH_POLL_S = 3600.0, 10.0
#: The A2 pre-check's bound on bringing an existing node up (its start and its health wait, r6.4.4).
PRECHECK_WAIT_S = 600
BACKING = re.compile(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$")


class CopyRefused(RuntimeError):
    """The freeze or case cannot be served as it stands (a part, the snapshot's UUID)."""


class NotConfigured(CopyRefused):
    """The lab tenant's settings (its directory, or the index patterns in them) are not available."""


class CopyFault(RuntimeError):
    """The copy could not be made."""


class NodeNotReady(RuntimeError):
    """The node is running but not answering yet (connection refused, 502/503/504): the one failure
    a health poll waits out. The cluster seam raises it; any other failure ends the poll."""


def utc(value: Any) -> datetime:
    """A moment however it is spelled (datetime or ISO text, `Z` or an offset), as aware UTC."""
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def alert_uuid(doc: Any) -> str | None:
    """An alert document's `kibana.alert.uuid`, stored flat or nested; None when it carries none.
    The one reader of an alert's uuid in the lab."""
    uuid = dug(doc, "kibana.alert.uuid") if isinstance(doc, dict) else None
    return uuid if isinstance(uuid, str) and uuid else None


def stamp(value: Any) -> str:
    return utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest_of(doc: Any) -> str:
    """Canonical-JSON sha256 (sorted keys, compact, ASCII-escaped), bare lowercase hex."""
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def dug(source: dict, dotted: str) -> Any:
    """`dotted` in a document stored flat (`{"a.b": 1}`) or nested (`{"a": {"b": 1}}`)."""
    if dotted in source:
        return source[dotted]
    node: Any = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


class WallClock:
    """The real clock, the one every lab script uses outside tests (which pass their own)."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def sleep_until(self, moment: datetime) -> None:
        while (left := (moment - self.now()).total_seconds()) > 0:
            time.sleep(min(left, 60.0))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_freeze(freeze: Any, name: str) -> None:
    elastic = freeze.get("elastic") if isinstance(freeze, dict) else None
    ok = (isinstance(elastic, dict) and isinstance(freeze.get("parts"), dict)
          and all(isinstance(elastic.get(k), str) and elastic[k] for k in ("repository", "snapshot", "uuid"))
          and isinstance(elastic.get("indices"), dict) and elastic["indices"]
          and isinstance(freeze.get("patterns"), list) and freeze["patterns"]
          and all(isinstance(p, str) and p for p in freeze["patterns"]))
    if ok:
        try:
            utc(freeze.get("T"))
            return
        except (TypeError, ValueError):
            pass
    raise CopyRefused(f"freeze {name}: freeze.yaml lacks T, elastic (repository, snapshot, uuid, "
                      "indices), patterns or parts")


ELASTIC_CONFIG = ("systems", "elastic", "config.env")


def tenant_settings_dir() -> Path:
    """The lab tenant's `settings/` directory, from `$V2_FROZEN_TENANT_DIR`."""
    tenant = os.environ.get("V2_FROZEN_TENANT_DIR")
    if not tenant:
        raise NotConfigured("V2_FROZEN_TENANT_DIR is not set: the lab tenant's directory")
    return Path(tenant) / "settings"


def tenant_patterns(tenant_settings: Any) -> list[str]:
    """`[events, alerts]` index patterns of the lab tenant: `ELASTIC_EVENTS_INDEX` and
    `ELASTIC_ALERTS_INDEX` in `<tenant_settings>/systems/elastic/config.env`, read by the product's
    own parser. The one reader of the tenant's patterns (D24); there is no default."""
    if not tenant_settings:
        raise NotConfigured("the lab tenant's settings directory is not set ($V2_FROZEN_TENANT_DIR)")
    path = Path(tenant_settings).joinpath(*ELASTIC_CONFIG)
    try:
        text = path.read_text()
    except OSError as exc:
        raise NotConfigured(f"{path} is unreadable: {exc}") from exc
    repo = str(Path(__file__).resolve().parents[2])
    if repo not in sys.path:
        sys.path.insert(0, repo)
    from defender.tenancy.tenant_settings import parse_env
    values = parse_env(text)
    keys = ("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX")
    if missing := [k for k in keys if not values.get(k)]:
        raise NotConfigured(f"{path} lacks {', '.join(missing)}")
    return [values[k] for k in keys]


def check_patterns(freeze: dict, tenant_settings: Any) -> None:
    """The freeze's patterns are the lab tenant's current ones (D24); order does not matter."""
    current = tenant_patterns(tenant_settings)
    if sorted(freeze["patterns"]) != sorted(current):
        raise CopyRefused(f"the freeze's index patterns {freeze['patterns']} are not the lab tenant's "
                          f"current {current}: the tenant changed since the capture")


def check_parts(freeze: dict, directory: Path) -> None:
    """Every part of the freeze is present and has the digest freeze.yaml names."""
    problems = []
    for name, want in sorted(freeze["parts"].items()):
        path = directory / name
        if not path.is_file():
            problems.append(f"{name} is missing ({path})")
        elif sha256_file(path) != str(want):
            problems.append(f"{name} differs from its digest ({path})")
    if problems:
        raise CopyRefused("freeze parts not as captured, not launching: " + "; ".join(problems))


def variant_id(freeze_id: str, overlay: dict | None) -> str:
    """The copy's identity: the freeze plus the whole resolved overlay (every leaf: each mutation's
    parameters and the span's start), so no change to the overlay can share a copy."""
    resolved = overlay if overlay is None or "span_start" not in overlay \
        else {**overlay, "span_start": stamp(overlay["span_start"])}
    return digest_of({"freeze": freeze_id, "overlay": resolved})


def es_mutations(overlay: dict | None) -> list[dict]:
    return [m for m in (overlay or {}).get("mutations") or [] if m.get("kind") in ES_KINDS]


# -- reading the cluster -------------------------------------------------------------------------


def _expr(patterns: list[str]) -> str:
    return ",".join(patterns)


def list_indices(es: Any, patterns: list[str]) -> dict[str, dict]:
    """`{name: {"uuid", "status"}}` of every index the patterns (and any scratch index) match."""
    rows = es.es_request("GET", f"/_cat/indices/{_expr([*patterns, '*' + SCRATCH])}"
                                "?format=json&h=index,uuid,status&expand_wildcards=all")
    return {r["index"]: {"uuid": r["uuid"], "status": r.get("status", "open")} for r in rows or []}


def observed_counts(es: Any, names: list[str]) -> dict[str, int]:
    return {n: int(es.es_request("GET", f"/{n}/_count")["count"]) for n in names}


def find_alert(es: Any, patterns: list[str], uuid: str) -> dict | None:
    """The `_source` of the alert with `kibana.alert.uuid` == uuid in the copy, or None."""
    found = es.es_request("POST", f"/{_expr(patterns)}/_search?expand_wildcards=open,hidden",
                          {"query": {"term": {"kibana.alert.uuid": uuid}}, "size": 2})
    hits = found["hits"]["hits"]
    if len(hits) > 1:
        raise CopyFault(f"alert {uuid} is in {len(hits)} documents of the copy")
    return hits[0]["_source"] if hits else None


def _stream_of(index: str) -> str | None:
    m = BACKING.match(index)
    return m.group(1) if m else None


# -- waiting --------------------------------------------------------------------------------------


def wait_for_cluster(es: Any, clock: Any, what: str, timeout_s: float = RESTORE_WAIT_S) -> None:
    """Poll `_cluster/health` until the cluster answers, is not red and has nothing initializing.
    Only `NodeNotReady` is waited out."""
    deadline = clock.now().timestamp() + timeout_s
    last: Any = None
    while True:
        try:
            last = es.es_request("GET", "/_cluster/health")
            if last.get("status") in ("green", "yellow") and not last.get("initializing_shards"):
                return
        except NodeNotReady as exc:
            last = str(exc)
        if clock.now().timestamp() > deadline:
            raise CopyFault(f"the frozen cluster was not ready after {what}: {last}")
        clock.sleep(HEALTH_POLL_S)


# -- the steps -------------------------------------------------------------------------------------


def register_repository(es: Any, freeze: dict, location: str) -> None:
    """Register the repository read-only (only the live cluster ever writes to it) and refuse a
    snapshot that is not the one the freeze names."""
    elastic = freeze["elastic"]
    repo, snap = elastic["repository"], elastic["snapshot"]
    es.es_request("PUT", f"/_snapshot/{repo}",
                  {"type": "fs", "settings": {"location": location, "readonly": True}})
    found = es.es_request("GET", f"/_snapshot/{repo}/{snap}")
    snapshots = found.get("snapshots") or []
    if len(snapshots) != 1 or snapshots[0].get("uuid") != elastic["uuid"]:
        got = snapshots[0].get("uuid") if len(snapshots) == 1 else f"{len(snapshots)} snapshots"
        raise CopyRefused(f"snapshot {repo}:{snap} has UUID {got}, not the {elastic['uuid']} the freeze names")
    if snapshots[0].get("state", "SUCCESS") != "SUCCESS":
        raise CopyRefused(f"snapshot {repo}:{snap} is {snapshots[0].get('state')}, not SUCCESS")


def _check_bulk(result: dict, what: str) -> dict:
    if result.get("failures") or result.get("version_conflicts"):
        raise CopyFault(f"{what}: {result.get('version_conflicts', 0)} conflicts, "
                        f"failures {result.get('failures')}")
    return result


def base_overlay(es: Any, names: list[str], T: str, tallies: dict[str, int], touched: set[str]) -> None:
    """Delete every document stamped after T, index by index (so each index's tally is known); an
    index it deleted from is `touched`."""
    for name in names:
        done = _check_bulk(es.es_request("POST", f"/{name}/_delete_by_query",
                                         {"query": {"range": {"@timestamp": {"gt": T}}}}),
                           f"base overlay on {name}")
        tallies[name] = tallies.get(name, 0) + int(done["deleted"])
        if int(done["deleted"]):
            touched.add(name)
        es.es_request("POST", f"/{name}/_refresh")


def _rewrite(es: Any, index: str, query: dict) -> int:
    """Pass `query`'s documents of `index` through the temporary pipeline, in place; returns how
    many fewer documents `index` holds. Documents go through a scratch index so each keeps its
    `_id` and `_version` (external versioning); the originals are deleted first with the index's
    tombstone retention at zero, so the copy back can reuse the version."""
    scratch = index + SCRATCH
    out = _check_bulk(es.es_request("POST", "/_reindex", {
        "source": {"index": index, "query": query},
        "dest": {"index": scratch, "pipeline": PIPELINE, "version_type": "external"}}),
        f"overlay copy of {index}")
    if not out.get("total"):
        return 0
    es.es_request("PUT", f"/{index}/_settings", {"index.gc_deletes": "0ms"})
    removed = _check_bulk(es.es_request("POST", f"/{index}/_delete_by_query", {"query": query}),
                          f"overlay delete on {index}")
    es.es_request("POST", f"/{index}/_refresh")
    created = 0
    if out.get("created"):
        es.es_request("POST", f"/{scratch}/_refresh")
        back = _check_bulk(es.es_request("POST", "/_reindex", {
            "source": {"index": scratch}, "dest": {"index": index, "version_type": "external"}}),
            f"overlay copy back into {index}")
        created = int(back["created"])
        es.es_request("DELETE", f"/{scratch}")
    es.es_request("PUT", f"/{index}/_settings", {"index.gc_deletes": None})
    es.es_request("POST", f"/{index}/_refresh")
    return int(removed["deleted"]) - created


def _page_ids(es: Any, index: str, query: dict) -> list[dict]:
    """Every hit of `query` in `index` (`_id`, `_index`, ancestry), in pages ordered by `_doc`."""
    found: list[dict] = []
    after: list | None = None
    while True:
        body: dict[str, Any] = {"size": PAGE, "_source": [ANCESTORS], "sort": [{"_doc": "asc"}], "query": query}
        if after:
            body["search_after"] = after
        hits = es.es_request("POST", f"/{index}/_search?expand_wildcards=open,hidden", body)["hits"]["hits"]
        found += hits
        if len(hits) < PAGE:
            return found
        after = hits[-1].get("sort")
        if not after:
            raise CopyFault(f"{index}: a full page came back without a sort value to continue from")


def _names(ancestor_index: str, target: str) -> bool:
    """An ancestor names `target` by its concrete index or by a pattern the rule searched, which
    matches the backing index or its data stream (real ancestors carry the rule's pattern)."""
    stream = _stream_of(target)
    return ancestor_index == target or fnmatch.fnmatchcase(target, ancestor_index) \
        or bool(stream and fnmatch.fnmatchcase(stream, ancestor_index))


def _alerts_derived_from(es: Any, patterns: list[str], targets: list[str],
                         span: dict) -> dict[str, list[str]]:
    """`{alert index: [alert ids]}` of the alerts with an ancestor event in `targets` that lies in
    `span`. Ancestry (`kibana.alert.ancestors`), not time, says what an alert was built from. The
    in-span events are found first and the alerts looked up by their ids, so the work follows the
    span, not the size of the alerts index (#1347 live check 10)."""
    derived: dict[str, set[str]] = {}
    for target in targets:
        events = [h["_id"] for h in _page_ids(es, target, {"bool": {"filter": [span]}})]
        for i in range(0, len(events), PAGE):
            batch = set(events[i:i + PAGE])
            for hit in _page_ids(es, _expr(patterns), {"terms": {f"{ANCESTORS}.id": sorted(batch)}}):
                ancestors = dug(hit.get("_source") or {}, ANCESTORS) or []
                if any(a.get("id") in batch and _names(str(a.get("index", "")), target) for a in ancestors):
                    derived.setdefault(hit["_index"], set()).add(hit["_id"])
    return {index: sorted(ids) for index, ids in sorted(derived.items())}


def fault_overlay(es: Any, mutation: dict, names: list[str], patterns: list[str], span: dict,
                  tallies: dict[str, int], touched: set[str]) -> None:
    """One fault overlay: the mutation's processor, verbatim, over the span of its stream's
    indices; a schema-drift also rewrites the alerts built from in-span events of those indices.
    Every index it runs a rewrite on is `touched`."""
    targets = [n for n in names if (s := _stream_of(n)) and fnmatch.fnmatchcase(s, mutation["stream"])]
    es.es_request("PUT", f"/_ingest/pipeline/{PIPELINE}", {"processors": [mutation["processor"]]})
    try:
        jobs = [(n, span) for n in targets]
        if mutation["kind"] == "schema-drift":
            derived = _alerts_derived_from(es, patterns, targets, span)
            jobs += [(index, {"ids": {"values": ids}}) for index, ids in sorted(derived.items())]
        for index, query in jobs:
            touched.add(index)
            tallies[index] = tallies.get(index, 0) + _rewrite(es, index, query)
    except BaseException:
        try:
            es.es_request("DELETE", f"/_ingest/pipeline/{PIPELINE}")
        except Exception:  # noqa: BLE001 - the first failure is the one to report
            pass
        raise
    es.es_request("DELETE", f"/_ingest/pipeline/{PIPELINE}")   # a pipeline left behind fails the copy


# -- the one ready step ----------------------------------------------------------------------------


@dataclass
class Copy:
    counts: dict[str, int]      # the freeze's counts minus the overlays' own tallies
    tallies: dict[str, int]
    touched: list[str]          # the indices the overlays changed: what the content digest covers
    restored: bool              # False: a clean marker for this variant was trusted


def _is_clean(marker: Any, vid: str) -> bool:
    return isinstance(marker, dict) and marker.get("dirty") is False and marker.get("variant") == vid \
        and isinstance(marker.get("tallies"), dict) and isinstance(marker.get("touched"), list)


def mark_dirty(ops: Any, freeze_id: str, overlay: dict | None) -> None:
    """Record that the copy cannot be trusted (a stale launch): the next launch restores whole."""
    ops.write_marker({"variant": variant_id(freeze_id, overlay), "dirty": True})


def _build(es: Any, clock: Any, freeze: dict, overlay: dict | None) -> tuple[dict[str, int], list[str]]:
    """Restore the whole snapshot into the fresh, empty node and apply the overlays; the tallies and
    the indices the overlays touched."""
    names, patterns = list(freeze["elastic"]["indices"]), list(freeze["patterns"])
    T = stamp(freeze["T"])
    es.es_request("POST", "/_ilm/stop")
    elastic = freeze["elastic"]
    es.es_request("POST", f"/_snapshot/{elastic['repository']}/{elastic['snapshot']}/_restore",
                  {"include_global_state": False})
    wait_for_cluster(es, clock, "the restore")
    for stream in sorted({s for n in names if (s := _stream_of(n))}):
        es.es_request("DELETE", f"/_data_stream/{stream}/_lifecycle")
    tallies: dict[str, int] = {}
    touched: set[str] = set()
    base_overlay(es, names, T, tallies, touched)
    mutations = es_mutations(overlay)
    if mutations:
        span = {"range": {"@timestamp": {"gte": stamp(overlay["span_start"]), "lte": T}}}  # type: ignore[index]
        for mutation in mutations:
            fault_overlay(es, mutation, names, patterns, span, tallies, touched)
    es.es_request("POST", f"/{_expr(patterns)}/_refresh?expand_wildcards=open,hidden")
    return tallies, sorted(touched)


def _holds_the_freeze(es: Any, freeze: dict, location: str) -> bool:
    """On a node that came up: the snapshot is the freeze's (refuses otherwise), and the node holds
    exactly the freeze's indices, all open."""
    register_repository(es, freeze, location)
    current = list_indices(es, list(freeze["patterns"]))
    return set(current) == set(freeze["elastic"]["indices"]) \
        and all(i["status"] != "close" for i in current.values())


def _came_up(es: Any, ops: Any, clock: Any, freeze: dict) -> bool:
    """Start the existing node and wait for it, within `PRECHECK_WAIT_S` for both. A node that does
    not start, or is not healthy in that time, holds no good copy to protect (r6.4.4): False, and
    the restore goes on into a fresh node. A refusal (the lab not configured) still refuses."""
    deadline = clock.now().timestamp() + PRECHECK_WAIT_S
    try:
        ops.ensure_node(freeze["T"], clock)
        wait_for_cluster(es, clock, "the node start", timeout_s=max(0.0, deadline - clock.now().timestamp()))
    except CopyRefused:
        raise
    except Exception as exc:   # noqa: BLE001 — any failure to come up means there is nothing to keep
        print(f"the existing frozen node did not come up ({exc}); restoring into a fresh node", file=sys.stderr)
        return False
    return True


def ready(es: Any, *, ops: Any, clock: Any, freeze: dict, freeze_id: str, overlay: dict | None,
          whole: bool = False, location: str = REPO_LOCATION) -> Copy:
    """Make the frozen cluster hold exactly this variant. A clean marker for the variant is
    trusted unless `whole` (make-a-case always restores, D23); anything else discards the node and
    its data and restores the whole snapshot into a fresh node (D25), once the snapshot's UUID has
    been checked on the node that is there (A2: a refusal leaves the old copy untouched; a node that does not come
    up within `PRECHECK_WAIT_S` holds nothing to keep). The node's clock reads T whenever it starts (D15 revised)."""
    check_freeze(freeze, freeze_id)
    vid = variant_id(freeze_id, overlay)
    marker = None if whole else ops.read_marker()
    # One bounded attempt to bring up the node that is there (r6.4.4): it serves both the reuse of a
    # clean copy and A2's check before a wipe, and a node that does not come up is never waited on twice.
    up = ops.node_exists() and _came_up(es, ops, clock, freeze)
    if up and _is_clean(marker, vid) and _holds_the_freeze(es, freeze, location):
        tallies = {n: int(t) for n, t in marker["tallies"].items()}   # type: ignore[index]
        touched = [str(n) for n in marker["touched"]]                  # type: ignore[index]
        restored = False
    else:
        if up:
            # A2 under D25: the snapshot must be the freeze's before the copy there is discarded.
            register_repository(es, freeze, location)
        mark_dirty(ops, freeze_id, overlay)   # before the wipe: a crash from here leaves no trusted copy
        ops.fresh_node(freeze["T"], clock)
        wait_for_cluster(es, clock, "the node start")
        register_repository(es, freeze, location)
        tallies, touched = _build(es, clock, freeze, overlay)
        ops.write_marker({"variant": vid, "dirty": False, "tallies": tallies, "touched": touched})
        restored = True
    counts = {n: int(c) - tallies.get(n, 0) for n, c in freeze["elastic"]["indices"].items()}
    return Copy(counts=counts, tallies=tallies, touched=touched, restored=restored)
