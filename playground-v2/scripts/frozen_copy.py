"""Readying one variant's frozen copy (#1347 A1), shared by make-a-case and the launcher.

A variant is a freeze plus the overlay's Elasticsearch part. Readying it means: unless a clean
marker already says the copy is this variant, discard the node and its data and start a fresh one
(D25), register the snapshot repository read-only and check the snapshot's UUID, restore the whole
snapshot and apply the base overlay (delete everything stamped after T) and then each fault
overlay; record a clean marker. The marker (`{variant, dirty, tallies, touched}`, on the engine's state
volume, outside the node's data) is written dirty before the node is discarded and clean after the
last change, so a crash leaves a copy nobody trusts; a dirty or unknown marker means a fresh node.

The index patterns come from the freeze (`patterns`, D24); `check_patterns` refuses a freeze whose
patterns differ from the lab tenant's current ones.

Every Elasticsearch call goes through `es.es_request(method, path, body=None)` (the chaos seam's
shape) and reaches the FROZEN cluster only. Overlays promise an end state: documents outside the
span are untouched, each in-span document is what the overlay's verbatim processor makes of it, and
keeps its `_id` and `_index`. A data-drop's survivors keep `_version`; a schema-drift rewrites in place
(`_update_by_query`, the only write Elasticsearch takes into a backing index), so a rewritten document
reads `_version` one higher than live would (the named gap of r6.4.5). No index's own ingest pipelines
run on an overlay's writes. A stream's backing indices are what the cluster reports, whatever their names.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
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
BACKING = re.compile(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$")   # a backing index's usual name
RESTORE_WAIT_S, HEALTH_POLL_S = 3600.0, 10.0
#: The A2 pre-check's bound on bringing an existing node up (its start and its health wait, r6.4.4).
PRECHECK_WAIT_S = 600


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


def held_indices(es: Any) -> dict[str, dict]:
    """`{name: {"uuid", "status"}}` of every index the cluster holds, from its metadata. Not
    `_cat/indices`: live (9.3), it leaves out failure-store indices (`.fs-…`) even when named,
    so a copy holding the freeze's would read as missing them."""
    found = es.es_request("GET", "/_cluster/state/metadata?filter_path=metadata.indices.*.state,"
                                 "metadata.indices.*.settings.index.uuid") or {}
    return {name: {"uuid": dug(meta, "settings.index.uuid"), "status": meta.get("state", "open")}
            for name, meta in (found.get("metadata") or {}).get("indices", {}).items()}


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


def streams_of(es: Any) -> dict[str, str]:
    """`{backing index: data stream}` as the cluster reports it (a restore brings the membership)."""
    out = es.es_request("GET", "/_data_stream/*?expand_wildcards=all") or {}
    return {i["index_name"]: ds["name"] for ds in out.get("data_streams", []) for i in ds.get("indices", [])}


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


PIPELINE_SETTINGS = ("index.default_pipeline", "index.final_pipeline")


@contextmanager
def _without_ingest(es: Any, index: str) -> Iterator[None]:
    """`index`'s own default and final pipelines are `_none` for the block and exactly what they were
    after (r6.4.5): stored events went through ingest once, and the overlay's processor is the only
    change. Live, the integration's pipelines are not on the frozen cluster, and a request-level
    pipeline does not skip a final one."""
    held = (es.es_request("GET", f"/{index}/_settings/{','.join(PIPELINE_SETTINGS)}?flat_settings=true")
            or {}).get(index, {}).get("settings", {})
    es.es_request("PUT", f"/{index}/_settings", {k: "_none" for k in PIPELINE_SETTINGS})
    try:
        yield
    finally:
        es.es_request("PUT", f"/{index}/_settings", {k: held.get(k) for k in PIPELINE_SETTINGS})


def _drift(es: Any, index: str, query: dict) -> int:
    """A schema-drift in place: `query`'s documents of `index` through the temporary pipeline by
    `_update_by_query` (Elasticsearch refuses any other write into a backing index). `_id` and
    `_index` are kept; `_version` goes one up, the named gap of r6.4.5. Returns how many it rewrote."""
    with _without_ingest(es, index):
        return int(_check_bulk(es.es_request("POST", f"/{index}/_update_by_query?pipeline={PIPELINE}&refresh=true",
                                  {"query": query}), f"overlay rewrite of {index}")["updated"])


def _drop(es: Any, index: str, query: dict) -> int:
    """A data-drop: `query`'s documents of `index` go through the temporary pipeline into a scratch
    index; the ones it dropped are deleted from `index`, and the survivors are never written, so they
    keep `_version`. Returns how many were deleted."""
    scratch = index + SCRATCH
    _check_bulk(es.es_request("POST", "/_reindex", {"source": {"index": index, "query": query},
                                                    "dest": {"index": scratch, "pipeline": PIPELINE}}),
                f"overlay copy of {index}")
    try:
        es.es_request("POST", f"/{scratch}/_refresh")
        kept = {h["_id"] for h in _page_ids(es, scratch, {"match_all": {}})}
    except BaseException:
        es.es_request("DELETE", f"/{scratch}?ignore_unavailable=true")
        raise
    es.es_request("DELETE", f"/{scratch}")
    dropped = sorted(h["_id"] for h in _page_ids(es, index, query) if h["_id"] not in kept)
    deleted = 0
    for i in range(0, len(dropped), PAGE):
        done = _check_bulk(es.es_request("POST", f"/{index}/_delete_by_query",
                                         {"query": {"ids": {"values": dropped[i:i + PAGE]}}}),
                           f"overlay delete on {index}")
        deleted += int(done["deleted"])
    es.es_request("POST", f"/{index}/_refresh")
    return deleted


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


def _page_ids_each(es: Any, patterns: list[str], query: dict) -> list[dict]:
    """`_page_ids` over every index the patterns match, one index at a time: `_doc` order is per shard,
    so paging it by `search_after` across several indices without a point-in-time skips documents."""
    rows = es.es_request("GET", f"/_cat/indices/{_expr(patterns)}?format=json&h=index&expand_wildcards=open,hidden")
    return [hit for name in sorted(r["index"] for r in rows or []) for hit in _page_ids(es, name, query)]


def _names(ancestor_index: str, target: str, stream: str | None) -> bool:
    """An ancestor names `target` (a backing index of `stream`) by its concrete index or by a pattern
    the rule searched, which matches the backing index or its data stream (real ancestors carry the
    rule's pattern)."""
    return ancestor_index == target or fnmatch.fnmatchcase(target, ancestor_index) \
        or bool(stream and fnmatch.fnmatchcase(stream, ancestor_index))


def _alerts_derived_from(es: Any, patterns: list[str], targets: dict[str, str],
                         span: dict) -> dict[str, list[str]]:
    """`{alert index: [alert ids]}` of the alerts with an ancestor event in `targets` that lies in
    `span`. Ancestry (`kibana.alert.ancestors`), not time, says what an alert was built from. The
    in-span events are found first and the alerts looked up by their ids, so the work follows the
    span, not the size of the alerts index (#1347 live check 10)."""
    derived: dict[str, set[str]] = {}
    for target, stream in targets.items():
        events = [h["_id"] for h in _page_ids(es, target, {"bool": {"filter": [span]}})]
        for i in range(0, len(events), PAGE):
            batch = set(events[i:i + PAGE])
            for hit in _page_ids_each(es, patterns, {"terms": {f"{ANCESTORS}.id": sorted(batch)}}):
                ancestors = dug(hit.get("_source") or {}, ANCESTORS) or []
                if any(a.get("id") in batch and _names(str(a.get("index", "")), target, stream) for a in ancestors):
                    derived.setdefault(hit["_index"], set()).add(hit["_id"])
    return {index: sorted(ids) for index, ids in sorted(derived.items())}


def unverifiable_ancestry(es: Any, freeze: dict, overlay: dict | None) -> list[str]:
    """The ancestor indices that make a schema-drift case unverifiable (r6.4.5): named by an in-span
    alert of the copy, concrete, not held by the copy, and by their backing-index name of a stream
    the drift targets. Derived alerts reached through them cannot be found by ancestry (live: the
    2026-10-29 `dedup-` consolidation gave the older events new ids). A pattern or `''` (threshold and
    ES|QL rules) does not count."""
    held = set(held_indices(es))
    found: set[str] = set()
    for mutation in es_mutations(overlay):
        if mutation["kind"] != "schema-drift":
            continue
        span = {"range": {"@timestamp": {"gte": stamp(overlay["span_start"]), "lte": stamp(freeze["T"])}}}  # type: ignore[index]
        query = {"bool": {"filter": [span, {"exists": {"field": f"{ANCESTORS}.index"}}]}}
        for hit in _page_ids_each(es, list(freeze["patterns"]), query):
            for a in dug(hit.get("_source") or {}, ANCESTORS) or []:
                name = str(a.get("index") or "")
                m = BACKING.match(name)
                if m and name not in held and fnmatch.fnmatchcase(m.group(1), mutation["stream"]):
                    found.add(name)
    return sorted(found)


def fault_overlay(es: Any, mutation: dict, streams: dict[str, str], patterns: list[str], span: dict,
                  tallies: dict[str, int], touched: set[str]) -> None:
    """One fault overlay: the mutation's processor, verbatim, over the span of its stream's
    indices; a schema-drift also rewrites the alerts built from in-span events of those indices.
    Every index in which it changed a document is `touched`. `streams` is the copy's membership (`streams_of`)."""
    targets = {n: s for n, s in sorted(streams.items()) if fnmatch.fnmatchcase(s, mutation["stream"])}
    es.es_request("PUT", f"/_ingest/pipeline/{PIPELINE}", {"processors": [mutation["processor"]]})
    try:
        jobs: list[tuple[str, dict]] = [(n, span) for n in targets]
        if mutation["kind"] == "schema-drift":
            derived = _alerts_derived_from(es, patterns, targets, span)
            jobs += [(index, {"ids": {"values": ids}}) for index, ids in sorted(derived.items())]
        for index, query in jobs:
            if mutation["kind"] == "data-drop":
                changed = _drop(es, index, query)
                tallies[index] = tallies.get(index, 0) + changed
            else:
                changed = _drift(es, index, query)
                tallies.setdefault(index, 0)
            if changed:
                touched.add(index)
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
    streams = {n: s for n, s in streams_of(es).items() if n in names}
    for stream in sorted(set(streams.values())):
        es.es_request("DELETE", f"/_data_stream/{stream}/_lifecycle")
    if dangling := unverifiable_ancestry(es, freeze, overlay):   # r6.4.5: before any overlay writes
        raise CopyRefused(f"the schema-drift's span holds alerts built from events of {dangling}, which the "
                          f"copy does not hold: their derived alerts cannot be found (pick a later span)")
    tallies: dict[str, int] = {}
    touched: set[str] = set()
    base_overlay(es, names, T, tallies, touched)
    mutations = es_mutations(overlay)
    if mutations:
        span = {"range": {"@timestamp": {"gte": stamp(overlay["span_start"]), "lte": T}}}  # type: ignore[index]
        for mutation in mutations:
            fault_overlay(es, mutation, streams, patterns, span, tallies, touched)
    es.es_request("POST", f"/{_expr(patterns)}/_refresh?expand_wildcards=open,hidden")
    return tallies, sorted(touched)


def _holds_the_freeze(es: Any, freeze: dict, location: str) -> bool:
    """On a node that came up: the snapshot is the freeze's (refuses otherwise), and the node holds
    exactly the freeze's indices, all open: each of them, and no other the patterns (or a scratch
    index) match. The node's own system indices are not the copy's."""
    register_repository(es, freeze, location)
    names = set(freeze["elastic"]["indices"])
    held = held_indices(es)
    globs = [*freeze["patterns"], "*" + SCRATCH]
    extra = {n for n in held if n not in names and any(fnmatch.fnmatchcase(n, g) for g in globs)}
    return names <= set(held) and not extra and all(held[n]["status"] != "close" for n in names)


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
