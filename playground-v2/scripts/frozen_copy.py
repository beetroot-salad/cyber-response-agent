"""Readying one variant's frozen copy (#1347 A1), shared by make-a-case and the launcher.

A variant is a freeze plus the overlay's Elasticsearch part. Readying it means: register the
snapshot repository read-only and check the snapshot's UUID; unless a clean marker already says the
copy is this variant, restore the whole snapshot and apply the base overlay (delete everything
stamped after T) and then each fault overlay; record a clean marker. A durable marker is written
dirty before the first change and clean after the last, so a crash leaves a copy nobody trusts.

Every Elasticsearch call goes through `es.es_request(method, path, body=None)` (the chaos seam's
shape) and reaches the FROZEN cluster only. Overlays promise an end state: documents outside the
span are untouched, each in-span document is what the overlay's verbatim processor makes of it, and
keeps its `_id`, `_index` and `_version`.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
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
MAX_WINDOW = 10000            # Elasticsearch's from+size ceiling
RESTORE_WAIT_S, HEALTH_POLL_S = 3600.0, 10.0
BACKING = re.compile(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$")


class CopyRefused(RuntimeError):
    """The freeze or case cannot be served as it stands (a part, the snapshot's UUID)."""


class CopyFault(RuntimeError):
    """The copy could not be made."""


def utc(value: Any) -> datetime:
    """A moment however it is spelled (datetime or ISO text, `Z` or an offset), as aware UTC."""
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


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
          and isinstance(elastic.get("indices"), dict) and elastic["indices"])
    if ok:
        try:
            utc(freeze.get("T"))
            return
        except (TypeError, ValueError):
            pass
    raise CopyRefused(f"freeze {name}: freeze.yaml lacks T, elastic (repository, snapshot, uuid, "
                      "indices) or parts")


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
    """The copy's identity: the freeze plus what the overlay does to Elasticsearch. A stub-only
    overlay (cmdb-stale) shares the copy of no overlay: stubs reload every launch."""
    mutations = es_mutations(overlay)
    span = stamp(overlay["span_start"]) if mutations else None
    return digest_of({"freeze": freeze_id, "mutations": mutations, "span_start": span})


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
    """Poll `_cluster/health` until the cluster answers, is not red and has nothing initializing."""
    deadline = clock.now().timestamp() + timeout_s
    last: Any = None
    while True:
        try:
            last = es.es_request("GET", "/_cluster/health")
            if last.get("status") in ("green", "yellow") and not last.get("initializing_shards"):
                return
        except Exception as exc:  # noqa: BLE001 - a node coming up refuses connections
            last = f"{type(exc).__name__}: {exc}"
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


def _clear(es: Any, current: dict[str, dict], keep: set[str]) -> None:
    """Make room for a restore: close what the snapshot will replace, delete what it will not."""
    for name, info in sorted(current.items()):
        if name in keep:
            if info["status"] != "close":
                es.es_request("POST", f"/{name}/_close")
        else:
            es.es_request("DELETE", f"/{name}")


def _check_bulk(result: dict, what: str) -> dict:
    if result.get("failures") or result.get("version_conflicts"):
        raise CopyFault(f"{what}: {result.get('version_conflicts', 0)} conflicts, "
                        f"failures {result.get('failures')}")
    return result


def base_overlay(es: Any, names: list[str], T: str, tallies: dict[str, int]) -> None:
    """Delete every document stamped after T, index by index (so each index's tally is known)."""
    for name in names:
        done = _check_bulk(es.es_request("POST", f"/{name}/_delete_by_query",
                                         {"query": {"range": {"@timestamp": {"gt": T}}}}),
                           f"base overlay on {name}")
        tallies[name] = tallies.get(name, 0) + int(done["deleted"])
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


def _alerts_derived_from(es: Any, patterns: list[str], targets: list[str],
                         span: dict) -> dict[str, list[str]]:
    """`{alert index: [alert ids]}` of the alerts with an ancestor event in `targets` that lies in
    `span`. Ancestry (`kibana.alert.ancestors`), not time, says what an alert was built from."""
    alerts: list[tuple[str, str, list]] = []
    for start in range(0, MAX_WINDOW, PAGE):
        page = es.es_request("POST", f"/{_expr(patterns)}/_search?expand_wildcards=open,hidden", {
            "query": {"exists": {"field": ANCESTORS}}, "_source": [ANCESTORS], "from": start, "size": PAGE})
        hits = page["hits"]["hits"]
        alerts += [(h["_index"], h["_id"], dug(h["_source"], ANCESTORS) or []) for h in hits]
        if len(hits) < PAGE:
            break
    else:
        raise CopyFault(f"more than {MAX_WINDOW} alerts carry ancestry; the overlay cannot page them")
    wanted: dict[str, set[str]] = {}
    for _index, _id, ancestors in alerts:
        for a in ancestors:
            if a.get("index") in targets:
                wanted.setdefault(a["index"], set()).add(a["id"])
    in_span: set[tuple[str, str]] = set()
    for index, ids in wanted.items():
        ordered = sorted(ids)
        for i in range(0, len(ordered), PAGE):
            batch = ordered[i:i + PAGE]
            found = es.es_request("POST", f"/{index}/_search", {
                "query": {"bool": {"filter": [{"ids": {"values": batch}}, span]}}, "size": len(batch)})
            in_span |= {(index, h["_id"]) for h in found["hits"]["hits"]}
    derived: dict[str, list[str]] = {}
    for index, _id, ancestors in alerts:
        if any((a.get("index"), a.get("id")) in in_span for a in ancestors):
            derived.setdefault(index, []).append(_id)
    return derived


def fault_overlay(es: Any, mutation: dict, names: list[str], patterns: list[str], span: dict,
                  tallies: dict[str, int]) -> None:
    """One fault overlay: the mutation's processor, verbatim, over the span of its stream's
    indices; a schema-drift also rewrites the alerts built from in-span events of those indices."""
    targets = [n for n in names if (s := _stream_of(n)) and fnmatch.fnmatchcase(s, mutation["stream"])]
    es.es_request("PUT", f"/_ingest/pipeline/{PIPELINE}", {"processors": [mutation["processor"]]})
    try:
        jobs = [(n, span) for n in targets]
        if mutation["kind"] == "schema-drift":
            derived = _alerts_derived_from(es, patterns, targets, span)
            jobs += [(index, {"ids": {"values": ids}}) for index, ids in sorted(derived.items())]
        for index, query in jobs:
            tallies[index] = tallies.get(index, 0) + _rewrite(es, index, query)
    finally:
        try:
            es.es_request("DELETE", f"/_ingest/pipeline/{PIPELINE}")
        except Exception:  # noqa: BLE001 - the first failure is the one to report
            pass


# -- the one ready step ----------------------------------------------------------------------------


@dataclass
class Copy:
    counts: dict[str, int]      # the freeze's counts minus the overlays' own tallies
    tallies: dict[str, int]
    restored: bool              # False: a clean marker for this variant was trusted


def _is_clean(marker: Any, freeze_id: str, vid: str, current: dict[str, dict], names: set[str]) -> bool:
    return bool(marker) and marker.get("dirty") is False and marker.get("freeze") == freeze_id \
        and marker.get("variant") == vid and set(current) == names \
        and all(i["status"] != "close" for i in current.values()) \
        and marker.get("index_uuids") == {n: i["uuid"] for n, i in current.items()}


def _build(es: Any, ops: Any, clock: Any, freeze: dict, freeze_id: str, overlay: dict | None,
           patterns: list[str], current: dict[str, dict], location: str) -> dict[str, int]:
    names = list(freeze["elastic"]["indices"])
    T = stamp(freeze["T"])
    ops.write_marker({"freeze": freeze_id, "variant": variant_id(freeze_id, overlay),
                      "dirty": True, "index_uuids": {}})
    es.es_request("POST", "/_ilm/stop")
    _clear(es, current, set(names))
    elastic = freeze["elastic"]
    es.es_request("POST", f"/_snapshot/{elastic['repository']}/{elastic['snapshot']}/_restore",
                  {"include_global_state": False})
    wait_for_cluster(es, clock, "the restore")
    for stream in sorted({s for n in names if (s := _stream_of(n))}):
        es.es_request("DELETE", f"/_data_stream/{stream}/_lifecycle")
    tallies: dict[str, int] = {}
    base_overlay(es, names, T, tallies)
    mutations = es_mutations(overlay)
    if mutations:
        span = {"range": {"@timestamp": {"gte": stamp(overlay["span_start"]), "lte": T}}}  # type: ignore[index]
        for mutation in mutations:
            fault_overlay(es, mutation, names, patterns, span, tallies)
    es.es_request("POST", f"/{_expr(patterns)}/_refresh?expand_wildcards=open,hidden")
    return tallies


def ready(es: Any, *, ops: Any, clock: Any, freeze: dict, freeze_id: str, overlay: dict | None,
          patterns: list[str], location: str = REPO_LOCATION) -> Copy:
    """Make the frozen cluster hold exactly this variant, restoring only if it must."""
    check_freeze(freeze, freeze_id)
    names = list(freeze["elastic"]["indices"])
    vid = variant_id(freeze_id, overlay)
    register_repository(es, freeze, location)
    current = list_indices(es, patterns)
    restored = not _is_clean(ops.read_marker(), freeze_id, vid, current, set(names))
    tallies: dict[str, int] = {}
    if restored:
        tallies = _build(es, ops, clock, freeze, freeze_id, overlay, patterns, current, location)
        ops.write_marker({"freeze": freeze_id, "variant": vid, "dirty": False,
                          "index_uuids": {n: i["uuid"] for n, i in list_indices(es, patterns).items()}})
    else:
        tallies = {n: 0 for n in names}   # unused: a trusted copy's counts are read, not derived
    counts = {n: int(c) - tallies.get(n, 0) for n, c in freeze["elastic"]["indices"].items()}
    return Copy(counts=counts, tallies=tallies, restored=restored)
