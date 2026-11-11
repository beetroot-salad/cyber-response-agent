"""#1347 r6.4.6 "One document walk, on a fixed view" (Amendment r6.4.6, first bullet).

Every walk over the copy's documents (a data-drop's survivors and its in-span events, the derived-alert lookup, the
unverifiable-ancestry check, the content digest) reads one fixed view of the indices it walks: a point-in-time opened
over them, paged with `_shard_doc` and `search_after`, closed on every exit, and refused when the documents read differ
from the total the first page reported. Live (Elasticsearch 9.3.3): a search with `pit` and an index in its path is
refused (400), `_shard_doc` sort values are single numbers, the `pit_id` did not change between pages, a PIT is a fixed
view (writes and merges after it opened are not seen), and a `_doc`-sorted `search_after` walk without one skips or
repeats documents when the index merges between pages.

The first half pins the fake that models it (R6: the demands below rely on it). The second half is observed at the
cluster after the real entry points (launch, make-a-case, the content digest the launch computes).
"""
from __future__ import annotations

import copy
import re
from urllib.parse import parse_qs

import pytest
from _lab_fakes import (ALERTS, AUTH, DATA_DROP, DEDUP, SPAN_START, SYSLOG, T, FakeGap, LabRig, expected_copy, instant,
                        run_processors, world_content)
from test_1347_inplace import _PAGE, ALERTS_2, _cluster, _many_alerts
from test_1347_make_case import _drift_profiles, _overlay

HIDDEN = ".ds-logs-system.auth-default-2026.10.21-000009"      # a hidden (dot) backing index
PIT_PATH = "keep_alive=2m&expand_wildcards=open,hidden"


# -- the fake -----------------------------------------------------------------------------------------------------


def _open(cluster, expr):
    return cluster.es_request("POST", f"/{expr}/_pit?{PIT_PATH}")["id"]


def _close(cluster, pit_id):
    return cluster.es_request("DELETE", "/_pit", {"id": pit_id})


def _pit_walk(cluster, expr, size, *, first_total=None, between=None):
    """Every hit of the indices `expr` names, paged the way the product is told to: open, search with `pit` and
    `_shard_doc`, carry `search_after` and the returned `pit_id`, close."""
    pit_id = _open(cluster, expr)
    seen, after, totals, page_no = [], None, [], 0
    while True:
        body = {"pit": {"id": pit_id, "keep_alive": "2m"}, "sort": [{"_shard_doc": "asc"}], "size": size,
                "track_total_hits": True, "query": {"match_all": {}}}
        if after is not None:
            body["search_after"] = after
        if between is not None and page_no:
            between(page_no)
        out = cluster.es_request("POST", "/_search", body)
        page_no += 1
        pit_id = out["pit_id"]
        totals.append(out["hits"]["total"])
        hits = out["hits"]["hits"]
        assert all(len(h["sort"]) == 1 and isinstance(h["sort"][0], int) for h in hits), "a _shard_doc is one number"
        seen += [(h["_index"], h["_id"]) for h in hits]
        if len(hits) < size:
            break
        after = hits[-1]["sort"]
    _close(cluster, pit_id)
    return seen, totals


def test_the_fake_walks_several_indices_through_one_point_in_time_and_closes_it():
    cluster = _cluster()
    world = world_content()
    want = {(n, i) for n in (AUTH, DEDUP) for i in world[n]}

    seen, totals = _pit_walk(cluster, f"{AUTH},{DEDUP}", 7)

    assert len(seen) == len(set(seen)) == len(want) and set(seen) == want
    assert all(t == {"value": len(want), "relation": "eq"} for t in totals), "the total is the walk's, on every page"
    assert cluster.open_pits == {} and len(cluster.pits_opened) == 1 and cluster.pits_closed == cluster.pits_opened


def test_the_fake_point_in_time_is_a_fixed_view_that_no_write_delete_or_merge_changes():
    cluster = _cluster()
    before, _ = _pit_walk(_cluster(), AUTH, 5)

    def spoil(page):
        cluster.merge(AUTH)
        cluster.put(AUTH, "auth-new", {"@timestamp": "2026-10-20T05:00:00Z"})
        del cluster.indices[AUTH]["docs"][f"auth-{page:02d}"]

    seen, totals = _pit_walk(cluster, AUTH, 5, between=spoil)

    assert seen == before and all(t["value"] == 36 for t in totals), "the view moved after the point-in-time opened"
    assert cluster.merges >= 1


def test_the_fake_refuses_what_elasticsearch_refuses_around_a_point_in_time():
    cluster = _cluster()
    pit_id = _open(cluster, AUTH)
    body = {"pit": {"id": pit_id, "keep_alive": "2m"}, "sort": [{"_shard_doc": "asc"}], "size": 3}

    with pytest.raises(RuntimeError, match=r"action_request_validation_exception.*\[indices\] cannot be used with point in time"):
        cluster.es_request("POST", f"/{AUTH}/_search", body)
    with pytest.raises(RuntimeError, match=r"illegal_argument_exception.*_shard_doc.*point in time"):
        cluster.es_request("POST", f"/{AUTH}/_search", {"sort": [{"_shard_doc": "asc"}]})
    with pytest.raises(RuntimeError, match="action_request_validation_exception.*keep_alive"):
        cluster.es_request("POST", f"/{AUTH}/_pit?expand_wildcards=open,hidden")
    with pytest.raises(FakeGap):
        cluster.es_request("POST", "/_search", {**body, "sort": [{"@timestamp": "asc"}]})
    with pytest.raises(FakeGap):
        cluster.es_request("POST", f"/{AUTH}/_pit?keep_alive=2m&routing=x")
    assert _close(cluster, pit_id) == {"succeeded": True, "num_freed": 1}
    # a closed id: searching and closing it again raise (live: 404; closing answers {succeeded: true, num_freed: 0})
    with pytest.raises(RuntimeError):
        cluster.es_request("POST", "/_search", body)
    with pytest.raises(RuntimeError):
        _close(cluster, pit_id)
    # a malformed id raises (live: 400)
    with pytest.raises(RuntimeError):
        cluster.es_request("POST", "/_search", {"pit": {"id": "never-opened"}, "sort": [{"_shard_doc": "asc"}]})
    with pytest.raises(RuntimeError):
        _close(cluster, "never-opened")


def test_the_fake_point_in_time_leaves_hidden_indices_out_unless_it_is_asked_for_them():
    cluster = _cluster()
    cluster.put(HIDDEN, "h-0", {"@timestamp": "2026-10-20T04:00:00Z"})

    def view(query):
        pit_id = cluster.es_request("POST", f"/*/_pit?{query}")["id"]
        out = cluster.es_request("POST", "/_search", {"pit": {"id": pit_id}, "sort": [{"_shard_doc": "asc"}],
                                                      "size": 500})
        _close(cluster, pit_id)
        return {h["_index"] for h in out["hits"]["hits"]}

    visible = view("keep_alive=2m")
    assert DEDUP in visible and HIDDEN not in visible and AUTH not in visible      # AUTH is a dot-named backing index
    both = view("keep_alive=2m&expand_wildcards=open,hidden")
    assert {DEDUP, HIDDEN, AUTH} <= both


def test_the_fake_tells_a_point_in_time_nobody_closed(tmp_path):
    rig = LabRig(tmp_path)
    rig.cluster.put(AUTH, "auth-00", {"@timestamp": "2026-10-20T04:00:00Z"})
    pit_id = _open(rig.cluster, AUTH)

    assert list(rig.cluster.open_pits) == [pit_id]
    with pytest.raises(AssertionError, match="never closed"):
        rig._edges_modelled()
    _close(rig.cluster, pit_id)
    rig._edges_modelled()


def test_the_fake_shows_that_a_doc_sorted_walk_without_a_point_in_time_skips_or_repeats_when_the_index_merges():
    cluster = _cluster()
    ids, seen, after = sorted(world_content()[AUTH]), [], None
    while True:
        body = {"size": 7, "sort": [{"_doc": "asc"}], "query": {"match_all": {}}}
        if after is not None:
            body["search_after"] = after
            cluster.merge(AUTH)     # the index merges between pages
        hits = cluster.es_request("POST", f"/{AUTH}/_search", body)["hits"]["hits"]
        seen += [h["_id"] for h in hits]
        if len(hits) < 7:
            break
        after = hits[-1]["sort"]

    assert sorted(seen) != ids, "a merge between pages left the plain walk whole: the fake cannot show the hazard"


def test_a_refresh_merges_only_when_the_fake_is_told_to():
    cluster = _cluster()
    first = cluster.es_request("POST", f"/{AUTH}/_search", {"size": 36, "sort": [{"_doc": "asc"}]})["hits"]["hits"]
    cluster.es_request("POST", f"/{AUTH}/_refresh")
    assert [h["_id"] for h in cluster.es_request("POST", f"/{AUTH}/_search", {"size": 36, "sort": [{"_doc": "asc"}]})[
        "hits"]["hits"]] == [h["_id"] for h in first]
    cluster.merge_on_refresh = True
    cluster.es_request("POST", f"/{AUTH}/_refresh")
    assert [h["_id"] for h in cluster.es_request("POST", f"/{AUTH}/_search", {"size": 36, "sort": [{"_doc": "asc"}]})[
        "hits"]["hits"]] != [h["_id"] for h in first]


def test_the_fake_reports_the_total_of_a_search_whatever_search_after_skips():
    cluster = _cluster()
    body = {"size": 5, "sort": [{"_doc": "asc"}], "track_total_hits": True}
    first = cluster.es_request("POST", f"/{AUTH}/_search", body)
    second = cluster.es_request("POST", f"/{AUTH}/_search", {**body, "search_after": first["hits"]["hits"][-1]["sort"]})

    assert first["hits"]["total"] == second["hits"]["total"] == {"value": 36, "relation": "eq"}


def test_the_fake_loses_the_hits_of_an_index_from_the_second_page_of_a_point_in_time_walk_on():
    cluster = _cluster()
    cluster.lose_from_pit_pages = lambda n: n == DEDUP
    seen, totals = _pit_walk(cluster, f"{AUTH},{DEDUP}", 10)

    first_page = seen[:10]
    assert {n for n, _i in first_page} <= {AUTH, DEDUP}
    assert all(t["value"] == 36 + 4 for t in totals)
    assert len(seen) < 40, "no hit was lost: the fault did not act"


# -- the walks, through the real entry points ----------------------------------------------------------------------


def _syslog_bulk(n: int, *, wide: bool = False) -> dict:
    """`n` more in-span syslog events (08:00 to 08:59 on the 20th), each with a field of its own when `wide`."""
    out = {}
    for k in range(n):
        minute, second = divmod(k, 60)
        source = {"@timestamp": f"2026-10-20T08:{minute:02d}:{second:02d}Z", "message": f"bulk line {k}",
                  "event.dataset": "system.syslog"}
        if wide:
            source[f"extra.field_{k:05d}"] = k
        out[f"bulk-{k:05d}"] = {"_source": source, "_version": 1}
    return out


def _in_span(source: dict) -> bool:
    return instant(SPAN_START) <= instant(source["@timestamp"]) <= instant(T) and source["event.dataset"] == "system.syslog"


def _dropped(docs: dict) -> set:
    return {i for i, d in docs.items() if _in_span(d["_source"]) and run_processors([DATA_DROP["processor"]], d["_source"]) is None}


def _bulk_state(bulk: dict) -> dict:
    """The copy after the base overlay and the data-drop over a syslog index that also holds `bulk`, written out from
    the world constants and the verbatim processor."""
    state = expected_copy("none")
    docs = {**{i: {"_source": src, "_version": v} for i, (v, src) in state[SYSLOG].items()}, **copy.deepcopy(bulk)}
    gone = _dropped(docs)
    state[SYSLOG] = {i: (d["_version"], d["_source"]) for i, d in docs.items() if i not in gone}
    return state


def _merging(cluster, _expr, body):
    """Every index merges before a page after the first, as long as the overlay's pipeline stands (the overlay
    phase); a point-in-time walk cannot see it."""
    if body.get("search_after") is None:
        return
    if any(m == "DELETE" and "/_ingest/pipeline/" in p for m, p, _b in cluster.requests):
        return
    cluster.merge()


def _bulk_rig(tmp_path, entry, n=2400, *, wide=False):
    bulk = _syslog_bulk(n, wide=wide)
    rig = LabRig(tmp_path, extra_indices={SYSLOG: {**world_content()[SYSLOG], **bulk}})
    state = _bulk_state(bulk)
    if entry == "launch":
        rig.write_variant_case(DATA_DROP, state=state)
    return rig, bulk, state


def _run(rig, entry, tmp_path):
    """The entry point; returns what to release (None for a launch)."""
    if entry == "launch":
        rig.launch()
        return None
    return rig.write_case("young", _overlay("data-drop-syslog"), profiles_dir=_drift_profiles(tmp_path))


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_data_drops_survivors_are_never_deleted_when_the_scratch_index_merges_between_pages(tmp_path, entry):
    """The walk over the scratch index and the one over the dropped-or-kept events span more than one page; the
    indices merge between pages. A pager that sorts by `_doc` skips survivors, and the overlay deletes whatever
    it did not see; a walk on a fixed view deletes exactly the events the processor dropped."""
    rig, bulk, state = _bulk_rig(tmp_path, entry)
    rig.cluster.on_search = _merging
    held = _run(rig, entry, tmp_path)
    try:
        docs = {**world_content()[SYSLOG], **bulk}
        gone = _dropped(docs)
        assert len(gone) > 300 and len(docs) - len(gone) > 2 * _PAGE // 2, "the world is too small to need a second page"
        assert any(r[2] and r[2].get("search_after") is not None for r in rig.cluster.requests if r[1].split("?")[0].endswith("/_search"))
        assert rig.cluster.merges > 0
        survivors = {i for i in docs if i not in gone and instant(docs[i]["_source"]["@timestamp"]) <= instant(T)}
        assert survivors <= set(rig.cluster.state()[SYSLOG]), (
            f"{len(survivors - set(rig.cluster.state()[SYSLOG]))} survivors were deleted")
        assert rig.cluster.state() == state, "the drop did not delete exactly the events the processor dropped"
        assert rig.cluster.open_pits == {}
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_every_point_in_time_a_step_opens_is_closed_and_the_walks_use_one(tmp_path, entry):
    rig = LabRig(tmp_path)
    if entry == "launch":
        rig.write_expected_case("drift")
        rig.launch()
        held = None
    else:
        held = rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path))
    try:
        assert rig.cluster.pits_opened, "no walk opened a point-in-time"
        assert rig.cluster.open_pits == {} and sorted(rig.cluster.pits_closed) == sorted(rig.cluster.pits_opened)
        opens = [r for r in rig.cluster.requests if r[0] == "POST" and r[1].split("?")[0].endswith("/_pit")]
        assert len(opens) == len(rig.cluster.pits_opened)
        for _m, path, _b in opens:
            query = parse_qs(path.partition("?")[2])
            assert query.get("keep_alive") and query.get("expand_wildcards") == ["open,hidden"], path
        searched = [r for r in rig.cluster.requests if r[1].split("?")[0].endswith("/_search")]
        assert all(r[1].split("?")[0] == "/_search" and r[2].get("pit") for r in searched if r[2] and r[2].get("search_after")), (
            "a paged search was made without a point-in-time, or with an index in its path")
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("kind", ["none", "drop", "drift"])
def test_every_launch_variant_closes_every_point_in_time_it_opened(tmp_path, kind):
    rig = LabRig(tmp_path)
    rig.write_expected_case(kind)
    rig.launch()

    assert rig.cluster.pits_opened and rig.cluster.open_pits == {}
    assert sorted(rig.cluster.pits_closed) == sorted(rig.cluster.pits_opened)


def _second_pit_page(method, path, body):
    return path == "/_search" and isinstance(body, dict) and "pit" in body and body.get("search_after") is not None


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_step_that_fails_partway_through_a_walk_still_closes_its_point_in_time(tmp_path, entry):
    rig, _bulk, _state = _bulk_rig(tmp_path, entry)
    rig.cluster.fail = _second_pit_page
    rig.launch_module
    with pytest.raises(Exception) as caught:      # noqa: PT011 - the injected failure, whatever it is wrapped in
        _run(rig, entry, tmp_path)

    assert not isinstance(caught.value, (AssertionError, AttributeError, TypeError, NameError)), repr(caught.value)
    assert rig.cluster.pits_opened, "the walk never opened a point-in-time: the fault was not reached"
    assert rig.cluster.open_pits == {}, "a point-in-time was left open"
    assert any(_second_pit_page(m, p, b) for m, p, b in rig.cluster.requests), "the fault was not reached"


def test_the_content_digest_closes_its_point_in_time_when_a_page_fails(tmp_path):
    rig = LabRig(tmp_path, extra_indices={SYSLOG: {**world_content()[SYSLOG], **_syslog_bulk(2400)}})
    rig.write_variant_case(None, state=_with_bulk(_syslog_bulk(2400)))
    outcome = []

    def during_the_run():
        rig.cluster.fail = _second_pit_page
        try:
            rig.ops.content_digest([SYSLOG])
        except Exception as exc:      # noqa: BLE001
            outcome.append(exc)
        rig.cluster.fail = None

    rig.run_hook = during_the_run
    rig.launch()

    assert len(outcome) == 1 and not isinstance(outcome[0], (AssertionError, AttributeError, TypeError, NameError)), outcome
    assert rig.cluster.pits_opened and rig.cluster.open_pits == {}


def _with_bulk(bulk: dict) -> dict:
    """The restored copy (the base overlay only) with `bulk` added to the syslog index."""
    state = expected_copy("none")
    state[SYSLOG] = {**state[SYSLOG], **{i: (1, d["_source"]) for i, d in copy.deepcopy(bulk).items()}}
    return state


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_drop_walk_that_reads_fewer_documents_than_its_first_page_counted_refuses_and_deletes_nothing(tmp_path, entry):
    """A page that silently misses a shard's hits (`_shards.failed` 1) would make the survivors look dropped. The
    walk compares what it read with the total its first page reported and refuses; no event is deleted."""
    rig, bulk, _state = _bulk_rig(tmp_path, entry)
    rig.cluster.lose_from_pit_pages = lambda name: name not in world_content()      # the scratch index
    with pytest.raises(Exception) as caught:      # noqa: PT011
        _run(rig, entry, tmp_path)

    assert not isinstance(caught.value, (AssertionError, AttributeError, TypeError, NameError)), repr(caught.value)
    assert rig.cluster.pits_opened and rig.cluster.open_pits == {}
    docs = {**world_content()[SYSLOG], **bulk}
    in_span = {i for i, d in docs.items() if _in_span(d["_source"]) and instant(d["_source"]["@timestamp"]) <= instant(T)}
    assert in_span <= set(rig.cluster.state()[SYSLOG]), "an in-span event was deleted by a walk that read too little"


def test_the_content_digest_refuses_a_walk_that_reads_fewer_documents_than_its_first_page_counted(tmp_path):
    rig = LabRig(tmp_path, extra_indices={SYSLOG: {**world_content()[SYSLOG], **_syslog_bulk(2400)}})
    rig.write_variant_case(None, state=_with_bulk(_syslog_bulk(2400)))
    outcome = []

    def during_the_run():
        rig.cluster.lose_from_pit_pages = lambda name: name == SYSLOG
        try:
            outcome.append(rig.ops.content_digest([SYSLOG]))
        except Exception as exc:      # noqa: BLE001
            outcome.append(exc)
        rig.cluster.lose_from_pit_pages = None

    rig.run_hook = during_the_run
    rig.launch()

    assert len(outcome) == 1 and isinstance(outcome[0], Exception), f"a digest was given over a partial read: {outcome}"
    assert not isinstance(outcome[0], (AssertionError, AttributeError, TypeError, NameError)), repr(outcome[0])


def test_the_content_digest_is_the_same_whatever_order_the_index_merges_into_between_pages(tmp_path):
    bulk = _syslog_bulk(2400)
    rig = LabRig(tmp_path, extra_indices={SYSLOG: {**world_content()[SYSLOG], **bulk}})
    rig.write_variant_case(None, state=_with_bulk(bulk))
    digests = []

    def during_the_run():
        digests.append(rig.ops.content_digest([SYSLOG]))
        rig.cluster.on_search = lambda c, _e, body: c.merge() if body.get("search_after") is not None else None
        digests.append(rig.ops.content_digest([SYSLOG]))
        rig.cluster.on_search = lambda c, _e, body: c.merge() if body.get("search_after") is not None else None
        digests.append(rig.ops.content_digest([SYSLOG]))
        rig.cluster.on_search = None

    rig.run_hook = during_the_run
    rig.launch()

    assert rig.cluster.merges >= 2, "the index never merged between pages: the claim was not exercised"
    assert len(digests) == 3 and all(re.fullmatch(r"[0-9a-f]{64}", d) for d in digests)
    assert digests[0] == digests[1] == digests[2], "the digest follows the order the index merged into"
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


# -- the derived-alert lookup: several alert indices, more than one page, no listing per batch ---------------------


def _auth_bulk(n: int) -> dict:
    """`n` more in-span auth events (08:00..08:59 on the 20th, dataset `system.auth`)."""
    out = {}
    for k in range(n):
        minute, second = divmod(k, 60)
        out[f"auth-bulk-{k:05d}"] = {"_source": {
            "@timestamp": f"2026-10-20T08:{minute:02d}:{second:02d}Z", "message": f"bulk auth {k}",
            "event.dataset": "system.auth", "user.name": "bulk", "source.ip": "10.9.0.1", "source.port": 45000 + k},
            "_version": 1}
    return out


def _listings(rig) -> int:
    """The requests that list the copy's indices (`_cat/indices`, the cluster metadata, a data-stream listing)."""
    return len([r for r in rig.cluster.requests
                if r[1].startswith(("/_cat/indices", "/_cluster/state/metadata", "/_data_stream"))])


def _ancestor_lookups(rig) -> int:
    return len([r for r in rig.cluster.requests if r[1].split("?")[0].endswith("/_search")
                and "kibana.alert.ancestors.id" in str(r[2] and r[2].get("query"))])


def _drift_over(tmp_path, n_events):
    n = _PAGE + 150
    second = {f"id-{u}": {"_source": doc, "_version": 1} for u, doc in _many_alerts("two", n).items()}
    auth = {**world_content()[AUTH], **_auth_bulk(n_events)}
    rig = LabRig(tmp_path, extra_alerts=_many_alerts("one", n), extra_indices={ALERTS_2: second, AUTH: auth})
    mark = len(rig.cluster.requests)
    held = rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path))
    return rig, held, mark, n


def test_the_derived_alert_lookup_over_several_alert_indices_and_batches_lists_no_index_per_batch(tmp_path):
    """The in-span events are looked up in batches of a page; the alerts derived from them live in two indices and
    take more than one page. One walk on one view serves every batch: the number of index listings does not grow
    with the number of batches."""
    small, held_small, _m, _n = _drift_over(tmp_path / "small", 0)
    held_small.release()
    big, held_big, _mark, n = _drift_over(tmp_path / "big", 2400)
    try:
        assert _ancestor_lookups(small) >= 1
        assert _listings(big) == _listings(small), (
            f"{_listings(big)} index listings for {_ancestor_lookups(big)} lookups, against {_listings(small)} "
            f"for {_ancestor_lookups(small)}: the lookup lists the indices per batch")
        state = big.cluster.state()
        for index, prefix in ((ALERTS, "one"), (ALERTS_2, "two")):
            rewritten = [i for i, (_v, src) in state[index].items() if i.startswith(f"id-{prefix}-")]
            assert len(rewritten) == n and all(
                "source.port_no" in state[index][i][1] and state[index][i][0] == 2 for i in rewritten), index
        assert big.cluster.open_pits == {} and big.cluster.pits_opened
    finally:
        held_big.release()
