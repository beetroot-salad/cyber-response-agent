"""#1347 r6.4.5: fault overlays rewrite in place and run no ingest of their own.

Design: Amendment r6.4.5, "Fault overlays rewrite in place". Live (Elasticsearch 9.3.3): any direct write into a data
stream's backing index is refused per document, so delete-and-copy-back cannot run on a log stream; an
`_update_by_query` works on one and keeps `_id`/`_index`, `_version` + 1. The frozen cluster does not hold the
integration and fleet pipelines the backing indices name (restored without global state), so a write that runs one
fails the document.

The first half pins the fake (R6: the demands below rely on it). The second half is observed at the cluster after the
real entry points (launch, make-a-case).
"""
from __future__ import annotations

import copy

import pytest
from _lab_fakes import (ALERTS, AUTH, DATA_DROP, DEDUP, DEDUP_IN_SPAN, DEDUP_OLD, FLEET_FINAL, NGINX, REPO, SCHEMA_DRIFT,
                        SNAP, SNAP_UUID, STREAMS, SYSLOG, SYSLOG_IN_SPAN, WORLD_SETTINGS, FakeCluster, FakeGap, Journal,
                        LabRig, expected_copy, run_processors, world_content)
from _lab_fakes import ALERTS_PATTERN
from test_1347_make_case import _drift_profiles, _overlay

RENAME = {"rename": {"field": "source.port", "target_field": "source.port_no", "ignore_missing": True}}
CREATE_REFUSED = ("index request with op_type=create targeting backing indices is disallowed, "
                  "target corresponding data stream instead")
INDEX_REFUSED = ("index request with op_type=index and no if_primary_term and if_seq_no set targeting "
                 "backing indices is disallowed")


def _cluster(settings: dict | None = None) -> FakeCluster:
    cluster = FakeCluster(Journal(), repo=REPO, snapshot=SNAP, snapshot_uuid=SNAP_UUID, content={}, streams=STREAMS,
                          settings=WORLD_SETTINGS if settings is None else settings)
    for name, docs in world_content().items():
        cluster._index(name)["settings"] = copy.deepcopy(cluster.content_settings.get(name, {}))
        for doc_id, d in docs.items():
            cluster.put(name, doc_id, d["_source"], d["_version"])
    return cluster


def _put(cluster, name, *processors):
    cluster.es_request("PUT", f"/_ingest/pipeline/{name}", {"processors": list(processors)})


# -- the fake -----------------------------------------------------------------------------------------------------


def test_the_fake_refuses_every_direct_write_into_a_backing_index_per_document_and_accepts_a_plain_index():
    cluster = _cluster()
    _put(cluster, "p", RENAME)
    for op_type, reason in (("create", CREATE_REFUSED), (None, INDEX_REFUSED)):
        dest = {"index": AUTH, **({"op_type": op_type} if op_type else {}), "pipeline": "p"}
        out = cluster.es_request("POST", "/_reindex", {"source": {"index": SYSLOG}, "dest": dest})
        assert out["created"] == 0 and out["failures"][0]["status"] == 400
        assert out["failures"][0]["cause"]["reason"] == reason, out["failures"][0]
    out = cluster.es_request("POST", "/_reindex", {"source": {"index": AUTH, "query": {"ids": {"values": ["auth-20"]}}},
                                                   "dest": {"index": "scratch", "pipeline": "p"}})
    assert out["created"] == 1 and out["failures"] == []
    assert cluster.state()["scratch"]["auth-20"][1]["source.port_no"] == 40020


def test_the_fake_updates_in_place_through_a_pipeline_on_a_backing_index_and_a_drop_is_a_noop():
    cluster = _cluster({})
    _put(cluster, "p", RENAME)
    before = cluster.state()[AUTH]

    out = cluster.es_request("POST", f"/{AUTH}/_update_by_query?pipeline=p",
                             {"query": {"ids": {"values": ["auth-20", "auth-21"]}}})
    after = cluster.state()[AUTH]
    assert out["updated"] == 2 and out["failures"] == []
    for doc_id in ("auth-20", "auth-21"):
        assert after[doc_id][0] == before[doc_id][0] + 1 and "source.port_no" in after[doc_id][1]
    assert {k: v for k, v in after.items() if k not in ("auth-20", "auth-21")} == {
        k: v for k, v in before.items() if k not in ("auth-20", "auth-21")}

    _put(cluster, "d", DATA_DROP["processor"])
    out = cluster.es_request("POST", f"/{SYSLOG}/_update_by_query?pipeline=d", {"query": {"match_all": {}}})
    assert out["noops"] > 0 and out["updated"] + out["noops"] == out["total"]
    assert len(cluster.state()[SYSLOG]) == 30, "a drop under _update_by_query deletes nothing"
    with pytest.raises(FakeGap):
        cluster.es_request("POST", f"/{AUTH}/_update_by_query?routing=x", {})


def test_the_fake_runs_the_requests_pipeline_else_the_default_then_always_the_final_and_fails_a_missing_one():
    cluster = _cluster()      # the integration's pipelines are not in the cluster
    _put(cluster, "p", RENAME)

    out = cluster.es_request("POST", f"/{AUTH}/_update_by_query?pipeline=p", {"query": {"match_all": {}}})
    assert out["updated"] == 0 and out["failures"][0]["cause"]["reason"] == (
        f"pipeline with id [{FLEET_FINAL}] does not exist"), out["failures"]
    out = cluster.es_request("POST", f"/{DEDUP}/_update_by_query", {"query": {"match_all": {}}})
    assert out["failures"][0]["cause"]["reason"] == "pipeline with id [logs-system.auth-1.2.0] does not exist"
    out = cluster.es_request("POST", f"/{DEDUP}/_update_by_query?pipeline=p", {"query": {"match_all": {}}})
    assert out["failures"] == [] and out["updated"] == 4, "the request's pipeline replaces the default; no final is set"
    out = cluster.es_request("POST", f"/{DEDUP_OLD}/_update_by_query", {"query": {"match_all": {}}})
    assert out["failures"] == [] and out["updated"] == 2, "both `_none`: no pipeline"
    out = cluster.es_request("POST", f"/{ALERTS}/_update_by_query?pipeline=nope", {"query": {"match_all": {}}})
    assert out["failures"][0]["cause"]["reason"] == "pipeline with id [nope] does not exist"
    assert {name for name, _ in cluster.ingest_runs} == {"p"}


def test_the_fake_reads_and_writes_pipeline_settings_as_elasticsearch_does():
    cluster = _cluster()
    names = "index.default_pipeline,index.final_pipeline"

    got = cluster.es_request("GET", f"/{AUTH}/_settings/{names}?flat_settings=true")
    assert got == {AUTH: {"settings": {"index.default_pipeline": "logs-system.auth-1.6.4",
                                       "index.final_pipeline": FLEET_FINAL}}}
    everywhere = cluster.es_request("GET", f"/{AUTH},{DEDUP},{ALERTS}/_settings/{names}?flat_settings=true")
    assert set(everywhere) == {AUTH, DEDUP}, "an index with neither set is absent"
    assert everywhere[DEDUP] == {"settings": {"index.default_pipeline": "logs-system.auth-1.2.0"}}
    with pytest.raises(FakeGap):
        cluster.es_request("GET", f"/{AUTH}/_settings/{names}")

    cluster.es_request("PUT", f"/{AUTH}/_settings", {"index.default_pipeline": "_none", "index.final_pipeline": None})
    assert cluster.indices[AUTH]["settings"] == {"index.default_pipeline": "_none"}
    cluster.es_request("PUT", f"/{DEDUP}/_settings", {"index": {"final_pipeline": "x"}})
    assert cluster.indices[DEDUP]["settings"]["index.final_pipeline"] == "x"


def test_the_world_carries_pipelines_the_frozen_cluster_does_not_have_on_its_backing_indices():
    rig_pipelines = _cluster().pipelines
    assert rig_pipelines == {}
    for index in (AUTH, SYSLOG, NGINX, DEDUP):
        assert WORLD_SETTINGS[index].get("index.default_pipeline") not in (None, "_none")
    assert WORLD_SETTINGS[AUTH]["index.final_pipeline"] == FLEET_FINAL
    assert "index.final_pipeline" not in WORLD_SETTINGS[DEDUP] and ALERTS not in WORLD_SETTINGS
    assert set(WORLD_SETTINGS[DEDUP_OLD].values()) == {"_none"}


def test_the_fake_expands_the_lifecycle_delete_over_existing_streams():
    cluster = _cluster()

    cluster.es_request("DELETE", "/_data_stream/logs-system.*/_lifecycle")
    cluster.es_request("DELETE", "/_data_stream/logs-nginx.access-default,logs-system.auth-default/_lifecycle")
    assert sorted(cluster.lifecycle_deletes) == ["logs-nginx.access-default", "logs-system.auth-default",
                                                 "logs-system.auth-default", "logs-system.syslog-default"]
    with pytest.raises(RuntimeError, match="resource_not_found"):
        cluster.es_request("DELETE", "/_data_stream/logs-none-here/_lifecycle")


def _walk(cluster, expr, size):
    seen, after = [], None
    while True:
        body = {"size": size, "sort": [{"_doc": "asc"}], "query": {"match_all": {}}}
        if after is not None:
            body["search_after"] = after
        hits = cluster.es_request("POST", f"/{expr}/_search", body)["hits"]["hits"]
        seen += [h["_id"] for h in hits]
        if len(hits) < size:
            return seen
        after = hits[-1]["sort"]


def test_the_fake_pages_by_doc_one_index_at_a_time_and_refuses_it_across_indices_without_a_pit():
    cluster = _cluster()

    assert sorted(_walk(cluster, AUTH, 7)) == sorted(world_content()[AUTH]) and len(_walk(cluster, AUTH, 7)) == 36
    with pytest.raises(FakeGap, match="_doc"):
        _walk(cluster, f"{AUTH},{DEDUP}", 7)
    first = cluster.es_request("POST", f"/{AUTH},{DEDUP}/_search", {"size": 3, "sort": [{"_doc": "asc"}]})
    assert len(first["hits"]["hits"]) == 3, "the first page, with no search_after, is allowed"


def test_an_update_in_place_moves_a_document_to_the_end_of_its_indexs_doc_order():
    cluster = _cluster({})
    _put(cluster, "p", RENAME)
    cluster.es_request("POST", f"/{AUTH}/_update_by_query?pipeline=p", {"query": {"ids": {"values": ["auth-00"]}}})

    walk = _walk(cluster, AUTH, 5)
    assert walk[-1] == "auth-00" and walk.count("auth-00") == 1 and len(walk) == 36


def test_the_fake_leaves_task_answers_and_template_created_data_streams_loud():
    cluster = _cluster()
    _put(cluster, "p", RENAME)
    for path, body in ((f"/{AUTH}/_update_by_query?wait_for_completion=false", {}),
                       ("/_reindex?wait_for_completion=false", {"source": {"index": AUTH}, "dest": {"index": "x"}})):
        with pytest.raises(FakeGap, match="wait_for_completion"):
            cluster.es_request("POST", path, body)
    with pytest.raises(FakeGap, match="data stream"):
        cluster.es_request("POST", "/_reindex", {"source": {"index": AUTH}, "dest": {"index": "logs-scratch-tmp"}})
    ok = cluster.es_request("POST", "/_reindex?wait_for_completion=true",
                            {"source": {"index": AUTH, "query": {"ids": {"values": ["auth-01"]}}},
                             "dest": {"index": "scratch-tmp"}})
    assert ok["created"] == 1


# -- the overlays, through the real entry points ------------------------------------------------------------------


def _ready(entry: str, kind: str, tmp_path):
    rig = LabRig(tmp_path)
    if entry == "launch":
        rig.write_expected_case(kind)
        rig.launch()
        return rig, None
    overlay = {"none": None, "cmdb": None, "drop": _overlay("data-drop-syslog"), "drift": _overlay("drift-test")}[kind]
    return rig, rig.write_case("young", overlay, profiles_dir=_drift_profiles(tmp_path))


KINDS = [(e, k) for e in ("launch", "make-a-case") for k in ("none", "drop", "drift", "cmdb")
         if not (e == "make-a-case" and k == "cmdb")]      # cmdb changes no document: make-a-case's tests cover it


@pytest.mark.parametrize("entry, kind", KINDS)
def test_every_variant_builds_with_no_write_refused_or_failed(tmp_path, entry, kind):
    rig, held = _ready(entry, kind, tmp_path)
    try:
        assert rig.cluster.state() == expected_copy(kind)
        assert rig.cluster.refused == [], rig.cluster.refused
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_schema_drift_document_differs_from_the_restored_one_only_by_the_processors_change(tmp_path, entry):
    """Every in-span document of the stream (both its indices) and every derived alert: the verbatim processor's
    output, same id, same index, `_version` exactly one higher (the named gap). Nothing else changes."""
    rig, held = _ready(entry, "drift", tmp_path)
    try:
        state, restored = rig.cluster.state(), expected_copy("none")
        derived = ("young", "derived-in", "derived-dedup", "derived-dedup-pattern")
        in_span = {(AUTH, i) for i in expected_copy("drift")[AUTH] if state[AUTH][i] != restored[AUTH][i]}
        in_span |= {(DEDUP, i) for i in DEDUP_IN_SPAN} | {(ALERTS, f"id-{u}") for u in derived}
        assert len(in_span) == 13 + 3 + 4
        expected = {index: dict(docs) for index, docs in restored.items()}
        for index, doc_id in in_span:
            version, source = restored[index][doc_id]
            expected[index][doc_id] = (version + 1, run_processors([SCHEMA_DRIFT["processor"]], source))
        assert state == expected
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_data_drop_deletes_exactly_the_in_span_events_the_processor_drops_and_leaves_survivors_untouched(tmp_path, entry):
    rig, held = _ready(entry, "drop", tmp_path)
    try:
        state, restored = rig.cluster.state(), expected_copy("none")
        dropped = {i for i in SYSLOG_IN_SPAN if run_processors([DATA_DROP["processor"]], restored[SYSLOG][i][1]) is None}

        assert dropped and dropped < set(SYSLOG_IN_SPAN)
        assert set(restored[SYSLOG]) - set(state[SYSLOG]) == dropped
        assert state == {**restored, SYSLOG: {i: v for i, v in restored[SYSLOG].items() if i not in dropped}}, (
            "a survivor was written (its _version or source differs from the restored one), or another index changed")
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry, kind", [(e, k) for e in ("launch", "make-a-case") for k in ("drop", "drift")])
def test_each_indexs_pipeline_settings_are_exactly_what_the_snapshot_had_after_the_overlays(tmp_path, entry, kind):
    """A set value is back as it was (a default pipeline that was set is set again, a `_none` stays `_none`), an
    unset one is unset (an index with neither set is not left with `_none`)."""
    rig, held = _ready(entry, kind, tmp_path)
    try:
        settings = {n: ix["settings"] for n, ix in rig.cluster.indices.items()}
        assert settings == {n: WORLD_SETTINGS.get(n, {}) for n in world_content()}, settings
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry, kind", [(e, k) for e in ("launch", "make-a-case") for k in ("none", "drop", "drift", "cmdb")
                                         if not (e == "make-a-case" and k == "cmdb")])
def test_no_request_runs_an_ingest_pipeline_other_than_the_overlays(tmp_path, entry, kind):
    """Observed at the fake: every pipeline a write ran is one the overlay put holding exactly the resolver's
    processor, never the integration's default or the fleet final pipeline (which would also fail the document, the
    cluster not holding them)."""
    rig, held = _ready(entry, kind, tmp_path)
    try:
        processor = {"drop": DATA_DROP, "drift": SCHEMA_DRIFT}.get(kind, {}).get("processor")
        overlay_pipelines = {name for name, body in rig.cluster.put_pipelines if body.get("processors") == [processor]}
        ran = {name for name, _index in rig.cluster.ingest_runs}

        assert ran <= overlay_pipelines, (ran - overlay_pipelines, rig.cluster.ingest_runs[:3])
        assert (not ran) if processor is None else bool(ran)
        assert all(body.get("processors") == [processor] for _name, body in rig.cluster.put_pipelines)
    finally:
        if held is not None:
            held.release()


# -- the derived-alert lookup pages per index (r6.4.5, "Paging by _doc is per index") -----------------------------

ALERTS_2 = ".internal.alerts-security.alerts-default-000002"
_PAGE = 1000


def _many_alerts(prefix: str, n: int) -> dict:
    """`n` alerts at or before T, each derived (by the rule's pattern) from an in-span auth event."""
    return {f"{prefix}-{k:05d}": {"@timestamp": "2026-10-20T06:00:00Z", "kibana.alert.uuid": f"{prefix}-{k:05d}",
                                  "kibana.alert.workflow_status": "closed", "source.port": 50000,
                                  "kibana.alert.ancestors": [{"id": f"auth-{20 + k % 5}", "type": "event",
                                                              "index": "logs-system.auth-*", "depth": 0}]}
            for k in range(n)}


def test_a_drift_whose_derived_alerts_span_two_alert_indices_and_more_than_one_page_builds(tmp_path):
    """The lookup of the alerts derived from the in-span events pages with `search_after` sorted by `_doc`, which
    Elasticsearch orders per shard: over two alert indices (both reached by the alerts pattern) with more than one
    page of hits it must walk each index in turn (or hold a point-in-time). The fake refuses the cross-index walk
    loudly, so a lookup that pages across the pattern fails here."""
    n = _PAGE + 150
    second = {f"id-{u}": {"_source": doc, "_version": 1} for u, doc in _many_alerts("two", n).items()}
    rig = LabRig(tmp_path, extra_alerts=_many_alerts("one", n), extra_indices={ALERTS_2: second})
    assert rig.freeze["elastic"]["indices"][ALERTS_2] == n and ALERTS_PATTERN.endswith("-*")

    with rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path)):
        state = rig.cluster.state()
        for index, prefix in ((ALERTS, "one"), (ALERTS_2, "two")):
            rewritten = [i for i, (_v, src) in state[index].items() if i.startswith(f"id-{prefix}-")]
            assert len(rewritten) == n and all(
                "source.port_no" in state[index][i][1] and state[index][i][0] == 2 for i in rewritten), index
