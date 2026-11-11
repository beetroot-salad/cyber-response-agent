"""#1347 r6.4.5: a stream's backing indices come from the cluster (`GET /_data_stream`), not from their names.

Design: Amendment r6.4.5, "A stream's backing indices come from the cluster". Live, four data streams have a backing
index named `dedup-logs-<dataset>-default` (an older consolidation); the shared world has one for the auth stream
(`_lab_fakes.DEDUP`, holding in-span auth events with `source.port`) and an index named like a backing index of the
auth stream that is NOT a member (`_lab_fakes.DECOY`).

Observed at the cluster (the fake's end state and request log), through the real entry points (launch, make-a-case).
"""
from __future__ import annotations

import collections
import copy

import pytest
from _lab_fakes import hit_indices, expected_touched
from _lab_fakes import (ALERTS, AUTH, DECOY, DECOY_IN_SPAN, DEDUP, DEDUP_IN_SPAN, DEDUP_OLD, NGINX, REPO, SNAP, SNAP_UUID,
                        STREAMS, SYSLOG, FakeCluster, FakeGap, Journal, LabRig, expected_copy, world_content)
from test_1347_make_case import _drift_profiles, _overlay

AUTH_STREAM = "logs-system.auth-default"


# -- the fake the demands rely on (R6) --------------------------------------------------------------------------


def _cluster() -> FakeCluster:
    cluster = FakeCluster(Journal(), repo=REPO, snapshot=SNAP, snapshot_uuid=SNAP_UUID, content={}, streams=STREAMS)
    for name in (DEDUP_OLD, DEDUP, AUTH, SYSLOG, NGINX, DECOY, ALERTS):
        cluster._index(name)
    return cluster


def test_the_fake_answers_get_data_stream_with_membership_from_its_streams_map_write_index_last():
    cluster = _cluster()

    got = cluster.es_request("GET", "/_data_stream/logs-system.auth-default")["data_streams"]
    assert [s["name"] for s in got] == [AUTH_STREAM]
    assert [i["index_name"] for i in got[0]["indices"]] == [DEDUP_OLD, DEDUP, AUTH], "the name DECOY looks like a backing index"

    both = cluster.es_request("GET", "/_data_stream/logs-nginx.access-default,logs-system.syslog-*")["data_streams"]
    assert sorted(s["name"] for s in both) == ["logs-nginx.access-default", "logs-system.syslog-default"]
    every = cluster.es_request("GET", "/_data_stream/logs-*")["data_streams"]
    assert sorted(s["name"] for s in every) == sorted(set(STREAMS.values()))
    assert cluster.es_request("GET", "/_data_stream/nothing-*")["data_streams"] == []
    with pytest.raises(RuntimeError, match="resource_not_found"):
        cluster.es_request("GET", "/_data_stream/nothing-here")


def test_the_fake_lists_only_backing_indices_the_cluster_holds_and_leaves_other_data_stream_calls_loud():
    cluster = _cluster()
    del cluster.indices[DEDUP]

    got = cluster.es_request("GET", "/_data_stream/logs-system.auth-default")["data_streams"]
    assert [i["index_name"] for i in got[0]["indices"]] == [DEDUP_OLD, AUTH]
    for method, path in (("POST", "/_data_stream/_migrate/x"), ("PUT", "/_data_stream/x"),
                         ("GET", "/_data_stream/x/_stats"), ("DELETE", "/_data_stream/x")):
        with pytest.raises(FakeGap):
            cluster.es_request(method, path)
    assert cluster.es_request("DELETE", "/_data_stream/logs-nginx.access-default/_lifecycle") == {"acknowledged": True}
    assert cluster.lifecycle_deletes == ["logs-nginx.access-default"]


# -- the world --------------------------------------------------------------------------------------------------


def test_the_world_holds_a_consolidated_backing_index_a_name_parse_cannot_see_and_a_lookalike_that_is_no_member():
    world = world_content()

    assert STREAMS[DEDUP] == AUTH_STREAM and DECOY not in STREAMS
    assert not DEDUP.startswith(".ds-") and DECOY.startswith(".ds-logs-system.auth-default-")
    assert set(world[DEDUP]) >= set(DEDUP_IN_SPAN) and set(world[DECOY]) == set(DECOY_IN_SPAN)
    for index in (DEDUP, DECOY):
        assert all(d["_source"]["event.dataset"] == "system.auth" and "source.port" in d["_source"]
                   for d in world[index].values())


# -- the schema-drift overlay over a stream with a consolidated index -------------------------------------------


def _drift_by(entry: str, tmp_path):
    rig = LabRig(tmp_path)
    if entry == "launch":
        rig.write_expected_case("drift")
        rig.launch()
        return rig, None
    held = rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path))
    return rig, held


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_schema_drift_renames_the_field_in_the_consolidated_index_too_keeping_id_and_index(tmp_path, entry):
    """A stream's index that no `.ds-` name parse finds is rewritten like the others: the documents in the span carry
    the renamed field, every other document is as restored, and no document moved index or changed id."""
    rig, held = _drift_by(entry, tmp_path)
    try:
        state, restored = rig.cluster.state(), expected_copy("none")

        assert set(state[DEDUP]) == set(restored[DEDUP]), "a document was added or removed"
        for doc_id in DEDUP_IN_SPAN:
            _version, source = state[DEDUP][doc_id]
            assert "source.port" not in source and source["source.port_no"] == restored[DEDUP][doc_id][1]["source.port"]
        assert state[DEDUP]["dedup-auth-00"] == restored[DEDUP]["dedup-auth-00"], "before the span"
        assert state[DEDUP] == expected_copy("drift")[DEDUP]
        assert state == expected_copy("drift")
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_the_alerts_derived_from_the_consolidated_index_are_rewritten_by_index_or_by_the_streams_pattern(tmp_path, entry):
    rig, held = _drift_by(entry, tmp_path)
    try:
        state, restored = rig.cluster.state()[ALERTS], expected_copy("none")[ALERTS]

        for uuid in ("derived-dedup", "derived-dedup-pattern"):
            _v, source = state[f"id-{uuid}"]
            assert "source.port" not in source and source["source.port_no"] == restored[f"id-{uuid}"][1]["source.port"]
        assert state == expected_copy("drift")[ALERTS]
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_an_index_named_like_a_backing_index_but_not_in_the_stream_is_not_rewritten(tmp_path, entry):
    """Positive control: membership is the cluster's word. The look-alike holds in-span auth events with the field,
    and an alert derived from one of them; none is touched (nor counted as touched)."""
    rig, held = _drift_by(entry, tmp_path)
    try:
        state, restored = rig.cluster.state(), expected_copy("none")

        assert state[DECOY] == restored[DECOY] and all(
            "source.port" in source and "source.port_no" not in source for _v, source in state[DECOY].values())
        assert state[ALERTS]["id-derived-decoy"] == restored[ALERTS]["id-derived-decoy"]
        assert not [m for m in rig.cluster.mutations if m["kind"] != "restore" and DECOY in m["target"]], \
            "an overlay write targeted the look-alike (the whole-snapshot restore is not a rewrite)"
    finally:
        if held is not None:
            held.release()


@pytest.mark.parametrize("kind", ["none", "drop", "drift"])
def test_each_streams_lifecycle_is_removed_once_not_once_per_backing_index_name(tmp_path, kind):
    """The auth stream has three indices that a name parse would put under it (the consolidated one is not among
    them, the look-alike is): its lifecycle is removed exactly once, as is every other stream's, before the first
    change to a document."""
    rig = LabRig(tmp_path)
    rig.write_expected_case(kind)
    rig.launch()

    counts = collections.Counter(rig.cluster.lifecycle_deletes)
    assert counts == {s: 1 for s in set(STREAMS.values())}, counts
    first_change = next(m for m in rig.cluster.mutations if m["kind"] in ("delete_by_query", "reindex"))
    assert set(STREAMS.values()) <= first_change["lifecycle_off"]


def test_a_copy_restored_from_the_world_lists_the_consolidated_index_as_a_member_of_its_stream(tmp_path):
    """The premise of the demands above, read at the restored copy through the same call the lab reads."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.launch()

    streams = rig.cluster.es_request("GET", "/_data_stream/logs-system.auth-*")["data_streams"]
    assert [i["index_name"] for i in streams[0]["indices"]] == [DEDUP_OLD, DEDUP, AUTH]
    assert copy.deepcopy(world_content()[DEDUP]).keys() == rig.cluster.state()[DEDUP].keys()


# -- a member with nothing in the span is not touched (r6.4.5: touched = an overlay changed a document) ------------


def test_a_stream_member_with_no_event_in_the_span_is_not_touched_and_no_document_of_it_is_digested(tmp_path):
    """`DEDUP_OLD` is a member of the drifted stream holding only older events: the schema-drift changes none of
    its documents, so it is not in the clean marker's `touched`, and a launch that reuses the copy (which digests
    the touched indices) is returned no document of it."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("drift")
    rig.launch()
    touched = expected_touched(expected_copy("drift"), None)

    assert DEDUP in touched and DEDUP_OLD not in touched
    assert set(rig.marker()["touched"]) == set(touched), rig.marker()
    assert rig.cluster.state()[DEDUP_OLD] == expected_copy("none")[DEDUP_OLD]
    seen = len(rig.cluster.requests)
    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert DEDUP_OLD not in hit_indices(rig.cluster, seen)
