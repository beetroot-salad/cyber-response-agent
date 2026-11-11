"""#1347 r6.4.6 "The snapshot defines the copy" (Amendment r6.4.6, second bullet), launcher side.

The freeze records `elastic.data_streams` beside `elastic.indices`: `{stream: sorted member indices}` (backing plus
failure-store indices). The reuse check holds when every freeze index is held and open, each freeze stream's members
(`indices` plus `failure_store.indices` of `GET /_data_stream`) equal the recorded list exactly, and no held index outside
the freeze matches a freeze pattern or a scratch name; the node's own indices (system indices, its own data streams) are
outside by construction. A freeze whose `data_streams` is not a mapping of non-empty names to non-empty lists of its
`elastic.indices` is refused before anything. (Capture's side is in test_1347_capture.py.)
"""
from __future__ import annotations

import pytest
import yaml
from _lab_fakes import (AUTH, DATA_STREAMS, FAILURE_STORE, ILM_HISTORY, NGINX, LabRig)
from test_1347_launcher import _NOT_A_REFUSAL, _no_lab_traffic

ROLLOVER = ".ds-logs-system.auth-default-2026.10.21-000005"     # a name no `logs-*` pattern matches
FS_EXTRA = ".fs-logs-system.syslog-default-2026.10.21-000003"
DOC = {"_source": {"@timestamp": "2026-10-20T05:00:00Z", "message": "x"}, "_version": 1}


def _two(tmp_path, spoil=None, kind="none"):
    rig = LabRig(tmp_path)
    rig.write_expected_case(kind)
    rig.launch()
    if spoil:
        spoil(rig)
    rig.launch()
    return rig


def test_the_freeze_records_the_snapshots_data_streams(tmp_path):
    rig = LabRig(tmp_path)
    members = rig.freeze["elastic"]["data_streams"]
    assert members == DATA_STREAMS
    assert sorted(members) == ["logs-nginx.access-default", "logs-system.auth-default", "logs-system.syslog-default"]
    assert FAILURE_STORE in members["logs-system.syslog-default"] and all(m == sorted(m) for m in members.values())


@pytest.mark.parametrize("kind", ["none", "drop", "drift"])
def test_a_clean_copy_with_the_nodes_own_stream_and_a_failure_store_member_is_reused(tmp_path, kind):
    rig = _two(tmp_path, kind=kind)
    meta = rig.cluster.es_request("GET", "/_data_stream/*")["data_streams"]

    assert rig.cluster.restores == 1
    assert any(ILM_HISTORY in [i["index_name"] for i in s["indices"]] for s in meta), "the node made no stream of its own"
    syslog = next(s for s in meta if s["name"] == "logs-system.syslog-default")
    assert [i["index_name"] for i in syslog["failure_store"]["indices"]] == [FAILURE_STORE]
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


def _rollover(rig):
    rig.cluster.stream_of[ROLLOVER] = "logs-system.auth-default"
    rig.cluster._index(ROLLOVER)["docs"]["r"] = DOC


def _extra_failure(rig):
    rig.cluster.failure_streams[FS_EXTRA] = "logs-system.syslog-default"
    rig.cluster._index(FS_EXTRA)["docs"]["r"] = DOC


def _detached(rig):
    del rig.cluster.stream_of[NGINX]       # held and open, but no stream's member any more


def _member_detached(rig):
    del rig.cluster.stream_of[AUTH]        # AUTH leaves its stream; DEDUP stays, so the stream still exists


def _failure_member_detached(rig):
    del rig.cluster.failure_streams[FAILURE_STORE]


@pytest.mark.parametrize("spoil", [_rollover, _extra_failure, _detached, _member_detached, _failure_member_detached],
                         ids=["rollover-generation", "extra-failure-store-member", "freeze-stream-gone",
                              "member-removed-stream-remains", "failure-store-member-removed"])
def test_a_clean_copy_whose_streams_are_not_the_freezes_is_restored_whole(tmp_path, spoil):
    rig = _two(tmp_path, spoil)

    assert rig.cluster.restores == 2
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert not {ROLLOVER, FS_EXTRA} & set(rig.cluster.indices)


def _drop(doc):
    del doc["elastic"]["data_streams"]


def _as_list(doc):
    doc["elastic"]["data_streams"] = sorted(doc["elastic"]["data_streams"])      # the r6.4.6 first draft


def _empty_members(doc):
    doc["elastic"]["data_streams"]["logs-nginx.access-default"] = []


def _empty_name(doc):
    doc["elastic"]["data_streams"][""] = [NGINX]


def _member_not_a_string(doc):
    doc["elastic"]["data_streams"]["logs-nginx.access-default"] = [7]


def _member_not_a_freeze_index(doc):
    doc["elastic"]["data_streams"]["logs-nginx.access-default"].append("logs-nginx.access-elsewhere")


def _members_a_string(doc):
    doc["elastic"]["data_streams"]["logs-nginx.access-default"] = NGINX


@pytest.mark.parametrize("spoil", [_drop, _as_list, _empty_members, _empty_name, _member_not_a_string,
                                   _member_not_a_freeze_index, _members_a_string])
def test_a_freeze_whose_data_streams_are_not_a_mapping_of_names_to_its_indices_is_refused_before_anything(tmp_path, spoil):
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    spoil(doc)
    (rig.freeze_dir / "freeze.yaml").write_text(yaml.safe_dump(doc))
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, _NOT_A_REFUSAL + (AssertionError,)), repr(caught.value)
    _no_lab_traffic(rig)
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records
