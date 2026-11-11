"""#1347 r6.4.6 "The snapshot defines the copy" (Amendment r6.4.6, second bullet), launcher side.

The freeze records `elastic.data_streams` beside `elastic.indices`. The reuse check holds when every freeze index is
held and open, each freeze stream's members (`indices` plus `failure_store.indices` of `GET /_data_stream`) are
freeze indices, and no held index outside the freeze matches a freeze pattern or a scratch name; the node's own
indices (system indices, its own data streams) are outside by construction. A freeze without `data_streams` is
refused before anything. (Capture's side is in test_1347_capture.py.)

Interpretation recorded: the freeze carries stream NAMES only, so "a freeze stream missing a member" is tested as a
freeze stream the copy lacks (its index held but no longer a member of any stream) and as a stream that holds a
member the freeze lacks; a member detached from a stream that still exists cannot be told from the freeze.
"""
from __future__ import annotations

import pytest
import yaml
from _lab_fakes import (FAILURE_STORE, ILM_HISTORY, NGINX, LabRig)
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
    assert rig.freeze["elastic"]["data_streams"] == ["logs-nginx.access-default", "logs-system.auth-default",
                                                     "logs-system.syslog-default"]


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


@pytest.mark.parametrize("spoil", [_rollover, _extra_failure, _detached],
                         ids=["rollover-generation", "extra-failure-store-member", "freeze-stream-gone"])
def test_a_clean_copy_whose_streams_are_not_the_freezes_is_restored_whole(tmp_path, spoil):
    rig = _two(tmp_path, spoil)

    assert rig.cluster.restores == 2
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert not {ROLLOVER, FS_EXTRA} & set(rig.cluster.indices)


def test_a_freeze_without_data_streams_is_refused_before_anything(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    del doc["elastic"]["data_streams"]
    (rig.freeze_dir / "freeze.yaml").write_text(yaml.safe_dump(doc))
    rig.launch_module
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, _NOT_A_REFUSAL + (AssertionError,)), repr(caught.value)
    _no_lab_traffic(rig)
    assert rig.rows() == [] and "frozen-engine" not in rig.store.records
