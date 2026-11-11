"""#1347 r6.4.5 "The copy's indices come from cluster metadata" (`GET /_cluster/state/metadata`), never `_cat/indices`.

Live (ES 9.3.3): `_cat/indices` leaves out failure-store indices (`.fs-...`) even when named, yet `_count` on one answers;
the metadata call lists every index, those and the node's own system indices (`.security-7`) included. The world's
freeze holds one failure-store index (`_lab_fakes.FAILURE_STORE`, three documents before T, in the freeze's counts).
Reuse means the copy holds every freeze index, all open, and no other index the patterns or a scratch name match.
"""
from __future__ import annotations

import re

import pytest
from _lab_fakes import FAILURE_STORE, NGINX, FakeGap, LabRig, world_content
from test_1347_inplace import _cluster


def test_the_fake_never_lists_a_failure_store_index_in_cat_indices_but_counts_and_lists_it_in_metadata():
    cluster = _cluster()
    filt = "metadata.indices.*.state,metadata.indices.*.settings.index.uuid"

    assert FAILURE_STORE in cluster.indices
    for expr in ("", "/*", f"/{FAILURE_STORE}", "/logs-*"):
        listed = {r["index"] for r in cluster.es_request("GET", f"/_cat/indices{expr}?expand_wildcards=all")}
        assert FAILURE_STORE not in listed, expr
    assert cluster.es_request("GET", f"/{FAILURE_STORE}/_count")["count"] == 3
    meta = cluster.es_request("GET", f"/_cluster/state/metadata?filter_path={filt}")["metadata"]["indices"]
    assert meta[FAILURE_STORE]["state"] == "open" and meta[FAILURE_STORE]["settings"]["index"]["uuid"]
    assert ".security-7" in meta and set(world_content()) <= set(meta)
    cluster.indices[NGINX]["closed"] = True
    assert cluster.es_request("GET", f"/_cluster/state/metadata?filter_path={filt}")[
        "metadata"]["indices"][NGINX]["state"] == "close"
    for query in ("filter_path=metadata.indices.*.state", "", f"filter_path={filt}&local=true"):
        with pytest.raises(FakeGap):
            cluster.es_request("GET", f"/_cluster/state/metadata?{query}")


def test_the_world_freeze_counts_a_failure_store_index_with_documents_before_T():
    rig_content = world_content()
    assert len(rig_content[FAILURE_STORE]) == 3 and FAILURE_STORE.startswith(".fs-")


def _two_launches(tmp_path, kind="none", between=None):
    rig = LabRig(tmp_path)
    rig.write_expected_case(kind)
    rig.launch()
    if between:
        between(rig)
    rig.launch()
    return rig


@pytest.mark.parametrize("kind", ["none", "drop", "drift"])
def test_a_clean_copy_holding_a_failure_store_index_is_reused_without_a_restore(tmp_path, kind):
    rig = _two_launches(tmp_path, kind)

    assert rig.cluster.restores == 1, "the reuse check listed the copy's indices where a failure store hides"
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert rig.cluster.state()[FAILURE_STORE] == {i: (d["_version"], d["_source"])
                                                   for i, d in world_content()[FAILURE_STORE].items()}


def test_the_copys_indices_are_read_from_metadata_and_a_system_index_is_not_the_copys(tmp_path):
    rig = _two_launches(tmp_path)

    assert rig.cluster.restores == 1 and ".security-7" not in rig.cluster.indices
    asked = [p for m, p in ((r[0], r[1]) for r in rig.cluster.requests)]
    assert any(p.startswith("/_cluster/state/metadata") for p in asked)


def test_the_content_digest_of_a_touched_failure_store_index_works(tmp_path):
    """A failure-store index named among the touched indices is digested (its documents are read through its
    name, which `_count` and `_search` answer): no 'holds no index' refusal, and the digest follows its documents."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    seen = []

    def during_the_run():      # the node is up and the stubs are loaded while the agent runs
        before = rig.ops.content_digest([FAILURE_STORE])
        rig.cluster.put(FAILURE_STORE, "failed-1", {"@timestamp": "2026-10-20T05:00:00Z", "message": "changed"})
        seen.extend([before, rig.ops.content_digest([FAILURE_STORE])])

    rig.run_hook = during_the_run
    rig.launch()

    assert re.fullmatch(r"[0-9a-f]{64}", seen[0]) and seen[1] != seen[0]


@pytest.mark.parametrize("breakage", ["missing-index", "closed-index", "extra-pattern-index"])
def test_the_reuse_check_still_refuses_a_copy_that_is_not_the_freeze(tmp_path, breakage):
    def spoil(rig):
        if breakage == "missing-index":
            del rig.cluster.indices[NGINX]
        elif breakage == "closed-index":
            rig.cluster.indices[NGINX]["closed"] = True
        else:
            rig.cluster._index("logs-extra-default")["docs"]["x"] = {"_source": {"@timestamp": "2026-10-20T05:00:00Z"},
                                                                  "_version": 1}

    rig = _two_launches(tmp_path, between=spoil)

    assert rig.cluster.restores == 2, breakage
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert "logs-extra-default" not in rig.cluster.indices and NGINX in rig.cluster.indices
