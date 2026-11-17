"""The content digest is read in full once per copy, and trusted after that only while nothing could change it.

Live (freeze live-20261114): the digest walks tens of millions of documents, about half an hour, on every
launch. The agent's user holds `read` only, so after a copy is built nothing writes to it. The launcher now
write-blocks the touched indices as the build's last change, reads the digest once and records it on the
marker with the stubs' half of it. A later launch trusts the record while every touched index still carries
the block and the freshly loaded stubs fingerprint the same; anything else is a full read. Elasticsearch takes
no write into a blocked index, so an edit to the copy has to lift the block first, and the fake models that.
"""
from __future__ import annotations

import json

from _lab_fakes import STATE_VOLUME, CONTEXT, WRITE_BLOCK, LabRig, is_clean_marker


def _full_reads(rig, since: int) -> int:
    """Point-in-time views opened after request number `since`: one per touched index a digest walks."""
    return sum(1 for m, p, _b in rig.cluster.requests[since:] if m == "POST" and "/_pit?" in p)


def _launch_counting(rig, **kw) -> int:
    seen = len(rig.cluster.requests)
    rig.launch(**kw)
    return _full_reads(rig, seen)


def _rewrite_marker(rig, change) -> None:
    sid = rig.docker.volumes[(CONTEXT, STATE_VOLUME)]
    files = rig.docker.stores[sid]
    (key,) = [k for k, d in files.items() if b'"variant"' in d]
    marker = json.loads(files[key])
    change(marker)
    files[key] = json.dumps(marker).encode()


def test_a_reused_copy_is_not_read_again_and_its_launch_is_still_valid(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    assert _launch_counting(rig) > 0
    marker = rig.marker()
    assert is_clean_marker(marker) and set(marker["verified"]) == {"content", "stubs"}, marker

    assert _launch_counting(rig) == 0
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert rig.cluster.restores == 1


def test_every_touched_index_is_blocked_before_the_copy_is_trusted(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    touched = rig.marker()["touched"]
    assert touched
    assert all(rig.cluster.indices[n]["settings"].get(WRITE_BLOCK) is True for n in touched)


def test_a_lifted_block_sends_the_next_launch_back_to_a_full_read_which_blocks_again(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    lifted = rig.marker()["touched"][0]
    rig.cluster.indices[lifted]["settings"].pop(WRITE_BLOCK)

    assert _launch_counting(rig) > 0
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]
    assert rig.cluster.indices[lifted]["settings"].get(WRITE_BLOCK) is True
    assert _launch_counting(rig) == 0


def test_an_edit_behind_the_launchers_back_is_stale_even_though_a_record_exists(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    touched = rig.marker()["touched"]
    victim = sorted(rig.cluster.indices[touched[0]]["docs"])[0]
    rig.cluster.put(touched[0], victim, {"@timestamp": "2026-10-20T04:36:00Z", "message": "changed"})
    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale"]
    assert "content" in rig.rows()[1]["reason"]


def test_stubs_that_no_longer_fingerprint_the_same_are_not_trusted(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    _rewrite_marker(rig, lambda m: m["verified"].update(stubs="0" * 64))

    assert _launch_counting(rig) > 0
    assert [r["verdict"] for r in rig.rows()] == ["valid", "valid"]


def test_a_recorded_content_that_is_not_the_cases_is_stale_without_reading(tmp_path):
    # The record is only ever what a full read saw; trusting it decides the verdict as that read did.
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    _rewrite_marker(rig, lambda m: m["verified"].update(content="f" * 64))

    assert _launch_counting(rig) == 0
    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale"]


def test_a_rebuild_carries_no_record(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    rig.write_expected_case("drift")      # another variant: the copy is restored whole
    assert _launch_counting(rig) > 0
    assert rig.cluster.restores == 2
    assert rig.marker()["verified"]["content"] == rig.case()["content"]


def test_a_stale_launch_drops_the_record_and_the_next_one_restores_and_reads(tmp_path):
    rig = LabRig(tmp_path)
    rig.write_expected_case("drop")
    rig.launch()
    _rewrite_marker(rig, lambda m: m["verified"].update(content="f" * 64))
    rig.launch()                                     # stale: the marker goes dirty
    assert "verified" not in rig.marker()

    assert _launch_counting(rig) > 0
    assert rig.cluster.restores == 2
    assert [r["verdict"] for r in rig.rows()] == ["valid", "stale", "valid"]


def test_the_reference_launch_after_a_case_write_reads_nothing_again(tmp_path):
    rig = LabRig(tmp_path)
    with rig.write_case("young", None) as held:
        assert rig.marker()["verified"]["content"] == rig.case()["content"]
        assert _launch_counting(rig, reference=True, lock_token=held.token) == 0
