"""#1347 r6.4.6 patches (Amendment r6.4.6, "Patches"), lab side: the data-drop's scratch index; the launcher's row append."""
from __future__ import annotations

import json
import os

import pytest
from _lab_fakes import ALERTS, SYSLOG, LabRig, canonical_digest, expected_copy, world_content
from test_1347_make_case import _drift_profiles, _overlay
from test_1347_pit_walk import _bulk_rig, _run, _syslog_bulk  # noqa: F401


@pytest.mark.parametrize("entry", ["launch", "make-a-case"])
def test_a_data_drops_scratch_index_is_created_with_dynamic_false_before_the_reindex(tmp_path, entry):
    """Live: a scratch index the reindex creates gets dynamic mappings and Elasticsearch's 1000-field limit, which
    a stream of many distinct fields passes. Only `_id` is read back from the scratch index, so it is created first
    with `dynamic: false`. The world's dropped stream holds more than 1000 distinct fields."""
    rig, bulk, state = _bulk_rig(tmp_path, entry, wide=True)
    held = _run(rig, entry, tmp_path)
    try:
        fields = {k for d in {**world_content()[SYSLOG], **bulk}.values() for k in d["_source"]}
        assert len(fields) > rig.cluster.total_fields_limit
        assert rig.cluster.refused == [], rig.cluster.refused[:2]
        assert rig.cluster.state() == state
        assert rig.cluster.auto_created == [], f"the reindex created {rig.cluster.auto_created} itself"
        reqs = rig.cluster.requests
        for k, (method, path, body) in enumerate(reqs):
            if method == "POST" and path.split("?")[0] == "/_reindex":
                dest = body["dest"]["index"]
                created = [b for m, p, b in reqs[:k] if m == "PUT" and p.split("?")[0] == f"/{dest}"]
                assert created and created[-1]["mappings"]["dynamic"] in (False, "false"), (dest, created)
    finally:
        if held is not None:
            held.release()


def test_the_scratch_index_the_fake_makes_for_a_reindex_follows_the_field_limit_live_has(tmp_path):
    rig = LabRig(tmp_path)
    cluster = rig.cluster
    cluster.total_fields_limit = 3
    for k in range(5):
        cluster.put("src", f"d{k}", {f"f{k}": 1})
    out = cluster.es_request("POST", "/_reindex", {"source": {"index": "src"}, "dest": {"index": "auto"}})
    assert out["failures"] and "total fields" in out["failures"][0]["cause"]["reason"] and cluster.auto_created == ["auto"]
    cluster.es_request("PUT", "/made", {"mappings": {"dynamic": False}})
    out = cluster.es_request("POST", "/_reindex", {"source": {"index": "src"}, "dest": {"index": "made"}})
    assert out["failures"] == [] and out["created"] == 5 and cluster.auto_created == ["auto"]


@pytest.fixture
def open_umask():
    """Umask 0: a file made with `open(..., "ab")` is 0666; one made the way `defender._io.append_jsonl` makes it
    asks for 0644 itself."""
    old = os.umask(0)
    yield
    os.umask(old)


def test_the_launchers_new_index_file_is_made_the_way_append_jsonl_makes_it(tmp_path, open_umask):
    """r6.4.6 patch (finding 10): the row append goes through `defender._io.append_jsonl`, whose new file asks for
    0644 whatever the umask is."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    assert not rig.index.exists()
    rig.launch()

    assert (rig.index.stat().st_mode & 0o777) == 0o644
    assert [r["verdict"] for r in rig.rows()] == ["valid"]


def test_a_torn_last_line_of_the_index_is_still_ended_before_the_next_row(tmp_path):
    """Regression guard, not a new demand: the launcher already ends a torn last line before appending, and moving the
    append onto `append_jsonl` must keep that."""
    rig = LabRig(tmp_path)
    rig.write_expected_case("none")
    rig.index.write_text(json.dumps({"slug": "older", "verdict": "valid"}) + "\n" + '{"slug": "torn", "ver')
    rig.launch()

    lines = rig.index.read_text().splitlines()
    assert json.loads(lines[0])["slug"] == "older" and lines[1] == '{"slug": "torn", "ver'
    assert json.loads(lines[2])["verdict"] == "valid" and len(lines) == 3


def test_there_is_one_canonical_digest_and_it_is_the_held_out_scorers():
    """r6.4.6 patch "one digest owner": the canonical-JSON digest is `evaluations.held_out.digest`; the lab's
    `frozen_copy` keeps no digest function of its own. (A regression guard where the code already complies.)"""
    import sys
    from pathlib import Path
    scripts = str(Path(__file__).resolve().parents[1])
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import frozen_copy
    from evaluations import held_out

    assert not hasattr(frozen_copy, "digest_of")
    for doc in ({"b": [1, 2], "a": {"z": None, "y": "\u00e9"}}, [], "x", world_content()[SYSLOG]):
        assert held_out.digest(doc) == canonical_digest(doc)


def test_the_digest_make_a_case_records_is_the_held_out_scorers_digest_of_the_same_document(tmp_path):
    from evaluations import held_out

    rig = LabRig(tmp_path)
    with rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path)):
        alert = expected_copy("drift")[ALERTS]["id-young"][1]
        assert rig.case()["alert"] == held_out.digest(alert)
        assert held_out.digest(json.loads((rig.case_dir / "alert.json").read_text())) == rig.case()["alert"]
