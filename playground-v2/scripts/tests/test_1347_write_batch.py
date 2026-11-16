"""make-a-case writes several cases of one variant from one whole restore, the content digest read once.

Each `write` restored the whole snapshot and read the digest in full (about forty minutes live) and kept the
lock through labelling, so a freeze's cases were written and labelled one at a time. `write_cases` restores
once (D23 holds: the copy is a whole restore, never a trusted marker), writes every case from it, and the
reference batch then joins its one lock. A refusal or failure of any case writes none.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from _lab_fakes import ALERTS, LabRig, canonical_digest, expected_copy

UUIDS = ["young", "derived-in", "syslog-alert"]


def _write(rig, pairs, **kw):
    mod = rig.make_module
    rig._sync_env()
    try:
        return mod, mod.write_cases(
            pairs, freeze_dir=rig.freeze_dir, overlay=None, tenant_settings=rig.tenant_settings,
            parts_dir=rig.parts, lock_store=rig.store, es=rig.ops.frozen_es(), ops=rig.ops, clock=rig.clock,
            profiles_dir=Path(__file__).resolve().parents[2] / "chaos" / "profiles",
            inventory=yaml.safe_load((Path(__file__).resolve().parents[2] / "hosts" / "inventory.yaml").read_text()),
            **kw)
    finally:
        rig._edges_modelled()


def _pits(rig, since=0):
    return sum(1 for m, p, _b in rig.cluster.requests[since:] if m == "POST" and "/_pit?" in p)


def _case(d: Path) -> dict:
    return yaml.safe_load((d / "case.yaml").read_text())


def test_one_restore_and_one_full_read_write_every_case(tmp_path):
    single = LabRig(tmp_path / "single")
    with single.write_case("young", None):
        pass
    one_case_reads = _pits(single)

    rig = LabRig(tmp_path / "batch")
    dirs = [tmp_path / f"case-{u}" for u in UUIDS]
    _mod, held = _write(rig, list(zip(dirs, UUIDS)))
    try:
        assert rig.cluster.restores == 1
        assert _pits(rig) == one_case_reads
        state = expected_copy("none")
        for d, u in zip(dirs, UUIDS):
            case = _case(d)
            assert case["alert"] == canonical_digest(state[ALERTS][f"id-{u}"][1])
            assert case["content"] == rig.expected_content(state, None)
            assert case["confirmed"] is None
        assert rig.store.records.get("frozen-engine")
    finally:
        held.release()


def test_a_non_candidate_among_them_is_refused_before_the_lock_and_writes_none(tmp_path):
    rig = LabRig(tmp_path)
    dirs = [tmp_path / "case-young", tmp_path / "case-future"]
    with pytest.raises(Exception, match="not a candidate"):
        _write(rig, list(zip(dirs, ["young", "future"])))
    assert not any(d.exists() for d in dirs)
    assert "lock.create" not in rig.journal.ops()


def test_a_case_that_fails_after_the_restore_writes_none_of_them_and_frees_the_lock(tmp_path):
    rig = LabRig(tmp_path)
    dirs = [tmp_path / f"case-{u}" for u in UUIDS]
    dirs[2].mkdir()
    (dirs[2] / "alert.json").write_text('{"not": "the copy\'s alert"}')
    with pytest.raises(Exception, match="not the copy's alert"):
        _write(rig, list(zip(dirs, UUIDS)))
    assert not dirs[0].exists() and not dirs[1].exists()
    assert not (dirs[2] / "case.yaml").exists()
    assert "frozen-engine" not in rig.store.records


def test_one_dir_named_twice_is_refused(tmp_path):
    rig = LabRig(tmp_path)
    d = tmp_path / "case-young"
    with pytest.raises(Exception, match="twice"):
        _write(rig, [(d, "young"), (d, "derived-in")])
    assert "lock.create" not in rig.journal.ops()
