"""#1347 r6.4.5: make-a-case refuses a schema-drift it cannot verify.

Design: Amendment r6.4.5, "Make-a-case refuses an unverifiable schema-drift". A schema-drift overlay is refused
(refused before anything, A2) when an in-span alert of the copy names, in `kibana.alert.ancestors`, a concrete index
that the copy does not hold and whose data stream (from its backing-index name) matches the mutation's stream: its
derived alerts could not be found by ancestry. An ancestor naming a pattern, or `''`, does not trigger it.

Refused before anything: no case, no alert.json, no overlay write (only the restore, which the check needs: it reads the copy),
the lock free, the marker dirty.
"""
from __future__ import annotations

import pytest
from _lab_fakes import AUTH, SCHEMA_DRIFT, LabRig, alert_doc, expected_variant
from test_1347_make_case import _NOT_A_REFUSAL, _drift_profiles, _overlay

MISSING_AUTH = ".ds-logs-system.auth-default-2026.09.30-000013"      # a backing index of the auth stream the copy lacks
MISSING_SYSLOG = ".ds-logs-system.syslog-default-2026.09.30-000013"
IN_SPAN, BEFORE_SPAN = "2026-10-20T08:15:00Z", "2026-10-20T06:30:00Z"


def _alert(at: str, ancestors: tuple) -> dict:
    return {"suspect": alert_doc("suspect", at, ancestors=ancestors, port=40500)}


def _refused(rig, tmp_path, overlay="drift-test"):
    rig.make_module
    with pytest.raises(Exception) as caught:
        rig.write_case("young", _overlay(overlay), profiles_dir=_drift_profiles(tmp_path))
    assert not isinstance(caught.value, _NOT_A_REFUSAL + (AssertionError, NotImplementedError)), repr(caught.value)
    _only_the_restore_and_dirty(rig)
    assert not (rig.case_dir / "case.yaml").exists() and not (rig.case_dir / "alert.json").exists()
    assert "frozen-engine" not in rig.store.records


def _only_the_restore_and_dirty(rig):
    """r6.4.5: the check reads the restored copy, so it runs after the restore and before any overlay write: the
    only cluster mutation is the restore, and the marker stays dirty."""
    assert [m["kind"] for m in rig.cluster.mutations] == ["restore"], rig.cluster.mutations
    assert rig.marker() is not None and rig.marker().get("dirty") is True, rig.marker()


def test_a_launch_of_a_case_whose_drift_is_unverifiable_on_the_copy_is_refused_with_no_row(tmp_path):
    rig = LabRig(tmp_path, extra_alerts=_alert(IN_SPAN, (("auth-77", MISSING_AUTH),)))
    rig.write_expected_case("drift")
    with pytest.raises(Exception) as caught:
        rig.launch()

    assert not isinstance(caught.value, _NOT_A_REFUSAL + (AssertionError, NotImplementedError)), repr(caught.value)
    assert rig.rows() == [] and "run" not in rig.journal.ops()
    _only_the_restore_and_dirty(rig)
    assert "frozen-engine" not in rig.store.records, "the engine lock is still held after the refusal"


@pytest.mark.parametrize("extra", [
    pytest.param(_alert(BEFORE_SPAN, (("auth-77", MISSING_AUTH),)), id="outside-span"),
    pytest.param(_alert(IN_SPAN, (("auth-25", AUTH),)), id="held-index"),
])
def test_a_launch_whose_alert_is_not_unverifiable_still_gives_a_valid_row(tmp_path, extra):
    rig = LabRig(tmp_path, extra_alerts=extra)
    rig.write_variant_case(SCHEMA_DRIFT, state=expected_variant(SCHEMA_DRIFT, extra_alerts=extra))

    rig.launch()

    assert [r["verdict"] for r in rig.rows()] == ["valid"], rig.rows()
    assert "frozen-engine" not in rig.store.records


@pytest.mark.parametrize("ancestor", [
    pytest.param(("auth-77", MISSING_AUTH), id="concrete-index-of-the-stream-the-copy-lacks"),
    pytest.param(("auth-12", MISSING_AUTH), id="the-id-an-event-of-the-copy-has"),
])
def test_an_in_span_alert_naming_a_missing_backing_index_of_the_drifted_stream_refuses_the_drift(tmp_path, ancestor):
    rig = LabRig(tmp_path, extra_alerts=_alert(IN_SPAN, (ancestor,)))

    _refused(rig, tmp_path)


def test_it_is_refused_whichever_of_several_ancestors_names_the_missing_index(tmp_path):
    rig = LabRig(tmp_path, extra_alerts=_alert(IN_SPAN, (("auth-25", "logs-system.auth-*"), ("auth-77", MISSING_AUTH))))

    _refused(rig, tmp_path)


@pytest.mark.parametrize("control, extra", [
    pytest.param("same-alert-outside-the-span", _alert(BEFORE_SPAN, (("auth-77", MISSING_AUTH),)), id="outside-span"),
    pytest.param("pattern-ancestor-with-an-id-no-event-has", _alert(IN_SPAN, (("no-such-event", "logs-system.auth-*"),)),
                 id="pattern"),
    pytest.param("ancestor-index-empty", _alert(IN_SPAN, (("syn-1", ""),)), id="empty-index"),
    pytest.param("missing-index-of-another-stream", _alert(IN_SPAN, (("syslog-77", MISSING_SYSLOG),)), id="other-stream"),
    pytest.param("a-held-concrete-index", _alert(IN_SPAN, (("auth-25", AUTH),)), id="held-index"),
    pytest.param("a-missing-index-of-no-stream", _alert(IN_SPAN, (("x-1", "some-plain-index-2026"),)), id="plain-index"),
])
def test_controls_that_are_not_unverifiable_make_the_drift_case(tmp_path, control, extra):
    rig = LabRig(tmp_path, extra_alerts=extra)
    rig.make_module

    with rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path)):
        assert (rig.case_dir / "case.yaml").exists(), control


@pytest.mark.parametrize("overlay", ["data-drop-syslog", "cmdb-stale-owner", None])
def test_the_same_alert_does_not_refuse_a_data_drop_a_cmdb_or_a_plain_case(tmp_path, overlay):
    rig = LabRig(tmp_path, extra_alerts=_alert(IN_SPAN, (("auth-77", MISSING_AUTH),)))
    rig.make_module

    with rig.write_case("young", None if overlay is None else _overlay(overlay), profiles_dir=_drift_profiles(tmp_path)):
        assert (rig.case_dir / "case.yaml").exists()

