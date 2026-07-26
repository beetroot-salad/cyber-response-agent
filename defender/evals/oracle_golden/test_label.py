"""Pins for the mechanical labeler (#711 M4/M9).

Every rule here was written because getting it wrong produced a WRONG GROUND
TRUTH during the M9a audit — and a wrong ground truth is worse than a wrong
oracle, because it is the thing the oracle is measured against. Four of these
pin defects the audit actually caught on the seed six.

The labeler's most important property is that it ABSTAINS. `needs-label` is not
a failure mode; it is the difference between "the activity touched nothing here"
and "no comparison this program can make decides it", and collapsing those two
is how a labeler biases every case the same way at once.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


LABEL = _load("oracle_golden_label", GOLDEN_DIR / "label.py")

STATS_Q = ('FROM logs-system.auth-*\n| WHERE host.name == "canary-1"\n'
           "| STATS n = COUNT(*) BY source.ip, user.name")
BARE_AGG_Q = 'FROM logs-system.auth-*\n| WHERE host.name == "x"\n| STATS total = COUNT(*)'
DOC_Q = ('FROM logs-falco.alerts-*\n| WHERE falco.rule == "r"\n'
         "| KEEP @timestamp, falco.rule, `falco.output_fields.fd.name`")


def _payload(values, columns=None):
    names = columns or (list(values[0]) if values else [])
    return {"query": "", "columns": [{"name": n} for n in names],
            "row_count": len(values), "values": values}


def _rowset_json(values, columns=None):
    import json
    return json.dumps(_payload(values, columns))


def _control(values, *, live=True, query=STATS_Q):
    return {"name": "C", "query": query, "live": live, "payload": _payload(values)}


# --------------------------------------------------------------------------
# the four classes
# --------------------------------------------------------------------------

def test_a_row_no_control_carries_is_plus_event():
    got = LABEL.query_class(
        _rowset_json([{"n": 9, "source.ip": "10.0.0.1", "user.name": "root"}]),
        [_control([])], query=STATS_Q)
    assert got == LABEL.PLUS_EVENT


def test_a_row_the_baseline_also_carries_is_plus_noise():
    """case-004: a routine `sre.alice` login on its habitual path must not read as
    a catch. `+noise` is EXISTENTIAL — seeing the row in any control window is
    evidence the instance is routine."""
    got = LABEL.query_class(
        _rowset_json([{"n": 5, "source.ip": "10.0.0.9", "user.name": "sre.alice"}]),
        [_control([]), _control([{"n": 6, "source.ip": "10.0.0.9",
                                  "user.name": "sre.alice"}])],
        query=STATS_Q)
    assert got == LABEL.PLUS_NOISE


def test_empty_against_a_consistently_present_baseline_is_minus_noise():
    got = LABEL.query_class(
        _rowset_json([]),
        [_control([{"n": 3, "source.ip": "a", "user.name": "b"}]),
         _control([{"n": 4, "source.ip": "a", "user.name": "b"}])],
        query=STATS_Q)
    assert got == LABEL.MINUS_NOISE


def test_empty_against_an_intermittent_baseline_is_zero_not_suppression():
    """The error this prevents is the one the SUITE EXISTS TO CATCH in the oracle:
    inferring suppression from absence. case-003's web-1 lead is empty in-window
    and has a baseline in one of three control windows — and web-1's agent was
    never touched. `-noise` is a universal claim, so every live control window
    must carry the stream."""
    got = LABEL.query_class(
        _rowset_json([]),
        [_control([]), _control([{"n": 3, "source.ip": "a", "user.name": "b"}])],
        query=STATS_Q)
    assert got == LABEL.ZERO


def test_empty_either_way_is_zero():
    assert LABEL.query_class(_rowset_json([]), [_control([])], query=STATS_Q) == LABEL.ZERO


# --------------------------------------------------------------------------
# the things it must refuse to decide
# --------------------------------------------------------------------------

def test_a_zero_byte_payload_is_errored_not_empty():
    """`query_tool.py` writes "" on a non-zero exit. Reading that as an empty
    result would turn a broken query into evidence of absence."""
    assert LABEL.query_class("", [_control([])], query=STATS_Q) == LABEL.ERRORED


def test_no_control_means_needs_label_not_a_guess():
    assert LABEL.query_class(_rowset_json([{"n": 1, "source.ip": "a", "user.name": "b"}]),
                             None, query=STATS_Q) == LABEL.NEEDS_LABEL


def test_a_dead_control_window_is_not_an_empty_baseline():
    """A window in a lever-down gap returns zero rows for every query. Counting it
    as an empty baseline suppressed case-003's real `-noise`."""
    got = LABEL.query_class(
        _rowset_json([]),
        [_control([], live=False),
         _control([{"n": 3, "source.ip": "a", "user.name": "b"}])],
        query=STATS_Q)
    assert got == LABEL.MINUS_NOISE


def test_a_state_system_is_never_defaulted_to_zero():
    assert LABEL.query_class(_rowset_json([]), [_control([])],
                             system="cmdb") == LABEL.STATE
    assert LABEL.declared_state_class({}, "cmdb") == LABEL.NEEDS_LABEL
    assert LABEL.declared_state_class({"state_classes": {"cmdb": "0"}}, "cmdb") == "0"


def test_a_doc_returning_query_with_no_keep_and_no_declared_key_abstains():
    """Keying on the whole ECS document includes `@timestamp` and `event.id`, so no
    attack row could ever equal a control row and EVERY such query would grade
    `+event` — a systematic bias toward manufacturing catches."""
    query = 'FROM logs-* | WHERE host.name == "x"'
    got = LABEL.query_class(
        _rowset_json([{"@timestamp": "2026-07-25T00:00:00Z", "event.id": "abc"}]),
        [_control([], query=query)], query=query)
    assert got == LABEL.NEEDS_LABEL


# --------------------------------------------------------------------------
# what makes a row "the same row"
# --------------------------------------------------------------------------

def test_the_row_key_comes_from_the_by_clause():
    assert LABEL.by_columns(STATS_Q) == ("source.ip", "user.name")
    assert LABEL.by_columns("| STATS n = COUNT(*) BY minute = DATE_TRUNC(1 minute, "
                            "@timestamp)") == ("minute",)


def test_the_row_key_falls_back_to_the_keep_clause():
    assert LABEL.keep_columns(DOC_Q) == ("@timestamp", "falco.rule",
                                         "falco.output_fields.fd.name")


def test_an_unstable_address_cannot_be_a_row_key():
    """Container addresses are reassigned on every lever-up, so a control a week
    back compares an address to a different machine and every row reads as new.
    This is the documented IP-rotation hazard, in code."""
    payload = _payload([{"n": 1, "source.ip": "172.18.0.6", "user.name": "sre.alice"}])
    assert LABEL.row_key_columns(payload, STATS_Q) == ("user.name",)


def test_a_timestamp_group_key_is_dropped():
    """A control window is at a different absolute time BY CONSTRUCTION, so keying
    on `BY minute = DATE_TRUNC(...)` makes every bucketed query a spurious
    `+event`."""
    query = "FROM x | STATS n = COUNT(*) BY minute = DATE_TRUNC(1 minute, @timestamp)"
    payload = _payload([{"n": 3, "minute": "2026-07-25T07:45:00.000Z"}])
    assert LABEL.row_key_columns(payload, query) is None


def test_a_bare_aggregate_row_of_zeros_counts_as_nothing_observed():
    """A `STATS` with no `BY` always returns exactly one row. case-001's control
    reads `total_failed: 0, first_seen: null` — `row_count == 1`, observed
    nothing."""
    empty = LABEL.distinguishing_rows(
        _payload([{"total_failed": 0, "distinct": 0, "first_seen": None}]), BARE_AGG_Q)
    assert empty == set()
    seen = LABEL.distinguishing_rows(
        _payload([{"total_failed": 95, "distinct": 1, "first_seen": "2026-07-25"}]),
        BARE_AGG_Q)
    assert seen


# --------------------------------------------------------------------------
# folding sub-queries into the lead
# --------------------------------------------------------------------------

@pytest.mark.parametrize(("classes", "expected"), [
    (["0", "+event"], "+event"),          # envelope truth is the UNION
    (["0", "+noise"], "+noise"),
    (["0", "-noise"], "-noise"),
    (["0", "0"], "0"),
    (["errored", "+event"], "+event"),    # an errored query is not an observation
    (["errored", "state"], LABEL.NEEDS_LABEL),
])
def test_lead_class_folds_to_the_strongest_delta(classes, expected):
    assert LABEL.lead_class(classes) == expected


def test_heterogeneous_is_disagreement_among_decidable_sub_queries():
    assert LABEL.is_heterogeneous(["0", "+event"]) is True
    assert LABEL.is_heterogeneous(["+event", "+event"]) is False


def test_heterogeneous_is_none_when_too_little_was_decidable():
    """"The sub-queries agree" and "we could not tell whether they agree" are
    different claims. Collapsing them lets an unmeasurable lead assert
    homogeneity."""
    assert LABEL.is_heterogeneous(["errored", "state"]) is None
    assert LABEL.is_heterogeneous(["+event"]) is None
