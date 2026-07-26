"""Pins for the generator's alert-selection rule (#711).

Only the pure selection logic is covered here — firing a scenario, running an
investigation and measuring controls are all I/O against a live stack.

This is the piece that produced the campaign's one silently-wrong case: with
baseline generators deliberately left running, unrelated alerts fire during the
capture window, and the generator took one about a different host. A case built
that way binds a story to an envelope its activity never touched.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


GEN = _load("oracle_golden_generate_case", GOLDEN_DIR / "generate_case.py")


class _FakeES:
    """Stands in for the one `es.sh` call `rules_fired_since` makes."""

    def __init__(self, hits: list[dict], returncode: int = 0) -> None:
        self.payload = json.dumps({"hits": {"hits": [{"_source": h} for h in hits]}})
        self.returncode = returncode
        self.stdout = self.payload

    def __call__(self, *_args, **_kwargs):
        return self


def _rules(hits, target_host, *, returncode=0):
    """`rules_fired_since` with its transport injected — no live stack, no patching."""
    return GEN.rules_fired_since(GEN.datetime.now(GEN.UTC), target_host,
                                 run=_FakeES(hits, returncode))


def test_an_alert_on_the_target_host_comes_first():
    """The whole point: with baseline running, an unrelated alert can be newer
    than the cell's own. Ordering by target host is what stops the generator
    binding a story about web-1 to an envelope about db-1."""
    assert _rules([
        {"kibana.alert.rule.rule_id": "unrelated-baseline", "host.name": "db-1"},
        {"kibana.alert.rule.rule_id": "ours", "host.name": "web-1"},
    ], "web-1")[0] == "ours"


def test_off_target_rules_are_still_offered_after_the_on_target_ones():
    """Preference, not exclusion — a cell whose own rule has not landed yet can
    still be captured, and the write-up says such a case must be read as a
    negative control rather than a capture of that cell."""
    assert _rules([
        {"kibana.alert.rule.rule_id": "elsewhere", "host.name": "db-1"},
    ], "web-1") == ["elsewhere"]


def test_a_nested_host_field_is_read():
    """Real alert docs carry `host.name` both flattened and nested; the seed
    fixtures show both shapes in one index."""
    assert _rules([
        {"kibana.alert.rule.rule_id": "nested", "host.name": {"name": "web-2"}},
        {"kibana.alert.rule.rule_id": "other", "host.name": "db-1"},
    ], "web-2")[0] == "nested"


def test_a_list_valued_host_field_is_read():
    assert _rules([
        {"kibana.alert.rule.rule_id": "listed", "host.name": ["web-2", "web-1"]},
    ], "web-2") == ["listed"]


def test_duplicate_rule_ids_collapse():
    """A threshold rule fires many alerts; the generator wants each rule once."""
    assert _rules([
        {"kibana.alert.rule.rule_id": "same", "host.name": "web-1"},
        {"kibana.alert.rule.rule_id": "same", "host.name": "web-1"},
        {"kibana.alert.rule.rule_id": "same", "host.name": "db-1"},
    ], "web-1") == ["same"]


def test_no_alerts_means_no_candidates():
    """Distinct from "a rule fired but we could not project it" — a cell that
    trips nothing has no captured envelope, and that is a real outcome."""
    assert _rules([], "web-1") == []


def test_a_failed_query_yields_no_candidates_rather_than_raising():
    """One transient ES failure must not abort a 10-minute poll."""
    hits = [{"kibana.alert.rule.rule_id": "x", "host.name": "web-1"}]
    assert _rules(hits, "web-1", returncode=1) == []


def test_a_hit_with_no_rule_id_is_skipped():
    assert _rules([
        {"host.name": "web-1"},
        {"kibana.alert.rule.rule_id": "real", "host.name": "web-1"},
    ], "web-1") == ["real"]
