"""Pure-function tests for the PREDICT loop-1 fast-path cache lookup.

In-memory Companion fixtures — no file I/O, no Claude subprocess.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from invlang.corpus import Companion  # noqa: E402
from scripts.handlers.predict_fastpath import (  # noqa: E402
    DEFAULT_MAX_AGE_DAYS,
    DEFAULT_MIN_SUPPORT,
    build_cache_key,
    lookup,
)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


_DISC = {
    "monitoring-pattern": [
        r"^(nagios|sensu|monitor.*|probe.*|check.*|sentinel.*|testuser)$",
    ],
    "service-account": [
        r"^(svc-.*|backup-.*|cron-.*|ansible-.*|deploy-.*)$",
    ],
}


def _prologue_5710(
    *,
    src_classification: str = "internal-monitoring-host",
    user_classification: str = "monitoring-pattern",
    user_identifier: str = "nagios",
    src_identifier: str = "172.22.0.5",
    target_identifier: str = "host-001",
) -> dict[str, Any]:
    return {
        "vertices": [
            {
                "id": "v-src",
                "type": "endpoint",
                "classification": src_classification,
                "identifier": src_identifier,
            },
            {
                "id": "v-user",
                "type": "identity",
                "classification": user_classification,
                "identifier": user_identifier,
            },
            {
                "id": "v-target",
                "type": "endpoint",
                "classification": "internal-server",
                "identifier": target_identifier,
            },
        ],
        "edges": [
            {
                "id": "e-001",
                "relation": "attempted_auth",
                "source_vertex": "v-src",
                "target_vertex": "v-target",
            }
        ],
    }


def _companion(
    case_id: str,
    *,
    prologue: dict[str, Any],
    primary_lead: str,
    age_days: int = 30,
    signature_id: str = "wazuh-rule-5710",
) -> Companion:
    iso = (
        datetime.now(timezone.utc) - timedelta(days=age_days)
    ).isoformat()
    body = {
        "prologue": prologue,
        "hypothesize": {"hypotheses": []},
        "findings": [
            {
                "id": "l-1",
                "loop": 1,
                "name": primary_lead,
                "outcome": {},
            }
        ],
        "conclude": {"disposition": "benign"},
    }
    # signature_id is recovered from the path by the corpus loader; mimic the
    # real shape so the query's signature filter sees a match.
    src_path = Path(f"/runs/case-{case_id}-rule5710/investigation.md")
    if signature_id != "wazuh-rule-5710":
        # Strip the rule suffix entirely so the path-derived id is None →
        # filtered out, mimicking a different-signature companion.
        src_path = Path(f"/runs/case-{case_id}-other/investigation.md")
    return Companion(
        case_id=case_id,
        source_path=src_path,
        body=body,
        created_at=iso,
    )


# ---------------------------------------------------------------------------
# build_cache_key
# ---------------------------------------------------------------------------


def test_build_cache_key_returns_none_when_signature_not_opted_in():
    assert build_cache_key(
        signature_id="wazuh-rule-5710",
        prologue=_prologue_5710(),
        discriminating_classifications=None,
    ) is None


def test_build_cache_key_buckets_by_family_index():
    key = build_cache_key(
        signature_id="wazuh-rule-5710",
        prologue=_prologue_5710(user_identifier="nagios"),
        discriminating_classifications=_DISC,
    )
    assert key is not None
    assert ("monitoring-pattern", "family_0") in key.key_attribute_signature


def test_build_cache_key_no_match_bucket_for_off_family_identifier():
    key = build_cache_key(
        signature_id="wazuh-rule-5710",
        prologue=_prologue_5710(user_identifier="admin"),
        discriminating_classifications=_DISC,
    )
    assert key is not None
    # admin doesn't match the monitoring-pattern family → no-match bucket
    assert ("monitoring-pattern", "no-match") in key.key_attribute_signature


# ---------------------------------------------------------------------------
# lookup — exact / collision / threshold / recency / catalog
# ---------------------------------------------------------------------------


_LEAD_CATALOG = {
    "source-classification",
    "username-classification",
    "authentication-history",
    "approved-monitoring-sources",
}


def _key_and_lookup(
    corpus: list[Companion],
    *,
    user_identifier: str = "nagios",
    discriminating_classifications: dict | None = None,
    lead_catalog: set[str] | None = None,
    rng: random.Random | None = None,
):
    disc = discriminating_classifications or _DISC
    prologue = _prologue_5710(user_identifier=user_identifier)
    key = build_cache_key(
        signature_id="wazuh-rule-5710",
        prologue=prologue,
        discriminating_classifications=disc,
    )
    return lookup(
        corpus,
        key,
        prologue=prologue,
        discriminating_classifications=disc,
        lead_catalog=lead_catalog or _LEAD_CATALOG,
        rng=rng,
    )


def test_lookup_exact_match_above_threshold_picks_lead():
    corpus = [
        _companion(f"c{i}", prologue=_prologue_5710(),
                   primary_lead="approved-monitoring-sources")
        for i in range(DEFAULT_MIN_SUPPORT)
    ]
    hit, telemetry = _key_and_lookup(corpus)
    assert hit is not None
    assert hit.selected_lead == "approved-monitoring-sources"
    assert hit.selection_method == "single"
    assert telemetry["selection_method"] == "single"


def test_lookup_adversarial_collision_misses():
    """Three precedents picked the lead for `nagios`; the live alert is
    `admin` (off-family). Different cache key → miss → fall through to
    subagent."""
    corpus = [
        _companion(f"c{i}", prologue=_prologue_5710(user_identifier="nagios"),
                   primary_lead="approved-monitoring-sources")
        for i in range(DEFAULT_MIN_SUPPORT)
    ]
    hit, telemetry = _key_and_lookup(corpus, user_identifier="admin")
    assert hit is None
    # No matching companions at this cache key → empty distribution + zero
    # key-attr scope. The structured counters encode the miss mode without
    # needing a string reason field.
    assert telemetry["lead_distribution"] == {}
    assert telemetry["scoped_key_attrs"] == 0


def test_lookup_below_min_support_misses():
    corpus = [
        _companion(f"c{i}", prologue=_prologue_5710(),
                   primary_lead="approved-monitoring-sources")
        for i in range(DEFAULT_MIN_SUPPORT - 1)
    ]
    hit, telemetry = _key_and_lookup(corpus)
    assert hit is None
    # Distribution populated but no lead clears min_support → empty eligible
    # set, miss. min_support carried for diagnosability.
    assert telemetry["lead_distribution"]
    assert max(telemetry["lead_distribution"].values()) < DEFAULT_MIN_SUPPORT
    assert telemetry["min_support"] == DEFAULT_MIN_SUPPORT


def test_lookup_old_companions_excluded():
    corpus = [
        _companion(
            f"c{i}", prologue=_prologue_5710(),
            primary_lead="approved-monitoring-sources",
            age_days=DEFAULT_MAX_AGE_DAYS + 30,
        )
        for i in range(DEFAULT_MIN_SUPPORT)
    ]
    hit, telemetry = _key_and_lookup(corpus)
    assert hit is None
    assert telemetry["scoped_signature"] == DEFAULT_MIN_SUPPORT
    assert telemetry["scoped_recent"] == 0


def test_lookup_lead_not_in_current_catalog_misses():
    corpus = [
        _companion(f"c{i}", prologue=_prologue_5710(),
                   primary_lead="deprecated-lead-name")
        for i in range(DEFAULT_MIN_SUPPORT + 1)
    ]
    hit, telemetry = _key_and_lookup(corpus)
    assert hit is None
    # Distribution populated but the lead isn't in the current catalog →
    # eligible set empty after the catalog filter.
    assert telemetry["lead_distribution"] == {"deprecated-lead-name": DEFAULT_MIN_SUPPORT + 1}
    assert telemetry["min_support"] == DEFAULT_MIN_SUPPORT


def test_lookup_different_signature_excluded():
    corpus = [
        _companion(f"c{i}", prologue=_prologue_5710(),
                   primary_lead="approved-monitoring-sources",
                   signature_id="wazuh-rule-other")
        for i in range(DEFAULT_MIN_SUPPORT + 1)
    ]
    hit, telemetry = _key_and_lookup(corpus)
    assert hit is None
    assert telemetry["scoped_signature"] == 0


# ---------------------------------------------------------------------------
# Top-K weighted random
# ---------------------------------------------------------------------------


def test_lookup_weighted_pick_among_top_k():
    """5 companions chose lead-A, 4 chose lead-B, 3 chose lead-C — all
    above min_support. Weighted random picks proportionally; over many
    runs the distribution should track the weights.
    """
    corpus = (
        [_companion(f"a{i}", prologue=_prologue_5710(), primary_lead="source-classification") for i in range(5)]
        + [_companion(f"b{i}", prologue=_prologue_5710(), primary_lead="username-classification") for i in range(4)]
        + [_companion(f"c{i}", prologue=_prologue_5710(), primary_lead="authentication-history") for i in range(3)]
    )
    counts: dict[str, int] = {}
    for seed in range(200):
        rng = random.Random(seed)
        hit, _ = _key_and_lookup(corpus, rng=rng)
        assert hit is not None
        assert hit.selection_method == "weighted"
        counts[hit.selected_lead] = counts.get(hit.selected_lead, 0) + 1
    # All three should appear (probabilistically; with 200 trials very safe)
    assert set(counts.keys()) == {
        "source-classification",
        "username-classification",
        "authentication-history",
    }
    # source-classification should dominate (weight 5 of 12)
    assert counts["source-classification"] > counts["authentication-history"]


def test_lookup_weighted_seeded_deterministic():
    corpus = (
        [_companion(f"a{i}", prologue=_prologue_5710(), primary_lead="source-classification") for i in range(5)]
        + [_companion(f"b{i}", prologue=_prologue_5710(), primary_lead="username-classification") for i in range(3)]
    )
    rng = random.Random(42)
    hit1, _ = _key_and_lookup(corpus, rng=rng)
    rng = random.Random(42)
    hit2, _ = _key_and_lookup(corpus, rng=rng)
    assert hit1.selected_lead == hit2.selected_lead


# ---------------------------------------------------------------------------
# Loop-N future-proofing
# ---------------------------------------------------------------------------


def test_lookup_with_non_none_frontier_signature_misses():
    """Loop-N support is deferred — a non-None frontier_signature returns a
    miss with a structured reason rather than fabricating an answer."""
    from scripts.handlers.predict_fastpath import CacheKey

    key = CacheKey(
        signature_id="wazuh-rule-5710",
        prologue_signature={
            "vertex_types": frozenset({"endpoint"}),
            "vertex_classifications": frozenset({"x"}),
            "edge_relations": frozenset({"y"}),
        },
        key_attribute_signature=frozenset(),
        frontier_signature="some-frontier-shape",
    )
    hit, telemetry = lookup(
        [],
        key,
        prologue={},
        discriminating_classifications=_DISC,
        lead_catalog=_LEAD_CATALOG,
    )
    assert hit is None
    assert telemetry["frontier_not_supported"] is True
