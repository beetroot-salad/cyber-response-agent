"""#947 — the three demands that need a real Elasticsearch cluster (F3).

Every test here carries `@pytest.mark.live` and is EXCLUDED from the default CI selection
(`-m "not llm and not live"`, the project profile's `gate.test`). That is not a softening: it is
the honest state of three claims this run could not close.

* **C19 — one alias composes base minus exclude plus inject.** Probed live against the
  playground on 2026-08-22 and it HOLDS; the probe indices were removed afterwards, so it is
  re-executable only against a live cluster.
* **C20 — a T0-bounded query and the document that arrives after T0.** NEVER EXECUTED. The
  added half — whether a document timestamped EXACTLY at the bound is inside or outside the
  window — was **decided without a probe at the §7 seam and is flagged for revisit the first
  time a real cluster is available**. The reading taken is INCLUSIVE, asserted by the review.
* **PO-J1 / PO-C25 — the alias's own answering behaviour.** Whether a search through an alias
  spanning a base index and an injection index that share a document id returns one hit or two,
  and whether an alias-wide filter silently removes a world's own injection, are both unprobed.
  They gate how the reachability count may be read at all, and the collision test below drives
  BOTH: a colliding id and a world whose exclusion matches the document it injected. A fixture
  whose filter cannot match its own injection observes only the first.

Executed at this base: `docker ps` lists only the devcontainer and `curl -s -m 3
localhost:9200` returns nothing (X12/G21) — exit 7, no cluster. So these were written against
the design and the 2026-08-22 probe rather than against an observation, and each says so.
"""
from __future__ import annotations

import pytest

from defender.tests import _triplet_947 as T

pytestmark = pytest.mark.live

TOKEN_B = T.world_token("b")
VIEW = f"wv-{TOKEN_B}-logs-"
INJECT = f"{VIEW}.inject"


@pytest.fixture
def cluster():
    """A reachable playground, or a skip that names why — never a fake standing in for one."""
    door = T.mod("learning.branch.staging").write_door_from_env()
    if door is None:
        pytest.skip("no Elasticsearch cluster is reachable; set the playground's write door")
    return door


def test_947_live_alias_serves_base_minus_exclude_plus_inject(cluster, tmp_path):
    """One staged alias serves the base corpus minus the world's exclusion plus its injection:
    a query through the view returns the base documents the predicate did not remove together
    with every injected document, and the same query through the base pattern returns neither
    the injection nor the effect of the exclusion."""
    ep = T.episode(tmp_path)
    staging = T.mod("learning.branch.staging")
    world = T.mod("runtime.branch._family").parse_world(T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[{"_id": "inj-1", "process": {"name": "sshd"}}],
                                  exclude={"term": {"process.name": "nc"}}))))
    staging.stage_world(world, episode_dir=ep, episode_token=T.EPISODE_TOKEN,
                        configured_patterns=T.CONFIGURED, door=cluster)
    try:
        through_view = cluster.count(VIEW, query={"match_all": {}})
        base_total = cluster.count(T.EVENTS_PATTERN, query={"match_all": {}})
        excluded = cluster.count(T.EVENTS_PATTERN, query={"term": {"process.name": "nc"}})
        assert through_view == base_total - excluded + 1
        assert cluster.count(VIEW, query={"term": {"process.name": "nc"}}) == 0
        assert cluster.count(T.EVENTS_PATTERN, query={"ids": {"values": ["inj-1"]}}) == 0
    finally:
        staging.teardown(ep, door=cluster)


def test_947_an_injected_document_outside_the_t0_window_is_invisible(cluster, tmp_path):
    """A document whose timestamp is after the episode's own T0 is invisible to the
    discriminating envelope, and one timestamped EXACTLY at T0 is INSIDE the window — the bound
    is inclusive. THE INCLUSIVE READING WAS DECIDED WITHOUT A PROBE and is what this test is for:
    the first run against a real cluster settles it, and a red here is the answer, not a
    regression."""
    ep = T.episode(tmp_path)
    staging = T.mod("learning.branch.staging")
    docs = [{"_id": "before", "@timestamp": "2026-07-28T16:18:44Z"},
            {"_id": "at", "@timestamp": T.AS_OF},
            {"_id": "after", "@timestamp": "2026-07-28T16:18:46Z"}]
    world = T.mod("runtime.branch._family").parse_world(
        T.world_doc("b", ov=T.overlay(elastic=T.elastic_overlay(inject=docs))))
    staging.stage_world(world, episode_dir=ep, episode_token=T.EPISODE_TOKEN,
                        configured_patterns=T.CONFIGURED, door=cluster)
    try:
        bounded = {"range": {"@timestamp": {"lte": T.AS_OF}}}
        assert cluster.count(VIEW, query={"bool": {"must": [bounded, {"ids": {
            "values": ["after"]}}]}}) == 0
        assert cluster.count(VIEW, query={"bool": {"must": [bounded, {"ids": {
            "values": ["at"]}}]}}) == 1
    finally:
        staging.teardown(ep, door=cluster)


def test_947_an_alias_spanning_a_colliding_document_id_answers_once_per_index(cluster, tmp_path):
    """Two unprobed alias facts, each one an observation this test EXISTS to record rather than
    a behaviour it predicts. PO-J1: an alias spanning a base index and an injection index that
    share a document id answers with one hit PER INDEX rather than collapsing them. PO-C25: a
    world whose own alias-wide exclusion MATCHES its own injected document still serves that
    document — if it does not, the filter silently deletes the world's own injection and
    `injection_unreachable_rejects` rejects every world whose predicate overlaps its own
    documents. A red on either is the answer, not a regression."""
    ep = T.episode(tmp_path)
    staging = T.mod("learning.branch.staging")
    family = T.mod("runtime.branch._family")
    colliding = cluster.any_base_document_id(T.EVENTS_PATTERN)
    world = family.parse_world(T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[{"_id": colliding, "process": {"name": "sshd"}}],
                                  exclude={"term": {"process.name": "nc"}}))))
    # PO-C25's world: the exclusion's own term is what its injected document carries.
    self_excluding = family.parse_world(T.world_doc("c", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[{"_id": "self-excluded", "process": {"name": "nc"}}],
                                  exclude={"term": {"process.name": "nc"}}))))
    for w in (world, self_excluding):
        staging.stage_world(w, episode_dir=ep, episode_token=T.EPISODE_TOKEN,
                            configured_patterns=T.CONFIGURED, door=cluster)
    try:
        assert cluster.count(VIEW, query={"ids": {"values": [colliding]}}) == 2
        assert cluster.count(INJECT, query={"ids": {"values": [colliding]}}) == 1
        own = T.mod("scripts.adapters.confinement").world_view(
            T.EVENTS_PATTERN, T.world_token("c"))
        assert cluster.count(f"{own}.inject",
                             query={"ids": {"values": ["self-excluded"]}}) == 1
        assert cluster.count(own, query={"ids": {"values": ["self-excluded"]}}) == 1, (
            "the world's alias-wide exclusion removed its own injection — PO-C25 answered NO, "
            "and injection_unreachable_rejects then rejects every self-overlapping world")
    finally:
        staging.teardown(ep, door=cluster)
