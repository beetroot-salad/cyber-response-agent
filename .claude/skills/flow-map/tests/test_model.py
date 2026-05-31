"""model.py — schema invariants: dedup, enrichment-on-merge, round-trip."""
from __future__ import annotations

from flowmap.model import Edge, Gap, Graph, Node


def test_add_node_dedup_first_writer_wins():
    g = Graph()
    g.add_node(Node(id="a", kind="py-func", label="", ref="f.py:1"))
    g.add_node(Node(id="a", kind="py-func", label="later", ref="f.py:99"))
    # identity is stable; ref of the first writer is kept
    assert len(g.nodes) == 1
    assert g.nodes["a"].ref == "f.py:1"
    # but an empty label is enriched by a later non-empty one
    assert g.nodes["a"].label == "later"


def test_add_node_does_not_overwrite_existing_label():
    g = Graph()
    g.add_node(Node(id="a", kind="py-func", label="first"))
    g.add_node(Node(id="a", kind="py-func", label="second"))
    assert g.nodes["a"].label == "first"


def test_add_edge_dedup_on_src_dst_kind():
    g = Graph()
    g.add_edge(Edge("a", "b", "calls", ref="x:1"))
    g.add_edge(Edge("a", "b", "calls", ref="x:2"))   # same triple -> dropped
    g.add_edge(Edge("a", "b", "dispatches", ref="x:3"))  # different kind -> kept
    assert len(g.edges) == 2


def test_site_significant_edges_keep_distinct_sites():
    """Two dispatches between the same endpoints at different lines are two
    facts — losing one would be a drift blind spot."""
    g = Graph()
    g.add_edge(Edge("s", "d", "dispatches", ref="f.md:282", via="skill-marker"))
    g.add_edge(Edge("s", "d", "dispatches", ref="f.md:461", via="skill-marker"))
    assert len({e.ref for e in g.edges}) == 2


def test_relationship_edges_still_dedup_by_endpoints():
    """calls is a relationship, not a site — one arrow regardless of call count."""
    g = Graph()
    g.add_edge(Edge("s", "d", "calls", ref="f.py:5"))
    g.add_edge(Edge("s", "d", "calls", ref="f.py:9"))
    assert len(g.edges) == 1


def test_round_trip_preserves_everything():
    g = Graph(built_from={"root": "/r"})
    g.add_node(Node(id="a", kind="py-func", label="L", ref="f.py:1",
                    sections=["s1"], signals={"decision_density": 3}))
    g.add_edge(Edge("a", "b", "calls", ref="f.py:5", via="ast",
                    confidence="deterministic", resolved_by="seed"))
    g.add_node(Node(id="b", kind="script", ref="t.py:1"))
    g.gaps.append(Gap("dynamic-dispatch", "f.py:9", "detail here"))

    g2 = Graph.from_dict(g.to_dict())
    assert g2.nodes["a"].signals == {"decision_density": 3}
    assert g2.nodes["a"].sections == ["s1"]
    assert g2.edges[0].via == "ast"
    assert g2.edges[0].confidence == "deterministic"
    assert g2.gaps[0].kind == "dynamic-dispatch"
    assert g2.built_from == {"root": "/r"}


def test_to_dict_has_schema_version():
    assert Graph().to_dict()["schema_version"] == 1
