"""Deterministic component card for a built graph (no LLM).

The graph is the universe; a question scopes a *view* into it. The LLM's only job
is to choose the Intent (see intent.py); given an Intent, the view is reproducible.

This module owns the component-card mode — one node in focus: its own identity
(label/ref) + who reaches it (inbound callers/dispatchers) + what it reaches
(outbound, grouped by edge kind). It answers "how does X work" for a single
component. The subsystem-map mode is rendered by the branch-aware logic view
(logic.py), not here.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Graph


@dataclass
class ScopeResult:
    graph: Graph                 # the scoped sub-graph (a real Graph, renderable)
    collapsed: int               # reserved: nodes hidden from the view (0 for a card)
    seed_id: str
    mode: str                    # "component-card"


def _out_edges(g: Graph, nid: str) -> list:
    return [e for e in g.edges if e.src == nid]


def _in_edges(g: Graph, nid: str) -> list:
    return [e for e in g.edges if e.dst == nid]


def _subgraph(g: Graph, keep: set[str]) -> Graph:
    sub = Graph(built_from=dict(g.built_from))
    for nid in keep:
        if nid in g.nodes:
            sub.nodes[nid] = g.nodes[nid]
    for e in g.edges:
        if e.src in keep and e.dst in keep:
            sub.add_edge(e)
    return sub


def component_card(g: Graph, node_id: str) -> ScopeResult:
    """Focus one node: it + its inbound callers + its outbound targets."""
    if node_id not in g.nodes:
        raise ValueError(f"node {node_id!r} not in the graph")
    keep = {node_id}
    keep |= {e.src for e in _in_edges(g, node_id)}
    keep |= {e.dst for e in _out_edges(g, node_id)}
    return ScopeResult(graph=_subgraph(g, keep), collapsed=0,
                       seed_id=node_id, mode="component-card")


def render_card_markdown(g: Graph, node_id: str) -> str:
    """A textual contract card for a single node, alongside its local sub-graph.

    Source-faithful: every line is read from the graph (which is ref-backed), so
    the card cannot drift from the code it describes.
    """
    n = g.nodes[node_id]
    bare = node_id.split("::")[-1].split("/")[-1]
    lines = [f"### {bare}", ""]
    if n.label:
        lines.append(f"{n.label}")
        lines.append("")
    lines.append(f"- **defined at** `{n.ref}`")
    if n.signals.get("decision_density"):
        lines.append(f"- **branches** {n.signals['decision_density']} "
                     "(if/for/while/try/match)")

    callers = sorted({e.src.split("::")[-1].split("/")[-1] for e in _in_edges(g, node_id)})
    if callers:
        lines.append(f"- **called by** {', '.join(f'`{c}`' for c in callers)}")

    out = _out_edges(g, node_id)
    by_kind: dict[str, list[str]] = {}
    for e in out:
        tgt = e.dst.split("::")[-1].split("/")[-1]
        tag = e.kind if e.via not in ("dynamic-import", "module-attr") else e.via
        by_kind.setdefault(tag, []).append(tgt)
    if out:
        lines.append("- **reaches**")
        for tag in sorted(by_kind):
            tgts = ", ".join(f"`{t}`" for t in sorted(set(by_kind[tag])))
            lines.append(f"  - _{tag}_ → {tgts}")
    return "\n".join(lines)
