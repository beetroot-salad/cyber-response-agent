"""flow-map graph model — the schema everything keys off.

Generic and substrate-agnostic. Scripts mint canonical, path-derived node
IDs; subagents (later steps) may only reference IDs the seed minted, or push
a `proposed_node` into `gaps`. Every node and edge carries `ref` (path:line)
so the rendered map always traces back to source, and every edge carries
`confidence` so LLM-resolved edges can later be promoted to deterministic
seed resolvers without touching the schema.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

SCHEMA_VERSION = 1

# Edge kinds whose call SITE is load-bearing: two dispatches/subprocess/hook
# firings between the same endpoints at different lines are distinct facts (and
# losing one is a drift blind spot). For these, `ref` is part of edge identity.
# Relationship kinds (calls, uses_tool) dedup by (src, dst, kind) — one arrow.
_SITE_SIGNIFICANT = {"dispatches", "runs_command", "fires_hook",
                     "reads_template", "reads_prompt"}


def _edge_key(e) -> tuple:
    if e.kind in _SITE_SIGNIFICANT:
        return (e.src, e.dst, e.kind, e.ref)
    return (e.src, e.dst, e.kind)

# Node kinds (open vocab — these are the ones step 1 emits).
NODE_KINDS = {
    "py-func",       # a function/method defined in a parsed module
    "py-module",     # a whole module (coarse node)
    "agent-prompt",  # a *.md system prompt dispatched via claude -p
    "script",        # a *.py invoked as a subprocess
    "skill",         # a SKILL.md
    "hook",          # a registered hook script
    "tool",          # a tool grant
    "template",      # a query template
    "system",        # a system of record
}

# Edge kinds + how each is resolved.
EDGE_KINDS = {
    "calls",          # ast: local function call
    "dispatches",     # spawns an LLM agent (claude -p) with an agent-prompt
    "runs_command",   # subprocess of a script
    "fires_hook",     # event -> hook
    "uses_tool",      # agent -> tool grant
    "reads_template", # gather -> query template
    "reads_prompt",   # weaker: reads a prompt file without spawning
}


@dataclass
class Node:
    id: str                       # canonical, path-derived, stable
    kind: str
    label: str = ""
    label_source: str = ""        # "harvested" | "synthesized" | ""
    ref: str = ""                 # path:line — always resolvable
    sections: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    label: str = ""
    ref: str = ""                 # path:line of the call/dispatch site
    via: str = ""                 # ast | run_claude | subprocess | settings-hook | frontmatter
    confidence: str = "deterministic"   # deterministic | llm
    resolved_by: str = "seed"           # seed | haiku


@dataclass
class Gap:
    kind: str                     # dynamic-dispatch | unresolved-const | external-call | ...
    ref: str
    detail: str
    proposed_node: dict | None = None


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    built_from: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        cur = self.nodes.get(node.id)
        if cur is None:
            self.nodes[node.id] = node
            return
        # Merge: first writer wins on identity; later passes may enrich.
        if not cur.label and node.label:
            cur.label, cur.label_source = node.label, node.label_source
        if not cur.ref and node.ref:
            cur.ref = node.ref
        if node.sections and not cur.sections:
            cur.sections = node.sections

    def add_edge(self, edge: Edge) -> None:
        if not any(_edge_key(e) == _edge_key(edge) for e in self.edges):
            self.edges.append(edge)

    # ---- serialization -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "built_from": self.built_from,
            "nodes": {nid: asdict(n) for nid, n in self.nodes.items()},
            "edges": [asdict(e) for e in self.edges],
            "gaps": [asdict(g) for g in self.gaps],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Graph":
        g = cls(built_from=d.get("built_from", {}))
        for nid, n in d.get("nodes", {}).items():
            g.nodes[nid] = Node(**n)
        for e in d.get("edges", []):
            g.edges.append(Edge(**e))
        for gap in d.get("gaps", []):
            g.gaps.append(Gap(**gap))
        return g
