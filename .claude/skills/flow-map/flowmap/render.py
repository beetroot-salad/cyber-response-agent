"""Graph -> Mermaid flowchart. Generic; style keyed on node/edge kind."""
from __future__ import annotations

import re

from .model import Graph

_ARROW = {
    "calls": "-->",
    "dispatches": "==>",
    "runs_command": "-->",
    "fires_hook": "-.->",
    "uses_tool": "-.->",
    "reads_template": "-->",
    "reads_prompt": "-.->",
}

_SHAPE = {
    "py-func": ("(", ")"),
    "py-module": ("[", "]"),
    "agent-prompt": ("([", "])"),
    "script": ("[", "]"),
    "skill": ("[[", "]]"),
    "hook": ("[/", "/]"),
    "tool": ("{{", "}}"),
    "template": ("[(", ")]"),
    "system": ("{{", "}}"),
}


def _sid(raw: str) -> str:
    return "N_" + re.sub(r"[^A-Za-z0-9_]", "_", raw)


def _short(node_id: str, label: str) -> str:
    # display the function/file name, with the harvested label as a second line
    tail = node_id.split("::")[-1].split(":")[-1]
    base = tail.replace('"', "'")
    if label:
        lab = label.replace('"', "'")
        if len(lab) > 48:
            lab = lab[:45] + "..."
        return f"{base}<br/><i>{lab}</i>"
    return base


def render_mermaid(g: Graph, title: str = "") -> str:
    lines = ["```mermaid", "flowchart TD"]
    if title:
        lines.append(f"  %% {title}")
    for nid, n in g.nodes.items():
        o, c = _SHAPE.get(n.kind, ("[", "]"))
        lines.append(f'  {_sid(nid)}{o}"{_short(nid, n.label)}"{c}:::{_kind_class(n.kind)}')
    for e in g.edges:
        arrow = _ARROW.get(e.kind, "-->")
        if e.kind in ("dispatches", "runs_command", "fires_hook"):
            lbl = e.kind if not e.label else e.kind
            lines.append(f"  {_sid(e.src)} {arrow}|{lbl}| {_sid(e.dst)}")
        else:
            lines.append(f"  {_sid(e.src)} {arrow} {_sid(e.dst)}")
    lines += [
        "  classDef pyfunc fill:#fff,stroke:#475569;",
        "  classDef agent fill:#dcfce7,stroke:#16a34a,stroke-width:2px;",
        "  classDef script fill:#f3e8ff,stroke:#9333ea;",
        "  classDef other fill:#f1f5f9,stroke:#64748b;",
        "```",
    ]
    if g.gaps:
        lines.append("")
        lines.append("**Gaps (unresolved deterministically):**")
        for gap in g.gaps:
            lines.append(f"- `{gap.kind}` @ {gap.ref} — {gap.detail}")
    return "\n".join(lines)


def _kind_class(kind: str) -> str:
    return {
        "py-func": "pyfunc",
        "agent-prompt": "agent",
        "script": "script",
    }.get(kind, "other")
