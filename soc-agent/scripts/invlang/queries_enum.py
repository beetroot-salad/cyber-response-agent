"""Corpus enumeration helpers.

Public functions:
  enumerate_corpus        — list distinct values of a corpus dimension
  enumerate_hypothesis_tree — parent-child hierarchy of hypothesis IDs
"""

from __future__ import annotations

from typing import Any

from .corpus import Companion
from ._shared import _parse_hypothesis_chain


ENUM_CHOICES = ("leads", "anchors", "archetypes", "hypotheses", "dispositions")


def enumerate_corpus(corpus: list[Companion], kind: str) -> dict[str, Any]:
    """List distinct values of a corpus dimension.

    kind — one of: leads, anchors, archetypes, hypotheses, dispositions
    """
    values: set[str] = set()
    for c in corpus:
        if kind == "leads":
            for lead in c.leads:
                values.add(lead.get("name", "?"))
        elif kind == "anchors":
            for lead in c.leads:
                for cons in (lead.get("outcome") or {}).get("anchor_consultations") or []:
                    if isinstance(cons, dict) and cons.get("anchor_id"):
                        values.add(cons["anchor_id"])
        elif kind == "archetypes":
            a = c.conclude.get("matched_archetype")
            if a:
                values.add(a)
        elif kind == "hypotheses":
            for h in c.iter_new_hypotheses():
                name = h.get("name")
                if name:
                    values.add(name)
        elif kind == "dispositions":
            d = c.conclude.get("disposition")
            if d:
                values.add(d)
        else:
            raise ValueError(f"unknown kind {kind!r}; choose from {ENUM_CHOICES}")
    return {"kind": kind, "values": sorted(values), "count": len(values)}


def enumerate_hypothesis_tree(corpus: list[Companion]) -> dict[str, Any]:
    """Return the parent-child hierarchy of hypothesis IDs across the corpus.

    Hierarchy is inferred from the h-001-002 ID structure.

    Returns:
      tree  — dict mapping root_id → list of {"id": child_id, "name": child_name}
      flat  — list of {"parent_id": str, "parent_name": str, "child_id": str, "child_name": str}
      count — total distinct hypothesis IDs seen
    """
    id_to_name: dict[str, str] = {}
    for c in corpus:
        for h in c.iter_new_hypotheses():
            h_id = h.get("id", "")
            name = h.get("name", "")
            if h_id:
                id_to_name[h_id] = name

    tree: dict[str, list[str]] = {}
    child_ids: set[str] = set()
    for h_id in id_to_name:
        chain = _parse_hypothesis_chain(h_id)
        if len(chain) >= 2:
            parent_id = chain[-2]
            tree.setdefault(parent_id, []).append(h_id)
            child_ids.add(h_id)

    root_ids = [h_id for h_id in id_to_name if h_id not in child_ids]

    tree_out: dict[str, list[dict[str, str]]] = {}
    for root_id in sorted(root_ids):
        children = tree.get(root_id, [])
        tree_out[root_id] = [
            {"id": c_id, "name": id_to_name.get(c_id, "")}
            for c_id in sorted(children)
        ]

    flat: list[dict[str, str]] = []
    for parent_id, children_ids in sorted(tree.items()):
        for child_id in sorted(children_ids):
            flat.append({
                "parent_id": parent_id,
                "parent_name": id_to_name.get(parent_id, ""),
                "child_id": child_id,
                "child_name": id_to_name.get(child_id, ""),
            })

    return {
        "tree": tree_out,
        "flat": flat,
        "count": len(id_to_name),
    }
