"""Natural-language intent → a resolved seed in an already-built graph.

Split, like the rest of flow-map, into a deterministic core and a thin LLM seam:

  * resolve_seed (deterministic) — map a target NAME to a real graph node id.
    The name comes from the LLM, but resolution is mechanical and BOUNDED: exact
    bare-name match, then unique substring match. Ambiguous or absent → error
    (never a guess, never an invented node). This is the "scripts own identity"
    invariant applied to the NL path.

  * parse_intent (LLM seam, injected) — turn the question + the catalog of real
    node names into an Intent {mode, target_name}. The classifier is handed ONLY
    names that exist, and its output is validated against them, so it can pick but
    not fabricate.

  * resolve_question — wires them: parse → validate → resolve. Pure-deterministic
    given an Intent, so the whole thing is testable with an injected parser. The
    CLI owns rendering: a component-card (scope.py) for component-card mode, the
    branch-aware logic view (logic.py) for subsystem-map mode.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .model import Graph

INTENT_MODEL = os.environ.get("FLOWMAP_INTENT_MODEL", "claude-haiku-4-5")
INTENT_TIMEOUT = int(os.environ.get("FLOWMAP_INTENT_TIMEOUT", "60"))

MODES = ("component-card", "subsystem-map")


@dataclass
class Intent:
    mode: str            # component-card | subsystem-map
    target_name: str     # a bare node name the resolver must map to a real id


class IntentError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Deterministic seed resolution — name -> real node id
# --------------------------------------------------------------------------- #


def _bare(nid: str) -> str:
    return nid.split("::")[-1].split("/")[-1]


def catalog(g: Graph) -> list[str]:
    """Sorted unique bare names of every node — the only vocabulary the LLM may
    pick from."""
    return sorted({_bare(nid) for nid in g.nodes})


def resolve_seed(g: Graph, name: str) -> str:
    """Map a bare name to exactly one node id, or raise. Never invents."""
    name = name.strip()
    exact = [nid for nid in g.nodes if _bare(nid) == name]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise IntentError(
            f"name {name!r} matches {len(exact)} nodes: "
            f"{sorted(exact)} — qualify it")
    # fall back to a unique case-insensitive substring match
    lname = name.lower()
    subs = [nid for nid in g.nodes if lname in _bare(nid).lower()]
    if len(subs) == 1:
        return subs[0]
    if not subs:
        raise IntentError(f"no node matches {name!r} (catalog has "
                          f"{len(g.nodes)} nodes)")
    raise IntentError(
        f"name {name!r} ambiguously matches {len(subs)} nodes: "
        f"{sorted(_bare(s) for s in subs)[:8]} — be more specific")


def validate_intent(intent: Intent) -> Intent:
    if intent.mode not in MODES:
        raise IntentError(f"mode {intent.mode!r} not in {MODES}")
    if not intent.target_name.strip():
        raise IntentError("intent has empty target_name")
    return intent


# --------------------------------------------------------------------------- #
# LLM seam — question -> Intent (injectable)
# --------------------------------------------------------------------------- #

_INTENT_SYSTEM = """You route a question about a codebase to a view of its flow graph.

You are given the question and a CATALOG of real node names. Choose:
- mode: "component-card" if the question is about ONE component ("how does X
  work", "what does X do"); "subsystem-map" if it is about a flow/subsystem
  whose driver is a function whose body sequences the steps ("how does the <Y>
  loop/pipeline/flow work").
- target_name: the single catalog name the question is about. It MUST be copied
  verbatim from the catalog — do not invent or paraphrase. For subsystem-map,
  pick the function that DRIVES the flow (its body is the sequence of steps).

Output STRICT JSON, no prose, no fence:
{"mode":"...","target_name":"..."}"""


def _default_parser(question: str, names: list[str]) -> Intent:
    from .haiku import _parse_obj, _run_haiku  # lazy: keep module importable w/o wiring
    user = (f"Question: {question}\n\nCATALOG ({len(names)} names):\n"
            + ", ".join(names))
    raw = _run_haiku(_INTENT_SYSTEM, user, timeout=INTENT_TIMEOUT)
    doc = _parse_obj(raw)
    return Intent(
        mode=doc.get("mode", ""),
        target_name=doc.get("target_name", ""),
    )


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


def resolve_question(g: Graph, question: str, *,
                     parser=_default_parser) -> tuple[Intent, str]:
    """question -> (validated Intent, resolved seed node id).

    The LLM seam (parser) picks mode + a catalog name; resolution to a real node
    id is mechanical and never invents. Rendering is the caller's job.
    """
    intent = validate_intent(parser(question, catalog(g)))
    return intent, resolve_seed(g, intent.target_name)
