"""LLM representation layer for the logic view — "locate with script, represent with LLM".

The deterministic CFG (logic.py) LOCATES structure: decision/loop nodes carry the
raw condition source (`ast.unparse`), agent nodes carry the dispatched prompt. This
layer RE-PHRASES that located structure into readable text — a cryptic
`ran_adversarial or ran_benign` decision into "either direction produced findings",
an agent's prompt into a one-line goal — WITHOUT touching the graph's structure.

Why this is safe: the request set is built mechanically from real node ids; the
representer may only return text keyed to those ids (a structural gate drops
anything else). So the LLM can rephrase a label but cannot add, drop, or reroute a
node or edge. The flow you verify is the deterministic one; only its wording is
model-authored.

The representer is injected (`representer=`) so tests run with zero live calls.
"""
from __future__ import annotations

import os
from pathlib import Path

from .model import Graph

REPRESENT_MODEL = os.environ.get("FLOWMAP_REPRESENT_MODEL", "claude-haiku-4-5")
REPRESENT_TIMEOUT = int(os.environ.get("FLOWMAP_REPRESENT_TIMEOUT", "90"))


def collect_requests(cfg: Graph, call_graph: Graph, root: Path) -> list[dict]:
    """One request per decision/loop (raw condition) + agent (prompt goal source).

    Each request: {id, kind: 'branch'|'agent', raw, ref}. `raw` is the material the
    LLM rephrases — condition source for branches, prompt opening for agents.
    """
    root = root.resolve()
    reqs: list[dict] = []
    for nid, n in cfg.nodes.items():
        if n.kind in ("decision", "loop"):
            reqs.append({"id": nid, "kind": "branch", "raw": n.label, "ref": n.ref})
        elif n.kind == "agent":
            raw = _prompt_opening(call_graph, n.label, root) or n.label
            reqs.append({"id": nid, "kind": "agent", "raw": raw,
                         "name": n.label, "ref": n.ref})
    return reqs


def _prompt_opening(call_graph: Graph, funcname: str, root: Path, n: int = 700) -> str | None:
    dst = next((e.dst for e in call_graph.edges
                if e.kind == "dispatches" and e.src.endswith(f"::{funcname}")), None)
    if not dst or not dst.startswith("agent-prompt:"):
        return None
    path = root / dst.split(":", 1)[1]
    if not path.is_file():
        return None
    return path.read_text().strip()[:n]


def apply_representation(cfg: Graph, labels: dict[str, str]) -> int:
    """Stamp represented text back. Branch/loop -> node.label (shown in chart);
    agent -> node.signals['goal'] (shown in the companion table, chart keeps the
    bare name). Returns count applied. Ignores ids not in the graph (gate)."""
    applied = 0
    for nid, text in labels.items():
        n = cfg.nodes.get(nid)
        if n is None or not text:
            continue
        if n.kind in ("decision", "loop"):
            n.label = text.strip()
            applied += 1
        elif n.kind == "agent":
            n.signals["goal"] = text.strip()
            applied += 1
    return applied


# --------------------------------------------------------------------------- #
# LLM seam (injectable)
# --------------------------------------------------------------------------- #

_SYSTEM = """You make a code flow chart readable. You are given items located in
source - each is either a BRANCH (a raw boolean condition) or an AGENT (the opening
of a subagent's prompt). Rewrite each into short, plain language.

- branch: turn the condition into a question or outcome a reader scans quickly.
  e.g. `not directions` -> "no learning direction?"; `is_skip_story(actor_story)` ->
  "actor skipped?"; `ran_adversarial or ran_benign` -> "any findings produced?".
  Keep it under ~6 words. Do not invent meaning the condition does not carry.
- agent: one line (<= ~12 words) naming what the agent is asked to DO. e.g. a
  red-team prompt -> "invent a plausible attack that evades this alert".

Output STRICT JSON, no prose, no fence:
{"labels":[{"id":"<verbatim id>","text":"<rewrite>"}]}
Echo each id exactly as given. One entry per item."""


def _default_representer(requests: list[dict]) -> dict[str, str]:
    from .haiku import _parse_obj, _run_haiku
    blocks = []
    for r in requests:
        blocks.append(f'--- id: {r["id"]}\nkind: {r["kind"]}\nraw: {r["raw"]}\n')
    user = ("Rewrite each item.\n\n" + "\n".join(blocks)
            + f"\nReturn one label per id ({len(requests)} total).")
    raw = _run_haiku(_SYSTEM, user, timeout=REPRESENT_TIMEOUT)
    doc = _parse_obj(raw)
    out: dict[str, str] = {}
    for item in doc.get("labels", []):
        if isinstance(item, dict) and "id" in item and "text" in item:
            out[str(item["id"])] = str(item["text"])
    return out


def represent_logic(cfg: Graph, call_graph: Graph, root: Path, *,
                    representer=_default_representer) -> dict:
    """Locate (script) -> represent (LLM) -> apply. Returns a summary.

    Structural gate: only labels whose id is a real request node are applied;
    requests with no returned label keep their deterministic raw label (so a
    partial/failed representer degrades to the verifiable raw view, never to a
    blank or invented one)."""
    reqs = collect_requests(cfg, call_graph, root)
    if not reqs:
        return {"requested": 0, "applied": 0}
    valid_ids = {r["id"] for r in reqs}
    labels = {k: v for k, v in representer(reqs).items() if k in valid_ids}
    applied = apply_representation(cfg, labels)
    return {"requested": len(reqs), "applied": applied,
            "unlabeled": len(reqs) - applied}
