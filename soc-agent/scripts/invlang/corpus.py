"""Investigation-language companion loader.

Two source shapes are supported:

1. Live investigation.md (default). A single markdown file containing one or
   more ```yaml fenced blocks — one per phase (prologue, hypothesize, gather,
   conclude). Blocks are merged into a single companion body. This is the
   canonical source for the query tool: it walks SOC_AGENT_RUNS_DIR for
   `**/investigation.md` and loads every finished (prologue + gather +
   conclude) investigation it finds.

2. Hand-curated companion YAML (allowlist). A single .yaml file holding the
   full four-phase companion body. Used for the pilot corpus; callers pass
   an explicit (root, paths) allowlist.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _corpus_root() -> Path:
    """Root directory the default loader scans for investigation.md files.

    Priority: INVLANG_CORPUS_ROOT override → SOC_AGENT_RUNS_DIR. Both unset
    raises — there is no filesystem default.
    """
    env = os.environ.get("INVLANG_CORPUS_ROOT")
    if env:
        return Path(env)
    runs = os.environ.get("SOC_AGENT_RUNS_DIR")
    if runs:
        return Path(runs)
    raise RuntimeError(
        "Neither INVLANG_CORPUS_ROOT nor SOC_AGENT_RUNS_DIR is set."
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "gather", "conclude"}
# v2.6: hypothesize is optional when screen_result: match short-circuits the loop.
_COMPANION_REQUIRED_KEYS = {"prologue", "gather", "conclude"}

YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)

# Pilot corpus allowlist — deliberate: only finalized v2.5/v2.6 translations.
# Update when a new case lands. Paths are relative to the corpus root.
PILOT_CORPUS_FILES: tuple[str, ...] = (
    "case-a1/walk-a1-v2.5.yaml",
    "case-a4/walk-a4-v2.5.yaml",
    "case-m365/walk-m365-v2.5.yaml",
    "case-real-rule5710/companion-v2.5.yaml",
    "case-ssh-brute/companion-v2.5.yaml",
    "case-ssh-cron/companion-v2.5.yaml",
)


# ---------------------------------------------------------------------------
# Companion dataclass
# ---------------------------------------------------------------------------

@dataclass
class Companion:
    """A loaded v2.5 companion with its source path and parsed body."""

    case_id: str
    source_path: Path
    body: dict[str, Any]

    @property
    def prologue(self) -> dict[str, Any]:
        return self.body.get("prologue", {})

    @property
    def hypotheses(self) -> list[dict[str, Any]]:
        return self.body.get("hypothesize", {}).get("hypotheses", [])

    @property
    def leads(self) -> list[dict[str, Any]]:
        return [entry for entry in self.body.get("gather", []) if isinstance(entry, dict)]

    @property
    def conclude(self) -> dict[str, Any]:
        return self.body.get("conclude", {})

    def iter_new_hypotheses(self) -> Iterator[dict[str, Any]]:
        """Yields hypotheses from HYPOTHESIZE + any new_hypotheses spawned in leads."""
        yield from self.hypotheses
        for lead in self.leads:
            for h in lead.get("new_hypotheses", []) or []:
                yield h


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def conclude_field(conclude: dict[str, Any], *path: str) -> Any:
    """Defensive nested access — returns None if any hop isn't a dict."""
    cur: Any = conclude
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _looks_like_companion(doc: Any) -> bool:
    # hypothesize is optional in v2.6 when screen_result: match short-circuits the loop
    return isinstance(doc, dict) and _COMPANION_REQUIRED_KEYS.issubset(doc.keys())


def _case_id_from_path(path: Path) -> str:
    return path.parent.name if path.parent.name not in {"", "."} else path.stem


_SIGNATURE_ID_RE = re.compile(r"rule(\d+)")


def signature_id_from_path(path: Path) -> str | None:
    """Recover `wazuh-rule-<N>` from a companion source path when the eval-run
    directory encodes it (e.g. `/workspace/runs/20260422-.../rule100001/...`).
    Returns None if no match — the corpus loader doesn't guarantee this field,
    so callers must tolerate absence.
    """
    m = _SIGNATURE_ID_RE.search(str(path))
    return f"wazuh-rule-{m.group(1)}" if m else None


def _merge_md_blocks(text: str) -> dict[str, Any]:
    """Merge every ```yaml block in an investigation.md into one companion body.

    Live investigations write one block per phase (prologue at CONTEXTUALIZE,
    hypothesize at HYPOTHESIZE, gather lead at ANALYZE, conclude at CONCLUDE);
    gather blocks may appear multiple times. This mirrors the merge in cli.py's
    `--ids` handler.
    """
    merged: dict[str, Any] = {}
    for match in YAML_BLOCK_RE.finditer(text):
        try:
            doc = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        for key in ("prologue", "hypothesize", "conclude"):
            if key in doc:
                merged[key] = doc[key]
        if "gather" in doc and isinstance(doc["gather"], list):
            merged.setdefault("gather", [])
            merged["gather"].extend(doc["gather"])
    return merged


def _load_from_path(path: Path) -> list[Companion]:
    """Parse a file and return every companion it contains (0 or more).

    .yaml  — one companion per file (whole document is the body).
    .md    — merge every ```yaml block into a single companion body.
    """
    results: list[Companion] = []
    if path.suffix == ".yaml":
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            return results
        if _looks_like_companion(doc):
            results.append(Companion(_case_id_from_path(path), path, doc))
    elif path.suffix == ".md":
        try:
            merged = _merge_md_blocks(path.read_text())
        except OSError:
            return results
        if _looks_like_companion(merged):
            results.append(Companion(_case_id_from_path(path), path, merged))
    return results


# ---------------------------------------------------------------------------
# Public loader
# ---------------------------------------------------------------------------

def extract_ids(body: dict[str, Any]) -> dict[str, list[str]]:
    """Walk a parsed companion body and return all IDs grouped by type.

    Returns a dict with keys 'vertices', 'edges', 'hypotheses', 'leads'.
    Includes IDs introduced both in the prologue and inside lead outcomes/new_hypotheses.
    """
    prologue = body.get("prologue", {})
    vertices   = [v["id"] for v in prologue.get("vertices", []) if "id" in v]
    edges      = [e["id"] for e in prologue.get("edges", [])    if "id" in e]
    hypotheses = [h["id"] for h in body.get("hypothesize", {}).get("hypotheses", []) if "id" in h]
    leads: list[str] = []
    for lead in body.get("gather", []):
        if not isinstance(lead, dict):
            continue
        if "id" in lead:
            leads.append(lead["id"])
        obs = lead.get("outcome", {}).get("observations", {})
        vertices.extend(v["id"]   for v in obs.get("vertices", [])          if "id" in v)
        edges.extend(   e["id"]   for e in obs.get("edges", [])              if "id" in e)
        hypotheses.extend(h["id"] for h in lead.get("new_hypotheses", [])   if "id" in h)
    return {"vertices": vertices, "edges": edges, "hypotheses": hypotheses, "leads": leads}


def hypothesis_topology(
    prologue: dict[str, Any],
    hypothesis: dict[str, Any],
    siblings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the topology fingerprint of one hypothesis.

    Shape:
        {
          attached_vertex: {type, classification} | None,
          relation: str | None,
          parent_vertex: {type, classification} | None,
          peers: tuple[str, ...],   # sorted names of sibling hypotheses
        }

    `siblings` is the list of other hypotheses co-proposed in the same block
    (pass `companion.hypotheses` for corpus use; the handler passes its parsed
    frontier). This hypothesis is filtered out by id.

    Expects the v2.8 structured shape: `proposed_edge: {relation, parent_vertex:
    {type, classification}}`. Attached-vertex type/classification are resolved
    from `prologue.vertices` by id. Missing lookups degrade to None — the
    narrowing ladder copes with gaps.
    """
    vertices_by_id = {
        v.get("id"): v
        for v in (prologue.get("vertices") or [])
        if isinstance(v, dict)
    }

    attached_id = hypothesis.get("attached_to_vertex")
    attached_v = vertices_by_id.get(attached_id)
    attached_vertex: dict[str, Any] | None = None
    if attached_v is not None:
        attached_vertex = {
            "type": attached_v.get("type"),
            "classification": attached_v.get("classification"),
        }

    proposed = hypothesis.get("proposed_edge")
    relation: str | None = None
    parent_vertex: dict[str, Any] | None = None
    if isinstance(proposed, dict):
        relation = proposed.get("relation")
        pv = proposed.get("parent_vertex")
        if isinstance(pv, dict):
            parent_vertex = {
                "type": pv.get("type"),
                "classification": pv.get("classification"),
            }

    this_id = hypothesis.get("id")
    peer_names: list[str] = []
    for h in siblings or []:
        if h.get("id") == this_id:
            continue
        nm = h.get("name")
        if nm:
            peer_names.append(nm)
    peers = tuple(sorted(peer_names))

    return {
        "attached_vertex": attached_vertex,
        "relation": relation,
        "parent_vertex": parent_vertex,
        "peers": peers,
    }


def discover_run_investigations(root: Path) -> list[Companion]:
    """Walk `root` for `**/investigation.md` and load each as one companion.

    Skips files that don't parse to a finished companion body (missing any of
    prologue / gather / conclude). Used as the default corpus source.
    """
    if not root.exists():
        return []
    companions: list[Companion] = []
    for md in sorted(root.rglob("investigation.md")):
        companions.extend(_load_from_path(md))
    return companions


def load_corpus(
    root: Path | None = None,
    paths: tuple[str, ...] | None = None,
) -> list[Companion]:
    """Load companions.

    Default (paths=None): walk `root` (or _corpus_root()) for
    `**/investigation.md` and merge each file's yaml blocks into one
    companion. This is the live-investigation source.

    Allowlist mode (paths is a tuple): load exactly those relative paths
    from `root`. Used for the hand-curated pilot corpus; pass
    `paths=PILOT_CORPUS_FILES` and `root=<pilot dir>` explicitly.
    """
    effective_root = root if root is not None else _corpus_root()
    if paths is None:
        return discover_run_investigations(effective_root)

    companions: list[Companion] = []
    for rel in paths:
        abs_path = effective_root / rel
        if not abs_path.exists():
            print(f"warning: {rel} not found under {effective_root}, skipping", file=sys.stderr)
            continue
        companions.extend(_load_from_path(abs_path))
    return companions
