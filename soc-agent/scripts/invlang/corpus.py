"""Investigation-language companion loader.

Walks `**/investigation.md` under the corpus root and parses each file's
`​```invlang` dense fences into a single companion body. The ```invlang
surface is the only on-disk format post-cutover (the validator rejects
yaml fences); every block tag projects to the canonical companion dict
via `scripts/handlers/_dense_parser.py`.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from collections.abc import Iterator


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

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "findings", "conclude"}
# v2.6: hypothesize is optional when screen_result: match short-circuits the loop.
_COMPANION_REQUIRED_KEYS = {"prologue", "findings", "conclude"}


# ---------------------------------------------------------------------------
# Companion dataclass
# ---------------------------------------------------------------------------

@dataclass
class Companion:
    """A loaded v2.5 companion with its source path and parsed body."""

    case_id: str
    source_path: Path
    body: dict[str, Any]
    # ISO-8601 timestamp stamped at the top of investigation.md on initial
    # write (`<!-- created: ... -->`). None when the header is absent;
    # temporal-filtered queries treat None as "exclude" so missing-header
    # companions can't silently slip into a recency window. Hour-level drift
    # vs. the originating alert is irrelevant at our 180-day granularity.
    created_at: str | None = None

    @property
    def prologue(self) -> dict[str, Any]:
        return self.body.get("prologue", {})

    @property
    def hypotheses(self) -> list[dict[str, Any]]:
        return self.body.get("hypothesize", {}).get("hypotheses", [])

    @property
    def leads(self) -> list[dict[str, Any]]:
        return [entry for entry in self.body.get("findings", []) if isinstance(entry, dict)]

    @property
    def conclude(self) -> dict[str, Any]:
        return self.body.get("conclude", {})

    def iter_new_hypotheses(self) -> Iterator[dict[str, Any]]:
        """Yields hypotheses from the `hypothesize:` block (emitted by PREDICT) +
        any new_hypotheses spawned in leads."""
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


_SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SOC_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOC_AGENT_ROOT))


def _merge_md_blocks(text: str) -> dict[str, Any]:
    """Parse every ```invlang fence in an investigation.md into one companion body.

    The dense parser projects all fences in the document into a single
    canonical companion dict (prologue, hypothesize, findings, conclude).
    Returns an empty dict when no fences are present or the dense surface
    is malformed — a stderr warning is emitted in the malformed case so
    corpus walks don't crash on a single bad file.
    """
    from scripts.handlers._dense_parser import (  # type: ignore
        DenseParseError,
        parse_dense_companion,
    )
    try:
        dense_doc = parse_dense_companion(text)
    except DenseParseError as e:
        print(
            f"[invlang.corpus] warning: malformed ```invlang block "
            f"during corpus walk — skipping dense surface. Error: {e}",
            file=sys.stderr,
        )
        return {}
    return dense_doc or {}


_CREATED_HEADER_RE = re.compile(
    r"<!--\s*created:\s*(?P<ts>\S+?)\s*-->"
)


def _read_created_header(text: str) -> str | None:
    """Pull the `<!-- created: <iso8601> -->` header out of an
    investigation.md body. Stamped at initial write by the CONTEXTUALIZE
    handler; absent on companions that predate the header convention.

    Returns None when the header is missing — temporal queries treat None as
    "exclude" so missing-header companions can't silently slip into a
    recency window.
    """
    m = _CREATED_HEADER_RE.search(text)
    return m.group("ts") if m else None


def write_created_header(now_iso: str) -> str:
    """Format the canonical `<!-- created: ... -->` header line, including
    a trailing blank line. Centralizes the format so the writer (CONTEXTUALIZE
    handler) and reader (`_read_created_header`) stay in sync.
    """
    return f"<!-- created: {now_iso} -->\n\n"


def _load_from_path(path: Path) -> list[Companion]:
    """Parse an investigation.md and return the companion it contains (0 or 1).

    Walks every ```invlang fence in the file via `_merge_md_blocks` into a
    single canonical companion body.
    """
    results: list[Companion] = []
    if path.suffix != ".md":
        return results
    try:
        text = path.read_text()
    except OSError:
        return results
    merged = _merge_md_blocks(text)
    if _looks_like_companion(merged):
        results.append(
            Companion(
                case_id=_case_id_from_path(path),
                source_path=path,
                body=merged,
                created_at=_read_created_header(text),
            )
        )
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
    for lead in body.get("findings", []):
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


@lru_cache(maxsize=16)
def _load_corpus_cached(effective_root: Path) -> tuple[Companion, ...]:
    """Memoized core: same `effective_root` returns the same tuple.

    Cached because corpus scans are filesystem-heavy and both live
    orchestrator runs and tests call this many times per session against
    an unchanging corpus. Returns a tuple so the cache entry is immutable
    — callers materialize to a list.
    """
    return tuple(discover_run_investigations(effective_root))


def load_corpus(root: Path | None = None) -> list[Companion]:
    """Load every finished `investigation.md` under `root` (or _corpus_root()).

    Each file's ```invlang fences are merged into one companion body via
    `_merge_md_blocks`. Files that don't yield a finished companion
    (missing prologue / findings / conclude) are skipped.

    Results are memoized per `effective_root` via `_load_corpus_cached`
    — clear with `clear_corpus_cache()` when callers need to see fresh
    corpus state (e.g. after a run writes a new investigation.md in the
    same process).
    """
    effective_root = root if root is not None else _corpus_root()
    return list(_load_corpus_cached(effective_root))


def clear_corpus_cache() -> None:
    """Drop the memoized corpus. Call between runs that intentionally share
    a process (rare — the orchestrator usually runs one investigation
    per process) if you need the second run to pick up companions the
    first run wrote."""
    _load_corpus_cached.cache_clear()
