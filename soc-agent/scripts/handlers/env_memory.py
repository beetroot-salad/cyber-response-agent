"""Environment-memory retrieval — anchor-tagged atoms from knowledge/environment/.

Atoms live as YAML lists under a `## Atoms` section in markdown files beneath
`knowledge/environment/{fleet,systems}/`. Each atom carries anchor lists
(mechanic, vertex_classification, vertex_identifier, signature_id, data_source)
and a unified validity window. At retrieval time we walk those files, extract
anchors from the live investigation state, score atoms by weighted overlap, and
return the top-K with stale / pre_window flags for prompt injection.

No index, no cache: walk-per-call. If retrieval becomes a bottleneck, swap in
an index then. Mechanic on hypotheses is derived from the
(parent_vertex.type, edge.relation, attached_vertex.type) triple via
TRIPLE_TO_MECHANIC — no schema extension to invlang.

The `_safe_env_memory_section` wrapper that calls into this module lives
beside `_safe_priors_section` in the predict handler — same degrade-to-banner
discipline; env-memory must never block the loop.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml


# Hypothesis statuses that mean "not actively proposing an upstream edge".
# Mirrors invlang spec (`docs/investigation-language.md` §Companion structure):
# default `active`; non-default values are `confirmed | refuted | shelved`.
# Confirmed hypotheses still constrain the search — only refuted/shelved are
# inactive for retrieval purposes.
INACTIVE_HYPOTHESIS_STATUSES: frozenset[str] = frozenset({"refuted", "shelved"})


# Shared regex for extracting fenced YAML blocks from invlang investigation.md
# files. Lint reuses this via import.
INV_FENCE_RE = re.compile(r"```yaml\s*\n(?P<body>.*?)\n```", re.DOTALL)


# ---------------------------------------------------------------------------
# Vocabularies + derivation table
# ---------------------------------------------------------------------------


MECHANIC_VOCAB: frozenset[str] = frozenset({
    "authentication",
    "process-exec",
    "file-write",
    "file-read",
    "network-connect",
    "dns-resolution",
    "privilege-transition",
    "scheduled-job",
    "data-transfer",
    "service-control",
    "interactive-session",
    "cred-access",
    "discovery-query",
    "ipc",
    "token-lifecycle",
})


# (parent_vertex.type, edge.relation, attached_vertex.type) → set of mechanics.
# Triples not in the table contribute no mechanic anchor. Ambiguous triples
# return multiple mechanics; an atom anchored on ANY of them matches.
# Grow with corpus — the lint surfaces uncovered triples observed in
# proposed_edge blocks.
TRIPLE_TO_MECHANIC: dict[tuple[str, str, str], frozenset[str]] = {
    ("process",    "spawned",            "process"):       frozenset({"process-exec"}),
    ("process",    "executed",           "file"):          frozenset({"process-exec"}),
    ("process",    "loaded_by",          "file"):          frozenset({"process-exec"}),
    ("process",    "wrote",              "file"):          frozenset({"file-write", "data-transfer"}),
    ("process",    "read",               "file"):          frozenset({"file-read", "data-transfer"}),
    ("process",    "opened",             "socket"):        frozenset({"network-connect"}),
    ("socket",     "connected_to",       "endpoint"):      frozenset({"network-connect"}),
    ("session",    "authenticated_as",   "identity"):      frozenset({"authentication"}),
    ("session",    "initiated_by",       "identity"):      frozenset({"authentication", "interactive-session"}),
    ("session",    "initiated_by",       "endpoint"):      frozenset({"interactive-session"}),
    ("endpoint",   "initiated_by",       "identity"):      frozenset({"authentication"}),
    ("endpoint",   "initiated_by",       "endpoint"):      frozenset({"network-connect"}),
    ("session",    "escalated_privilege","session"):       frozenset({"privilege-transition"}),
    ("identity",   "elevated-to",        "identity"):      frozenset({"privilege-transition"}),
    ("command",    "executed_in",        "session"):       frozenset({"interactive-session"}),
    ("command",    "targeted",           "endpoint"):      frozenset({"discovery-query"}),
    ("command",    "targeted",           "storage"):       frozenset({"discovery-query"}),
    ("command",    "targeted",           "database"):      frozenset({"discovery-query"}),
    ("command",    "targeted",           "identity"):      frozenset({"discovery-query"}),
    ("command",    "targeted",           "file"):          frozenset({"file-read", "discovery-query"}),
    ("session",    "listed",             "storage"):       frozenset({"discovery-query"}),
    ("session",    "listed",             "database"):      frozenset({"discovery-query"}),
    ("process",    "listed",             "storage"):       frozenset({"discovery-query"}),
    ("process",    "listed",             "database"):      frozenset({"discovery-query"}),
    ("session",    "modified",           "identity"):      frozenset({"cred-access", "service-control"}),
    ("session",    "modified",           "storage"):       frozenset({"file-write", "data-transfer"}),
    ("session",    "modified",           "file"):          frozenset({"file-write"}),
    ("process",    "modified",           "identity"):      frozenset({"cred-access"}),
    ("process",    "modified",           "file"):          frozenset({"file-write"}),
    ("endpoint",   "attempted_auth",     "endpoint"):      frozenset({"authentication"}),
    ("process",    "attempted_auth",     "endpoint"):      frozenset({"authentication"}),
    ("session",    "attempted_auth",     "endpoint"):      frozenset({"authentication"}),
    ("process",    "resolved",           "domain"):        frozenset({"dns-resolution"}),
    ("scheduler",  "fired",              "job"):           frozenset({"scheduled-job"}),
    ("identity",   "issued",             "token"):         frozenset({"token-lifecycle"}),
    ("session",    "refreshed",          "token"):         frozenset({"token-lifecycle"}),
    ("identity",   "revoked",            "token"):         frozenset({"token-lifecycle"}),
    ("process",    "controlled",         "service"):       frozenset({"service-control"}),
    ("session",    "controlled",         "service"):       frozenset({"service-control"}),
    ("process",    "ipc",                "process"):       frozenset({"ipc"}),
}


# Lint-only category-default windows (days). Used by env_memory_lint.py to
# warn on atoms whose declared window grossly exceeds the typical for its
# inferred category. Not enforced at retrieval — atoms outside any window
# surface with a flag, never excluded.
DEFAULT_VALIDITY_DAYS: dict[str, int] = {
    "entity-status":      30,
    "asset-topology":     180,
    "mechanism-context":  365,
    "source-quirk":       365,
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


_ANCHOR_KEYS: tuple[str, ...] = (
    "mechanic",
    "vertex_classification",
    "vertex_identifier",
    "signature_id",
    "data_source",
)


@dataclass(frozen=True)
class Atom:
    """One environment-memory atom parsed from a knowledge file."""
    id: str
    body: str
    anchors: dict[str, tuple[str, ...]]      # values normalised to str tuples
    valid_from: date
    valid_to: date
    status: str                               # "live" | "superseded" | "tombstoned"
    source_file: Path

    def category(self) -> str:
        """Descriptive category inferred from anchor presence (lint only)."""
        has_mech = bool(self.anchors.get("mechanic"))
        has_id_or_class = bool(self.anchors.get("vertex_identifier") or self.anchors.get("vertex_classification"))
        has_source = bool(self.anchors.get("data_source") or self.anchors.get("signature_id"))
        if has_mech:
            return "mechanism-context"
        if has_id_or_class and not has_source:
            return "entity-status"
        if has_source and not has_mech:
            return "source-quirk"
        return "mechanism-context"


# ---------------------------------------------------------------------------
# Atom file parsing
# ---------------------------------------------------------------------------


_ATOMS_HEADING_RE = re.compile(r"^##\s+Atoms\s*$", re.MULTILINE)
_FENCE_RE = re.compile(r"```(?:yaml)?\s*\n(?P<body>.*?)\n```", re.DOTALL)


class AtomParseError(ValueError):
    """Raised when an atom YAML block is structurally invalid."""


def parse_atoms_from_file(path: Path) -> list[Atom]:
    """Locate the `## Atoms` section in `path`, parse each fenced YAML block as
    a list of atom records, return Atom instances. Files without an `## Atoms`
    section return []. Empty list inside the section returns []. Malformed atoms
    raise AtomParseError with the source file context."""
    text = path.read_text()
    m = _ATOMS_HEADING_RE.search(text)
    if not m:
        return []
    section = text[m.end():]
    atoms: list[Atom] = []
    for fence in _FENCE_RE.finditer(section):
        body = fence.group("body")
        try:
            parsed = yaml.safe_load(body)
        except yaml.YAMLError as e:
            raise AtomParseError(f"{path}: yaml parse failed: {e}") from e
        if parsed is None:
            continue
        if not isinstance(parsed, list):
            raise AtomParseError(f"{path}: ## Atoms block must be a YAML list, got {type(parsed).__name__}")
        for raw in parsed:
            atoms.append(_atom_from_dict(raw, path))
    return atoms


def _atom_from_dict(raw: Any, path: Path) -> Atom:
    if not isinstance(raw, dict):
        raise AtomParseError(f"{path}: atom entry must be a mapping, got {type(raw).__name__}")
    aid = raw.get("id")
    if not isinstance(aid, str) or not aid:
        raise AtomParseError(f"{path}: atom missing non-empty `id`")
    body = raw.get("body")
    if not isinstance(body, str) or not body.strip():
        raise AtomParseError(f"{path}:{aid}: atom missing non-empty `body`")
    anchors_raw = raw.get("anchors") or {}
    if not isinstance(anchors_raw, dict):
        raise AtomParseError(f"{path}:{aid}: `anchors` must be a mapping")
    anchors: dict[str, tuple[str, ...]] = {}
    for key, vals in anchors_raw.items():
        if key not in _ANCHOR_KEYS:
            raise AtomParseError(f"{path}:{aid}: unknown anchor key `{key}` (allowed: {sorted(_ANCHOR_KEYS)})")
        if vals is None:
            continue
        if not isinstance(vals, list):
            raise AtomParseError(f"{path}:{aid}: anchor `{key}` must be a list")
        anchors[key] = tuple(str(v) for v in vals if v is not None)
    valid_raw = raw.get("valid")
    if not isinstance(valid_raw, dict):
        raise AtomParseError(f"{path}:{aid}: missing `valid: {{from, to}}`")
    vf = _parse_date(valid_raw.get("from"))
    vt = _parse_date(valid_raw.get("to"))
    if vf is None or vt is None:
        raise AtomParseError(f"{path}:{aid}: `valid.from` and `valid.to` must be ISO dates")
    if vf > vt:
        raise AtomParseError(f"{path}:{aid}: valid.from > valid.to")
    status = raw.get("status", "live")
    if status not in ("live", "superseded", "tombstoned"):
        raise AtomParseError(f"{path}:{aid}: status must be live | superseded | tombstoned")
    return Atom(
        id=aid,
        body=body.rstrip("\n"),
        anchors=anchors,
        valid_from=vf,
        valid_to=vt,
        status=status,
        source_file=path,
    )


def _parse_date(v: Any) -> date | None:
    if isinstance(v, date) and not isinstance(v, datetime):
        return v
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, str):
        try:
            return date.fromisoformat(v)
        except ValueError:
            return None
    return None


def walk_atom_files(soc_agent_root: Path) -> list[Path]:
    """Return every `*.md` under `knowledge/environment/{fleet,systems}/`.
    Order is filesystem-sorted for determinism."""
    base = soc_agent_root / "knowledge" / "environment"
    out: list[Path] = []
    for sub in ("fleet", "systems"):
        d = base / sub
        if not d.is_dir():
            continue
        out.extend(sorted(d.rglob("*.md")))
    return out


def load_all_atoms(soc_agent_root: Path) -> list[Atom]:
    """Walk + parse every atom-bearing file. Files without a `## Atoms` section
    are silently skipped. Per-file parse errors are isolated: a malformed file
    is skipped (with a stderr note) so the rest of the corpus still surfaces.
    Lint runs `parse_atoms_from_file` directly to surface those errors."""
    out: list[Atom] = []
    for path in walk_atom_files(soc_agent_root):
        try:
            out.extend(parse_atoms_from_file(path))
        except AtomParseError as e:
            print(f"env_memory: skipping malformed atom file: {e}", file=sys.stderr)
    return out


# ---------------------------------------------------------------------------
# Mechanic derivation
# ---------------------------------------------------------------------------


def derive_mechanics_for_edge(
    parent_type: str | None,
    relation: str | None,
    child_type: str | None,
) -> frozenset[str]:
    """Lookup in TRIPLE_TO_MECHANIC; return empty frozenset on miss / None."""
    if not parent_type or not relation or not child_type:
        return frozenset()
    return TRIPLE_TO_MECHANIC.get((parent_type, relation, child_type), frozenset())


# ---------------------------------------------------------------------------
# Anchor extraction from investigation state
# ---------------------------------------------------------------------------


def extract_anchors(ctx: Any) -> dict[str, set[str]]:
    """Pull anchors from the current investigation state.

    Reads `{ctx.run_dir}/investigation.md`, walks every `prologue:`,
    `hypothesize:`, and `findings:` block. Collects:

      - `vertex_identifier` + `vertex_classification` from prologue vertices
        and from every `outcome.observations.vertices[]` and `new_hypotheses[]`
        in findings.
      - `mechanic`: derive each active hypothesis's
        (parent_vertex.type, proposed_edge.relation, attached_vertex.type)
        triple via `derive_mechanics_for_edge`. attached_vertex.type is
        resolved from the materialised vertex set.
      - `signature_id`: from `ctx.signature_id`.

    Missing investigation.md → only signature_id populated. Always returns a
    dict with all anchor keys (possibly empty sets) so callers don't branch
    on presence."""
    anchors: dict[str, set[str]] = {k: set() for k in _ANCHOR_KEYS}
    sig = getattr(ctx, "signature_id", None)
    if sig:
        # Add the full signature_id string AND any ≥4-digit run inside it.
        # ctx.signature_id is typically `wazuh-rule-100001`; atom anchors
        # commonly use the bare numeric `100001` to stay vendor-neutral.
        # Atoms can match either form.
        anchors["signature_id"].add(str(sig))
        anchors["signature_id"].update(re.findall(r"\d{4,}", str(sig)))

    inv_path = getattr(ctx, "run_dir", None)
    if inv_path is None:
        return anchors
    inv_file = Path(inv_path) / "investigation.md"
    if not inv_file.exists():
        return anchors
    text = inv_file.read_text()

    # Walk every yaml fence; merge vertex maps + collect hypotheses.
    vertices_by_id: dict[str, dict] = {}
    hypotheses: list[dict] = []
    shelved_ids: set[str] = set()
    for m in INV_FENCE_RE.finditer(text):
        try:
            parsed = yaml.safe_load(m.group("body"))
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue

        prologue = parsed.get("prologue")
        if isinstance(prologue, dict):
            for v in prologue.get("vertices") or []:
                _index_vertex(v, vertices_by_id, anchors)

        hyp_block = parsed.get("hypothesize")
        if isinstance(hyp_block, dict):
            for h in hyp_block.get("hypotheses") or []:
                if isinstance(h, dict):
                    hypotheses.append(h)
            for sid in hyp_block.get("shelved") or []:
                shelved_ids.add(str(sid))

        findings = parsed.get("findings")
        if isinstance(findings, list):
            for lead in findings:
                if not isinstance(lead, dict):
                    continue
                outcome = lead.get("outcome") or {}
                obs = outcome.get("observations") or {}
                for v in obs.get("vertices") or []:
                    _index_vertex(v, vertices_by_id, anchors)
                for h in lead.get("new_hypotheses") or []:
                    if isinstance(h, dict):
                        hypotheses.append(h)

    # Derive mechanics from active hypotheses (skip shelved + structurally-refuted).
    for h in hypotheses:
        if h.get("status") in INACTIVE_HYPOTHESIS_STATUSES:
            continue
        if h.get("id") in shelved_ids:
            continue
        proposed = h.get("proposed_edge") or {}
        if not isinstance(proposed, dict):
            continue
        relation = proposed.get("relation")
        parent = proposed.get("parent_vertex") or {}
        parent_type = parent.get("type") if isinstance(parent, dict) else None
        attached_id = h.get("attached_to_vertex")
        child_type = vertices_by_id.get(attached_id, {}).get("type")
        mechs = derive_mechanics_for_edge(parent_type, relation, child_type)
        anchors["mechanic"].update(mechs)
        # Also surface the proposed parent's classification — a hypothesis
        # carries strong intent about what it expects upstream; atoms keyed
        # on that classification are highly relevant.
        if isinstance(parent, dict):
            pclass = parent.get("classification")
            if isinstance(pclass, str) and pclass:
                anchors["vertex_classification"].add(pclass)

    return anchors


def _index_vertex(v: Any, by_id: dict[str, dict], anchors: dict[str, set[str]]) -> None:
    if not isinstance(v, dict):
        return
    vid = v.get("id")
    if isinstance(vid, str):
        by_id[vid] = v
    ident = v.get("identifier")
    if isinstance(ident, str) and ident:
        anchors["vertex_identifier"].add(ident)
    cls = v.get("classification")
    if isinstance(cls, str) and cls:
        anchors["vertex_classification"].add(cls)


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


# Anchor weights for top-K scoring. Mechanic + vertex_identifier weight higher
# because they're the most discriminating — mechanic ties an atom to a specific
# OS/auth/network primitive; vertex_identifier ties it to a specific named
# thing. Classification, signature, and source are coarser.
_ANCHOR_WEIGHTS: dict[str, float] = {
    "mechanic":              2.0,
    "vertex_identifier":     1.5,
    "vertex_classification": 1.0,
    "signature_id":          1.0,
    "data_source":           1.0,
}


def _score_atom(atom: Atom, ctx_anchors: dict[str, set[str]]) -> float:
    score = 0.0
    for key, weight in _ANCHOR_WEIGHTS.items():
        atom_vals = set(atom.anchors.get(key, ()))
        if not atom_vals:
            continue
        ctx_vals = ctx_anchors.get(key) or set()
        if atom_vals & ctx_vals:
            score += weight
    return score


def retrieve(
    soc_agent_root: Path,
    ctx: Any,
    k: int = 8,
    *,
    today: date | None = None,
) -> list[tuple[Atom, dict[str, bool]]]:
    """Walk knowledge/environment/{fleet,systems}/**/*.md, parse atoms, score
    against anchors extracted from `ctx`, return top-K with stale / pre_window
    flags. Atoms with status != "live" are excluded (tombstoned/superseded
    atoms surface only via lint reports, never retrieval). Bounded windows do
    NOT hard-exclude — flag only, LLM downweights."""
    today = today or date.today()
    ctx_anchors = extract_anchors(ctx)
    atoms = load_all_atoms(soc_agent_root)
    scored: list[tuple[float, str, Atom]] = []
    for atom in atoms:
        if atom.status != "live":
            continue
        score = _score_atom(atom, ctx_anchors)
        if score <= 0.0:
            continue
        scored.append((score, atom.id, atom))
    # Tiebreak: higher score first, then atom-id ascending for stability.
    scored.sort(key=lambda t: (-t[0], t[1]))
    out: list[tuple[Atom, dict[str, bool]]] = []
    for _, _, atom in scored[:k]:
        flags = {
            "stale":      today > atom.valid_to,
            "pre_window": today < atom.valid_from,
        }
        out.append((atom, flags))
    return out


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------


def format_env_memory_block(matched: Iterable[tuple[Atom, dict[str, bool]]]) -> str:
    """Render the prompt block. Empty input → empty string (caller skips
    the section header entirely)."""
    items = list(matched)
    if not items:
        return ""
    lines = ["## Environment memory", ""]
    for atom, flags in items:
        stale = "true" if flags.get("stale") else "false"
        pre = "true" if flags.get("pre_window") else "false"
        lines.append(
            f'<environment-memory atom_id="{atom.id}" stale="{stale}" pre_window="{pre}">'
        )
        lines.append(atom.body)
        lines.append("</environment-memory>")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
