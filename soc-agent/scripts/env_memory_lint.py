#!/usr/bin/env python3
"""Environment-memory lint — walk knowledge/environment/{fleet,systems}/, parse
all atoms, validate schema + references + freshness, surface conflict
candidates and uncovered hypothesis triples.

Exit codes:
    0 — all blocking checks passed (warnings allowed)
    1 — at least one blocking check failed

Blocking:
    - schema (atom YAML structure, required fields, valid date range)
    - reference: mechanic anchors ∈ MECHANIC_VOCAB
    - reference: signature_id contains a substring of ≥4 contiguous digits

Warning-only:
    - reference: vertex_classification heuristic (unknown surface — informational)
    - window-expiry: valid.to < today (tombstone candidate)
    - default-window: valid.to - valid.from > category default (review for over-claim)
    - conflict candidates: atoms with overlapping anchor scope (no body parsing)
    - triple-coverage: (parent_type, rel, child_type) triples seen in run
      proposed_edge blocks but absent from TRIPLE_TO_MECHANIC
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers.env_memory import (  # noqa: E402
    DEFAULT_VALIDITY_DAYS,
    MECHANIC_VOCAB,
    TRIPLE_TO_MECHANIC,
    Atom,
    AtomParseError,
    parse_atoms_from_file,
    walk_atom_files,
)


_DIGIT_RUN_RE = re.compile(r"\d{4,}")
_INV_FENCE_RE = re.compile(r"```yaml\s*\n(?P<body>.*?)\n```", re.DOTALL)


def _check_schema(soc_agent_root: Path) -> tuple[list[Atom], list[str]]:
    """Walk + parse every atom file. Errors are collected as strings rather
    than raising, so lint reports all problems in one pass."""
    atoms: list[Atom] = []
    errors: list[str] = []
    for path in walk_atom_files(soc_agent_root):
        try:
            atoms.extend(parse_atoms_from_file(path))
        except AtomParseError as e:
            errors.append(f"SCHEMA: {e}")
    return atoms, errors


def _check_references(atoms: list[Atom]) -> tuple[list[str], list[str]]:
    blocking: list[str] = []
    warnings: list[str] = []
    for atom in atoms:
        for mech in atom.anchors.get("mechanic", ()):
            if mech not in MECHANIC_VOCAB:
                blocking.append(
                    f"REFERENCE: {atom.source_file}:{atom.id}: mechanic `{mech}` "
                    f"not in MECHANIC_VOCAB ({sorted(MECHANIC_VOCAB)})"
                )
        for sig in atom.anchors.get("signature_id", ()):
            if not _DIGIT_RUN_RE.search(str(sig)):
                blocking.append(
                    f"REFERENCE: {atom.source_file}:{atom.id}: signature_id `{sig}` "
                    "must contain a run of ≥4 contiguous digits"
                )
    return blocking, warnings


def _check_freshness(atoms: list[Atom], today: date) -> list[str]:
    warnings: list[str] = []
    for atom in atoms:
        if atom.status != "live":
            continue
        if atom.valid_to < today:
            days = (today - atom.valid_to).days
            warnings.append(
                f"WINDOW-EXPIRED: {atom.source_file}:{atom.id} expired {days}d ago "
                f"(valid.to={atom.valid_to}); tombstone candidate"
            )
        window_days = (atom.valid_to - atom.valid_from).days
        cat = atom.category()
        default = DEFAULT_VALIDITY_DAYS.get(cat)
        if default is not None and window_days > default * 2:
            warnings.append(
                f"DEFAULT-WINDOW: {atom.source_file}:{atom.id} window {window_days}d "
                f"exceeds 2x default {default}d for category `{cat}`; review for over-claim"
            )
    return warnings


def _check_conflict_candidates(atoms: list[Atom]) -> list[str]:
    """Group live atoms by (mechanic-set, classification-set) and by signature_id.
    Any group with >1 distinct atom is a candidate pool for human review.
    No body parsing — the user reasons through whether they actually conflict."""
    warnings: list[str] = []
    by_mech_class: dict[tuple[str, str], list[Atom]] = defaultdict(list)
    by_sig: dict[str, list[Atom]] = defaultdict(list)
    for atom in atoms:
        if atom.status != "live":
            continue
        mechs = tuple(sorted(atom.anchors.get("mechanic", ())))
        classes = tuple(sorted(atom.anchors.get("vertex_classification", ())))
        if mechs and classes:
            by_mech_class[(",".join(mechs), ",".join(classes))].append(atom)
        for sig in atom.anchors.get("signature_id", ()):
            by_sig[str(sig)].append(atom)
    for key, group in sorted(by_mech_class.items()):
        if len(group) > 1:
            ids = ", ".join(sorted(a.id for a in group))
            warnings.append(
                f"CONFLICT-CANDIDATE: mechanic+classification scope ({key[0]}; {key[1]}) "
                f"shared by atoms [{ids}] — review for true conflicts"
            )
    for sig, group in sorted(by_sig.items()):
        # De-dupe: only flag if we haven't already flagged this exact set
        # via the mech+classification grouping above.
        if len(group) > 1:
            ids = ", ".join(sorted(a.id for a in group))
            warnings.append(
                f"CONFLICT-CANDIDATE: signature_id `{sig}` shared by atoms "
                f"[{ids}] — review for true conflicts"
            )
    return warnings


def _check_triple_coverage(soc_agent_root: Path, runs_dir: Path | None) -> list[str]:
    """Walk a sample of runs/*/investigation.md, extract (parent_type, rel,
    child_type) triples from hypothesis proposed_edge blocks, list any
    not in TRIPLE_TO_MECHANIC."""
    if runs_dir is None:
        runs_dir = soc_agent_root / "runs"
    if not runs_dir.is_dir():
        return []
    seen: set[tuple[str, str, str]] = set()
    for inv_file in sorted(runs_dir.rglob("investigation.md"))[:200]:
        try:
            text = inv_file.read_text()
        except OSError:
            continue
        vertices_by_id: dict[str, dict] = {}
        hypotheses: list[dict] = []
        for m in _INV_FENCE_RE.finditer(text):
            try:
                parsed = yaml.safe_load(m.group("body"))
            except yaml.YAMLError:
                continue
            if not isinstance(parsed, dict):
                continue
            for v in (parsed.get("prologue") or {}).get("vertices") or []:
                if isinstance(v, dict) and isinstance(v.get("id"), str):
                    vertices_by_id[v["id"]] = v
            hyp_block = parsed.get("hypothesize") or {}
            for h in hyp_block.get("hypotheses") or []:
                if isinstance(h, dict):
                    hypotheses.append(h)
            for lead in parsed.get("findings") or []:
                if not isinstance(lead, dict):
                    continue
                obs = (lead.get("outcome") or {}).get("observations") or {}
                for v in obs.get("vertices") or []:
                    if isinstance(v, dict) and isinstance(v.get("id"), str):
                        vertices_by_id[v["id"]] = v
                for h in lead.get("new_hypotheses") or []:
                    if isinstance(h, dict):
                        hypotheses.append(h)
        for h in hypotheses:
            proposed = h.get("proposed_edge") or {}
            if not isinstance(proposed, dict):
                continue
            relation = proposed.get("relation")
            parent = proposed.get("parent_vertex") or {}
            parent_type = parent.get("type") if isinstance(parent, dict) else None
            child_type = vertices_by_id.get(h.get("attached_to_vertex"), {}).get("type")
            if parent_type and relation and child_type:
                seen.add((parent_type, relation, child_type))
    warnings: list[str] = []
    for triple in sorted(seen - set(TRIPLE_TO_MECHANIC.keys())):
        warnings.append(
            f"TRIPLE-COVERAGE: {triple} observed in runs but missing from "
            "TRIPLE_TO_MECHANIC; consider adding"
        )
    return warnings


def main() -> int:
    p = argparse.ArgumentParser(description="Environment-memory lint")
    p.add_argument("--root", type=Path, default=SOC_AGENT_ROOT,
                   help="soc-agent root (default: derived from script path)")
    p.add_argument("--runs-dir", type=Path, default=None,
                   help="runs/ dir to sample for triple coverage (default: <root>/runs)")
    p.add_argument("--quiet", action="store_true", help="suppress warnings")
    args = p.parse_args()

    today = date.today()
    atoms, schema_errors = _check_schema(args.root)
    ref_errors, ref_warnings = _check_references(atoms)
    freshness_warnings = _check_freshness(atoms, today)
    conflict_warnings = _check_conflict_candidates(atoms)
    triple_warnings = _check_triple_coverage(args.root, args.runs_dir)

    blocking = schema_errors + ref_errors
    warnings = ref_warnings + freshness_warnings + conflict_warnings + triple_warnings

    for line in blocking:
        print(line, file=sys.stderr)
    if not args.quiet:
        for line in warnings:
            print(line, file=sys.stderr)

    print(
        f"env_memory_lint: {len(atoms)} atoms, "
        f"{len(blocking)} blocking, {len(warnings)} warnings"
    )
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
