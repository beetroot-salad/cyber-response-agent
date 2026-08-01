#!/usr/bin/env python3
"""Score the pilot's stories.

Extraction is ITEM-TOLERANT on purpose: one malformed line from the model must not
zero an arm (it did, on the first pass). Malformed items are counted, not swallowed —
YAML well-formedness is a quality signal about the arm, not a harness verdict.

Commitment is scored on BOUND claims only. A claim whose asserted_value is a hedge
("something suspicious", "external C2 destinations") commits to nothing an oracle could
refute, so counting it would reward exactly the vagueness the metric exists to punish.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent

# A bound value names a thing: an id, an address, a path, a timestamp, a number, a
# quoted literal. A hedge describes a category.
_HEDGE = re.compile(
    r"\b(external|internal|suspicious|malicious|unknown|some|any|various|"
    r"non-|not |or |likely|possible|possibly|e\.g\.|etc)\b", re.I)
_CONCRETE = re.compile(
    r"(\d{1,3}(\.\d{1,3}){3}|/[\w./-]+|\d{4}-\d{2}-\d{2}T|\bPID\b|^\d+$|"
    r"^[\w.-]+@|^[a-z0-9-]+-\d+$|^\d+(\.\d+)?$)", re.I)


def extract(story: str) -> tuple[list[dict], int]:
    """Return (claims, malformed_item_count) from the last yaml-ish block."""
    blocks = re.findall(r"```ya?ml\s*\n(.*?)```", story, re.DOTALL)
    if not blocks:
        return [], 0
    block = blocks[-1]
    try:
        doc = yaml.safe_load(block)
        if isinstance(doc, dict) and isinstance(doc.get("claims"), list):
            return [c for c in doc["claims"] if isinstance(c, dict)], 0
    except Exception:  # noqa: BLE001 — fall through to item-wise recovery
        pass

    # Item-wise recovery: split on top-level "- " and parse each alone.
    items, malformed = [], 0
    chunks = re.split(r"\n(?=\s*-\s)", block)
    for ch in chunks:
        if not ch.strip().lstrip().startswith("-"):
            continue
        try:
            doc = yaml.safe_load(ch)
        except Exception:  # noqa: BLE001
            malformed += 1
            continue
        if isinstance(doc, list) and doc and isinstance(doc[0], dict):
            items.append(doc[0])
        else:
            malformed += 1
    return items, malformed


def is_bound(claim: dict) -> bool:
    v = str(claim.get("asserted_value", "")).strip()
    if not v:
        return False
    if _CONCRETE.search(v):
        return True
    return not _HEDGE.search(v) and len(v.split()) <= 4


def score(arm_dir: Path) -> dict | None:
    story_p, meta_p = arm_dir / "story.md", arm_dir / "meta.json"
    if not story_p.is_file():
        return None
    meta = json.loads(meta_p.read_text()) if meta_p.is_file() else {}
    claims, malformed = extract(story_p.read_text(encoding="utf-8"))
    bound = [c for c in claims if is_bound(c)]
    unqueried = [c for c in claims
                 if str(c.get("would_show_in", "")).strip().lower() == "unqueried"]
    return {
        "arm": arm_dir.name,
        "claims": len(claims),
        "bound": len(bound),
        "hedged": len(claims) - len(bound),
        "malformed_items": malformed,
        "unqueried": len(unqueried),
        "calls": meta.get("calls"),
        "prompt_chars_total": meta.get("prompt_chars_total"),
        "wall_seconds": meta.get("wall_seconds"),
        "story_chars": meta.get("story_chars"),
        "bound_per_call": round(len(bound) / meta["calls"], 2) if meta.get("calls") else None,
    }


def main() -> int:
    fixture = sys.argv[1] if len(sys.argv) > 1 else None
    base = HERE / "runs"
    fixtures = [base / fixture] if fixture else sorted(p for p in base.iterdir() if p.is_dir())
    rows = []
    for fx in fixtures:
        for arm in sorted(p for p in fx.iterdir() if p.is_dir()):
            r = score(arm)
            if r:
                r["fixture"] = fx.name
                rows.append(r)

    cols = ["arm", "claims", "bound", "hedged", "malformed_items", "unqueried",
            "calls", "bound_per_call", "prompt_chars_total", "wall_seconds"]
    w = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols} if rows else {}
    print("  ".join(c.ljust(w[c]) for c in cols))
    print("  ".join("-" * w[c] for c in cols))
    for r in sorted(rows, key=lambda r: -(r["bound"] or 0)):
        print("  ".join(str(r.get(c, "")).ljust(w[c]) for c in cols))

    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "pilot.json").write_text(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
