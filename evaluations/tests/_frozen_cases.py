"""Test-side fixtures for #1347 r6.4: bound held-out cases, and the spec's binding oracle.

A held-out case is `<slug>/{alert.json, ground_truth.yaml, case.yaml}` beside
`freezes/<freeze-id>/freeze.yaml`. An index row is `{slug, run_id, binding, knowledge, verdict,
reason, verified_at}`. `digest` restates A8 (sorted-key compact canonical JSON, bare lowercase
hex) so a scorer that binds differently fails; production code does not import it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

FREEZE_ID = "f-2026-10-20"
FREEZE = {"T": "2026-10-20T09:00:00Z",
          "elastic": {"repository": "frozen-cases", "snapshot": "s1", "uuid": "U",
                      "indices": {"logs-system.auth-2026.10": 990}},
          "parts": {"stubs.tar": "a" * 64}, "captured_by": "op"}


def digest(doc: object) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def case_doc(slug: str, **over: object) -> dict:
    return {"freeze": FREEZE_ID, "alert": "b" * 64, "age": 3000, "overlay": None,
            "counts": {"logs-system.auth-2026.10": 990}, "content": "c" * 64,
            "confirmed": {"by": "op", "at": "2026-10-21T10:00:00Z", "reference_run": f"ref-{slug}"},
            **over}


def make_cases(root: Path) -> Path:
    """Give every labelled fixture under `root` a case.yaml and the shared freeze."""
    for gt in sorted(root.glob("*/ground_truth.yaml")):
        (gt.parent / "case.yaml").write_text(yaml.safe_dump(case_doc(gt.parent.name)))
    (root / "freezes" / FREEZE_ID).mkdir(parents=True, exist_ok=True)
    (root / "freezes" / FREEZE_ID / "freeze.yaml").write_text(yaml.safe_dump(FREEZE))
    return root


def binding(root: Path, slug: str) -> str:
    case = yaml.safe_load((root / slug / "case.yaml").read_text())
    freeze = yaml.safe_load((root / "freezes" / case["freeze"] / "freeze.yaml").read_text())
    return digest([digest(freeze), digest(case)])


def row(root: Path, slug: str, run_id: str, /, **over: object) -> dict:
    base = {"slug": slug, "run_id": run_id, "binding": binding(root, slug), "knowledge": "k" * 40,
            "verdict": "valid", "reason": "", "verified_at": "2026-11-08T12:30:00Z"}
    return {k: v for k, v in {**base, **over}.items() if v is not None}


def write_index(path: Path, *rows: object) -> Path:
    """JSON Lines of `rows` (dicts, or raw strings written as given)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows))
    return path
