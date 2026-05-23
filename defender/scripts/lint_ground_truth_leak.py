#!/usr/bin/env python3
"""Ground-truth leak scan — flag label files reachable from agent runs.

Triggered by commit f11210f (defender/advisory: move harness out of
defender/ to fix ground-truth leak). The harness lived inside the
agent's read-accessible scope; agents in every arm Read `cases.json`
and `fixtures/POS-*/README.md`, both of which carried `ground_truth`
labels. Pilot trials were silently invalidated.

What this check does:
  - Walks experiment and fixture roots.
  - Flags files whose NAME looks like a label/answer key
    (cases.json, ground_truth*, expected_*, gold*, disposition.json).
  - Reports a finding when a label file lives inside an
    agent-accessible root (declared via Read(...) in run-settings.json
    or --add-dir in defender/run.py).

Filename-only matching keeps this fast (no per-file content scan).
False positives are intentionally tolerated under code-smells.

Run from repo root:  python defender/scripts/lint_ground_truth_leak.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"

SCAN_ROOTS = [
    REPO_ROOT / "experiments",
    DEFENDER / "fixtures",
    DEFENDER / "tests" / "fixtures",
]

NAME_PATTERNS = [
    re.compile(r"^cases?\.json$", re.IGNORECASE),
    re.compile(r"ground[-_]?truth", re.IGNORECASE),
    re.compile(r"^expected[-_].+\.(?:json|ya?ml|md)$", re.IGNORECASE),
    re.compile(r"^gold[-_].+\.(?:json|ya?ml|md)$", re.IGNORECASE),
    re.compile(r"^disposition\.json$", re.IGNORECASE),
    re.compile(r"^answers?\.(?:json|ya?ml|md)$", re.IGNORECASE),
]


def _is_label_name(name: str) -> str | None:
    for pat in NAME_PATTERNS:
        if pat.search(name):
            return pat.pattern
    return None


def _agent_accessible_roots() -> list[str]:
    """String prefixes for paths the agent can Read during a run."""
    roots: set[str] = set()
    for path in (DEFENDER / "run.py", DEFENDER / "run-settings.json"):
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"--add-dir\s+([\w/.\-${}]+)", text):
            raw = m.group(1).replace("${", "").replace("}", "")
            if raw.startswith("/"):
                roots.add(raw.rstrip("/"))
        for m in re.finditer(r'"Read\(([^)]+)\)"', text):
            spec = m.group(1).rstrip("*/")
            if spec.startswith("/"):
                roots.add(spec)
    # Default: the repo root is accessible during local dev runs.
    roots.add(str(REPO_ROOT))
    return sorted(roots, key=len, reverse=True)


def _reachable(path: Path, roots: list[str]) -> str | None:
    p = str(path)
    for r in roots:
        if p == r or p.startswith(r + "/"):
            return r
    return None


def main() -> int:
    roots = _agent_accessible_roots()
    print("Agent-accessible roots (heuristic):")
    for r in roots:
        print(f"  - {r}")
    print()

    findings: list[str] = []
    for scan_root in SCAN_ROOTS:
        if not scan_root.is_dir():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file():
                continue
            reason = _is_label_name(path.name)
            if not reason:
                continue
            access_root = _reachable(path, roots)
            if not access_root:
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            access_rel = (
                Path(access_root).relative_to(REPO_ROOT).as_posix()
                if access_root.startswith(str(REPO_ROOT))
                else access_root
            )
            findings.append(
                f"{rel}: label-file name matches /{reason}/; reachable from `{access_rel}`"
            )

    print(f"=== ground-truth-leak ({len(findings)} finding(s)) ===")
    for f in findings:
        print(f"  {f}")
    print()
    print("A finding means a label-shaped file lives in a directory the agent can Read")
    print("at runtime. Move the file outside agent scope, or rename it (see commit f11210f).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
