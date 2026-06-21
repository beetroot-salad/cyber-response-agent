#!/usr/bin/env python3
"""Stale-reference scan — for symbols/files removed in a PR's diff,
verify the post-PR tree has no remaining references.

Catches the recurring "rename refactor missed a callsite" class:
- f1a6014: stale `WAZUH_CLI_VENV` after rename
- 0aa4924: stale `scripts/siem` refs after refactor to `scripts/tools`
- b77a276: `_prior_recall` import path broken in hook contexts
- 8ef005f: test glob still matched old pre-suffix filename pattern

Algorithm:
  1. Diff against `$STALE_REF_BASE` (default `origin/main`).
  2. Collect identifiers removed by `-`-side lines:
       - `def NAME(` / `class NAME`
       - top-level `NAME =` (uppercase constants)
       - removed `from ... import NAME` targets
  3. Filter: skip identifiers <6 chars without an underscore, and skip
     common stdlib symbols (typing/Callable/etc.) — they're never
     project-specific stale-ref signal.
  4. Batch-grep the remaining tree for each survivor in one `git grep
     -F -e A -e B ...` call. Idents with >50 hits are too common to be
     stale-ref signal; skip them. Idents with 1–50 hits in files OUTSIDE
     the diff's own changed files are surfaced.

Exits 0 if clean, 1 otherwise. Soft signal under code-smells.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_REF = os.environ.get("STALE_REF_BASE", "origin/main")

# Maximum total hits before we declare an ident too common to be signal.
HIT_CAP = 50

REMOVED_DEF = re.compile(r"^-\s*(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
REMOVED_ASSIGN = re.compile(r"^-\s*([A-Z][A-Z0-9_]{3,})\s*=")
REMOVED_PY_IMPORT = re.compile(
    r"^-\s*from\s+([\w.]+)\s+import\s+([\w,\s]+)|"
    r"^-\s*import\s+([\w.]+)"
)

# Identifiers that are never project-specific stale-ref signal.
GENERIC_NAMES = {
    "main", "handle", "author", "format_output",
    "Callable", "Iterable", "Iterator", "Optional", "Union", "Any",
    "typing", "dataclass", "field", "Path", "List", "Dict",
}

EXCLUDED_GREP_DIRS = (
    ".git", ".venv", "__pycache__", "node_modules",
    "defender/run-visualizations", "defender/fixtures",
    "defender/run-transcripts", "defender/lessons", "defender/lessons-actor",
    ".claude/worktrees", "experiments",
    # Task files and design docs reference removed symbols historically;
    # they are not code that should be kept consistent with current names.
    "tasks", "docs",
    # POC design notes — same rationale.
    "defender/docs",
)


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        return subprocess.check_output(
            cmd, cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL, timeout=timeout
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""


def _changed_files() -> set[str]:
    out = _run(["git", "diff", "--name-only", f"{BASE_REF}...HEAD"])
    return {line.strip() for line in out.splitlines() if line.strip()}


def _collect_removed_idents() -> set[str]:
    diff = _run(["git", "diff", "--unified=0", f"{BASE_REF}...HEAD"])
    if not diff:
        return set()
    idents: set[str] = set()
    for line in diff.splitlines():
        if not line.startswith("-") or line.startswith("---"):
            continue
        for pat in (REMOVED_DEF, REMOVED_ASSIGN):
            m = pat.match(line)
            if m:
                idents.add(m.group(1))
        m = REMOVED_PY_IMPORT.match(line)
        if m:
            for g in m.groups():
                if not g:
                    continue
                for part in re.split(r"[\s,]+", g):
                    part = part.strip().split(".")[-1]
                    if part and len(part) >= 4:
                        idents.add(part)
    return idents


def _renamed_or_deleted_paths() -> set[str]:
    out = _run(["git", "diff", "--name-status", f"{BASE_REF}...HEAD"])
    paths: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("D") and len(parts) >= 2:
            paths.add(parts[1])
        elif parts[0].startswith("R") and len(parts) >= 3:
            paths.add(parts[1])
    return paths


def _is_specific(ident: str) -> bool:
    if ident in GENERIC_NAMES:
        return False
    if "_" in ident:
        return True
    return len(ident) >= 8


def _batch_grep(idents: list[str], exclude_files: set[str]) -> dict[str, list[str]]:
    """Return {ident: [filtered_lines]} from one combined git grep call."""
    if not idents:
        return {}
    cmd = ["git", "grep", "-n", "-F"]
    for ident in idents:
        cmd.extend(["-e", ident])
    out = _run(cmd, timeout=60)
    by_ident: dict[str, list[str]] = {i: [] for i in idents}
    for line in out.splitlines():
        # Format: path:lineno:content
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        rel = parts[0]
        if rel in exclude_files:
            continue
        if any(rel.startswith(d + "/") or rel == d for d in EXCLUDED_GREP_DIRS):
            continue
        # Determine which ident matched (greedy first-hit).
        for ident in idents:
            if ident in parts[2]:
                by_ident[ident].append(line[:200])
                break
    return by_ident


def main() -> int:
    if not _run(["git", "rev-parse", "--verify", BASE_REF]):
        print(f"WARN: base ref `{BASE_REF}` not found; skipping stale-ref scan", file=sys.stderr)
        return 0

    changed = _changed_files()
    idents = _collect_removed_idents()
    removed_paths = _renamed_or_deleted_paths()

    for p in removed_paths:
        for component in Path(p).parts:
            if len(component) >= 5 and "." not in component:
                idents.add(component)

    specific = sorted(i for i in idents if _is_specific(i))
    skipped = sorted(i for i in idents if not _is_specific(i))

    if skipped:
        print(f"Skipped {len(skipped)} generic identifiers: {', '.join(skipped[:10])}"
              + ("..." if len(skipped) > 10 else ""))
    if not specific:
        print("=== stale-refs (0 findings — no specific removed identifiers) ===")
        return 0

    print(f"Scanning {len(specific)} specific removed identifier(s) (base={BASE_REF})")
    results = _batch_grep(specific, changed)

    total_findings = 0
    print()
    for ident in specific:
        hits = results.get(ident, [])
        if not hits:
            continue
        if len(hits) > HIT_CAP:
            print(f"  SKIP `{ident}`: {len(hits)} hits (too common — likely false positive)")
            continue
        total_findings += len(hits)
        print(f"  STALE `{ident}`: {len(hits)} reference(s) remain")
        for h in hits[:5]:
            print(f"    {h}")
        if len(hits) > 5:
            print(f"    ... and {len(hits) - 5} more")
        print()

    print(f"=== stale-refs ({total_findings} finding(s)) ===")
    return 1 if total_findings else 0


if __name__ == "__main__":
    sys.exit(main())
