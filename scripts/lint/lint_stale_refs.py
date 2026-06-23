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
  4. Skip identifiers that still have a binding site (def/class/assignment/
     import) ANYWHERE in the post-PR tree — they were moved, re-exported, or
     their import line merely reflowed (single→multi-line), not removed. A
     genuine stale ref is a symbol defined NOWHERE yet still referenced.
  5. Batch-grep the remaining tree for each survivor in one word-boundary
     (`git grep -w -F -e A -e B ...`) call — `-w` so a removed `_by_id` does
     not match `template_path_by_id`. Idents with >50 hits are too common to
     be signal; skip them. Idents with 1–50 hits in files OUTSIDE the diff's
     own changed files are surfaced.

Exits 0 if clean, 1 otherwise.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_REF = os.environ.get("STALE_REF_BASE", "origin/main")
BASELINE_PATH = Path(__file__).with_name("lint_stale_refs_baseline.json")

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
    """Return {ident: [filtered_lines]} from one combined git grep call.

    Word-boundary (`-w`) so a removed `_by_id` doesn't match `template_path_by_id`;
    the attribution below is `\\b`-anchored for the same reason."""
    if not idents:
        return {}
    cmd = ["git", "grep", "-n", "-w", "-F"]
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
        # Determine which ident matched (greedy first whole-word hit).
        for ident in idents:
            if re.search(rf"\b{re.escape(ident)}\b", parts[2]):
                by_ident[ident].append(line[:200])
                break
    return by_ident


def _is_binding(line: str, ident: str) -> bool:
    """True if `line` defines or imports `ident` — a `def`/`class`, a module-level
    assignment, or any `import` line naming it (module path or target)."""
    e = re.escape(ident)
    return bool(
        re.search(rf"\b(?:async\s+)?(?:def|class)\s+{e}\b", line)
        or re.search(rf"^\s*{e}\s*(?::[^=]+)?=(?!=)", line)   # assignment / annotated
        or ("import" in line and re.search(rf"\b{e}\b", line))  # import (module or target)
        or re.fullmatch(rf"\s*{e},?\s*", line)               # multiline import member
    )


def _still_defined(idents: list[str]) -> set[str]:
    """Idents that still have a binding site (def/class/assignment/import) ANYWHERE
    in the post-PR tree — i.e. moved or re-exported, not removed. A genuine stale
    ref is a symbol defined NOWHERE yet still referenced; a move/rename/import
    reflow leaves the symbol defined elsewhere and is not stale. Scans the whole
    tree (changed files included — that is where a moved def now lives)."""
    if not idents:
        return set()
    cmd = ["git", "grep", "-n", "-w", "-F"]
    for ident in idents:
        cmd.extend(["-e", ident])
    out = _run(cmd, timeout=60)
    defined: set[str] = set()
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        rel, content = parts[0], parts[2]
        if any(rel.startswith(d + "/") or rel == d for d in EXCLUDED_GREP_DIRS):
            continue
        for ident in idents:
            if ident not in defined and _is_binding(content, ident):
                defined.add(ident)
    return defined


HEADER = (
    "lint_stale_refs baseline — references that survive a rename/delete in the "
    "PR diff. Fingerprint is file:ident. CI fails on a surviving reference absent "
    "here. Regenerate: python scripts/lint/lint_stale_refs.py --update-baseline. "
    "This baseline is normally empty (the check is diff-relative); an entry means "
    'a knowingly-tolerated stray reference. "" means un-triaged.'
)


def _hit_file(hit: str) -> str:
    """Extract the path from a `path:lineno:content` git-grep hit line."""
    return hit.split(":", 1)[0]


def _scan() -> list[Finding]:
    if not _run(["git", "rev-parse", "--verify", BASE_REF]):
        print(f"WARN: base ref `{BASE_REF}` not found; skipping stale-ref scan", file=sys.stderr)
        return []

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

    # Drop idents still defined/imported somewhere post-PR (moved, re-exported, or
    # an import line merely reflowed) — those are not stale, only a removed-AND-
    # undefined symbol with surviving references is.
    moved = _still_defined(specific)
    if moved:
        print(f"Skipped {len(moved)} still-defined identifier(s) (moved/re-exported): "
              f"{', '.join(sorted(moved)[:10])}" + ("..." if len(moved) > 10 else ""))
    specific = [i for i in specific if i not in moved]

    if not specific:
        print("No specific removed identifiers in the diff.")
        return []

    print(f"Scanning {len(specific)} specific removed identifier(s) (base={BASE_REF})")
    results = _batch_grep(specific, changed)

    findings: list[Finding] = []
    print()
    for ident in specific:
        hits = results.get(ident, [])
        if not hits:
            continue
        if len(hits) > HIT_CAP:
            print(f"  SKIP `{ident}`: {len(hits)} hits (too common — likely false positive)")
            continue
        print(f"  STALE `{ident}`: {len(hits)} reference(s) remain")
        for h in hits[:5]:
            print(f"    {h}")
        if len(hits) > 5:
            print(f"    ... and {len(hits) - 5} more")
        print()
        for h in hits:
            findings.append(
                Finding(fingerprint=f"{_hit_file(h)}:{ident}", display=f"STALE {ident}: {h}")
            )
    return findings


def main(argv: list[str]) -> int:
    findings = _scan()
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_stale_refs", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
