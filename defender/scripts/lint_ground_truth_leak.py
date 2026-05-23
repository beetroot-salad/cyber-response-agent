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


def _load_permission_specs() -> tuple[list[str], list[re.Pattern]]:
    """Return (allow_read_roots, deny_read_patterns) from run-settings.json
    + any --add-dir paths from run.py / run shell scripts."""
    allow: set[str] = set()
    deny: list[re.Pattern] = []
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
                allow.add(raw.rstrip("/"))
        # Parse JSON-shaped Read(...) entries; track whether they came
        # from allow or deny by reading the JSON structure.
    settings_path = DEFENDER / "run-settings.json"
    if settings_path.exists():
        try:
            import json as _json
            data = _json.loads(settings_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        perms = data.get("permissions", {})
        for entry in perms.get("allow", []) or []:
            m = re.match(r"Read\((.+)\)$", entry)
            if not m:
                continue
            spec = m.group(1).rstrip("*/")
            if spec.startswith("/"):
                allow.add(spec)
        for entry in perms.get("deny", []) or []:
            m = re.match(r"Read\((.+)\)$", entry)
            if not m:
                continue
            spec = m.group(1)
            # Convert glob to regex: ** = .*, * = [^/]*
            regex = re.escape(spec)
            regex = regex.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
            deny.append(re.compile(regex + "$"))
    # If run-settings.json had no Read(...) allow entries (and run.py
    # didn't pass --add-dir), the agent runs under whatever cwd permission
    # the harness grants. We don't second-guess that — only flag files
    # under explicitly-allowed Read roots.
    return sorted(allow, key=len, reverse=True), deny


def _reachable(path: Path, allow_roots: list[str], deny_patterns: list[re.Pattern]) -> str | None:
    p = str(path)
    # Deny wins over allow.
    p_under_root = p
    try:
        p_under_root = "/" + str(path.relative_to(REPO_ROOT))
    except ValueError:
        pass
    candidates = {p, p_under_root, path.name}
    for pat in deny_patterns:
        for c in candidates:
            if pat.match(c) or pat.search(c):
                return None
    for r in allow_roots:
        if p == r or p.startswith(r + "/"):
            return r
    return None


def main() -> int:
    allow_roots, deny_patterns = _load_permission_specs()
    print("Agent-accessible roots (heuristic):")
    for r in allow_roots:
        print(f"  - {r}")
    if deny_patterns:
        print(f"Deny patterns: {len(deny_patterns)} (Read entries from run-settings.json)")
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
            access_root = _reachable(path, allow_roots, deny_patterns)
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
