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

Pre-existing leaks are ratcheted via lint_ground_truth_leak_baseline.json (see
scripts/lint/_baseline.py); the gate fails only on a NEW reachable label file.

Run from repo root:  python scripts/lint/lint_ground_truth_leak.py
Regenerate the baseline:  python scripts/lint/lint_ground_truth_leak.py --update-baseline

Exit codes:
  0  clean, or every finding is baselined
  1  a new reachable label file
  2  the gate COULD NOT RUN — the permission specs it scans against are unreadable
     or malformed. Never a silent pass (the lint_vulture / lint_stale_refs
     convention, #618/#621).

The exit-2 channel exists because this gate's clean answer and its blind answer used
to be the same bytes. `_load_permission_specs` swallowed every exception into
`data = {}`, and an empty allow-set is a LEGITIMATE state here (see its closing
comment) — so a malformed `run-settings.json` produced no allow roots, `_reachable`
returned None for every candidate, and the gate printed 0 findings and exited 0.
That is not one file dropping out of the scan: it is the whole check switched off,
reporting clean. Parse failure and "genuinely no allow entries" must therefore be
distinguishable, which is what `SpecsUnreadable` makes them.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from _baseline import Finding, gate


class SpecsUnreadable(RuntimeError):
    """A permission spec this gate REQUIRES to parse did not. Without it the allow-set is
    empty, every candidate reads as unreachable, and the scan would report clean having
    computed nothing. The gate cannot run, and so must not report clean."""

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_ground_truth_leak_baseline.json")

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
        except OSError as exc:
            raise SpecsUnreadable(
                f"{path.relative_to(REPO_ROOT)} exists but could not be read ({exc}) — "
                f"its --add-dir grants are part of the agent-accessible set this gate "
                f"scans against, so skipping it would shrink that set to a subset and "
                f"report clean on the difference."
            ) from exc
        for m in re.finditer(r"--add-dir\s+([\w/.\-${}]+)", text):
            raw = m.group(1).replace("${", "").replace("}", "")
            if raw.startswith("/"):
                allow.add(raw.rstrip("/"))
        # Parse JSON-shaped Read(...) entries; track whether they came
        # from allow or deny by reading the JSON structure.
    settings_path = DEFENDER / "run-settings.json"
    if settings_path.exists():
        # No `except: data = {}` fallback. An empty allow-set is a legitimate answer here
        # (see the closing comment) and a malformed file must not be able to counterfeit it.
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SpecsUnreadable(
                f"defender/run-settings.json could not be parsed ({exc.__class__.__name__}: "
                f"{exc}) — its Read(...) allow entries ARE the agent-accessible set this gate "
                f"tests reachability against, so an unparseable file makes every label file "
                f"look unreachable. Fix the JSON, then re-run."
            ) from exc
        if not isinstance(data, dict):
            raise SpecsUnreadable(
                f"defender/run-settings.json parsed as {type(data).__name__}, not an object — "
                f"no `permissions` block can be read from it, so the allow-set would be empty "
                f"for a structural reason rather than a declared one."
            )
        perms = data.get("permissions", {}) or {}
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


HEADER = (
    "lint_ground_truth_leak baseline — label/answer-key files reachable from an "
    "agent run. Fingerprint is the file path. CI fails on a reachable label file "
    "absent here. Regenerate: "
    "python scripts/lint/lint_ground_truth_leak.py --update-baseline. "
    'Annotate intentional entries; "" means un-triaged debt to move or rename.'
)


def _scan() -> list[Finding]:
    allow_roots, deny_patterns = _load_permission_specs()
    print("Agent-accessible roots (heuristic):")
    for r in allow_roots:
        print(f"  - {r}")
    if deny_patterns:
        print(f"Deny patterns: {len(deny_patterns)} (Read entries from run-settings.json)")
    print()

    findings: list[Finding] = []
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
                Finding(
                    fingerprint=rel,
                    display=f"{rel}: label-file name matches /{reason}/; reachable from `{access_rel}`",
                )
            )
    return findings


def main(argv: list[str]) -> int:
    # Before --update-baseline too: you must not be able to bless an empty result that was
    # never computed (#621's preflight ordering).
    try:
        findings = _scan()
    except SpecsUnreadable as exc:
        print(f"lint_ground_truth_leak: {exc}", file=sys.stderr)
        return 2
    print("A finding means a label-shaped file lives in a directory the agent can Read")
    print("at runtime. Move the file outside agent scope, or rename it (see commit f11210f).")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_ground_truth_leak", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
