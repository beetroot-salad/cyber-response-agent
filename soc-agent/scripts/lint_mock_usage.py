#!/usr/bin/env python3
"""Ratchet-style linter: discourage `unittest.mock` in tests.

Project preference is fixtures + fakes (real-ish in-memory implementations) over
`MagicMock` / `@patch`. Mocks couple tests to call shape rather than behavior;
fakes survive refactors and exercise the real seam.

This linter:
  - scans `soc-agent/tests/**.py` for mock usage,
  - reads a baseline allowlist of files currently permitted to use mocks,
  - prints every current mock-using file (so the picture is visible), and
  - exits non-zero if ANY file outside the allowlist uses mocks.

To shrink the allowlist: rewrite a permitted test using a fixture+fake, then
remove its line from `soc-agent/tests/.mock_allowlist`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "soc-agent" / "tests"
ALLOWLIST_PATH = TESTS_DIR / ".mock_allowlist"

# Match imports + decorator/usage forms. Comments and string literals can
# false-positive but the cost is "add a noqa" — acceptable for a ratchet.
MOCK_PATTERNS = [
    re.compile(r"^\s*from\s+unittest\.mock\s+import\b", re.MULTILINE),
    re.compile(r"^\s*from\s+mock\s+import\b", re.MULTILINE),
    re.compile(r"^\s*import\s+unittest\.mock\b", re.MULTILINE),
    re.compile(r"^\s*import\s+mock\b", re.MULTILINE),
    re.compile(r"\bMagicMock\b"),
    re.compile(r"\bAsyncMock\b"),
    re.compile(r"@(?:mock\.|unittest\.mock\.)?patch\b"),
    re.compile(r"\bmock\.patch\b"),
]


def file_uses_mocks(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    return any(pat.search(text) for pat in MOCK_PATTERNS)


def load_allowlist() -> set[str]:
    if not ALLOWLIST_PATH.exists():
        return set()
    return {
        line.strip()
        for line in ALLOWLIST_PATH.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def main() -> int:
    if not TESTS_DIR.exists():
        print(f"tests dir not found: {TESTS_DIR}", file=sys.stderr)
        return 2

    allowlist = load_allowlist()
    test_files = sorted(TESTS_DIR.rglob("test_*.py"))

    using_mocks: list[str] = []
    for path in test_files:
        if file_uses_mocks(path):
            rel = path.relative_to(REPO_ROOT).as_posix()
            using_mocks.append(rel)

    new_offenders = [p for p in using_mocks if p not in allowlist]
    stale_allowlist = [p for p in allowlist if p not in using_mocks]

    print(f"Mock-using test files: {len(using_mocks)}")
    for p in using_mocks:
        marker = "  " if p in allowlist else "* "
        print(f"  {marker}{p}")
    print()
    print("Legend: '*' = NOT in allowlist (new offender)")
    print(f"Allowlist: {ALLOWLIST_PATH.relative_to(REPO_ROOT).as_posix()}")

    exit_code = 0
    if new_offenders:
        print()
        print(f"FAIL: {len(new_offenders)} test file(s) use mocks but are not "
              f"in the allowlist. Prefer fixtures + fakes; if you must use "
              f"mocks, add the path to {ALLOWLIST_PATH.name}.", file=sys.stderr)
        for p in new_offenders:
            print(f"  - {p}", file=sys.stderr)
        exit_code = 1

    if stale_allowlist:
        print()
        print(f"WARN: {len(stale_allowlist)} allowlist entry/entries no longer "
              f"use mocks — please remove them to keep the ratchet tight:",
              file=sys.stderr)
        for p in stale_allowlist:
            print(f"  - {p}", file=sys.stderr)
        # Stale entries are a warning, not a hard failure.

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
