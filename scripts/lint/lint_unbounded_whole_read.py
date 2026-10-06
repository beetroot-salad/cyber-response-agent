#!/usr/bin/env python3
"""Unbounded whole-file read: flag a read under ``defender/`` that takes a whole file into
memory by path, outside ``defender._io`` (#1188).

A whole-file read sizes its buffer from the file. A box-planted sparse file (``truncate -s
1T``) once made that a ``MemoryError``, which is not an ``OSError``, so it skipped every
reader's fail-safe path and crashed the host process. Two things now bound it:

- the writer: every box starts with ``--ulimit fsize=READ_LIMIT`` (#1198), so no file a box
  process writes is larger than ``defender._io.READ_LIMIT``;
- the reader: every read through ``_io`` is capped at ``READ_LIMIT``, and a caller's ``limit``
  can only lower it (#1188 D1).

A direct ``read_text``/``read_bytes`` has neither guarantee for a file a HOST process writes:
tool writes for the model, logs, queues, alert copies, backend payloads. So each one is a
deliberate choice, marked on its line with who writes the file and what bounds it.

What it flags, under ``defender/`` production code (tests and the root ``_io.py`` excluded):
any ``<x>.read_text(...)`` / ``<x>.read_bytes(...)``, matched by attribute name whatever the
receiver. That includes the class-qualified ``Path.read_text(p)`` (and
``pathlib.Path.read_bytes(p)``, an aliased ``P.read_text(p)``): it is the same attribute, with
the class as receiver.

What it does not flag: reads through an open handle (``f.read()``, ``json.load(f)``,
``open(p).read()``) and ``sys.stdin``, because there is no handle tracking and none of them
reads a path today; and ``_io``'s own readers, whose cap cannot be lifted.

Mark a deliberate site with ``# lint-whole-read: ok — <reason>`` on the call's line span. The
reason is required: a bare marker does not suppress. Say who writes the file and what bounds
it. "Bounded at the writer by the box fsize limit" holds only when every writer is a box
process. The baseline ships EMPTY, so a new unmarked read fails CI.

Run from repo root:  python scripts/lint/lint_unbounded_whole_read.py
Exit 0 = clean, 1 = new finding, 2 = scan blind.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse
from _baseline import Finding, gate
from lint_unpinned_text_io import _is_test_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unbounded_whole_read_baseline.json")

EXCLUDED_DIRS = frozenset({".venv", "__pycache__"})
#: The shared bounded read step, relative to the scan root: its reads are capped by construction.
IO_REL = "_io.py"
#: A marker with a reason after the dash. A bare `ok` does not suppress.
_MARKER = re.compile(r"lint-whole-read: ok\s*(?:—|--?)\s*\S")

_READS = ("read_text", "read_bytes")


def _kind(call: ast.Call) -> str | None:
    """``read_text``/``read_bytes`` for a whole-file read by path, else None."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in _READS:
        return func.attr
    return None


def _marked(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno  # type: ignore[attr-defined]
    end = getattr(node, "end_lineno", start) or start
    return any(_MARKER.search(lines[i - 1]) for i in range(start, end + 1) if 0 < i <= len(lines))


def _scan_file(rel: str, tree: ast.Module, lines: list[str], honor_markers: bool) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if (isinstance(node, ast.Call) and (kind := _kind(node))
                and not (honor_markers and _marked(node, lines))):
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=f"{rel}:{node.lineno}: whole-file {kind} with no size limit "
                            f"(in {func_name}())",
                ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path, *, honor_markers: bool = True) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree).
    ``honor_markers=False`` also reports marked reads (the census of every whole read)."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel == IO_REL or EXCLUDED_DIRS.intersection(Path(rel).parts) or _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines(), honor_markers))
    return findings


HEADER = (
    "lint_unbounded_whole_read baseline — whole-file read_text/read_bytes by path outside "
    "defender/_io (#1188). Fingerprint is defender/<file>:<function>:<kind>. This baseline ships "
    "EMPTY: a deliberate read carries `# lint-whole-read: ok — <who writes it, what bounds it>` "
    "on its line, and an entry here is a regression someone chose."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    root = SCOPE if scope is None else scope
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    # An injected scope scans unprefixed (the tests' fingerprints); the real run prefixes the
    # repo-relative root.
    prefix = "" if scope is not None else f"{root.relative_to(REPO_ROOT).as_posix()}/"
    try:
        findings = [Finding(fingerprint=prefix + f.fingerprint, display=prefix + f.display)
                    for f in _scan(root)]
    except ScanBlind as exc:
        print(f"lint_unbounded_whole_read: {exc}", file=sys.stderr)
        return 2
    print(
        "Read a whole file through defender._io (read_text_utf8 / read_plain / read_guarded …, "
        "capped at READ_LIMIT), or mark the line `# lint-whole-read: ok — <who writes the file "
        "and what bounds it>`."
    )
    return gate(
        findings, baseline, args,
        label="lint_unbounded_whole_read", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main())
