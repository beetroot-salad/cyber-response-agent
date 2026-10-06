#!/usr/bin/env python3
"""Unbounded whole-file read: flag a read under ``defender/`` that takes a whole file into
memory by path, outside ``defender._io`` (#1188, design amendment 3).

A whole-file read sizes its buffer from the file. A box-planted sparse file (``truncate -s
1T``) once made that a ``MemoryError``, which is not an ``OSError``, so it skipped every
reader's fail-safe path and crashed the host process. Two things now bound it:

- the writer: every box starts with ``--ulimit fsize=READ_LIMIT`` (#1198), so no file a box
  process writes is larger than ``defender._io.READ_LIMIT``;
- the reader: every read through ``_io`` is capped at ``READ_LIMIT``, and a caller's ``limit``
  can only lower it (#1188 D1).

A direct ``read_text``/``read_bytes`` has neither guarantee for a file a HOST process writes:
tool writes for the model, logs, queues, alert copies, backend payloads. A per-site reason
for why one is still bounded proved easy to get wrong, so production code reads through
``_io`` instead; the only exceptions are stdlib-only modules that run where ``defender``
cannot be imported.

What it flags, under ``defender/`` production code (tests and the root ``_io.py`` excluded):
any use of an attribute named ``read_text`` / ``read_bytes``, called or not, matched by name
whatever the receiver. That covers ``p.read_text()``, the class-qualified ``Path.read_text(p)``
(and ``pathlib.Path.read_bytes(p)``, an aliased ``P.read_text(p)``: the same attribute, with
the class as receiver), and a method reference handed on (``map(Path.read_text, ps)``,
``partial(Path.read_bytes, p)``, ``r = p.read_text``).

What it does not flag: ``getattr(p, "read_text")``; reads through an open handle
(``f.read()``, ``json.load(f)``, ``open(p).read()``) and ``sys.stdin``, because there is no
handle tracking and none of them reads a path today; and ``_io``'s own readers, whose cap
cannot be lifted.

The remedy is ``_io.read_text_utf8`` (for ``read_text(encoding="utf-8")``) or
``_io.read_bytes_capped`` (for ``read_bytes()``): the same semantics, capped. Production code
holds no direct whole read (#1188 amendment 3). A rare deliberate exception takes
``# lint-whole-read: ok — <reason>`` on the read's line span; the reason must be text, not just
dashes. Today's exceptions are stdlib-only modules run without ``defender`` on ``sys.path``
(``runtime/box/_image.py`` and two eval scripts). The baseline ships EMPTY, so a new direct
read fails CI.

Run from repo root:  python scripts/lint/lint_unbounded_whole_read.py
Exit 0 = clean, 1 = new finding, 2 = scan blind.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, source_files
from _baseline import Finding, gate
from lint_unpinned_text_io import _is_test_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unbounded_whole_read_baseline.json")

EXCLUDED_DIRS = frozenset({".venv", "__pycache__"})
#: The shared bounded read step, relative to the scan root: its reads are capped by construction.
IO_REL = "_io.py"
#: A marker with a reason after the dash. A bare `ok`, or one followed only by dashes, does not
#: suppress.
_MARKER = re.compile(r"lint-whole-read: ok\s*(?:—|--?)[\s—-]*[^\s—-]")

_READS = ("read_text", "read_bytes")


def _kind(node: ast.AST) -> str | None:
    """``read_text``/``read_bytes`` for a use of a whole-file reader, called or not, else None."""
    if isinstance(node, ast.Attribute) and node.attr in _READS:
        return node.attr
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
        # A called reader is judged over the whole call's lines (a marker may sit on an
        # argument line); its `func` attribute is then not visited on its own.
        called = isinstance(node, ast.Call) and _kind(node.func) is not None
        kind = _kind(node.func) if called else _kind(node)  # type: ignore[attr-defined]
        if kind and not (honor_markers and _marked(node, lines)):
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=f"{rel}:{node.lineno}: whole-file {kind} with no size limit "
                            f"(in {func_name}())",
                ))
        for child in ast.iter_child_nodes(node):
            if not (called and child is node.func):  # type: ignore[attr-defined]
                visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path, *, honor_markers: bool = True) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree).
    ``honor_markers=False`` also reports marked reads (the census of every whole read)."""
    findings: list[Finding] = []
    for rel in source_files(root, EXCLUDED_DIRS):
        if rel == IO_REL or _is_test_module(rel):
            continue
        path = root / rel
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines(), honor_markers))
    return findings


HEADER = (
    "lint_unbounded_whole_read baseline — whole-file read_text/read_bytes by path outside "
    "defender/_io (#1188). Fingerprint is defender/<file>:<function>:<kind>. This baseline ships "
    "EMPTY: read through _io.read_text_utf8 / read_bytes_capped, or mark a rare exception "
    "`# lint-whole-read: ok — <reason>` on its line. An entry here is a regression someone chose."
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
        "Read a whole file through defender._io — read_text_utf8 for read_text(encoding='utf-8'), "
        "read_bytes_capped for read_bytes(): the same semantics, capped at READ_LIMIT. A rare "
        "deliberate exception takes `# lint-whole-read: ok — <reason>` on its line."
    )
    return gate(
        findings, baseline, args,
        label="lint_unbounded_whole_read", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main())
