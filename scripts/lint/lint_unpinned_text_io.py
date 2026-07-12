#!/usr/bin/env python3
"""Unpinned text-I/O — flag text reads/writes under ``defender/`` that decode or encode
under the **ambient locale** instead of pinning ``encoding="utf-8"``.

Every text file this system touches is UTF-8 and says so: the lessons corpora (42 of the
checked-in lessons carry non-ASCII, em-dashes in ``description`` above all), the invlang
companions the defender authors, the alerts a vendor hands us. A bare ``read_text()`` /
``open(p)`` / ``write_text(s)`` does NOT read or write UTF-8 — it uses
``locale.getencoding()``, which on an image where the C locale cannot be coerced (PEP 538
handles most, not all) is ascii. Three failures follow, and only the first is loud:

1. **Read raises.** A valid UTF-8 lesson containing ``café`` dies with an ascii
   ``UnicodeDecodeError``. Where a guard warn-skips it, the lesson silently vanishes from
   the actor's retrieval and the curator's manifest — data loss dressed as a malformed file.
2. **Write mangles.** An ambient-locale write beside a pinned read is worse than either
   alone: the lesson is written as latin-1 bytes, committed, and then warn-skipped by every
   walk that reads it back (#588).
3. **The pipe.** ``subprocess.run(..., text=True)`` decodes the CHILD's stdout under the
   parent's ambient locale — and the children here (``defender-lessons``,
   ``defender-invlang``) print corpus text by design.

The gate exists because of the SECOND bug, not the first: #589 was a hand-rolled copy of a
guard that ``defender/_corpus.py`` already had right, one directory over, complete with a
docstring explaining the trap. A convention that lives only in a docstring gets re-derived
wrong. (ruff's ``PLW1514`` covers part of this surface, but only where it can infer a
``pathlib.Path`` receiver — it misses ``runtime/tools.py``'s reads, i.e. #588 itself. This
check is syntactic on purpose.)

What it flags, under ``defender/`` production code:

- ``<x>.read_text(...)`` / ``<x>.write_text(...)`` with no ``encoding=`` keyword
- ``open(...)`` / ``<x>.open(...)`` in TEXT mode (mode literal absent, or present with no
  ``b``) with no ``encoding=``
- ``subprocess.run/Popen/check_output(..., text=True | universal_newlines=True)`` with no
  ``encoding=``

What it does NOT flag: ``read_bytes``/``write_bytes`` and any binary mode (there is nothing
to decode); ``os.open`` and the ``gzip``/``io``/``tarfile``/``zipfile`` openers (fds and
binary streams, no encoding parameter to give); a ``subprocess`` call with no ``text=True``
(bytes in, bytes out); an ``open(p, mode)`` whose mode is a non-literal expression (the gate
cannot know it is text, and guessing would make it unusable).

Tests are out of scope: a fixture must be free to ``write_bytes`` a deliberately-undecodable
file, or to shape a latin-1 one, which is exactly what the #589/#588 suite does.

The canonical readers are ``defender._io.read_text_utf8`` (pinned, raising) and
``read_text_soft`` (pinned, returns ``(text, reason)``); the matching WRITE-side pin for a
CLI's stdout is ``defender._io.use_utf8_stdio``. And when you guard a read, guard it with
``defender._io.TEXT_READ_ERRORS`` — a ``UnicodeDecodeError`` is a ``ValueError``, NOT an
``OSError``, and not a ``json.JSONDecodeError`` either, so an ``except OSError`` around a
read does not hold it (that is #589, exactly).

Mark a deliberate site with ``# lint-text-io: ok — <reason>`` on the call's line span.
Pre-existing sites are ratcheted via ``lint_unpinned_text_io_baseline.json``; the gate fails
only on a NEW file+function pair. The baseline ships EMPTY — every site under defender/ was
pinned when the gate landed, so an entry appearing in it is a regression someone chose.

Run from repo root:  python scripts/lint/lint_unpinned_text_io.py
Regenerate the baseline:  python scripts/lint/lint_unpinned_text_io.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unpinned_text_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-text-io: ok",)

# Openers that take no `encoding` at all — an fd (`os.open`) or a binary stream.
_NON_TEXT_OPENER_ROOTS = ("os", "gzip", "io", "tarfile", "zipfile", "shutil")

_SUBPROCESS_FUNCS = ("run", "Popen", "check_output", "call", "check_call")


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _has_kw(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def _kw_is_true(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _open_receiver_root(call: ast.Call) -> str | None:
    """For ``<root>.…​.open(...)``, the root Name id — so ``os.open`` can be told from
    ``path.open``. None for a bare ``open(...)`` or an unnamable receiver."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    cur: ast.expr = func.value
    while isinstance(cur, (ast.Attribute, ast.Subscript, ast.Call)):
        cur = cur.value if not isinstance(cur, ast.Call) else cur.func
    return cur.id if isinstance(cur, ast.Name) else None


def _open_mode(call: ast.Call) -> str | None:
    """The mode string of an ``open(...)``/``.open(...)`` call, or None when it is not a
    string literal. ``open(p, "a")`` reads the 2nd positional; ``p.open("a")`` the 1st; both
    honor ``mode=``. A mode-less open defaults to read — i.e. TEXT."""
    func = call.func
    mode_arg: ast.expr | None = None
    if isinstance(func, ast.Name) and func.id == "open":
        mode_arg = call.args[1] if len(call.args) >= 2 else None
    elif isinstance(func, ast.Attribute) and func.attr == "open":
        mode_arg = call.args[0] if call.args else None
    if mode_arg is None:
        for kw in call.keywords:
            if kw.arg == "mode":
                mode_arg = kw.value
                break
    if mode_arg is None:
        return "r"
    if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
        return mode_arg.value
    return None


def _kind(call: ast.Call) -> str | None:
    """Which unpinned-text-IO shape this call is, or None."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        # a bare `open(...)`
        if isinstance(func, ast.Name) and func.id == "open" and not _has_kw(call, "encoding"):
            mode = _open_mode(call)
            if mode is not None and "b" not in mode:
                return "open"
        return None

    attr = func.attr
    if attr in ("read_text", "write_text"):
        return None if _has_kw(call, "encoding") else attr.split("_")[0]
    if attr == "open":
        if _open_receiver_root(call) in _NON_TEXT_OPENER_ROOTS or _has_kw(call, "encoding"):
            return None
        mode = _open_mode(call)
        return "open" if mode is not None and "b" not in mode else None
    if attr in _SUBPROCESS_FUNCS and not _has_kw(call, "encoding"):
        # Only a TEXT-mode child pipe decodes; a bytes-mode one has nothing to get wrong.
        if _kw_is_true(call, "text") or _kw_is_true(call, "universal_newlines"):
            return "subprocess"
    return None


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno  # type: ignore[attr-defined]
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


_ADVICE = {
    "read": "unpinned read_text() — use defender._io.read_text_utf8/read_text_soft",
    "write": 'unpinned write_text() — pass encoding="utf-8"',
    "open": 'unpinned text-mode open() — pass encoding="utf-8"',
    "subprocess": 'subprocess text=True with no encoding= — the child pipe decodes under the ambient locale',
}


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and (kind := _kind(node)) and not _suppressed(node, lines):
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=f"{rel}:{node.lineno}: {_ADVICE[kind]} (in {func_name}())",
                ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(SCOPE.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if _is_test_module(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unpinned_text_io baseline — text reads/writes under defender/ that decode or "
    "encode under the AMBIENT LOCALE instead of pinning encoding=\"utf-8\" (#588/#589). "
    "Fingerprint is file:function:kind (read|write|open|subprocess; no line number). CI "
    "fails on a fingerprint absent here. This baseline ships EMPTY — an entry in it is a "
    "regression someone chose. Regenerate: python scripts/lint/lint_unpinned_text_io.py "
    "--update-baseline."
)


def main(argv: list[str]) -> int:
    if not SCOPE.is_dir():
        print(f"defender/ not found at {SCOPE}", file=sys.stderr)
        return 2
    findings = _scan()
    print(
        'Pin every text read/write to UTF-8: defender._io.read_text_utf8 / read_text_soft '
        'for reads, encoding="utf-8" on write_text/open, encoding="utf-8" on a '
        "subprocess text=True pipe. And guard a read with defender._io.TEXT_READ_ERRORS — "
        "a UnicodeDecodeError is a ValueError, NOT an OSError (#589)."
    )
    print("Mark a deliberate site with `# lint-text-io: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_unpinned_text_io", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
