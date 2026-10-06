#!/usr/bin/env python3
"""Unpinned text-I/O: flag text reads/writes under ``defender/`` and the ``spec-flow/scripts/``
tool tree that decode or encode under the ambient locale instead of pinning ``encoding="utf-8"``.

Every text file this system touches is UTF-8 (lessons corpora with em-dashes, invlang
companions, vendor alerts). A bare ``read_text()`` / ``open(p)`` / ``write_text(s)`` uses
``locale.getencoding()``, which is ascii on an image where the C locale cannot be coerced
(PEP 538 handles most, not all). Three failures follow, only the first loud:

1. Read raises. A valid UTF-8 lesson containing ``café`` dies with ``UnicodeDecodeError``;
   where a guard warn-skips it, the lesson silently vanishes from retrieval.
2. Write mangles. An ambient-locale write beside a pinned read commits latin-1 bytes that
   every later reader warn-skips.
3. The pipe. ``subprocess.run(..., text=True)`` decodes the child's stdout under the
   parent's locale, and the children here print corpus text.

A convention that lives only in a docstring gets re-derived wrong, hence a gate. ruff's
``PLW1514`` covers only calls where it can infer a ``pathlib.Path`` receiver; this check is
syntactic on purpose.

What it flags, under the scanned trees (``defender/`` production code + ``spec-flow/scripts/``):

- ``<x>.read_text(...)`` / ``<x>.write_text(...)`` with no ``encoding=`` keyword
- an opener in text mode with no ``encoding=`` — ``open`` / ``io.open`` / ``codecs.open`` /
  ``os.fdopen``, the compression openers ``gzip``/``bz2``/``lzma`` (binary by default, but
  they take ``encoding=`` in text mode), the ``tempfile`` openers, and any other
  ``<x>.open(...)`` (the duck-typed ``<p>.open(...)`` above all)
- ``subprocess.run/Popen/check_output/call/check_call(..., text=True |
  universal_newlines=True)`` with no ``encoding=``

Each callee is identified by resolved origin (``scripts/lint/_astlib.py``), not spelling, so
aliases count — and the mode's positional slot and default are properties of the callee
(``open(file, mode)`` is path-first, ``Path.open(mode)`` is not; ``gzip.open`` defaults to
``"rb"``).

What it does not flag: ``read_bytes``/``write_bytes`` and any binary mode; ``os.open`` (an
fd; its third arg is permission bits) and ``tarfile.open`` (no ``encoding`` parameter); a
``subprocess`` call without ``text=True``; an opener whose mode is a non-literal expression
(a hoisted ``MODE = "r"`` module constant is resolved, so it is not an escape hatch).

An ``.open`` whose origin is not in the opener tables is treated as the duck-typed opener,
never skipped: the receiver may be an imported object (``PATHS.lessons_dir.open()`` resolves
cleanly), and skipping it would drop exactly the Path-like open this gate exists for. Skips
come from a positive table only.

Known limitation — a handle bound to a local: ``zf = zipfile.ZipFile(p); zf.open(n)`` is
indistinguishable from the Path-like ``p.open(n)`` without local-binding tracking, so it is
flagged. It fails safe (a false alarm); ``# lint-text-io: ok — <reason>`` is the remedy. The
same holds for an untabled module opener called with a literal path.

Tests are out of scope: a fixture must be free to write deliberately undecodable or latin-1
files.

Under ``defender/`` the canonical readers are ``defender._io.read_text_utf8`` (pinned, raising)
and ``read_text_soft`` (pinned, returns ``(text, reason)``); the write-side pin for a CLI's
stdout is ``defender._io.use_utf8_stdio``. Guard a read with ``defender._io.TEXT_READ_ERRORS``:
a ``UnicodeDecodeError`` is a ``ValueError``, not an ``OSError`` (nor a
``json.JSONDecodeError``), so ``except OSError`` does not hold it. Under ``spec-flow/scripts/``
those helpers are out of reach (the plugin has no ``defender`` on its path), so pin
``encoding="utf-8"`` inline and, for a CLI, reconfigure ``sys.stdout``/``stderr`` in ``main``
as ``check_actors.py`` does.

Mark a deliberate site with ``# lint-text-io: ok — <reason>`` on the call's line span.
Pre-existing sites are ratcheted via ``lint_unpinned_text_io_baseline.json``; the gate fails
only on a new file+function pair. Fingerprints are prefixed with the tree-relative path
(``defender/…`` vs ``spec-flow/scripts/…``) so the two trees can't collide. The baseline ships
empty, so an entry is a chosen regression.

Run from repo root:  python scripts/lint/lint_unpinned_text_io.py
Regenerate the baseline:  python scripts/lint/lint_unpinned_text_io.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import (
    ScanBlind,
    read_and_parse,
    ModuleEnv,
    callee,
    has_kw,
    kw_is_true,
    module_env,
    open_mode,
    opener_slot,
    source_files,
)
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
# The trees this gate scans. `defender/` is production code with the `defender._io` helpers
# one import away. `spec-flow/scripts/` is standalone plugin tooling that cannot import
# `defender._io`, so its sites pin `encoding="utf-8"` inline; an unpinned read there can drop a
# non-ASCII source file's import edges and report clean.
SCOPES = (REPO_ROOT / "defender", REPO_ROOT / "spec-flow" / "scripts")
BASELINE_PATH = Path(__file__).with_name("lint_unpinned_text_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKERS = ("lint-text-io: ok",)

_SUBPROCESS_ORIGINS = tuple(
    f"subprocess.{f}" for f in ("run", "Popen", "check_output", "call", "check_call")
)


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _kind(call: ast.Call, env: ModuleEnv) -> str | None:
    """Which unpinned-text-IO shape this call is, or None."""
    if has_kw(call, "encoding"):
        return None  # pinned, whatever it is

    # `<p>.read_text()` / `<p>.write_text(s)` — duck-typed Path-like, by attribute name.
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in ("read_text", "write_text"):
        return func.attr.split("_")[0]

    # subprocess by resolved origin, so `from subprocess import run` is caught and a local
    # `runner.run(cmd, text=True)` wrapper is not.
    if callee(call, env) in _SUBPROCESS_ORIGINS:
        # Only a text-mode child pipe decodes.
        if kw_is_true(call, "text") or kw_is_true(call, "universal_newlines"):
            return "subprocess"
        return None

    if opener_slot(call, env) is None:
        return None
    # The mode comes from the callee's resolved slot, else the callee's own default (text
    # for open/io/codecs, binary for gzip/bz2/lzma/tempfile). An unreadable mode expression
    # is unflagged; the gate does not guess.
    mode = open_mode(call, env)
    return "open" if mode is not None and "b" not in mode else None


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
    env = module_env(tree)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and (kind := _kind(node, env)) and not _suppressed(node, lines):
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


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for rel in source_files(root, EXCLUDED_DIRS):
        path = root / rel
        if _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


def _prefixed_scan(root: Path, prefix: str) -> list[Finding]:
    """`_scan(root)` with `prefix` prepended to every fingerprint and display, so findings in
    the two trees never collide. An empty prefix is the single-scope test seam."""
    if not prefix:
        return _scan(root)
    return [
        Finding(fingerprint=prefix + f.fingerprint, display=prefix + f.display)
        for f in _scan(root)
    ]


HEADER = (
    "lint_unpinned_text_io baseline — text reads/writes under defender/ and spec-flow/scripts/ "
    "that decode or encode under the AMBIENT LOCALE instead of pinning encoding=\"utf-8\" "
    "(#588/#589; scope widened to the spec-graph tooling in #655). Fingerprint is "
    "<tree>/file:function:kind (read|write|open|subprocess; no line number), path relative to the "
    "repo root. CI fails on a fingerprint absent here. This baseline ships EMPTY — an entry in it is "
    "a regression someone chose. Regenerate: python scripts/lint/lint_unpinned_text_io.py "
    "--update-baseline."
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
    # An injected `scope` scans as-is with no prefix (the tests' fingerprints). The real run
    # prefixes each root's repo-relative path, so one baseline entry cannot silence a
    # same-named site in the other tree.
    roots = [scope] if scope is not None else list(SCOPES)
    for root in roots:
        if not root.is_dir():
            print(f"scan scope not found at {root}", file=sys.stderr)
            return 2
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    findings: list[Finding] = []
    try:
        for root in roots:
            prefix = "" if scope is not None else f"{root.relative_to(REPO_ROOT).as_posix()}/"
            findings.extend(_prefixed_scan(root, prefix))
    except ScanBlind as exc:
        print(f"lint_unpinned_text_io: {exc}", file=sys.stderr)
        return 2
    print(
        'Pin every text read/write to UTF-8: defender._io.read_text_utf8 / read_text_soft '
        'for reads, encoding="utf-8" on write_text/open, encoding="utf-8" on a '
        "subprocess text=True pipe. And guard a read with defender._io.TEXT_READ_ERRORS — "
        "a UnicodeDecodeError is a ValueError, NOT an OSError (#589)."
    )
    print("Mark a deliberate site with `# lint-text-io: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_unpinned_text_io", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
