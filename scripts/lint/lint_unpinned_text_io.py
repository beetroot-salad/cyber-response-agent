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

from _astlib import ModuleEnv, arg_at, callee, has_kw, kw_is_true, module_env, str_value
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unpinned_text_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-text-io: ok",)

# Openers that DO take `encoding=`, keyed by resolved origin -> (mode's positional slot,
# mode's default). Both facts are properties of the CALLEE, and both were previously
# guessed: `_open_mode` read args[0] as the mode for every `<x>.open(...)`, which is right
# only for `Path.open(mode)`. Every module-level opener is path-FIRST, so the gate read the
# file path as the mode string — `codecs.open("f.bin", "rb")` scanned "clean" because the
# letter 'b' appears in "f.bin" (#594/#602). Verified against inspect.signature.
_OPENERS = {
    "builtins.open": (1, "r"),
    "io.open": (1, "r"),                          # io.open IS builtins.open
    "codecs.open": (1, "r"),
    "gzip.open": (1, "rb"),                       # binary by default, but takes encoding= in text mode
    "bz2.open": (1, "rb"),
    "lzma.open": (1, "rb"),
    "tempfile.NamedTemporaryFile": (0, "w+b"),
    "tempfile.TemporaryFile": (0, "w+b"),
    "tempfile.SpooledTemporaryFile": (0, "w+b"),
}
# `Path.open(mode)` and friends: the receiver is a VALUE, so the callee never resolves.
# Duck-typed on purpose — this is the case the gate most exists to catch.
_DUCK_OPENER = (0, "r")
# Genuinely encoding-less: `os.open` returns an fd (its 3rd arg is the PERMISSION bits,
# not a text mode); `tarfile.open` has no `encoding` parameter.
_NO_ENCODING_OPENERS = ("os.open", "tarfile.open")

_SUBPROCESS_ORIGINS = tuple(
    f"subprocess.{f}" for f in ("run", "Popen", "check_output", "call", "check_call")
)


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


def _opener_slot(call: ast.Call, env: ModuleEnv) -> tuple[int, str] | None:
    """``(mode's positional slot, mode's default)`` for an opener call, or None if this
    call is not an opener at all.

    The slot and the default come from the RESOLVED callee — never from the call's shape.
    A duck-typed receiver (``p.open("r")``, callee unresolvable) is an opener too, and the
    most important one: it is the Path-like case the gate exists to catch. Treating
    "unresolvable" as "skip" would silently gut this gate while the empty baseline stayed
    green.
    """
    origin = callee(call, env)
    if origin in _NO_ENCODING_OPENERS:
        return None
    if origin in _OPENERS:
        return _OPENERS[origin]
    if origin is not None:
        return None  # resolves to something else entirely — not an opener
    # Unresolvable callee: an opener only if it is spelled `.open(...)` on a value.
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return _DUCK_OPENER
    return None


def _kind(call: ast.Call, env: ModuleEnv) -> str | None:
    """Which unpinned-text-IO shape this call is, or None."""
    if has_kw(call, "encoding"):
        return None  # pinned, whatever it is

    # `<p>.read_text()` / `<p>.write_text(s)` — duck-typed Path-like, by attribute name.
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in ("read_text", "write_text"):
        return func.attr.split("_")[0]

    # subprocess by resolved ORIGIN, so `from subprocess import run` is caught and a local
    # `runner.run(cmd, text=True)` wrapper is not. The old check tested the bare attribute
    # `run`/`Popen`/… with NO receiver test at all, so it was wrong in both directions.
    if callee(call, env) in _SUBPROCESS_ORIGINS:
        # Only a TEXT-mode child pipe decodes; a bytes-mode one has nothing to get wrong.
        if kw_is_true(call, "text") or kw_is_true(call, "universal_newlines"):
            return "subprocess"
        return None

    slot = _opener_slot(call, env)
    if slot is None:
        return None
    index, default = slot
    mode_arg = arg_at(call, index, "mode")
    # No mode passed -> the callee's own default (text for open/io/codecs, BINARY for
    # gzip/bz2/lzma/tempfile). A mode expression we cannot read -> unflagged; the gate
    # does not guess.
    mode = default if mode_arg is None else str_value(mode_arg, env)
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
    """Findings under ``root``, fingerprints relative to it — so the gate is
    drivable on an injected tmp tree, not just the repo checkout."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
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
    "Fingerprint is file:function:kind (read|write|open|subprocess; no line number), file "
    "relative to the scan scope. CI fails on a fingerprint absent here. This baseline ships "
    "EMPTY — an entry in it is a regression someone chose. Regenerate: python scripts/lint/"
    "lint_unpinned_text_io.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    findings = _scan(root)
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
