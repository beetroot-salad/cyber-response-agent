#!/usr/bin/env python3
"""Unpinned text-I/O — flag text reads/writes under ``defender/`` and the ``spec-flow/scripts/``
tool tree that decode or encode under the **ambient locale** instead of pinning ``encoding="utf-8"``.

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

What it flags, under the scanned trees (``defender/`` production code + ``spec-flow/scripts/``):

- ``<x>.read_text(...)`` / ``<x>.write_text(...)`` with no ``encoding=`` keyword
- an OPENER in TEXT mode with no ``encoding=`` — ``open`` / ``io.open`` / ``codecs.open`` /
  ``os.fdopen``, the compression openers ``gzip``/``bz2``/``lzma`` (binary by default, but
  they take ``encoding=`` in text mode), the ``tempfile`` openers, and any other
  ``<x>.open(...)`` (the duck-typed ``<p>.open(...)`` above all — see below)
- ``subprocess.run/Popen/check_output/call/check_call(..., text=True |
  universal_newlines=True)`` with no ``encoding=``

Each callee is identified by its RESOLVED ORIGIN (``scripts/lint/_astlib.py``), not by how
it was spelled — ``from subprocess import run`` and ``import gzip as gz`` are the same case
as the dotted form. That is not merely alias-proofing: the mode's positional slot and its
default are properties of the callee (``open(file, mode)`` is path-first, ``Path.open(mode)``
is not; ``gzip.open`` defaults to ``"rb"`` where ``open`` defaults to ``"r"``), and this gate
used to GUESS both — reading ``args[0]`` as the mode of any ``<x>.open(...)``, i.e. reading
the file path as the mode string (#594/#602).

What it does NOT flag: ``read_bytes``/``write_bytes`` and any binary mode (nothing to
decode); ``os.open`` (an fd — its third arg is the PERMISSION bits, not a text mode) and
``tarfile.open`` (no ``encoding`` parameter to give); a ``subprocess`` call with no
``text=True`` (bytes in, bytes out); an opener whose mode is a non-literal expression the
gate cannot read (guessing would make it unusable — a hoisted ``MODE = "r"`` module constant
IS resolved, so tidying a literal into a constant is not an escape hatch).

An ``.open`` whose origin is NOT in the opener tables is treated as the duck-typed opener,
never skipped. "It resolved, so the receiver is a module, so it is not a Path" is false: the
receiver may be an imported OBJECT — ``PATHS.lessons_dir.open()`` resolves cleanly, and
skipping it would drop exactly the Path-like open this gate exists for, with the empty
baseline staying green throughout. Skips come from a POSITIVE table only.

Known limitation — a handle bound to a local: ``zf = zipfile.ZipFile(p); zf.open(n)``. The
receiver is a VALUE, so its callee is unresolvable and indistinguishable from the Path-like
``p.open(n)`` the gate exists to catch — it is therefore treated as a text opener and
flagged. Telling the two apart needs local-binding tracking, which ``_astlib`` deliberately
does not do (#605). It fails SAFE (a false alarm, not a missed violation) and there is no
such site under ``defender/``; ``# lint-text-io: ok — <reason>`` is the sanctioned remedy.
The same is true of an untabled module opener called with a literal path.

Tests are out of scope: a fixture must be free to ``write_bytes`` a deliberately-undecodable
file, or to shape a latin-1 one, which is exactly what the #589/#588 suite does.

Under ``defender/`` the canonical readers are ``defender._io.read_text_utf8`` (pinned, raising)
and ``read_text_soft`` (pinned, returns ``(text, reason)``); the matching WRITE-side pin for a
CLI's stdout is ``defender._io.use_utf8_stdio``. And when you guard a read, guard it with
``defender._io.TEXT_READ_ERRORS`` — a ``UnicodeDecodeError`` is a ``ValueError``, NOT an
``OSError``, and not a ``json.JSONDecodeError`` either, so an ``except OSError`` around a
read does not hold it (that is #589, exactly). Under ``spec-flow/scripts/`` those helpers are out
of reach (the plugin has no ``defender`` on its path), so pin ``encoding="utf-8"`` inline and, for
a CLI, reconfigure ``sys.stdout``/``stderr`` in ``main`` — the shape ``check_actors.py`` uses.

Mark a deliberate site with ``# lint-text-io: ok — <reason>`` on the call's line span.
Pre-existing sites are ratcheted via ``lint_unpinned_text_io_baseline.json``; the gate fails
only on a NEW file+function pair. Across BOTH scanned trees a fingerprint is prefixed with the
tree-relative path (``defender/…`` vs ``spec-flow/scripts/…``) so the two can't collide. The
baseline ships EMPTY — every site under both trees was pinned when its scope came under the gate,
so an entry appearing in it is a regression someone chose.

Run from repo root:  python scripts/lint/lint_unpinned_text_io.py
Regenerate the baseline:  python scripts/lint/lint_unpinned_text_io.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import (
    ModuleEnv,
    callee,
    has_kw,
    kw_is_true,
    module_env,
    open_mode,
    opener_slot,
)
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
# The trees this gate scans. `defender/` is production code, with the canonical `defender._io`
# helpers one import away. `spec-flow/scripts/` is the portable spec-graph tooling: it CANNOT
# import `defender._io` (it ships as a standalone plugin), so its sites pin `encoding="utf-8"`
# inline — as `check_binds.py` already did and `check_actors.py`/`_config.py` now do. That tree
# was dark to this gate until #655: an unpinned read there dropped a non-ASCII source file's import
# edges and reported clean, the #643 false-clean.
SCOPES = (REPO_ROOT / "defender", REPO_ROOT / "spec-flow" / "scripts")
BASELINE_PATH = Path(__file__).with_name("lint_unpinned_text_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-text-io: ok",)

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

    if opener_slot(call, env) is None:
        return None
    # The mode comes from the callee's resolved slot, falling back to the callee's own
    # default (text for open/io/codecs, BINARY for gzip/bz2/lzma/tempfile). A mode
    # expression the gate cannot read -> unflagged; the gate does not guess.
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


def _prefixed_scan(root: Path, prefix: str) -> list[Finding]:
    """`_scan(root)` with `prefix` prepended to every fingerprint AND display. The real run passes
    each scope's repo-relative path (`defender/`, `spec-flow/scripts/`) so a finding in one tree can
    never collide with a same-path finding in the other; an empty prefix is the single-scope test
    seam, returning `_scan(root)` untouched."""
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
    # A single injected `scope` scans as-is — fingerprints relative to it, no prefix — so the
    # `_scan(tree)` tests keep their exact fingerprints. The real run scans EVERY root in SCOPES and
    # prefixes each finding with the root's repo-relative path, so a `defender/` finding and a
    # `spec-flow/scripts/` finding can never collide on the same file:function:kind — which would let
    # one baseline entry silence a real site in the other tree.
    roots = [scope] if scope is not None else list(SCOPES)
    for root in roots:
        if not root.is_dir():
            print(f"scan scope not found at {root}", file=sys.stderr)
            return 2
    findings: list[Finding] = []
    for root in roots:
        prefix = "" if scope is not None else f"{root.relative_to(REPO_ROOT).as_posix()}/"
        findings.extend(_prefixed_scan(root, prefix))
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
