#!/usr/bin/env python3
"""Link-following read of a box-writable tree: the read-side twin of
``lint_unguarded_tree_write``.

A run dir is the box's rw bind, so an entry there may be a symlink the model planted. Writes
into such trees go through alias-refusing primitives; reads must not trust the same directory
when it is stat'ed and copied. ``defender/_run_paths.artifact_file`` / ``artifact_dir`` are
the answer — both ``lstat``, so they judge the entry rather than what it points at — and this
gate makes reaching for them the default.

What it flags, inside `SCOPE` (``defender/``) and only in `LINT_TREE_READER_MODULES`:

* a call resolving to ``shutil.copy`` / ``copy2`` / ``copyfile`` / ``copytree`` / ``move``.
  All five follow a link at the source, so copying a planted link writes the target's bytes
  into learning state under an artifact's name. Resolved by callee, so aliases count.
* the duck-typed ``<x>.is_file()`` / ``<x>.is_dir()`` shapes (the receiver is a ``Path``
  value, not a module).

What it does not flag:

* ``artifact_file`` / ``artifact_dir`` — plain calls, never matching by construction.
* ``.exists()``. ``is_file()``/``is_dir()`` are admit checks, where following a link admits
  the target. ``.exists()`` here is a refuse check ("something is already here, so stop"),
  where following a link fails closed; the safe idiom ``p.exists() or p.is_symlink()`` also
  covers the broken link. Flagging it would bury real findings under correct code.
* ``.is_symlink()`` / ``.lstat()`` — the link-aware spellings.

Scoped to a positive census rather than all of ``defender/`` because ``.is_file()`` on a
config path or fixture is ordinary and correct. The census is the set of modules that read a
path inside a run dir, an episode dir, or the drain corpus. A module that reads such a tree
and is not listed is not covered, so keep the census current.

Ratcheted like its write-side twin (``lint_tree_read_follows_link_baseline.json``), with
``require_reasons`` on: every entry must be annotated.

Run from repo root:  python scripts/lint/lint_tree_read_follows_link.py
Regenerate the baseline:  python scripts/lint/lint_tree_read_follows_link.py --update-baseline
Exit 0 = clean, 1 = new sites or an un-triaged baseline entry, 2 = scan blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, require_paths
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_tree_read_follows_link_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")

#: Copy helpers that follow a link at the source. ``copytree``'s ``symlinks=True`` governs what
#: it finds while walking, not the root it was handed.
_UNSAFE_CALLEES = frozenset({
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
})

#: The link-following admit predicates (``exists`` is deliberately absent; see module doc).
_UNSAFE_METHODS = frozenset({"is_file", "is_dir"})

#: Modules that read a path inside a box-writable tree (a run dir, an episode dir, the drain
#: corpus). A module that grows such a read and is not added here is not covered.
LINT_TREE_READER_MODULES: frozenset[str] = frozenset({
    "_provenance.py",
    "run_common.py",
    "runtime/branch/__init__.py",
    "runtime/branch/_frontier.py",
    "runtime/branch/_seed.py",
    "runtime/branch/_spec.py",
    "learning/branch/cli.py",
    "learning/branch/capture.py",
    "learning/branch/ledger.py",
    "learning/core/persist.py",
    "learning/lead_repository.py",
    # Readers of the episode tree: sibling run dirs (each a box's rw bind) plus archived
    # copies taken out of them.
    "learning/branch/archive.py",
    "learning/branch/episode.py",
    "learning/branch/review.py",
    "learning/branch/staging.py",
    # The stage timing record at the episode root.
    "learning/branch/timing.py",
    "learning/branch/questioner/__init__.py",
    "runtime/branch/_family.py",
    # The family judge, whose input is the episode tree: archived world dirs, the episode's
    # `judge.yaml`/`review.yaml`/`family.yaml`, per-draw records, and the runs base.
    "learning/judge/__init__.py",
    "learning/judge/enqueue.py",
    "learning/judge/family.py",
    "learning/judge/render.py",
    # The episode page, rendered from the episode tree through package readers.
    "scripts/visualize/visualize_episode.py",
})

SUPPRESS_MARKERS = ("lint-tree-read-follows-link: ok",)


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


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _unsafe_reason(call: ast.Call, env: ModuleEnv) -> str | None:
    origin = callee(call, env)
    if origin in _UNSAFE_CALLEES:
        return origin
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in _UNSAFE_METHODS:
        return f"<value>.{func.attr}"
    return None


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    if _is_test_module(rel) or rel not in LINT_TREE_READER_MODULES:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    env = module_env(tree)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and not _suppressed(node, lines):
            reason = _unsafe_reason(node, env)
            if reason is not None:
                fp = f"{rel}:{func_name}:{reason}"
                if fp not in seen:
                    seen.add(fp)
                    findings.append(Finding(
                        fingerprint=fp,
                        display=(
                            f"{rel}:{node.lineno}: link-following read of a box-writable tree "
                            f"({reason}) in {func_name}() — judge the entry with "
                            f"defender._run_paths.artifact_file / artifact_dir (both lstat) "
                            f"before admitting or copying it"
                        ),
                    ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_tree_read_follows_link baseline — a stat or copy that follows a symlink while "
    "reading a tree a live box can write (a run dir, an episode dir, the drain corpus). "
    "Fingerprint is file:function:idiom, file relative to the scan scope. Scope is the "
    "LINT_TREE_READER_MODULES census. Every entry needs a reason (require_reasons is on). "
    "Regenerate: python scripts/lint/lint_tree_read_follows_link.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    try:
        if root.resolve() == SCOPE.resolve():
            # Over this repo only: a planted tree under test holds a subset on purpose.
            require_paths(root, LINT_TREE_READER_MODULES)
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_tree_read_follows_link: {exc}", file=sys.stderr)
        return 2

    print(
        "Judge an entry in a box-writable tree with defender._run_paths.artifact_file / "
        "artifact_dir (lstat) rather than is_file()/is_dir()/shutil.copy*, which follow a link "
        "and admit its target."
    )
    print("Mark a sanctioned exception with `# lint-tree-read-follows-link: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_tree_read_follows_link", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main())
