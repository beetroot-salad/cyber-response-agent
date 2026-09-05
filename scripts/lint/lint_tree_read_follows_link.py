#!/usr/bin/env python3
"""Link-following READ of a box-writable tree — the read-side twin of
``lint_unguarded_tree_write``.

#771 M3 settled the write side: a run dir is the box's rw bind, so an entry there may be a
symlink the model planted, and every write into such a tree goes through the alias-refusing
primitives. The READ side got no such seam, and the asymmetry is the bug: the same directory
this repo refuses to write through unexamined is trusted when it is stat'ed and copied.
``defender/_run_paths.artifact_file`` / ``artifact_dir`` are the answer — both ``lstat``, so
they judge the ENTRY rather than what it points at — and this gate is what makes reaching for
them the default instead of a thing an author has to remember.

What it flags, inside `SCOPE` (``defender/``) and only in `LINT_TREE_READER_MODULES`:

* a call resolving to ``shutil.copy`` / ``copy2`` / ``copyfile`` / ``copytree`` / ``move``.
  All five follow a link at the SOURCE, so copying a planted link writes the TARGET's bytes
  into learning state under an artifact's name, where every later reader takes them for a
  legitimate in-run file. Resolved by CALLEE, so ``from shutil import copy2 as cp`` is the
  same finding as the spelled form.
* the duck-typed ``<x>.is_file()`` / ``<x>.is_dir()`` shapes. Unresolvable by import origin —
  the receiver is a ``Path`` VALUE, not a module — and matched the same way
  ``lint_unguarded_tree_write`` matches ``<x>.write_text(...)``.

What it does NOT flag, and why the omissions are the gate's whole precision:

* ``artifact_file`` / ``artifact_dir`` — the sanctioned lstat predicates. They are plain
  calls, not attribute calls on a value, so they never match by construction.
* ``.exists()``. The asymmetry is real, not an oversight. ``is_file()``/``is_dir()`` are
  ADMIT checks — "this is the right kind of thing, so act on it" — and following a link
  there admits the target. ``.exists()`` in this tree is a REFUSE check ("something is
  already here, so stop"), where following a link fails CLOSED: the established safe idiom
  is ``p.exists() or p.is_symlink()``, which covers the broken link ``exists()`` alone
  misses. Flagging it would bury this gate's real findings under the pattern that is already
  correct.
* ``.is_symlink()`` / ``.lstat()`` — the link-aware spellings themselves.

Scoped to a POSITIVE census rather than all of ``defender/`` because ``.is_file()`` on a
config path, a fixture, or an interpreter is ordinary and correct everywhere else; a gate that
flagged those would carry a baseline nobody reads. The census is the set of modules that read
a path INSIDE a run dir, an episode dir, or the drain corpus — the trees a live box can write.
Adding a module that reads such a tree and not adding it here is the failure mode; the census
is small enough to review in a diff for exactly that reason.

Ratcheted like its write-side twin (``lint_tree_read_follows_link_baseline.json``), with
``require_reasons`` ON: the baseline ships small and fully annotated, so an entry added later
with an empty reason fails the gate rather than joining a wall of un-triaged debt.

Run from repo root:  python scripts/lint/lint_tree_read_follows_link.py
Regenerate the baseline:  python scripts/lint/lint_tree_read_follows_link.py --update-baseline
Exit 0 = clean, 1 = new sites or an un-triaged baseline entry, 2 = scan blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_tree_read_follows_link_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

#: Copy helpers that follow a link at the SOURCE. ``copytree``'s ``symlinks=True`` governs what
#: it finds while WALKING and says nothing about the root it was handed, so it is here too.
_UNSAFE_CALLEES = frozenset({
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
})

#: The link-following ADMIT predicates. See the module docstring for why ``exists`` is absent.
_UNSAFE_METHODS = frozenset({"is_file", "is_dir"})

#: Modules that read a path inside a box-writable tree (a run dir, an episode dir, the drain
#: corpus). A module that grows such a read and is not added here is a module this gate stops
#: covering — the same failure ``lint_unguarded_tree_write``'s census comment names.
LINT_TREE_READER_MODULES: frozenset[str] = frozenset({
    "_provenance.py",
    "run_common.py",
    "runtime/branch.py",
    "learning/branch/cli.py",
    "learning/branch/capture.py",
    "learning/branch/ledger.py",
    "learning/core/persist.py",
    "learning/lead_repository.py",
    # #947's readers of the episode tree, which holds three sibling run dirs (each a box's rw
    # bind) plus the archived copies taken out of them. `archive.py` in particular already
    # carried a `lint-tree-read-follows-link: ok` marker, which suppressed a gate that was not
    # scanning the file — "adding a module that reads such a tree and not adding it here is the
    # failure mode", per the module docstring above.
    "learning/branch/archive.py",
    "learning/branch/episode.py",
    "learning/branch/review.py",
    "learning/branch/staging.py",
    "learning/branch/questioner/__init__.py",
    "runtime/branch/_family.py",
    # #921's family judge, whose whole input is that same episode tree read back: the archived
    # world dirs (copied out of three boxes' rw binds), the episode's own `judge.yaml`/
    # `review.yaml`/`family.yaml`, the per-draw records it writes and re-reads, and the
    # operator's runs base. Four modules that grow such reads and are not added here are four
    # modules this gate stops covering — the failure mode this census's own comment names.
    "learning/judge/__init__.py",
    "learning/judge/enqueue.py",
    "learning/judge/family.py",
    "learning/judge/render.py",
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
