#!/usr/bin/env python3
"""Every test calls the target, checked statically.

A test that never drives the target symbol asserts around it — a fixture check, a
re-implementation, an environmental probe — and stays green whatever the implementation
does. "Every test calls the target — directly, via a helper in the same file whose body
does, or by driving an object a call to the target returned" is a static reachability
question, so this script answers it.

Target identification is `_suite.target_modules`: the suite's project-rooted imports
that resolve to nothing are the not-yet-written target; `--target <dotted.module>` adds
or replaces targets for the modify-existing-code case the heuristic cannot see. A test
"touches" the target when its body — or, transitively, a same-file helper it calls, or
a function in the SAME DIRECTORY's conftest.py (a fixture) — references a symbol
imported from a target module or the target module's own name. (The third charge
clause is subsumed: an object a target call returned only exists in a body that made
the target call.)

Usage:
    spec-graph calls <suite-dir> [--target <dotted.module> ...]
Exit codes: 0 every test reaches the target; 1 a test doesn't; 2 no target could be
identified (heuristic empty and no --target given) — could-not-look, never a pass.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import _cli
import _suite


def _local_targets(tree: ast.Module, targets: dict[str, set[str]], target_names: set[str]) -> set[str]:
    """The names that reach the target from THIS file's namespace: the shared target
    names, plus whatever the file's own imports and module-level aliases bind to them."""
    local = set(target_names)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        # Match the module key too: an explicit `--target` names an existing module, for
        # which the heuristic collected no symbols.
        from_target = isinstance(node, ast.ImportFrom) and node.module in targets
        for a in node.names:
            if from_target and a.name != "*":
                local.add(a.asname or a.name)
            elif a.asname and (a.name in targets or a.name.split(".")[-1] in target_names):
                # Aliases: `from mod import target as t` / `import app.mod as m` make
                # `t` / `m` target names in this file.
                local.add(a.asname)
    # Module-level aliases (`drive = functools.partial(summarize, tmp)`, `summ = summarize`)
    # bind target-reaching names outside any function. Body order resolves alias chains.
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if _suite.names_in(node.value) & local:
                assigned = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in assigned:
                    if isinstance(t, ast.Name):
                        local.add(t.id)
    return local


def _module_refs(tree: ast.Module) -> dict[str, set[str]]:
    # Merged per name: `ast.walk` flattens methods and nested defs into one namespace, so
    # same-named helpers must union rather than overwrite each other.
    refs: dict[str, set[str]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            refs.setdefault(n.name, set()).update(_suite.names_in(n))
    return refs


def _reaching(refs: dict[str, set[str]], local_targets: set[str]) -> set[str]:
    # Fixed point: a function touches the target directly or via a same-file helper chain.
    touches = {name for name, r in refs.items() if r & local_targets}
    changed = True
    while changed:
        changed = False
        for name, r in refs.items():
            if name not in touches and r & touches:
                touches.add(name)
                changed = True
    return touches


def check(suite_dir: Path, targets: dict[str, set[str]]) -> list[str]:
    # A target is reachable by any of: a symbol imported from it, its own module name
    # (last segment, for `import a.b.c` / `a.b.c.f()` forms), or an alias of either.
    target_names: set[str] = set()
    for dotted, symbols in targets.items():
        target_names.add(dotted.split(".")[-1])
        target_names.update(symbols)

    # Same-dir conftest.py only: a fixture that reaches the target makes its name
    # target-reaching for every test here. Parent-dir conftests would need pytest's rootdir
    # discovery.
    conftest_reaching: set[str] = set()
    conftest = suite_dir / "conftest.py"
    if conftest.is_file():
        try:
            ctree = ast.parse(conftest.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            pass
        else:
            conftest_reaching = _reaching(
                _module_refs(ctree), _local_targets(ctree, targets, target_names)
            )

    findings: list[str] = []
    for py in _suite.suite_files(suite_dir):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue  # the null-stub gate reports unscannable files
        local_targets = _local_targets(tree, targets, target_names) | conftest_reaching
        refs = _module_refs(tree)
        touches = _reaching(refs, local_targets)
        for name in refs:
            if name.startswith("test_") and name not in touches:
                findings.append(
                    f"NO-CALL {py.name}::{name}: never references the target "
                    f"({sorted(local_targets)[:6]}…) — directly, through a same-file helper, "
                    f"or through a same-dir conftest fixture. A test that never drives the "
                    f"target binds nothing about it."
                )
    return findings


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, multi={"--target"})
    explicit: list[str] = opts["target"]
    if len(args) != 1:
        print("usage: spec-graph calls <suite-dir> [--target <dotted.module> ...]", file=sys.stderr)
        return 2
    suite_dir = Path(args[0]).resolve()
    # A directory with no tests is could-not-look, checked before targets because an
    # explicit `--target` would get past the no-targets arm.
    if not _suite.has_tests(suite_dir):
        print(_suite.no_tests_refusal("check_calls", suite_dir), file=sys.stderr)
        return 2
    # Anchor the root at the argument: it may live in another repo than the cwd.
    targets, floor = _suite.target_modules(suite_dir, _suite.repo_root(suite_dir))
    for t in explicit:
        targets.setdefault(t, set())
    for note in floor:
        print(f"  WARN [check_calls] {note}", file=sys.stderr)
    if not targets:
        print(
            f"check_calls: no target identified for {suite_dir} — every suite import resolves "
            f"or is indistinguishable from a dependency. A modify-existing spec's target is "
            f"invisible to the import heuristic, and a brand-new TOP-LEVEL module reads as a "
            f"third-party import; name it with --target <dotted.module>.",
            file=sys.stderr,
        )
        return 2
    findings = check(suite_dir, targets)
    for f in findings:
        print(f"  {f}")
    print(f"\n[check_calls] {len(findings)} test(s) that never reach the target.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
