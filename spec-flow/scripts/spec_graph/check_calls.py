#!/usr/bin/env python3
"""spec-graph check #6 — every test calls the target (the phase-F AST check, mechanized).

A test that never drives the target symbol asserts around it — a fixture check, a
re-implementation, an environmental probe — and stays green whatever the implementation
does. The phase-F charge ("AST check: every test calls the target — directly, via a
helper in the same file whose body does, or by driving an object a call to the target
returned") is a static reachability question, so this script answers it.

Target identification is `_suite.target_modules`: the suite's project-rooted imports
that resolve to nothing are the not-yet-written target; `--target <dotted.module>` adds
or replaces targets for the modify-existing-code case the heuristic cannot see. A test
"touches" the target when its body — or, transitively, a same-file helper it calls —
references a symbol imported from a target module or the target module's own name.
(The third charge clause is subsumed: an object a target call returned only exists in a
body that made the target call.)

Usage:
    spec-graph calls [graph.yaml | suite-dir] [--target <dotted.module> ...] [--config <path>]
Exit codes: 0 every test reaches the target; 1 a test doesn't; 2 no target could be
identified (heuristic empty and no --target given) — could-not-look, never a pass.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import _config
import _suite


def _fn_refs(fn: ast.AST) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def check(suite_dir: Path, targets: dict[str, set[str]]) -> list[str]:
    # A target is reachable by any of: a symbol imported from it, its own module name
    # (last segment, for `import a.b.c` / `a.b.c.f()` forms), or an alias of either.
    target_names: set[str] = set()
    for dotted, symbols in targets.items():
        target_names.add(dotted.split(".")[-1])
        target_names.update(symbols)

    findings: list[str] = []
    for py in _suite.suite_files(suite_dir):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            continue  # unscannable files are the null-stub gate's collection error to report
        # Aliases: `from mod import target as t` makes `t` a target name in this file.
        local_targets = set(target_names)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    if a.asname and a.name.split(".")[-1] in target_names:
                        local_targets.add(a.asname)
        # Refs are MERGED per name, never last-one-wins: `ast.walk` flattens methods and
        # nested defs into one namespace, so two same-named helpers in different classes
        # used to overwrite each other and the fixed point judged both bodies by whichever
        # the walk reached last. Union keeps the resolution name-based (which is all the
        # call sites in `refs` can be matched by) without depending on walk order.
        refs: dict[str, set[str]] = {}
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                refs.setdefault(n.name, set()).update(_fn_refs(n))
        # Fixed point: a function touches the target directly, or calls a same-file
        # function that does. Iterate until stable (helper chains, any depth).
        touches = {name for name, r in refs.items() if r & local_targets}
        changed = True
        while changed:
            changed = False
            for name, r in refs.items():
                if name not in touches and r & touches:
                    touches.add(name)
                    changed = True
        for name in refs:
            if name.startswith("test_") and name not in touches:
                findings.append(
                    f"NO-CALL {py.name}::{name}: never references the target "
                    f"({sorted(local_targets)[:6]}…) — directly or through a same-file helper. "
                    f"A test that never drives the target binds nothing about it."
                )
    return findings


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    config: str | None = None
    explicit: list[str] = []
    args: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--config":
            config = next(it, None)
        elif a == "--target":
            t = next(it, None)
            if t:
                explicit.append(t)
        else:
            args.append(a)
    cfg = _config.load(config)
    root = _config.repo_root()
    if args:
        p = Path(args[0])
        suite_dirs = [p if p.is_dir() else p.parent]
    else:
        suite_dirs = sorted({g.parent for g in _config.artifacts(cfg)})
    if not suite_dirs:
        print("check_calls: no suite directory (no graphs matched and none given)", file=sys.stderr)
        return 2
    all_findings: list[str] = []
    blind: list[Path] = []
    for d in suite_dirs:
        targets, floor = _suite.target_modules(d, root)
        for t in explicit:
            targets.setdefault(t, set())
        for note in floor:
            print(f"  WARN [check_calls] {note}", file=sys.stderr)
        if not targets:
            # Collected, not returned on: bailing here threw away every finding the
            # already-scanned dirs produced, so a real NO-CALL went unreported because a
            # LATER dir happened to be unlookable.
            blind.append(d)
            continue
        all_findings.extend(check(d, targets))
    for f in all_findings:
        print(f"  {f}")
    print(f"\n[check_calls] {len(all_findings)} test(s) that never reach the target "
          f"over {len(suite_dirs) - len(blind)} suite dir(s).")
    if blind:
        print(
            f"check_calls: no target identified for {[str(d) for d in blind]} — every suite "
            f"import resolves. A modify-existing spec's target is invisible to the import "
            f"heuristic; name it with --target <dotted.module>.",
            file=sys.stderr,
        )
        return 2
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
