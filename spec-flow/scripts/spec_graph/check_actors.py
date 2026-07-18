#!/usr/bin/env python3
"""spec-graph check #2 — execution-context census (the F2 class).

A write-tests spec graph enumerates `structure.actors` — the callers/frames a change is
modelled against. That list is authored from the DESIGN, so it captures the production
consumers and misses execution contexts nobody thought to write down. The canonical escape
(the project this check was forged in): an EVAL HARNESS drove the change through a subprocess
in which a module-level "constant" — the anchor path the guard trusted — was silently relocated
onto a tmp tree, so the guard's hidden assumption ("the anchor is the fixed main checkout") was
never tested and it false-positived there. No actor, no demand, no test → escape.

THE CHECK (mechanical, grep-derived — the "enumerate consumers from reality, not the design
doc" lane): derive the set of EXECUTION CONTEXTS that drive the changed subsystem straight
from the repo — every CLI / harness / eval entrypoint that reaches a changed module (directly,
or via the 1-hop CLI that wraps it, or by subprocessing it) — then diff against what the graph
models. A driver context the graph neither names nor maps to an actor is a blind spot: model
it (and discover its hidden axes) or waive it consciously.

Independence is the point (Fable): the driver set comes from the CODE, so it can't inherit
the design doc's blind spots the way a design-grounded enumerator would.

Where the project's code lives, which stems are entrypoints, and what the graph calls each
actor are all read from `.claude/spec-flow.json` (see `_config.py`) — the method is portable,
the census targets are not.

Usage:
    spec-graph actors [graph.yaml] [--base <ref>] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself;
`$CLAUDE_PLUGIN_ROOT` does NOT expand in SKILL.md prose, so never spell a path with it).
Exit 1 if an unmodelled driver reaches the change. Waive an out-of-scope context by listing
its stem under a top-level `actor_waivers:` in the graph.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import yaml

import _config


def _sh(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, cwd=_config.repo_root(), capture_output=True, text=True, check=False
    ).stdout


def _changed_paths(base: str) -> set[Path]:
    # Anchored at the repo root, both times. git resolves a pathspec against the process CWD, so
    # running `spec-graph` from a subdirectory (`cd defender && …`, exactly what this project's
    # gate command does) would scope `*.py` to that subtree — and a diff that touched nothing
    # under it would come back EMPTY. The census would then find no changed module to match, go
    # quiet, and exit 0: a gate that passes green on a diff it never looked at.
    #
    # PATH-granular (not stem-granular): two modules can share a stem (`pkg_a/driver.py` vs
    # `pkg_b/driver.py`), so the reach comparison keys on the resolved file path, not the stem —
    # both here and through the transitive closure. A stem key false-fires on same-stem changes
    # in a package the entrypoint never actually reaches.
    root = _config.repo_root()
    out = _sh(["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"])
    return {
        root / f
        for f in out.splitlines()
        if f.strip() and "/tests/" not in f
    }


def _module_targets(importer: Path, text: str, root: Path) -> set[Path]:
    """The project module FILES a file imports, resolved on the filesystem.

    Namespace-package resolution (defender has no `__init__.py`): a dotted name `a.b.c` maps to
    `root/a/b/c.py` directly — no `__init__.py` walk, which would fail to resolve `defender.x`.
    Relative imports resolve against the importer's own directory. `from pkg import name` credits
    `pkg/name.py` when that submodule file exists (a real module reach) and `pkg.py` when THAT
    exists (then `name` is a symbol of module `pkg`); a `from pkg import some_symbol` that names
    neither resolves to nothing — no phantom driver invented for a function or a class."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    targets: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                cand = (root / Path(*alias.name.split("."))).with_suffix(".py")
                if cand.is_file():
                    targets.add(cand)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative: `.` is the importer's own package (its directory)
                base = importer.parent
                for _ in range(node.level - 1):
                    base = base.parent
                if node.module:
                    base = base / Path(*node.module.split("."))
            else:
                base = root / Path(*(node.module or "").split("."))
            # A relative import with more leading dots than the file has package ancestors walks
            # `base` above the repo root: it names no project module, and `base.with_suffix` would
            # raise on the filesystem root. Bound resolution to within (or at) the root.
            if base != root and root not in base.parents:
                continue
            for alias in node.names:  # each name may be a submodule file …
                cand = (base / alias.name).with_suffix(".py")
                if cand.is_file():
                    targets.add(cand)
            base_mod = base.with_suffix(".py")  # … or `base` is the module, names its symbols
            if base_mod.is_file():
                targets.add(base_mod)
    return targets


def _import_edges(files: list[Path], root: Path) -> dict[Path, set[Path]]:
    """The project import graph, bounded to the census: file → the census files it imports. A
    reach that leaves the codeRoots (into a non-census module) is dropped here, so it can never
    re-enter — an outside-codeRoots-only reach is an accepted, silent gap."""
    fileset = set(files)
    edges: dict[Path, set[Path]] = {}
    for f in files:
        try:
            text = f.read_text()
        except (OSError, UnicodeDecodeError):
            edges[f] = set()
            continue
        edges[f] = _module_targets(f, text, root) & fileset
    return edges


def _reach(entry: Path, edges: dict[Path, set[Path]]) -> set[Path]:
    """Every census file `entry` reaches transitively via project-module imports. Cycle-safe (a
    `visited` set), so a 2-node ↔, an N-node ring, or a self-loop terminates rather than hangs."""
    seen: set[Path] = set()
    stack = list(edges.get(entry, set()))
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(edges.get(n, set()))
    return seen


def _subprocessed_py_stems(text: str) -> set[str]:
    """The `.py` module stems a file names as SUBPROCESS targets — `str(tmp / … /
    "lead_author.py")` yields `lead_author`. This is the F2 signature: re-executing one of the
    project's own modules as a subprocess is exactly what relocates a module-level "constant"
    (a `PATHS`-style anchor computed from the tree it runs in) onto a different tree."""
    if "subprocess" not in text and "Popen" not in text:
        return set()
    return {m.group(1) for m in re.finditer(r"['\"][^'\"]*?([A-Za-z_][\w]+)\.py['\"]", text)}


def _is_entrypoint(path: Path, text: str, extra_stems: set[str]) -> bool:
    """A driver context: a CLI main, an eval/harness file, or a project-declared runner stem
    (`specGraph.entrypointStems`). Excludes pytest files (`test_*`) and private internals
    (`_foo.py`) — those are not execution contexts that drive the subsystem."""
    stem = path.stem
    if stem.startswith("test_") or stem.startswith("_"):
        return False
    return (
        "__main__" in text
        or "/evals/" in str(path)
        or "harness" in stem
        or stem in extra_stems
    )


def check(graph_path: Path, base: str, cfg: dict) -> list[str]:
    graph_text = graph_path.read_text()
    graph = yaml.safe_load(graph_text)
    waivers = set(graph.get("actor_waivers", []) or [])
    aliases: dict[str, str] = cfg["contextAliases"]
    entry_stems = set(cfg["entrypointStems"])

    root = _config.repo_root()
    changed = _changed_paths(base)
    files = _config.source_files(cfg)
    project_stems = {f.stem for f in files}
    edges = _import_edges(files, root)

    findings: list[str] = []
    for f in files:
        text = f.read_text()
        if not _is_entrypoint(f, text, entry_stems):
            continue
        # Two ways a driver reaches the change: an in-process import of a changed module —
        # resolved to files and followed TRANSITIVELY over the project import graph, then
        # intersected with the changed set (the arm stays gated on `changed`) — or a subprocess
        # RE-EXEC of one of the project's own modules (the F2 relocated-anchor hazard).
        reached_changed = (_reach(f, edges) - {f}) & changed
        subprocs = (_subprocessed_py_stems(text) & project_stems) - {f.stem}
        if not reached_changed and not subprocs:
            continue
        # Suppression is keyed on the ENTRYPOINT (its stem or contextAlias), never a module on the
        # reach path — a modelled intermediate must not silence an unmodelled entrypoint.
        stem = f.stem
        if stem in waivers:
            continue
        actor = aliases.get(stem)
        modelled = (
            re.search(rf"\b{re.escape(stem)}\b", graph_text) is not None
            or (actor is not None and re.search(rf"\b{re.escape(actor)}\b", graph_text) is not None)
        )
        if modelled:
            continue
        # Say which arm(s) fired, and don't overclaim. When both trip, report BOTH reasons —
        # neither masks the other. The subprocess arm is deliberately NOT gated on `changed`: a
        # re-exec context is a standing hazard, and a guard introduced anywhere can make a
        # long-unchanged harness newly load-bearing, so it fires on drivers that need not touch
        # this diff at all — a claim the import arm has not made.
        rel = f.relative_to(root)
        reasons: list[str] = []
        if reached_changed:
            reasons.append(
                f"reaches the changed subsystem [in-process import of changed "
                f"{sorted(p.stem for p in reached_changed)}]"
            )
        if subprocs:
            reasons.append(
                f"re-executes {sorted(subprocs)} as a subprocess (relocating the tree anchor onto "
                f"whatever tree it runs in — a standing hazard this graph does not cover)"
            )
        reach = " and ".join(reasons)
        findings.append(
            f"{graph_path.name}: driver `{rel}` {reach} but is not modelled (no actor, no demand "
            f"names `{stem}`). Model it as an actor — or waive under actor_waivers if out of scope."
        )
    return findings


def main(argv: list[str]) -> int:
    base = "main"
    config: str | None = None
    args = []
    it = iter(argv)
    for a in it:
        if a == "--base":
            base = next(it, "main")
        elif a == "--config":
            config = next(it, None)
        else:
            args.append(a)
    cfg = _config.load(config)
    graphs = [Path(a) for a in args] or _config.artifacts(cfg)
    all_findings: list[str] = []
    for g in graphs:
        all_findings.extend(check(g, base, cfg))
    for f in all_findings:
        print(f"  UNMODELLED {f}")
    n = len(all_findings)
    print(f"\n[check_actors] {n} unmodelled driver context(s) over {len(graphs)} graph(s) (base={base}).")
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
