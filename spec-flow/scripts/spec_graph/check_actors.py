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
    python "$CLAUDE_PLUGIN_ROOT"/scripts/spec_graph/check_actors.py [graph.yaml] [--base <ref>] [--config <path>]
Exit 1 if an unmodelled driver reaches the change. Waive an out-of-scope context by listing
its stem under a top-level `actor_waivers:` in the graph.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

import _config


def _sh(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def _changed_stems(base: str) -> set[str]:
    out = _sh(["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"])
    return {
        Path(f).stem
        for f in out.splitlines()
        if f.strip() and "/tests/" not in f
    }


def _imported_stems(text: str) -> set[str]:
    """The module stems a file IMPORTS — the final component of each `import`/`from` target.
    Precise (not loose tokens): `from ...pipeline.actor_engine import X` yields `actor_engine`,
    but a local var named `main` does NOT match the `main.py` module."""
    return {
        m.group(1).split(".")[-1]
        for m in re.finditer(r"^\s*(?:from|import)\s+([\w.]+)", text, re.MULTILINE)
    }


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

    changed = _changed_stems(base)
    files = _config.source_files(cfg)
    project_stems = {f.stem for f in files}

    findings: list[str] = []
    for f in files:
        text = f.read_text()
        if not _is_entrypoint(f, text, entry_stems):
            continue
        # Two ways a driver reaches the change: an in-process import of a changed module, or
        # a subprocess RE-EXEC of one of the project's own modules (the F2 relocated-anchor hazard).
        imports_changed = _imported_stems(text) & changed
        subprocs = (_subprocessed_py_stems(text) & project_stems) - {f.stem}
        if not imports_changed and not subprocs:
            continue
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
        how = (
            f"subprocess re-exec of {sorted(subprocs)} (relocates the tree anchor)" if subprocs
            else f"in-process import of changed {sorted(imports_changed)}"
        )
        rel = f.relative_to(_config.repo_root())
        findings.append(
            f"{graph_path.name}: driver `{rel}` reaches the changed subsystem "
            f"[{how}] but is not modelled (no actor, no demand names `{stem}`). Model it "
            f"as an actor — or waive under actor_waivers if out of scope."
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
