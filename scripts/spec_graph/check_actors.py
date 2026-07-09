#!/usr/bin/env python3
"""spec-graph check #2 — execution-context census (the F2 class).

A write-tests spec graph enumerates `structure.actors` — the callers/frames a change is
modelled against. That list is authored from the DESIGN, so it captures the production
consumers and misses execution contexts nobody thought to write down. In #551 the
lead-author EVAL HARNESS (`evals/harness_lead.py`) drives the change through a subprocess
in which a "constant" (`PATHS.defender_dir`) is silently relocated onto the tmp tree — so a
guard's hidden assumption ("PATHS is the fixed main checkout") was never tested, and
`requires_explicit_tree` false-positives there. No actor, no demand, no test → escape.

THE CHECK (mechanical, grep-derived — the "enumerate consumers from reality, not the design
doc" lane): derive the set of EXECUTION CONTEXTS that drive the changed subsystem straight
from the repo — every CLI / harness / eval entrypoint that reaches a changed module (directly,
or via the 1-hop CLI that wraps it, or by subprocessing it) — then diff against what the graph
models. A driver context the graph neither names nor maps to an actor is a blind spot: model
it (and discover its hidden axes) or waive it consciously.

Independence is the point (Fable): the driver set comes from the CODE, so it can't inherit
the design doc's blind spots the way a design-grounded enumerator would.

Usage:
    python scripts/spec_graph/check_actors.py [spec_graph.yaml] [--base <ref>]
Exit 1 if an unmodelled driver reaches the change. Waive an out-of-scope context by listing
its stem under a top-level `actor_waivers:` in the graph.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

# Production entrypoint stem → the graph actor id that models it (the graph names actors
# semantically, not by file). A context is "modelled" if its stem OR its mapped actor is
# named anywhere in the graph text.
_CONTEXT_ALIAS = {
    "run": "run_investigation",
    "driver": "run_investigation",
    "tools_gather": "gather_dispatch",
    "tools": "tool_write_file",
}

_ROOTS = ("defender/runtime", "defender/learning", "defender/evals", "defender/run.py")


def _sh(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def _changed_stems(base: str) -> set[str]:
    out = _sh(["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"])
    return {
        Path(f).stem
        for f in out.splitlines()
        if f.strip() and "/tests/" not in f
    }


def _py_files() -> list[Path]:
    files: list[Path] = []
    for root in _ROOTS:
        p = Path(root)
        files.extend(p.rglob("*.py") if p.is_dir() else ([p] if p.is_file() else []))
    return [f for f in files if "/tests/" not in str(f) and "__pycache__" not in str(f)]


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
    "lead_author.py")` yields `lead_author`. This is the F2 signature: re-executing a defender
    module as a subprocess is exactly what relocates `PATHS` onto a different tree."""
    if "subprocess" not in text and "Popen" not in text:
        return set()
    return {m.group(1) for m in re.finditer(r"['\"][^'\"]*?([A-Za-z_][\w]+)\.py['\"]", text)}


def _is_entrypoint(path: Path, text: str) -> bool:
    """A driver context: a CLI main, or an eval/harness file (evals/ tree or *harness*),
    or a stage/loop runner. Excludes pytest files (`test_*`) and private internals
    (`_foo.py`) — those are not execution contexts that drive the subsystem."""
    stem = path.stem
    if stem.startswith("test_") or stem.startswith("_"):
        return False
    return (
        "__main__" in text
        or "/evals/" in str(path)
        or "harness" in stem
        or stem in {"loop", "run"}
    )


def check(graph_path: Path, base: str) -> list[str]:
    graph_text = graph_path.read_text()
    graph = yaml.safe_load(graph_text)
    waivers = set(graph.get("actor_waivers", []) or [])

    changed = _changed_stems(base)
    files = _py_files()
    defender_stems = {f.stem for f in files}

    findings: list[str] = []
    for f in files:
        text = f.read_text()
        if not _is_entrypoint(f, text):
            continue
        # Two ways a driver reaches the change: an in-process import of a changed module, or
        # a subprocess RE-EXEC of a defender module (the F2 relocated-PATHS hazard).
        imports_changed = _imported_stems(text) & changed
        subprocs = (_subprocessed_py_stems(text) & defender_stems) - {f.stem}
        if not imports_changed and not subprocs:
            continue
        stem = f.stem
        if stem in waivers:
            continue
        actor = _CONTEXT_ALIAS.get(stem)
        modelled = (
            re.search(rf"\b{re.escape(stem)}\b", graph_text) is not None
            or (actor is not None and re.search(rf"\b{re.escape(actor)}\b", graph_text) is not None)
        )
        if modelled:
            continue
        how = (
            f"subprocess re-exec of {sorted(subprocs)} (relocates PATHS)" if subprocs
            else f"in-process import of changed {sorted(imports_changed)}"
        )
        findings.append(
            f"{graph_path.name}: driver `{f}` reaches the changed subsystem "
            f"[{how}] but is not modelled (no actor, no demand names `{stem}`). Model it "
            f"as an actor — or waive under actor_waivers if out of scope."
        )
    return findings


def main(argv: list[str]) -> int:
    base = "main"
    args = []
    it = iter(argv)
    for a in it:
        if a == "--base":
            base = next(it, "main")
        else:
            args.append(a)
    graphs = [Path(a) for a in args] or sorted(Path("defender/tests").glob("spec_graph_*.yaml"))
    all_findings: list[str] = []
    for g in graphs:
        all_findings.extend(check(g, base))
    for f in all_findings:
        print(f"  UNMODELLED {f}")
    n = len(all_findings)
    print(f"\n[check_actors] {n} unmodelled driver context(s) over {len(graphs)} graph(s) (base={base}).")
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
