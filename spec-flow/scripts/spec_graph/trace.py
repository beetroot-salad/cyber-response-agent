#!/usr/bin/env python3
"""spec-graph trace — derive the grounding censuses from the code, not from recall.

Two reverse-BFS queries over one statically derived reference graph (#635, split as
#644/#645). Both answer the question the write-tests grounding leaf previously answered
by recall — the single point of failure schema.md names ("extraction completeness is the
gate's single point of failure. No mechanical cross-check exists yet"):

* **drivers** (T1, #644) — anchor the changed modules (`git diff <base>...HEAD`), close
  over referrers transitively to the entrypoint frontier: the execution contexts that
  reach the change. The import graph, entrypoint census, and subprocess arm are
  `check_actors`' own (one engine, two consumers) — this is the same census emitted as
  a table for the grounding brief instead of diffed against a graph.
* **resource** (T2, #645) — anchor a declared resource's sink symbols
  (`specGraph.resources` in the project profile), take their referrers split by sink
  kind: the resource's writers and readers, each with the call-site path expression
  (the template the axes are read off). A tool, not a gate: a floor over
  runtime-composed paths cannot soundly fail a graph.

**The honest floor** (NON-1): a static pass sees reference edges, not runtime edges.
Reported, never silently dropped — subprocess re-exec edges (from `check_actors`' arm),
in-process dynamic dispatch (`importlib.import_module`, registry lookups), files the
census could not parse, and grep-only hits the resolver could not tie to an import. A
module with no path found is *unreached by any resolved edge*, never proven unreachable.

`specGraph.resources` shape (mirrors `entrypointStems`):

    "resources": {
      "lessons_jsonl": {
        "writers": ["learning/_io.py::append_jsonl"],
        "readers": ["learning/_io.py::read_jsonl_rows", "learning/_io.py::read_text_utf8"],
        "grep": ["lessons.jsonl"]
      }
    }

Each sink is `<file relative to repo root>::<symbol>`; `grep` lists extra literals whose
raw occurrences are reported as floor (the string-composed paths no resolver follows).

Usage:
    spec-graph trace drivers  [--base <ref>] [--config <path>]
    spec-graph trace resource [<name> ...]   [--config <path>]
Exit codes: 0 the census answered (the table is the output), 2 it could not answer
(empty census, unknown resource, no resources configured).
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import _cli
import _config
import check_actors


def _floor_dynamic(texts: dict[Path, str], root: Path) -> list[str]:
    """In-process dynamic dispatch sites — no static edge exists, so any reach through
    them is invisible to the walk. Floor, not resolution (NON-1 ii)."""
    hits: list[str] = []
    for f, text in sorted(texts.items()):
        if "import_module" not in text and "__import__" not in text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if "import_module(" in line or "__import__(" in line:
                hits.append(f"{f.relative_to(root)}:{i}: {line.strip()}")
    return hits


def drivers(base: str, cfg: dict) -> int:
    # Verify the base ref FIRST: `git diff` against a nonexistent/unfetched ref exits 128
    # with EMPTY stdout (the census's _sh is check=False), which downstream reads as "no
    # changed modules — nothing to anchor", exit 0: a could-not-look dressed as an answered
    # census. rev-parse is the cheap oracle for "does this ref name a commit here".
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
        cwd=_config.repo_root(), capture_output=True, text=True, encoding="utf-8", check=False,
    )
    if probe.returncode != 0:
        print(
            f"trace drivers: base ref `{base}` does not resolve to a commit here (misspelled, "
            f"or not fetched?) — the census could not look. Fetch the ref or pass a valid "
            f"--base, then re-run.",
            file=sys.stderr,
        )
        return 2
    census = check_actors._Census(base, cfg)
    root = census.root
    census_files = set(census.files)  # hoisted: inside the genexp this rebuilt per changed path
    changed = sorted(p for p in census.changed if p in census_files)
    if not changed:
        print(f"[trace drivers] no changed census modules against base={base} — nothing to anchor.")
        return 0
    # Forward reach from each entrypoint, inverted into per-changed-module driver lists —
    # the same closure check_actors gates on, reported as the census itself.
    reach = {e: check_actors._reach(e, census.edges) for e in census.entrypoints}
    # Scanned once per entrypoint, not once per (changed module × entrypoint) pair: the
    # regex sweeps each entrypoint's whole source, and it does not vary with `mod`.
    subproc_stems = {
        e: check_actors._subprocessed_py_stems(census.texts.get(e, ""))
        for e in census.entrypoints
    }
    print(f"[trace drivers] base={base}; {len(changed)} changed module(s), "
          f"{len(census.entrypoints)} entrypoint(s) in census.\n")
    for mod in changed:
        rel = mod.relative_to(root)
        via_import = sorted(
            str(e.relative_to(root)) for e, r in reach.items() if mod in r and e != mod
        )
        via_subproc = sorted(
            str(e.relative_to(root)) for e in census.entrypoints
            if mod.stem in subproc_stems[e] and e != mod
        )
        print(f"{rel}:")
        for d in via_import:
            print(f"  driver {d}  [in-process import closure]")
        for d in via_subproc:
            print(f"  driver {d}  [subprocess re-exec — floor edge: the module runs on "
                  f"whatever tree the driver hands it]")
        if mod in census.entrypoints:
            print("  (is itself an entrypoint)")
        if not via_import and not via_subproc and mod not in census.entrypoints:
            print("  no resolved driver — UNREFUTED, not proven unreachable (see floor below)")
    gaps = census.load_bearing_gaps()
    dynamic = _floor_dynamic(census.texts, root)
    # A subprocess re-exec issued from a NON-entrypoint module (cli.py → runner.py →
    # re-execs a changed module) emits no driver edge above — the subproc scan covers only
    # entrypoints — so the relocated-PATHS class would escape silently. Floor, not
    # resolution (NON-1): the walk cannot say which driver reaches the re-exec site.
    entry_set = set(census.entrypoints)
    reexec = [
        f"{f.relative_to(root)}: names {sorted(stems)} as subprocess target(s) — subprocess "
        f"re-exec from a non-entrypoint: no static driver edge exists; classify by hand"
        for f, text in sorted(census.texts.items())
        if f not in entry_set and (stems := check_actors._subprocessed_py_stems(text))
    ]
    if gaps or dynamic or reexec:
        print("\nfloor — reach the static walk cannot resolve (report these in the brief, "
              "never as 'no driver'):")
        for f, reason in sorted(gaps.items()):
            print(f"  {f.relative_to(root)}: {reason}")
        for h in dynamic:
            print(f"  dynamic dispatch: {h}")
        for h in reexec:
            print(f"  {h}")
    return 0


def _sink_calls(
    texts: dict[Path, str], root: Path, sink_file: Path, symbol: str
) -> tuple[list[str], list[str]]:
    """(resolved call sites, grep floor) for one sink symbol.

    Resolved: the file imports the sink's module (any form the import graph resolves) or
    imports the symbol itself, AND calls the symbol — reported with the call's first
    argument's source text, which is the path template the identity axes are read off.
    Floor: the symbol's name occurs in a file the resolver could not tie to the sink —
    a string-composed or dynamically dispatched use the brief must judge, not drop."""
    resolved: list[str] = []
    floor: list[str] = []
    for f, text in sorted(texts.items()):
        if symbol not in text or f == sink_file:
            continue
        imports_sink = sink_file in check_actors._module_targets(f, text, root)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            floor.append(f"{f.relative_to(root)}: unparseable — occurrence of `{symbol}` unresolved")
            continue
        calls: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None
            )
            if name != symbol:
                continue
            arg = ast.get_source_segment(text, node.args[0]) if node.args else "<no positional arg>"
            calls.append(f"{f.relative_to(root)}:{node.lineno}: {symbol}({arg}, …)")
        if calls and imports_sink:
            resolved.extend(calls)
        else:
            # Called without a resolvable import (re-export, dynamic), or named but never
            # called (aliased, passed as a value, quoted) — the walk can't classify it.
            floor.append(
                f"{f.relative_to(root)}: names `{symbol}` but the walk cannot tie it to "
                f"{sink_file.relative_to(root)} — classify by hand"
            )
    return resolved, floor


def _resource_texts(root: Path) -> dict[Path, str]:
    """Every *.py under the repo root, pruning only `_config._PRUNE` dirs — read utf-8.

    Deliberately WIDER than the execution-context census: that census excludes tests/ and
    anything outside codeRoots, but a writer in `tests/conftest.py` or an eval harness
    outside the codeRoots still mutates the shared resource — dropping it from the sink
    scan and the grep floor violates NON-1 ("Reported, never silently dropped"). `drivers`
    stays on the census, because its contract IS the execution-context census."""
    files = sorted(f for f in _config._walk(root) if f.suffix == ".py")
    return check_actors._read_texts(files)


def resource(names: list[str], cfg: dict) -> int:
    declared: dict = cfg.get("resources", {}) or {}
    if not declared:
        print(
            "trace resource: no `specGraph.resources` declared in .claude/spec-flow.json — "
            "declare each shared root's sink symbols (see this script's docstring), then re-run.",
            file=sys.stderr,
        )
        return 2
    unknown = [n for n in names if n not in declared]
    if unknown:
        print(f"trace resource: unknown resource(s) {unknown} — declared: {sorted(declared)}",
              file=sys.stderr)
        return 2
    root = _config.repo_root()
    texts = _resource_texts(root)  # repo-wide, not the codeRoots census — see _resource_texts
    unresolved: list[str] = []
    for name in names or sorted(declared):
        spec = declared[name] or {}
        print(f"{name}:")
        for kind in ("writers", "readers"):
            for sink in spec.get(kind, []) or []:
                rel, _, symbol = str(sink).partition("::")
                sink_file = root / rel
                if not symbol or not sink_file.is_file():
                    print(f"  {kind[:-1]} sink `{sink}`: UNRESOLVED — expected "
                          f"`<file>::<symbol>` with the file present; fix the config entry")
                    unresolved.append(str(sink))
                    continue
                resolved, floor = _sink_calls(texts, root, sink_file, symbol)
                for site in resolved:
                    print(f"  {kind[:-1]} {site}")
                for site in floor:
                    print(f"  floor [{kind[:-1]}?] {site}")
        for literal in spec.get("grep", []) or []:
            for f, text in sorted(texts.items()):
                if literal not in text:
                    continue  # containment first: splitlines over every file is the hot loop
                for i, line in enumerate(text.splitlines(), 1):
                    if literal in line:
                        print(f"  floor [literal `{literal}`] {f.relative_to(root)}:{i}: "
                              f"{line.strip()[:120]}")
        print()
    print("[trace resource] writers/readers are RESOLVED call sites; every `floor` line is "
          "reach the walk could not classify — the brief carries it, never drops it.")
    if unresolved:
        # A census whose sink never resolved looked at NOTHING for that sink — exit 2, not 0:
        # "could not answer" must never present as an answered census (the script contract).
        print(f"trace resource: {len(unresolved)} sink(s) UNRESOLVED ({unresolved}) — the "
              f"census could not look; fix the config entries and re-run.", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--base", "--config"})
    base = opts["base"] or "main"
    if not args or args[0] not in ("drivers", "resource"):
        print("usage: spec-graph trace {drivers [--base <ref>] | resource [<name> ...]}",
              file=sys.stderr)
        return 2
    cfg = _config.load(opts["config"])
    try:
        if args[0] == "drivers":
            return drivers(base, cfg)
        return resource(args[1:], cfg)
    except check_actors.CensusBlind as exc:
        print(f"trace: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
