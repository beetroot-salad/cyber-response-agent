#!/usr/bin/env python3
"""spec-graph check #2 — execution-context census.

A spec graph's `structure.actors` is authored from the design, so it lists production
consumers and misses execution contexts nobody wrote down, e.g. an eval harness that
re-executes a module in a subprocess where a module-level anchor path points at a tmp tree.
No actor means no demand and no test for that context.

This check derives the execution contexts from the code instead: every CLI / harness / eval
entrypoint that reaches a changed module (by transitive import, or by subprocessing one of
the project's modules), then diffs that against what the graph models. An unmodelled driver
must be modelled or waived.

Code roots, entrypoint stems, and actor aliases come from `.claude/spec-flow.json` (see
`_config.py`).

Usage:
    spec-graph actors [graph.yaml] [--base <ref>] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself;
`$CLAUDE_PLUGIN_ROOT` does NOT expand in SKILL.md prose, so never spell a path with it).
Exit codes:
  0  the census answered, and no unmodelled driver reaches the change
  1  an unmodelled driver reaches the change. Waive an out-of-scope context by listing its
     stem under a top-level `actor_waivers:` in the graph.
  2  the census could not answer: no graph artifacts matched, the source census is empty,
     `--base` names no commit here, git refused the diff, or a file that could hide a driver
     could not be parsed/read. A gate that cannot look must not report clean.

A census gap that is not load-bearing (no entrypoint reaches the file, no diff touched it)
is only a stderr WARN.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import yaml

import _cli
import _config


class CensusBlind(RuntimeError):
    """The census could not be built well enough to answer (exit 2, not "nothing found")."""


# file → why it contributes no import edges (unparseable or unreadable). A driver reaching the
# change only through such a file would go unreported, so gaps are never silent.
_GAPS: dict[Path, str] = {}


def _gap(path: Path, reason: str) -> None:
    """Record a census gap and warn on stderr (stdout is the parsed findings stream). `main`
    later decides whether the gap is load-bearing."""
    _GAPS[path] = reason
    print(f"  WARN [check_actors] {path}: {reason}", file=sys.stderr)


def _sh(cmd: list[str]) -> str:
    # utf-8 pinned: `git diff --name-only` can emit non-ASCII paths. A non-zero exit or a decode
    # failure is blindness, not an empty diff, so both raise `CensusBlind`.
    try:
        proc = subprocess.run(
            cmd, cwd=_config.repo_root(),
            capture_output=True, text=True, encoding="utf-8", check=False
        )
    except UnicodeDecodeError as exc:
        raise CensusBlind(
            f"`{' '.join(cmd)}` emitted bytes that are not utf-8 in {_config.repo_root()} "
            f"({exc}) — the changed set could not be built. Set `core.quotePath=true` (git's "
            f"default) so non-ASCII paths arrive C-quoted."
        ) from exc
    if proc.returncode != 0:
        raise CensusBlind(
            f"`{' '.join(cmd)}` exited {proc.returncode} in {_config.repo_root()} — the changed "
            f"set could not be built, so every reach question would answer for a structural "
            f"reason rather than a factual one. git said: {(proc.stderr or '').strip() or '(nothing)'}"
        )
    return proc.stdout


def _changed_paths(base: str) -> set[Path]:
    # Run at the repo root: git resolves pathspecs against CWD, so from a subdirectory `*.py`
    # would scope to that subtree and an unrelated diff would come back empty (a false pass).
    #
    # Path-granular, not stem-granular: two modules can share a stem.
    #
    # Unfiltered: test paths are excluded by `_config._kept` when the census is built, and
    # `check` intersects this set with census-bounded reach.
    root = _config.repo_root()
    # Resolve the base first, so a misspelled or unfetched ref is named as such rather than
    # surfacing as a failed (or empty) diff.
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
        cwd=root, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    if probe.returncode != 0:
        raise CensusBlind(
            f"base ref `{base}` does not resolve to a commit here (misspelled, or not fetched?) "
            f"— the changed set could not be built, so the import-reach arm would answer over an "
            f"empty diff and report it as clean. Fetch the ref or pass a valid --base."
        )
    out = _sh(["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"])
    return {root / f for f in out.splitlines() if f.strip()}


def _module_targets(importer: Path, text: str, root: Path) -> set[Path]:
    """The project module FILES a file imports, resolved on the filesystem.

    Namespace-package resolution (no `__init__.py` walk): `a.b.c` maps to `root/a/b/c.py`.
    Relative imports resolve against the importer's directory. `from pkg import name` credits
    `pkg/name.py` and/or `pkg.py` when they exist; a name that is only a symbol credits nothing
    extra. `from pkg import *` on a package directory credits its direct `*.py` children only
    (binding a sub-package does not import its modules)."""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        _gap(importer, f"unparseable ({e.__class__.__name__}: {e}) — contributes no import edges")
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
            # Too many leading dots walks above the repo root: no project module (and
            # `with_suffix` would raise on the filesystem root).
            if base != root and root not in base.parents:
                continue
            for alias in node.names:  # each name may be a submodule file …
                if alias.name == "*":
                    # Package: credit direct children only (`glob`, not `rglob`); `is_file`
                    # skips a directory named `*.py`. Module: handled by `base_mod` below.
                    if base.is_dir():
                        targets.update(p for p in base.glob("*.py") if p.is_file())
                    continue
                cand = (base / alias.name).with_suffix(".py")
                if cand.is_file():
                    targets.add(cand)
            base_mod = base.with_suffix(".py")  # … or `base` is the module, names its symbols
            if base_mod.is_file():
                targets.add(base_mod)
    return targets


def _read_texts(files: list[Path]) -> dict[Path, str]:
    """Every census file's source, read once and shared by the import graph and the entrypoint
    scan so they agree on which files exist.

    An unreadable file is omitted here but stays a census member (see `_import_edges`)."""
    texts: dict[Path, str] = {}
    for f in files:
        try:
            texts[f] = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            _gap(f, f"unreadable ({e.__class__.__name__}) — contributes no import edges")
    return texts


def _import_edges(files: list[Path], texts: dict[Path, str], root: Path) -> dict[Path, set[Path]]:
    """The project import graph, bounded to the census: file → the census files it imports.
    Reach through non-census modules is an accepted gap.

    An unreadable module loses its outgoing edges but remains a valid target, so a changed
    module is still reported when it fails to decode."""
    fileset = set(files)
    return {f: _module_targets(f, texts[f], root) & fileset if f in texts else set() for f in files}


class _Census:
    """The repo-derived half of the check: the changed set, the source census, and its import
    graph. Depends only on (base, cfg), so it is built once and shared across graphs."""

    def __init__(self, base: str, cfg: dict) -> None:
        _GAPS.clear()
        self.root = _config.repo_root()
        self.changed = _changed_paths(base)
        self.files = _config.source_files(cfg)
        if not self.files:
            raise CensusBlind(
                f"the source census is EMPTY — codeRoots {cfg['codeRoots'] or '(unset: whole repo)'} "
                f"matched no .py files under {self.root}. Every reach question then answers 'no' for "
                f"a structural reason, not a factual one. Fix `specGraph.codeRoots` in "
                f".claude/spec-flow.json."
            )
        self.texts = _read_texts(self.files)
        # Keyed on the full census, not `texts`: an unreadable module is still a subprocess target.
        self.project_stems = {f.stem for f in self.files}
        self.edges = _import_edges(self.files, self.texts, self.root)
        self.entrypoints = [
            f for f, text in self.texts.items()
            if _is_entrypoint(f, text, set(cfg["entrypointStems"]))
        ]

    def load_bearing_gaps(self) -> dict[Path, str]:
        """The census gaps that could actually be hiding a driver.

        A blind file loses only its outgoing edges (targets resolve via `is_file()`, not parsing),
        so who imports it is still known. A gap is load-bearing when an entrypoint reaches the
        file, the diff touched it, or it is itself an entrypoint; anything else stays a WARN."""
        if not _GAPS:
            return {}
        reachable: set[Path] = set()
        for e in self.entrypoints:
            reachable |= _reach(e, self.edges)
        return {
            f: reason for f, reason in _GAPS.items()
            if f in reachable or f in self.changed or f in self.entrypoints
        }


def _reach(entry: Path, edges: dict[Path, set[Path]]) -> set[Path]:
    """Every census file `entry` reaches transitively via project-module imports. Cycle-safe."""
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
    """The `.py` module stems a file names as subprocess targets (`"lead_author.py"` →
    `lead_author`). Re-executing a project module in a subprocess can relocate a module-level
    anchor computed from the tree it runs in."""
    if "subprocess" not in text and "Popen" not in text:
        return set()
    return {m.group(1) for m in re.finditer(r"['\"][^'\"]*?([A-Za-z_][\w]+)\.py['\"]", text)}


def _is_entrypoint(path: Path, text: str, extra_stems: set[str]) -> bool:
    """A driver context: a CLI main, an eval/harness file, or a project-declared runner stem
    (`specGraph.entrypointStems`). Excludes pytest files (`test_*`) and private internals
    (`_foo.py`) by default.

    The config is consulted first, so an explicitly declared stem beats both exclusions."""
    stem = path.stem
    if stem in extra_stems:
        return True
    if stem.startswith("test_") or stem.startswith("_"):
        return False
    return (
        "__main__" in text
        or "/evals/" in str(path)
        or "harness" in stem
    )


def check(graph_path: Path, census: _Census, cfg: dict) -> list[str]:
    graph_text = graph_path.read_text(encoding="utf-8")
    graph = _cli.load_graph(graph_path)
    waivers = set(graph.get("actor_waivers", []) or [])
    aliases: dict[str, str] = cfg["contextAliases"]

    root, changed = census.root, census.changed
    edges, project_stems = census.edges, census.project_stems

    findings: list[str] = []
    for f in census.entrypoints:
        text = census.texts[f]
        # A driver reaches the change by transitive import of a changed module, or by
        # re-executing one of the project's modules in a subprocess.
        reached_changed = (_reach(f, edges) - {f}) & changed
        subprocs = (_subprocessed_py_stems(text) & project_stems) - {f.stem}
        if not reached_changed and not subprocs:
            continue
        # Keyed on the entrypoint, never a module on the reach path: a modelled intermediate must
        # not silence an unmodelled entrypoint.
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
        # Report every arm that fired. The subprocess arm is not gated on `changed`: a re-exec
        # context is a standing hazard that any new guard can make load-bearing.
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
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--base", "--config"})
    cfg = _config.load(opts["config"])
    # The profile's branch, not "main": an unresolvable base is a hard exit 2.
    base = opts["base"] or cfg["defaultBranch"]
    graphs = [Path(a) for a in args] or _config.artifacts(cfg)
    try:
        if not graphs:
            raise CensusBlind(
                f"no graph artifacts to check — `specGraph.artifacts` "
                f"({cfg['artifacts']!r}) matched nothing under {_config.repo_root()}. "
                f"Checking zero graphs finds zero findings for a reason that has nothing to do "
                f"with the code; fix the glob, or pass a graph path explicitly."
            )
        census = _Census(base, cfg)
        all_findings: list[str] = []
        unreadable: list[Path] = []
        for g in graphs:
            # An unreadable graph is exit 2 (could not look), not a traceback behind exit 1.
            try:
                all_findings.extend(check(g, census, cfg))
            # `ValueError` covers UnicodeDecodeError, which is not an OSError.
            except (OSError, ValueError, yaml.YAMLError, TypeError, AttributeError) as e:
                print(f"check_actors: cannot read {g}: {e.__class__.__name__}: {e}",
                      file=sys.stderr)
                unreadable.append(g)
                continue
        blind = census.load_bearing_gaps()
    except CensusBlind as exc:
        print(f"check_actors: {exc}", file=sys.stderr)
        return 2
    if blind:
        # Exit 2 and not waivable: a place we could not look, on a path that could hide a driver.
        print("check_actors: the census went blind where it matters —", file=sys.stderr)
        for f, reason in sorted(blind.items()):
            print(f"  {f}: {reason}", file=sys.stderr)
        print(
            "Each file above is reachable from an entrypoint, or the diff touched it, so a driver "
            "that reaches the change through it would go unreported. Make the file parseable/readable "
            "and re-run — a gap here cannot be waived, only closed.",
            file=sys.stderr,
        )
        return 2
    for f in all_findings:
        print(f"  UNMODELLED {f}")
    n = len(all_findings)
    print(f"\n[check_actors] {n} unmodelled driver context(s) over {len(graphs)} graph(s) (base={base}).")
    if unreadable:
        return 2
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
