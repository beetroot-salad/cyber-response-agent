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
Exit codes:
  0  the census answered, and no unmodelled driver reaches the change
  1  an unmodelled driver reaches the change. Waive an out-of-scope context by listing its
     stem under a top-level `actor_waivers:` in the graph.
  2  the census COULD NOT ANSWER — no graph artifacts matched, the source census came back
     empty, or a file the gate could not parse/read sits somewhere a driver could hide.
     Never a silent pass (the #618/#621 convention: a gate that cannot look must not report
     clean).

The 1-vs-2 split is the point. Exit 1 means the gate looked and found something; exit 2 means
it could not look. Collapsing them would let a broken intermediate file — which denies exactly
the import edges the reach question needs — certify the graph clean. A gap that is NOT
load-bearing (no entrypoint reaches the file, no diff touched it) stays a stderr WARN and
changes no exit code: reddening on a vendored fixture nobody imports would be noise.
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
    """The census could not be built well enough to answer. Distinct from "answered: nothing
    found" — see `main`'s exit-code contract. A gate that cannot look must not report clean."""


# file → why it contributes no import edges. Every path that drops a file out of the import graph
# records here: one `ast.parse` rejects, or one the walk cannot read. A driver whose only reach to
# the change runs through such a file goes UNREPORTED, so the gap must never be silent.
_GAPS: dict[Path, str] = {}


def _gap(path: Path, reason: str) -> None:
    """Record a census gap AND surface it. stderr, not stdout: the findings stream is the tool's
    parsed output. Recording is what lets `main` ask the question the WARN alone could not —
    whether this particular blindness sits on a path that could hide a driver (load-bearing, exit
    2) or on a file no entrypoint reaches and no diff touched (a warning, exit unaffected)."""
    _GAPS[path] = reason
    print(f"  WARN [check_actors] {path}: {reason}", file=sys.stderr)


def _sh(cmd: list[str]) -> str:
    # encoding pinned (not the ambient locale): the child is git, and `git diff --name-only` can
    # emit non-ASCII paths — decoding those under a C/ascii locale would raise, and this is the very
    # output that drives the changed set (a crash here is a gate that never looked). Same #588/#589
    # class as the source reads, subprocess side.
    return subprocess.run(
        cmd, cwd=_config.repo_root(),
        capture_output=True, text=True, encoding="utf-8", check=False
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
    #
    # UNFILTERED on purpose. This used to drop `"/tests/" in f`, a SECOND definition of "a test
    # path" that disagreed with the census's own (`_config._kept`: a `tests` component, so
    # top-level `tests/foo.py` survived here and was excluded there). The disagreement was inert
    # only because `check` intersects this set against the reach, which is census-bounded — so the
    # census predicate already decides membership, and a local filter can only ever re-diverge
    # from it. One definition, in `_config._kept`, applied where the census is built.
    root = _config.repo_root()
    out = _sh(["git", "diff", "--name-only", f"{base}...HEAD", "--", "*.py"])
    return {root / f for f in out.splitlines() if f.strip()}


def _module_targets(importer: Path, text: str, root: Path) -> set[Path]:
    """The project module FILES a file imports, resolved on the filesystem.

    Namespace-package resolution (defender has no `__init__.py`): a dotted name `a.b.c` maps to
    `root/a/b/c.py` directly — no `__init__.py` walk, which would fail to resolve `defender.x`.
    Relative imports resolve against the importer's own directory. `from pkg import name` credits
    `pkg/name.py` when that submodule file exists (a real module reach) and `pkg.py` when THAT
    exists (then `name` is a symbol of module `pkg`); a `from pkg import some_symbol` that names
    neither resolves to nothing — no phantom driver invented for a function or a class.
    `from pkg import *` binds `pkg`'s submodule namespace, so when `pkg` is a directory it credits
    its DIRECT `pkg/*.py` children (and `pkg.py` if `pkg` is a module, via the `base_mod` fallback)
    — never `pkg/sub/*.py`, because binding a sub-PACKAGE does not auto-import its module files,
    exactly as the named arm resolves `from pkg import subpkg` to nothing. That is the conservative
    reach a star can bind, bounded by the `fileset` intersection in `_import_edges` so it invents no
    out-of-census reach."""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        # Not a silent skip: an unparseable file contributes NO import edges, so every driver whose
        # only reach to the change runs through it stops being reported. Surface it (see _gap).
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
            # A relative import with more leading dots than the file has package ancestors walks
            # `base` above the repo root: it names no project module, and `base.with_suffix` would
            # raise on the filesystem root. Bound resolution to within (or at) the root.
            if base != root and root not in base.parents:
                continue
            for alias in node.names:  # each name may be a submodule file …
                if alias.name == "*":
                    # `from pkg import *` — alias.name is the literal "*", which pathlib cannot
                    # glob (`base/"*.py"` never `.is_file()`). When `base` is a package directory
                    # the star binds its submodule namespace, so credit its DIRECT `base/*.py`
                    # children (the same conservative model, and the same one-level depth, the named
                    # arm uses) — `glob`, not `rglob`. When `base` is a module file, the star names
                    # that module's symbols — left to the `base_mod` fallback below. `is_file`
                    # filters a directory that merely ends in `.py`, which `glob("*.py")` matches.
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
    """Every census file's source, read ONCE. Both consumers — the import graph and the
    per-entrypoint scan — read the same text, so reading here (rather than at each use) keeps the
    two from disagreeing about which files exist: a file the graph tolerated as unreadable used to
    crash the entrypoint loop on a second, unguarded read.

    Only the KEYS are dropped for an unreadable file, never the file itself — it stays a census
    member (see `_import_edges`), because a module nobody can read is still a module others import
    and still a module the diff can touch."""
    texts: dict[Path, str] = {}
    for f in files:
        try:
            texts[f] = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            _gap(f, f"unreadable ({e.__class__.__name__}) — contributes no import edges")
    return texts


def _import_edges(files: list[Path], texts: dict[Path, str], root: Path) -> dict[Path, set[Path]]:
    """The project import graph, bounded to the census: file → the census files it imports. A
    reach that leaves the codeRoots (into a non-census module) is dropped here, so it can never
    re-enter — an outside-codeRoots-only reach is an accepted, silent gap.

    `fileset` spans ALL census files, not just the readable ones: an unreadable (or unparseable)
    module loses its OUTGOING edges — it cannot say what it imports — but must remain a valid
    TARGET, or a changed module would stop being reported merely because it failed to decode."""
    fileset = set(files)
    return {f: _module_targets(f, texts[f], root) & fileset if f in texts else set() for f in files}


class _Census:
    """The repo-derived half of the check — the changed set, the source census, and the import
    graph over it. All three depend only on (base, cfg), NOT on the graph under test, so they are
    built ONCE and reused across every artifact: `main()` checks 14 graphs in this project, and
    rebuilding meant 14 git subprocesses, 14 filesystem walks and 14 full-repo AST parses to
    produce identical results."""

    def __init__(self, base: str, cfg: dict) -> None:
        _GAPS.clear()  # this census owns the gap set; a second one in-process starts clean
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

        A parse failure denies a file's OUTGOING edges — but not its incoming ones: `_module_targets`
        resolves a target by `is_file()` on the filesystem and never parses it, so who imports the
        blind file is still known. That is what makes this question answerable at all, and it is why
        "fail closed only where the gap could matter" does not need the very edges the failure denied.

        A gap is load-bearing when an entrypoint reaches the blind file (the reach continues THROUGH
        it into territory we cannot see) or when the diff touched it (we cannot tell what the changed
        file itself imports). Everything else — a vendored fixture, a file using syntax newer than the
        runner, anything no entrypoint reaches and no diff touched — stays a WARN and reds nothing."""
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
    (`_foo.py`) — those are not execution contexts that drive the subsystem.

    The config is consulted FIRST, so an explicit listing beats both exclusions. `entrypointStems`
    exists precisely to name the runners the heuristics miss, and the heuristics used to run
    before it: a project declaring `"entrypointStems": ["_harness"]` had that entry silently
    ignored — a config option that did not do what it said, with no warning. The `_`/`test_` rules
    stay as DEFAULTS for stems nobody declared."""
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
    # One read, in `_read_texts` (utf-8 pinned): the entrypoint scan and the import graph now share
    # it, so they cannot disagree about which files the census contains. The twin unguarded read
    # that used to live here crashed on exactly the files `_import_edges` had chosen to tolerate.
    for f in census.entrypoints:
        text = census.texts[f]
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
    # utf-8 out is the OUTPUT twin of the utf-8-pinned reads in `_read_texts` — see _cli.
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--base", "--config"})
    base = opts["base"] or "main"
    cfg = _config.load(opts["config"])
    graphs = [Path(a) for a in args] or _config.artifacts(cfg)
    try:
        if not graphs:
            raise CensusBlind(
                f"no graph artifacts to check — `specGraph.artifacts` "
                f"({cfg['artifacts']!r}) matched nothing under {_config.repo_root()}. "
                f"Checking zero graphs finds zero findings for a reason that has nothing to do "
                f"with the code; fix the glob, or pass a graph path explicitly."
            )
        census = _Census(base, cfg)  # repo-derived, graph-independent — built once, not per graph
        all_findings: list[str] = []
        unreadable: list[Path] = []
        for g in graphs:
            # The family's could-not-read contract (exit 2): a list-top-level graph used
            # to surface as an AttributeError traceback behind exit 1 ("found findings").
            try:
                all_findings.extend(check(g, census, cfg))
            except (OSError, yaml.YAMLError, TypeError, AttributeError) as e:
                print(f"check_actors: cannot read {g}: {e.__class__.__name__}: {e}",
                      file=sys.stderr)
                unreadable.append(g)
                continue
        blind = census.load_bearing_gaps()
    except CensusBlind as exc:
        print(f"check_actors: {exc}", file=sys.stderr)
        return 2
    if blind:
        # Exit 2, not 1, and deliberately NOT waivable through actor_waivers: this is not a driver
        # we found, it is a place we could not look — and it sits on a path that could hide one.
        # `main` keeps the exit-1 channel meaning "the census answered, and the answer is a finding".
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
