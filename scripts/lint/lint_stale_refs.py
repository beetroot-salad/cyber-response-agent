#!/usr/bin/env python3
"""Stale-reference scan: for symbols/files removed in a PR's diff, verify the post-PR tree has
no remaining references (the "rename refactor missed a callsite" class).

The diff runs from `merge-base($STALE_REF_BASE, HEAD)` to the working tree, not to HEAD, because
the reference half (`git grep`) reads the working tree; both halves must read the same tree or
uncommitted deletions go unseen. On a clean tree (CI) the two are identical.

Algorithm:
  1. Diff from `merge-base($STALE_REF_BASE, HEAD)` (default base `origin/main`) to the
     working tree.
  2. Collect identifiers removed by `-`-side lines:
       - `def NAME(` / `class NAME`, except a def nested in a function body (resolved
         against the base tree's AST): invisible outside its scope, it can strand nothing;
         nor a method of a class whose every base comes from outside the repo (an override
         of that base's API, e.g. a test double's `Path.with_suffix`: the name belongs to the
         base). A base defined in the file or imported from a repo module keeps its class's
         methods collected. The cost: a new, repo-specific method on a class whose only bases
         are foreign is not collected
       - top-level `NAME =` (uppercase constants)
       - removed `from ... import NAME` targets
  3. Skip identifiers under 8 chars with no underscore, and common stdlib symbols.
  4. Skip identifiers that still have a binding site (def/class/assignment/import) anywhere
     in the post-PR tree: moved, re-exported, or an import reflowed. Idents harvested from
     paths are skipped likewise by `_path_named` when a tracked directory or file still
     carries the name. Archival trees (`_ARCHIVAL_DIRS`) cannot vouch for a name.
  5. Grep the tree once for all survivors, word-boundary (`git grep -w -F -e A -e B ...`),
     so a removed `_by_id` does not match `template_path_by_id`. Idents with >50 hits are
     too common to be signal; idents with 1–50 hits outside the diff's changed files are
     surfaced.

A hit in a Python file is classified against that file's AST (bound, declared as a parameter,
or read), not the line's text: a parameter alone on a line of a multi-line signature reads
textually like a multi-line import member. Non-Python files use textual heuristics.

Fail-closed: every git command must succeed, else `GitError` and exit 2, so "git could not
answer" is never confused with "the answer is empty". In particular a shallow CI checkout can
resolve the base ref yet have no merge-base, so the preflight checks the merge-base, not just
the ref. The one allowed non-zero exit is `git grep` returning 1 for "no match".

Exit codes:
  0  clean, or every finding is baselined
  1  a new stale reference
  2  the gate could not run — unresolvable base ref, no merge-base, or a git failure.

Suppression:
  - `# lint-stale-ref: ok — <reason>` on the referencing line, for a reference that names a
    dead symbol on purpose (e.g. a negative-assertion test proving the dead command is denied).
  - A YAML frontmatter `name: <ident>` line is a declaration, not a reference, and is never
    reported. Line-scoped: other references in the same file still count.

Run from repo root:  python scripts/lint/lint_stale_refs.py
"""
from __future__ import annotations

import ast
import fnmatch
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_REF = os.environ.get("STALE_REF_BASE", "origin/main")
BASELINE_PATH = Path(__file__).with_name("lint_stale_refs_baseline.json")

HIT_CAP = 50

# Patterns per `git grep` call: the matcher degrades superlinearly in the pattern count, so
# batching cuts total cost.
_GREP_BATCH = 200

REMOVED_DEF = re.compile(r"^-\s*(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
REMOVED_ASSIGN = re.compile(r"^-\s*([A-Z][A-Z0-9_]{3,})\s*=")
REMOVED_PY_IMPORT = re.compile(
    r"^-\s*from\s+([\w.]+)\s+import\s+([\w,\s]+)|"
    r"^-\s*import\s+([\w.]+)"
)

# Identifiers that are never project-specific stale-ref signal. The ordinary-English words are
# here because a deleted test double like `def successful(...)` would otherwise condemn every
# ordinary use of the word in the tree.
GENERIC_NAMES = {
    "main", "handle", "author", "format_output",
    "successful", "interrupted",
    "Callable", "Iterable", "Iterator", "Optional", "Union", "Any",
    "typing", "dataclass", "field", "Path", "List", "Dict",
    # A stdlib protocol method: deleting a test's `sys.meta_path` finder would otherwise
    # condemn every `importlib.util.find_spec(...)` call.
    "find_spec",
}

# Trees holding frozen copies of things the live tree may have deleted: a name surviving only
# here cannot vouch that it survives. Distinct from EXCLUDED_GREP_DIRS ("is this dir a
# reference source"), which includes live dirs.
_ARCHIVAL_DIRS = ("experiments/", ".claude/worktrees/", "docs/archive/", "spec-flow/specs/archive/")

# Trees whose removals are not code changes (local scratch: research runs, experiment
# harnesses). Their throwaway definitions collide with ordinary English, so deleting one would
# donate many identifiers and every unrelated mention would read as stale. Excluded from the
# removal diff, since the `-` side is what manufactures them.
#
# `experiments` must be here structurally: it is also in `_ARCHIVAL_DIRS`, so deleting one file
# under it would donate the component `experiments` as a removed identifier nothing could clear.
NON_SOURCE_DIRS = ("seam-harness", "experiments")

EXCLUDED_GREP_DIRS = (
    ".git", ".venv", "__pycache__", "node_modules",
    "defender/fixtures",
    "defender/lessons", "defender/lessons-actor",
    ".claude/worktrees", "experiments",
    # Task files and design docs reference removed symbols historically;
    # they are not code that should be kept consistent with current names.
    "tasks", "docs",
    "defender/docs",
    # The spec corpus quotes pre-change code by construction.
    "spec-flow/specs",
    # An entry matches `rel == d` or `rel` under `d + "/"`, so it does not cover a
    # same-prefixed sibling directory; these are listed explicitly rather than relaxing the
    # match to a bare prefix, which would swallow any future `defender/tests-*` sibling.
    "defender/fixtures-e2e",
    "defender/lessons-environment",
    "defender/lessons-questioner",
    # Judge-alignment dataset: human-labelled samples whose text quotes the code of its
    # moment. Rewriting them to today's vocabulary would falsify the labels.
    "defender/learning/judge-alignment",
    # Golden case records: each names the code path that produced it, and rewriting that
    # would falsify what was run. The eval code beside it is still scanned.
    "defender/evals/oracle_golden/cases",
)

# Globs for inert-by-construction artifacts that cannot live under one excluded root. Empty:
# the spec corpus is one directory in EXCLUDED_GREP_DIRS. Note `*` does not cross a `/`.
EXCLUDED_GREP_GLOBS: tuple[str, ...] = ()

# On the REFERENCING line: this reference names a dead symbol deliberately.
SUPPRESS = "lint-stale-ref: ok"

# A YAML frontmatter `name:` line declares an identity; it does not call anything.
FRONTMATTER_NAME = re.compile(r"^\s*name:\s*(\S+)\s*$")

# A `def` signature line — the only place a bare `ident` in a parameter slot declares a local
# rather than referencing the module-level symbol. Textual fallback for files with no AST.
DEF_SIGNATURE = re.compile(r"^\s*(?:async\s+)?def\s")

# Every maximal word run on a line: narrows "which removed identifiers could this line be
# about" to a set lookup, keeping the per-hit loops off an idents x hits product.
#
# Exact for a word-shaped name: `\b` is defined off the same `\w` class, so
# `re.search(rf"\b{ident}\b", line)` is true exactly when `ident` is one of the line's maximal
# runs (`1foo` yields `1foo`, not `foo`). Names that are not one run (path stems with `-`/`.`)
# are matched one regex each.
WORD_RUN = re.compile(r"\w+")


def _referencing(content: str, word_idents: set[str], other: dict[str, re.Pattern]) -> set[str]:
    """Which of the removed identifiers this line mentions, as `\b<ident>\b` would answer."""
    found = set(WORD_RUN.findall(content)) & word_idents
    found.update(i for i, pat in other.items() if pat.search(content))
    return found


def _split_idents(idents: Sequence[str]) -> tuple[set[str], dict[str, re.Pattern]]:
    """`(word-shaped, {the rest: its \b-anchored pattern})`."""
    word = {i for i in idents if WORD_RUN.fullmatch(i)}
    other = {i: re.compile(rf"\b{re.escape(i)}\b") for i in idents if i not in word}
    return word, other


@dataclass(frozen=True)
class _PyFacts:
    """What each line of one Python file binds, declares, and reads — keyed `(lineno, name)`.

    `bindings` makes an ident "still defined" (def/class name, import alias, assignment
    target). A parameter is not a binding: it binds a local, and treating it as a definition
    would drop the ident from the entire scan. It goes in `params`, which is line-scoped and
    only says "this line does not reference the name".

    `loads` keeps `def f(x=x())` — a parameter that also reads the symbol it shadows — a
    reference."""

    bindings: frozenset[tuple[int, str]]
    params: frozenset[tuple[int, str]]
    loads: frozenset[tuple[int, str]]
    #: `bindings` inverted to `lineno -> names` (derived).
    bindings_by_line: dict[int, frozenset[str]]


def _collect_py_facts(tree: ast.AST) -> _PyFacts:
    bindings: set[tuple[int, str]] = set()
    params: set[tuple[int, str]] = set()
    loads: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings.add((node.lineno, node.name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # `alias.lineno` is the member's own line, so a reflowed multi-line import
            # binds each name on its own line.
            for alias in node.names:
                for name in (alias.asname, alias.name.split(".")[0]):
                    if name and name != "*":
                        bindings.add((alias.lineno, name))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        bindings.add((sub.lineno, sub.id))
        elif isinstance(node, ast.arg):
            params.add((node.lineno, node.arg))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads.add((node.lineno, node.id))
        elif isinstance(node, ast.Attribute):
            loads.add((node.lineno, node.attr))
        elif isinstance(node, ast.keyword) and node.arg:
            loads.add((node.lineno, node.arg))
    by_line: dict[int, set[str]] = {}
    for lineno, name in bindings:
        by_line.setdefault(lineno, set()).add(name)
    return _PyFacts(
        frozenset(bindings), frozenset(params), frozenset(loads),
        {ln: frozenset(names) for ln, names in by_line.items()},
    )


class _PySources:
    """The AST facts of every Python file a grep hit lands in, parsed once each."""

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root
        self._cache: dict[str, _PyFacts | None] = {}

    def facts(self, rel: str) -> _PyFacts | None:
        """None when there is no AST (not Python, or does not parse); callers fall back to
        textual heuristics."""
        if rel not in self._cache:
            self._cache[rel] = self._parse(rel)
        return self._cache[rel]

    def _parse(self, rel: str) -> _PyFacts | None:
        if not rel.endswith(".py"):
            return None
        try:
            text = (self._repo_root / rel).read_text(encoding="utf-8", errors="replace")
            return _collect_py_facts(ast.parse(text))
        except (OSError, SyntaxError, ValueError):
            return None


class GitError(RuntimeError):
    """A git command the gate requires to succeed did not; the gate must not report clean."""


def _git(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 30,
    ok_codes: tuple[int, ...] = (0,),
) -> str:
    """Run `git <args>` and return stdout. Raise GitError unless the exit code is in
    `ok_codes`; an empty return always means git ran and found nothing."""
    printable = "git " + " ".join(args)
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="surrogateescape",
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"`{printable}` timed out after {timeout}s") from exc
    except OSError as exc:
        raise GitError(f"`{printable}` could not run: {exc}") from exc
    if proc.returncode not in ok_codes:
        raise GitError(
            f"`{printable}` exited {proc.returncode}: {(proc.stderr or '').strip()}"
        )
    return proc.stdout


def _git_ok(args: Sequence[str], *, cwd: Path, timeout: int = 30) -> bool:
    """Predicate form, for a probe whose non-zero exit is the answer. Never raises."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="surrogateescape",
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _base_ref_error(repo_root: Path, base_ref: str) -> str | None:
    """None if `base_ref` is a usable diff base; otherwise the operator-facing reason.

    Both probes are fatal. A shallow clone can resolve the ref but have no merge-base, so a
    rev-parse-only guard would pass while the gate checks nothing."""
    if not _git_ok(
        ["rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"], cwd=repo_root
    ):
        return (
            f"cannot resolve base ref `{base_ref}` — nothing can be diffed, so nothing "
            f"can be checked. In CI: give the job's actions/checkout `fetch-depth: 0`. "
            f"Locally: `git fetch origin main`, or point STALE_REF_BASE at a ref you have."
        )
    if not _git_ok(["merge-base", base_ref, "HEAD"], cwd=repo_root):
        return (
            f"`{base_ref}` resolves but has NO merge-base with HEAD — a shallow/grafted "
            f"clone. The diff is taken FROM that merge-base, so without one there is nothing "
            f"to diff and the gate would check nothing (#618). Give the job's "
            f"actions/checkout `fetch-depth: 0`; fetching the base ref at `--depth=N` "
            f"creates the ref but NOT an ancestor — the graft remains."
        )
    return None


def _diff_base(repo_root: Path, base_ref: str) -> str:
    """`merge-base(base_ref, HEAD)`, the commit every diff is taken from, resolved once.

    Diffs pass it with no second revision, so they run against the working tree (index and
    unstaged edits included), the same tree `git grep` reads. Diffing against HEAD would make
    uncommitted deletions invisible while their references stay visible."""
    return _git(["merge-base", base_ref, "HEAD"], cwd=repo_root).strip()


def _changed_files(repo_root: Path, diff_base: str) -> set[str]:
    out = _git(["diff", "--name-only", diff_base], cwd=repo_root)
    return {line.strip() for line in out.splitlines() if line.strip()}


_DIFF_FILE_HEADER = re.compile(r"^diff --git a/(.*?) b/(.*)$")


def _function_local_defs(repo_root: Path, diff_base: str, path: str) -> set[str]:
    """Names in the base version of `path` whose removal strands nothing, minus any bound at
    module or class scope in the same file some other way: a `def`/`class` inside a function
    body, and a method of a class whose every base comes from outside the repo.

    A function-local name is invisible outside its scope, and it is often an ordinary word
    used elsewhere as prose. A method overriding an outside base's API is that base's name,
    not the file's: deleting a test double's `with_suffix` would otherwise condemn every
    `Path.with_suffix` call. Read off the base tree's AST because the diff's `-` line cannot
    say what scope it sat in (a nested `def` and a method are both indented four)."""
    try:
        text = _git(["show", f"{diff_base}:{path}"], cwd=repo_root)
        tree = ast.parse(text)
    except (GitError, SyntaxError, ValueError):
        return set()
    # A base is the repo's when the file defines it or imports it from a repo module (relative,
    # or whose top-level package is a folder or module at the repo root).
    repo_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            top = (n.module or "").split(".")[0]
            if n.level or (top and ((repo_root / top).is_dir()
                                    or (repo_root / f"{top}.py").is_file())):
                repo_names.update(a.asname or a.name for a in n.names)
    local: set[str] = set()
    scoped: set[str] = set()

    def overrides_outside_base(cls: ast.ClassDef) -> bool:
        bases = [b for b in cls.bases if not (isinstance(b, ast.Name) and b.id == "object")]
        return bool(bases) and not any(
            isinstance(b, ast.Name) and b.id in repo_names for b in bases)

    def walk(node: ast.AST, in_function: bool) -> None:
        overriding = isinstance(node, ast.ClassDef) and overrides_outside_base(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                strands_nothing = in_function or (
                    overriding and not isinstance(child, ast.ClassDef))
                (local if strands_nothing else scoped).add(child.name)
                walk(child, in_function or not isinstance(child, ast.ClassDef))
            else:
                walk(child, in_function)

    walk(tree, False)
    return local - scoped


def _collect_removed_idents(repo_root: Path, diff_base: str) -> set[str]:
    diff = _git(["diff", "--unified=0", diff_base, "--", ".",
                 *(f":(exclude){d}" for d in NON_SOURCE_DIRS)], cwd=repo_root)
    idents: set[str] = set()
    current: str | None = None
    local_defs: set[str] = set()
    for line in diff.splitlines():
        header = _DIFF_FILE_HEADER.match(line)
        if header:
            current = header.group(1)
            local_defs = (_function_local_defs(repo_root, diff_base, current)
                          if current.endswith(".py") else set())
            continue
        if not line.startswith("-") or line.startswith("---"):
            continue
        m = REMOVED_DEF.match(line)
        if m and m.group(1) not in local_defs:
            idents.add(m.group(1))
        m = REMOVED_ASSIGN.match(line)
        if m:
            idents.add(m.group(1))
        m = REMOVED_PY_IMPORT.match(line)
        if m:
            # Only the from-import's targets (group 2) are collected, never the module path:
            # dropping an import line says the name may be gone, not the module, and a
            # module's binding site is a file that `_still_defined`'s AST scan cannot see. A
            # deleted module is caught by the deleted-path stem walk in `_scan`.
            targets = m.group(2)
            if targets:
                for part in re.split(r"[\s,]+", targets):
                    part = part.strip().split(".")[-1]
                    if part and len(part) >= 4:
                        idents.add(part)
    return idents


def _renamed_or_deleted_paths(
    repo_root: Path, diff_base: str
) -> tuple[set[str], set[str]]:
    """`(gone, deleted)` — every path the diff removed from its old location, and the
    subset deleted outright rather than renamed.

    Only deleted paths contribute their stem: a renamed `a/foo_helper.py` ->
    `b/foo_helper.py` keeps its module name, so collecting it would flag every importer."""
    out = _git(["diff", "--name-status", diff_base, "--", ".",
                *(f":(exclude){d}" for d in NON_SOURCE_DIRS)], cwd=repo_root)
    gone: set[str] = set()
    deleted: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("D") and len(parts) >= 2:
            gone.add(parts[1])
            deleted.add(parts[1])
        elif parts[0].startswith("R") and len(parts) >= 3:
            gone.add(parts[1])
    return gone, deleted


def _is_specific(ident: str) -> bool:
    if ident in GENERIC_NAMES:
        return False
    if "_" in ident:
        return True
    return len(ident) >= 8


def _is_excluded_path(rel: str) -> bool:
    if any(rel == d or rel.startswith(d + "/") for d in EXCLUDED_GREP_DIRS):
        return True
    return any(fnmatch.fnmatch(rel, g) for g in EXCLUDED_GREP_GLOBS)


def _grep_lines(repo_root: Path, idents: Sequence[str]) -> list[str]:
    """The single `git grep` site. rc 1 means "no match"; rc >= 2 raises.

    `EXCLUDED_GREP_DIRS` is pushed down as `:(exclude)` pathspecs purely for cost: every
    consumer already drops excluded paths, and `_is_excluded_path` stays the authority (it
    also applies `EXCLUDED_GREP_GLOBS`). The excluded trees are most of the repo's bytes, and
    without the pushdown a large retirement's grep blows the 60s ceiling. That ceiling is
    deliberately not raised, so a real regression still fails.

    Batched because `grep -F` is superlinear in the pattern count (~1500 patterns: 120s in
    one call, a few seconds in batches of `_GREP_BATCH`), so batching reduces total work.
    Each batch keeps the 60s ceiling."""
    if not idents:
        return []
    lines: list[str] = []
    for start in range(0, len(idents), _GREP_BATCH):
        cmd = ["grep", "-n", "-w", "-F"]
        for ident in idents[start:start + _GREP_BATCH]:
            cmd.extend(["-e", ident])
        cmd.append("--")
        cmd.extend(f":(exclude){d}" for d in EXCLUDED_GREP_DIRS)
        # Consumers read these lines as an unordered bag and each ident is in exactly one
        # batch, so the union equals the one-shot answer.
        lines.extend(_git(cmd, cwd=repo_root, timeout=60, ok_codes=(0, 1)).splitlines())
    return lines


def _hits(lines: Sequence[str]) -> list[tuple[str, int, str]]:
    """Parse `git grep -n` output — `path:lineno:content` — dropping anything malformed."""
    parsed: list[tuple[str, int, str]] = []
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        parsed.append((parts[0], int(parts[1]), parts[2]))
    return parsed


def _is_declaration(
    facts: _PyFacts | None, lineno: int, content: str, ident: str
) -> bool:
    """True if this line declares the name rather than referencing it:

    - a YAML frontmatter `name: <ident>` — a skill keeps its own name after a like-named
      CLI shim is deleted;
    - the ident in a parameter slot of a signature (per the AST, so multi-line signatures
      work). A default value stays a reference, whether `def f(x=<ident>())` or
      `def f(x=g(<ident>))`, which a textual regex cannot tell from a parameter.

    (The prose says `<ident>`, never a real name: this gate greps its own source.)

    Hit-scoped, not ident-scoped: as a binding either shape would drop the ident from the
    scan entirely and whitelist surviving references to the dead command."""
    m = FRONTMATTER_NAME.match(content)
    if m and m.group(1) == ident:
        return True
    if facts is not None:
        return (lineno, ident) in facts.params and (lineno, ident) not in facts.loads
    e = re.escape(ident)  # no AST (not Python, or unparseable) — fall back to the text
    return bool(
        DEF_SIGNATURE.match(content)
        and re.search(rf"[(,]\s*\*{{0,2}}{e}\s*[,:)=]", content)
    )


def _batch_grep(
    idents: list[str], exclude_files: set[str], hits: list[tuple[str, int, str]],
    py: _PySources,
) -> dict[str, list[str]]:
    """Return {ident: [filtered_lines]} from the tree-wide grep.

    Word-boundary (`-w`) so a removed `_by_id` doesn't match `template_path_by_id`;
    the attribution below is `\\b`-anchored for the same reason."""
    by_ident: dict[str, list[str]] = {i: [] for i in idents}
    # Walk candidates in `idents` order so "first ident it references" is stable.
    order = {ident: i for i, ident in enumerate(idents)}
    word_idents, other_idents = _split_idents(idents)
    for rel, lineno, content in hits:
        if rel in exclude_files or _is_excluded_path(rel):
            continue
        if SUPPRESS in content:
            continue
        # Attribute the line to the first ident it REFERENCES. A declaration is skipped
        # rather than breaking the loop: one line can declare `a` and still call `b`.
        candidates = sorted(
            _referencing(content, word_idents, other_idents), key=order.__getitem__)
        for ident in candidates:
            if _is_declaration(py.facts(rel), lineno, content, ident):
                continue
            by_ident[ident].append(f"{rel}:{lineno}:{content}"[:200])
            break
    return by_ident


def _is_binding(
    facts: _PyFacts | None, lineno: int, line: str, ident: str
) -> bool:
    """True if this line defines or imports `ident`. In Python the AST says so (a parameter
    is not a binding; see `_PyFacts`); otherwise fall back to the text."""
    if facts is not None:
        return (lineno, ident) in facts.bindings
    e = re.escape(ident)
    return bool(
        re.search(rf"\b(?:async\s+)?(?:def|class)\s+{e}\b", line)
        or re.search(rf"^\s*{e}\s*(?::[^=]+)?=(?!=)", line)   # assignment / annotated
        or ("import" in line and re.search(rf"\b{e}\b", line))  # import (module or target)
    )


@lru_cache(maxsize=1)
def _tracked_paths(repo_root: Path) -> frozenset[str]:
    """Every git-tracked path still on disk, repo-relative. Cached; called per ident.

    `git ls-files` reads the index, so a file deleted with plain `rm` would otherwise vouch
    for its own name while the grep reads a tree without it."""
    return frozenset(
        rel for rel in _git(["ls-files"], cwd=repo_root).splitlines()
        if rel and (repo_root / rel).exists()
    )


def _module_named(repo_root: Path, ident: str) -> bool:
    """Whether `ident` names a module or package that still exists in the tree.

    A module's binding site is a file, which `_is_binding` cannot see. `from PACKAGE import
    MODULE` puts the module in the target position, where it is collected like any name, so
    without this check deleting one importer of a live module makes every other importer
    read as stale. A deleted module is still caught by `_scan`'s deleted-path stem walk.

    Scoped to git-tracked paths, never a filesystem walk: `.worktrees/` or a vendored
    checkout may hold a stale copy that would mask a real deletion."""
    tracked = _tracked_paths(repo_root)
    return any(
        (rel.endswith(f"/{ident}.py") or rel == f"{ident}.py"
         or rel.endswith(f"/{ident}/__init__.py") or rel == f"{ident}/__init__.py")
        and not _is_excluded_path(rel)
        for rel in tracked
    )


def _path_named(repo_root: Path, ident: str) -> bool:
    """Whether `ident` still names a tracked directory component or file stem.

    `_scan` harvests idents from removed paths, which is wrong whenever the name outlives
    those paths — e.g. deleting 24 of 25 files under `held-out/` must not make every
    reference to the surviving directory stale.

    Only tracked paths count, so an untracked copy cannot mask a real deletion. Not filtered
    through `_is_excluded_path`: that list means "not a reference source", and includes live
    dirs like `defender/fixtures`. Only `_ARCHIVAL_DIRS` are excluded, since their frozen
    copies cannot vouch for survival.

    Gives up the ambiguous case where a name survives only in an unrelated file, the same
    choice `_module_named` makes."""
    tracked = _tracked_paths(repo_root)
    for rel in tracked:
        if rel.startswith(_ARCHIVAL_DIRS) or rel in _ARCHIVAL_DIRS:
            continue
        pure = PurePosixPath(rel)
        if ident in pure.parts[:-1] or pure.stem == ident:
            return True
    return False


def _still_defined(
    idents: list[str], hits: list[tuple[str, int, str]], py: _PySources,
    repo_root: Path | None = None,
) -> set[str]:
    """Idents that still have a binding site (def/class/assignment/import) anywhere in the
    post-PR tree, i.e. moved, re-exported, or import-reflowed rather than removed. Changed
    files are included, since that is where a moved def lives.

    This is the one ident-scoped filter — a single binding drops the ident everywhere — so
    bindings come from the AST for Python, never the text (a parameter or list element alone
    on a line looks like a multi-line import member). Module bindings are files; see
    `_module_named`."""
    word_idents, other_idents = _split_idents(idents)
    wanted = set(idents)
    defined: set[str] = set()
    for rel, lineno, content in hits:
        if not wanted:
            break
        if _is_excluded_path(rel):
            continue
        facts = py.facts(rel)
        # With an AST the line's bindings are already indexed by line; without one, every
        # textual arm needs the name on the line. Either way the candidate set is complete.
        candidates = (facts.bindings_by_line.get(lineno, frozenset()) if facts is not None
                      else _referencing(content, word_idents, other_idents))
        for ident in candidates & wanted:
            if _is_binding(facts, lineno, content, ident):
                defined.add(ident)
        wanted -= defined
    if repo_root is not None:
        defined.update(i for i in idents if i not in defined and _module_named(repo_root, i))
        defined.update(i for i in idents if i not in defined and _path_named(repo_root, i))
    return defined


HEADER = (
    "lint_stale_refs baseline — references that survive a rename/delete in the "
    "PR diff. Fingerprint is file:ident. CI fails on a surviving reference absent "
    "here. Regenerate: python scripts/lint/lint_stale_refs.py --update-baseline. "
    "This baseline is normally EMPTY: the check is diff-relative, and the recurring "
    "not-a-reference shapes (spec artifacts, frozen spec graphs, frontmatter `name:` "
    "declarations, deliberate `# lint-stale-ref: ok` references) are rules in the lint "
    'rather than entries here. An entry means a knowingly-tolerated stray reference; '
    '"" means un-triaged.'
)


def _hit_file(hit: str) -> str:
    """Extract the path from a `path:lineno:content` git-grep hit line."""
    return hit.split(":", 1)[0]


def _scan(
    repo_root: Path, base_ref: str, *, exclude_files: frozenset[str] = frozenset()
) -> list[Finding]:
    # Resolved once and threaded, so every diff uses the same base (and the working tree).
    diff_base = _diff_base(repo_root, base_ref)
    changed = _changed_files(repo_root, diff_base) | set(exclude_files)
    idents = _collect_removed_idents(repo_root, diff_base)
    removed_paths, deleted_paths = _renamed_or_deleted_paths(repo_root, diff_base)

    for p in removed_paths:
        for component in Path(p).parts:
            if len(component) >= 5 and "." not in component:
                idents.add(component)

    # The component walk above drops every file basename (they carry a suffix), so take the
    # stem of deleted (not renamed) paths explicitly.
    for p in deleted_paths:
        stem = Path(p).stem
        if len(stem) >= 5 and "." not in stem:
            idents.add(stem)

    specific = sorted(i for i in idents if _is_specific(i))
    skipped = sorted(i for i in idents if not _is_specific(i))

    if skipped:
        print(f"Skipped {len(skipped)} generic identifiers: {', '.join(skipped[:10])}"
              + ("..." if len(skipped) > 10 else ""))

    # One grep serves both passes: `_batch_grep`'s idents are a subset of `_still_defined`'s.
    py = _PySources(repo_root)
    grep_hits = _hits(_grep_lines(repo_root, specific))

    moved = _still_defined(specific, grep_hits, py, repo_root)
    if moved:
        print(f"Skipped {len(moved)} still-defined identifier(s) (moved/re-exported): "
              f"{', '.join(sorted(moved)[:10])}" + ("..." if len(moved) > 10 else ""))
    specific = [i for i in specific if i not in moved]

    if not specific:
        print("No specific removed identifiers in the diff.")
        return []

    print(f"Scanning {len(specific)} specific removed identifier(s) "
          f"(base={base_ref}, against the working tree)")
    results = _batch_grep(specific, changed, grep_hits, py)

    findings: list[Finding] = []
    print()
    for ident in specific:
        hits = results.get(ident, [])
        if not hits:
            continue
        if len(hits) > HIT_CAP:
            print(f"  SKIP `{ident}`: {len(hits)} hits (too common — likely false positive)")
            continue
        print(f"  STALE `{ident}`: {len(hits)} reference(s) remain")
        for h in hits[:5]:
            print(f"    {h}")
        if len(hits) > 5:
            print(f"    ... and {len(hits) - 5} more")
        print()
        for h in hits:
            findings.append(
                Finding(fingerprint=f"{_hit_file(h)}:{ident}", display=f"STALE {ident}: {h}")
            )
    return findings


def _self_reference(baseline_path: Path, repo_root: Path) -> frozenset[str]:
    """The baseline necessarily spells the identifiers it tolerates, so it greps as a
    surviving reference to each. A gate must not be able to find itself."""
    try:
        rel = baseline_path.resolve().relative_to(repo_root.resolve())
    except (ValueError, OSError):  # baseline outside the scanned repo (tests inject one)
        return frozenset()
    return frozenset({rel.as_posix()})


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path = REPO_ROOT,
    base_ref: str = BASE_REF,
    baseline_path: Path = BASELINE_PATH,
) -> int:
    args = sys.argv[1:] if argv is None else argv

    # Preflight before --update-baseline too, so an uncomputed empty result can't be blessed.
    err = _base_ref_error(repo_root, base_ref)
    if err is not None:
        print(f"lint_stale_refs: {err}", file=sys.stderr)
        return 2

    try:
        findings = _scan(
            repo_root, base_ref,
            exclude_files=_self_reference(baseline_path, repo_root),
        )
    except GitError as exc:
        print(f"lint_stale_refs: {exc}", file=sys.stderr)
        return 2

    print("Suppress a deliberate dead-name reference with `# lint-stale-ref: ok — <reason>`.")
    return gate(
        findings, baseline_path, args,
        label="lint_stale_refs", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
