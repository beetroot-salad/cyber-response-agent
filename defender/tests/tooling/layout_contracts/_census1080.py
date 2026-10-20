"""The static checks #1080's placement demands run: the O1 import census, the O2 direction
test, the placement check over `defender/scripts/`, and the file-depth-anchor scan. NO tests."""
from __future__ import annotations

import ast
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from defender import _git
from defender.tests.tooling.layout_contracts import _spec1080 as S

SCRIPTS_PKG = "defender.scripts"
STUB_TRANSPORT = "defender.integrations._stub_transport"
ADAPTERS = "defender/integrations"

#: No production files remain at the historical scripts paths. The old import namespace
#: remains the census target so a future import or compatibility shim is still rejected.
STAYING_COMMANDS = ()
OUT_STAYING = ()
WRAPPER_SHIMS = ("defender-sql", "defender-lessons")

#: The spring cleanup retired all 20 formerly allowed imports into scripts.
O1_EXCEPTIONS: tuple[tuple[str, str, str], ...] = ()


# ======================================================================================
# Listing the tree
# ======================================================================================


def tracked_files(root: Path, *tops: str) -> list[str]:
    """Every TRACKED file under each of `tops` (repo-relative, POSIX), from `git ls-files -z`
    — tracked only, so an untracked scratch file or a nested checkout never counts (s003)."""
    out = _git.git(["ls-files", "-z", "--", *tops], cwd=root)  # lint-oracle: ok — the census's own scope (tracked files), not an expected value for tenant.py's read
    return sorted(p for p in out.split("\0") if p)


def _junk(relpath: str) -> bool:
    return any(part in S.JUNK_DIRS for part in relpath.split("/")[:-1])


def census_files(root: Path) -> list[str]:
    """The census's importer scope: tracked `.py` under `defender/` and the repo's `tooling/`,
    minus junk directories (even force-added: s154), the test exemption and `defender/scripts/`."""
    return [r for r in tracked_files(root, "defender", "tooling")
            if r.endswith(".py") and not _junk(r) and not S.is_test_path(r)
            and not S.under(r, "defender/scripts")]


def read(root: Path, relpath: str, overlay: Mapping[str, str] | None = None) -> bytes:
    if overlay and relpath in overlay:
        return overlay[relpath].encode("utf-8")
    return (root / relpath).read_bytes()


# ======================================================================================
# O1 — the import census
# ======================================================================================


@dataclass(frozen=True, order=True)
class Edge:
    """One import statement's edge: importer file, line, and the module it names."""

    importer: str
    line: int
    target: str


class CensusBlind(AssertionError):
    """The census met an in-scope file it cannot parse ([153]): a blind spot never passes."""


def _module_exists(root: Path, dotted_name: str) -> bool:
    p = root.joinpath(*dotted_name.split("."))
    return p.with_suffix(".py").is_file() or p.is_dir()


def targets_of(stmt: S.ImportStmt, root: Path) -> list[str]:
    """The modules one statement names: `import a.b` → `a.b`; `from a import b` → `a.b` when
    that is a module (or the package `defender.scripts` itself), else `a`; `*` → the module."""
    if not stmt.names:
        return [stmt.module]
    out: list[str] = []
    for n in stmt.names:
        sub = f"{stmt.module}.{n}" if stmt.module else n
        if n != "*" and (sub == SCRIPTS_PKG or _module_exists(root, sub)):
            out.append(sub)
        else:
            out.append(stmt.module)
    return list(dict.fromkeys(out))


def is_scripts_target(target: str) -> bool:
    return target == SCRIPTS_PKG or target.startswith(SCRIPTS_PKG + ".")


def imports(root: Path, files: Iterable[str], overlay: Mapping[str, str] | None = None
            ) -> list[S.ImportStmt]:
    """Every import statement in `files`; raises `CensusBlind` naming each unparseable file."""
    blind: list[str] = []
    out: list[S.ImportStmt] = []
    for r in files:
        try:
            out.extend(S.import_statements(r, read(root, r, overlay)))
        except (SyntaxError, ValueError) as e:
            blind.append(f"{r}: {type(e).__name__}: {e}")
    if blind:
        raise CensusBlind("the census cannot read in-scope files: " + "; ".join(blind))
    return out


def census(root: Path = S.REPO_ROOT, overlay: Mapping[str, str] | None = None) -> list[Edge]:
    """Every import of a `defender.scripts` module from outside `defender/scripts/` (O1)."""
    files = set(census_files(root))
    for r in overlay or {}:
        if r.endswith(".py") and not _junk(r) and not S.is_test_path(r) \
                and not S.under(r, "defender/scripts") \
                and (S.under(r, "defender") or S.under(r, "tooling")):
            files.add(r)
    edges = {Edge(st.path, st.line, t) for st in imports(root, sorted(files), overlay)
             for t in targets_of(st, root) if is_scripts_target(t)}
    return sorted(edges)


def o1_exceptions(root: Path = S.REPO_ROOT) -> tuple[tuple[str, str, str], ...]:
    """O1's named exceptions (E1 of the 2026-10-04 scope cut): (importer, target, owner). Data,
    the same for every root; `root` is kept so a caller scanning a planted copy reads alike."""
    del root
    return O1_EXCEPTIONS


def o1_violations(root: Path = S.REPO_ROOT, overlay: Mapping[str, str] | None = None
                  ) -> list[Edge]:
    allowed = {(i, t) for i, t, _ in o1_exceptions(root)}
    return [e for e in census(root, overlay) if (e.importer, e.target) not in allowed]


def stale_o1_exceptions(root: Path = S.REPO_ROOT, overlay: Mapping[str, str] | None = None
                        ) -> list[tuple[str, str, str]]:
    """Listed exceptions whose edge no longer exists in the tree ([218])."""
    live = {(e.importer, e.target) for e in census(root, overlay)}
    return [x for x in o1_exceptions(root) if (x[0], x[1]) not in live]


# ======================================================================================
# O2 — the direction test ((a) integrations' generic core imports down; (b) nothing below
# reports imports reports, except N5's page entry points)
# ======================================================================================

#: dF7 (a), M-G (b): the direction test's whole exception list — N5's edges, learning's own
#: page entry points importing reports. Matched on the importer (a file, or a directory
#: boundary-matched) and the reports package.
N5_EXCEPTIONS: tuple[tuple[str, str], ...] = (
    ("defender/learning/branch/cli.py", "defender.reports"),
    ("defender/learning/frontend", "defender.reports"),
)

#: Symbols whose modules are integrations' per-vendor carve-outs (M-C (a)): write-back and
#: the product Elastic module. A carve-out is the defining module's sub-package when it sits
#: in one under integrations, else the module file itself.
CARVE_OUT_ANCHORS = ("record_case_ticket", "world_view", "esql_payload", "split_first_command",
                     "confine_index")


def carve_outs(root: Path = S.REPO_ROOT) -> tuple[str, ...]:
    out: set[str] = set()
    for sym in CARVE_OUT_ANCHORS:
        for d in S.definitions(sym, root):
            if S.under(d, S.INTEGRATIONS):
                parent = d.rsplit("/", 1)[0]
                out.add(parent if parent != S.INTEGRATIONS else d)
    return tuple(sorted(out))


def integrations_core(root: Path = S.REPO_ROOT, overlay: Mapping[str, str] | None = None
                      ) -> list[str]:
    """Every `.py` under `defender/integrations/` that is not in a carve-out (walked from the
    disk, package marker or not: s128)."""
    files = set(S.py_files(root, ("defender/integrations",)))
    files |= {r for r in overlay or {} if r.endswith(".py") and S.under(r, S.INTEGRATIONS)}
    cuts = carve_outs(root)
    return sorted(r for r in files if not any(S.under(r, c) for c in cuts))


def _flat_tier_or_own(target: str) -> bool:
    parts = target.split(".")
    if parts[0] != "defender":
        return True  # the stdlib or a third-party package
    if len(parts) >= 2 and parts[1].startswith("_"):
        return True  # a flat-tier `defender/_*.py` module
    return target == "defender.integrations" or target.startswith("defender.integrations.")


def _reports(target: str) -> bool:
    return target == "defender.reports" or target.startswith("defender.reports.")


def _excepted(importer: str, target: str, exceptions: Sequence[tuple[str, str]]) -> bool:
    return any(S.under(importer, imp) and (target == t or target.startswith(t + "."))
               for imp, t in exceptions)


def direction_findings(root: Path = S.REPO_ROOT, overlay: Mapping[str, str] | None = None,
                       *, exceptions: Sequence[tuple[str, str]] = N5_EXCEPTIONS) -> list[Edge]:
    """Every edge the direction test refuses: (a) an integrations core module importing a
    `defender.*` module that is neither flat tier nor integrations; (b) a module under
    `runtime/` or `learning/` importing reports, outside `exceptions`."""
    core = integrations_core(root, overlay)
    below = set(S.py_files(root, ("defender/runtime", "defender/learning")))
    below |= {r for r in overlay or {} if r.endswith(".py") and not S.is_test_path(r)
              and (S.under(r, S.RUNTIME) or S.under(r, "defender/learning"))}
    found: set[Edge] = set()
    for st in imports(root, core, overlay):
        for t in targets_of(st, root):
            if not _flat_tier_or_own(t):
                found.add(Edge(st.path, st.line, t))
    for st in imports(root, sorted(below), overlay):
        for t in targets_of(st, root):
            if _reports(t) and not _excepted(st.path, t, exceptions):
                found.add(Edge(st.path, st.line, t))
    return sorted(found)


# ======================================================================================
# D1 — what `defender/scripts/` holds
# ======================================================================================


def shim_target(root: Path, shim: str) -> str:
    """The repo-relative engine file a `bin/` shim of the tree at `root` runs as a module."""
    return S.rel(S.shim_exec_target(shim, root), root)


def wrappers(root: Path = S.REPO_ROOT) -> tuple[str, ...]:
    """The shims' wrappers under `defender/scripts/`: none since the post-review change (human,
    2026-10-04) — each shim runs its engine as a module. Kept as the placement check's name."""
    return ()


def adapters_expected() -> tuple[str, ...]:
    """The files `integrations/` keeps until #1172: since the 2026-10-04 scope cut, ALL of
    its base files (the eight `*_adapter.py`, `_stub_transport.py`, `README.md`, and `faults.py`,
    `confinement.py`, `esql_text.py`, whose moves are parked with #1172 / #1121) — named off the
    base inventory."""
    base = S.base_inventory()["files"]
    files = [f.replace("defender/scripts/adapters/", "defender/integrations/")
             for f in base if S.under(f, "defender/scripts/adapters")]
    assert len([f for f in files if f.endswith("_adapter.py")]) == 8, files
    assert len(files) == 13, files
    return tuple(sorted([*files, "defender/integrations/__init__.py", "defender/integrations/ticket_writer.py"]))


def placement_findings(root: Path = S.REPO_ROOT) -> list[str]:
    """Every tracked file under `defender/scripts/` that is none of: a staying command, a
    shim's wrapper, one of the files `integrations/` keeps, or one of the cut's named
    `OUT_STAYING` files (any file type: [6])."""
    allowed = {*STAYING_COMMANDS, *wrappers(root), *adapters_expected(), *OUT_STAYING}
    return [r for r in tracked_files(root, "defender/scripts")
            if not _junk(r) and r not in allowed]


# ======================================================================================
# M2 — the file-depth anchor scan
# ======================================================================================


def _mentions_file(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(node))


def file_depth_anchors(source: str | bytes, filename: str = "<src>") -> list[int]:
    """Lines where a module derives a path from its own file DEPTH: `<…__file__…>.parents[N]`
    with N ≥ 1 (or a non-constant N), `<…__file__…>.parent.parent`, or
    `os.path.dirname(os.path.dirname(<…__file__…>))`. A single `.parent` (a sibling such as
    `Path(__file__).parent / "assets"` that travels with its module) is allowed."""
    tree = ast.parse(source, filename=filename)
    hits: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) \
                and n.value.attr == "parents" and _mentions_file(n.value.value):
            idx = n.slice
            if not (isinstance(idx, ast.Constant) and isinstance(idx.value, int)
                    and idx.value == 0):
                hits.add(n.lineno)
        elif isinstance(n, ast.Attribute) and n.attr == "parent" \
                and isinstance(n.value, ast.Attribute) and n.value.attr == "parent" \
                and _mentions_file(n.value.value) or isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "dirname" and n.args and isinstance(n.args[0], ast.Call) \
                and isinstance(n.args[0].func, ast.Attribute) \
                and n.args[0].func.attr == "dirname" and _mentions_file(n.args[0]):
            hits.add(n.lineno)
    return sorted(hits)


# ======================================================================================
# A planted copy of the tree
# ======================================================================================


def tree_copy(dst: Path, *, commit: bool = False, also: Sequence[str] = ()) -> Path:
    """A git repo at `dst` holding a copy of this checkout's tracked source the static checks
    read: every tracked non-test `.py` under `defender/` and `scripts/`, every tracked file
    under `defender/scripts/` and `defender/bin/`, and every tracked file (any type) under each
    repo-relative prefix in `also` (a lint run in the copy needs its baselines and the skills'
    markers). `git add`ed (and committed when `commit`, for a linked worktree or a clone).
    Returns `dst`."""
    src = S.REPO_ROOT
    keep = {r for r in tracked_files(src, "defender", "tooling", *also)
            if (r.endswith(".py") and not S.is_test_path(r))
            or S.under(r, "defender/scripts") or S.under(r, "defender/bin")
            or any(S.under(r, a) for a in also)}
    for r in sorted(keep):
        if not (src / r).exists():
            continue
        to = dst / r
        to.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / r, to, follow_symlinks=False)
    _git.git(["init", "-q"], cwd=dst)
    _git.git(["add", "-A"], cwd=dst)
    if commit:
        _git.git(["-c", "user.name=spec1080", "-c", "user.email=spec1080@example.invalid",
                  "commit", "-q", "--no-verify", "-m", "copy"], cwd=dst)
    return dst


def plant(root: Path, relpath: str, source: str, *, add: bool = True) -> int:
    """Write `source` at `root/relpath` (appending when the file exists) and `git add` it;
    returns the 1-based line number of the planted text's first line."""
    p = root / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    before = p.read_text(encoding="utf-8") if p.exists() else ""
    if before and not before.endswith("\n"):
        before += "\n"
    p.write_text(before + source, encoding="utf-8")
    if add:
        _git.git(["add", "-f", "--", relpath], cwd=root)
    return before.count("\n") + 1
