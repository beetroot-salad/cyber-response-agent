# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT imported.
# This is defender/tests/scripts_1080_split/_census1080.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. The
# nodes the cut narrowed carry a `# PRE-CUT …` marker naming the issue(s) that own the cut part.
# The live suite imports the narrowed module; the pre-cut test copies beside this file (and the
# parked tests in ../) were written against this version.
"""The static checks #1080's placement demands run: the O1 import census, the O2 direction
test, the placement check over `defender/scripts/`, and the file-depth-anchor scan. NO tests.

All four are STATIC (s129): they read files and parse ASTs, never import a module to learn
where it is defined, so they run in the dev-only code-smells job as well as here. Each takes a
checkout ROOT, so a planted copy of the tree (a tmp git repo built by `tree_copy`) is scanned
by exactly the code that scans the real one; an `overlay` (repo-relative path → source) adds
or replaces files on top of a root without copying it, for the cheap positive controls.

WHAT THE CENSUS COUNTS (O1, §7 auto-resolutions): import STATEMENTS only — `import x`,
`from x import y`, wherever they sit (module level, function body, `try`, `if TYPE_CHECKING:`,
a platform conditional: s002), relative forms resolved against the importer's package (s150),
aliases, wildcards and several names on a line each counted (s149), the bare
`from defender import scripts` and `import defender.scripts` included ([148]). A path load, a
`-m` run, a spawn by path or a dotted name in a string is NOT an import (H1 (a), [1], s151,
s152). Targets are `defender.scripts` and anything under it — never the repo's own top-level
`scripts/` package (s156). Importers: every TRACKED `.py` under `defender/` and the repo's
`scripts/` (`git ls-files`, so an untracked scratch file, a nested checkout, a `.venv` link and
`__pycache__` never count: s003, s154), minus the test exemption drawn by location ([155]:
under a directory named `tests`, or a `conftest.py`) and minus `defender/scripts/` itself
(inside-scripts edges are free: s157). A file the census cannot parse fails it, named ([153]).

THE EXCEPTION LISTS ARE DATA HERE AND ASSERTED BY TESTS: O1's three named (importer, target)
edges into `scripts/adapters/_stub_transport.py` (M-A (a) with H4 (i)), each retired by a
named ticket, the write-back importer found by the symbol it defines; O2's N5 edges (dF7 (a)):
learning's page entry points importing reports. A listed edge that no longer exists is a
finding ([218]), never a silent widening.

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

import ast
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from defender import _git
from defender.tests.scripts_1080_split import _spec1080 as S

SCRIPTS_PKG = "defender.scripts"
STUB_TRANSPORT = "defender.scripts.adapters._stub_transport"
ADAPTERS = "defender/scripts/adapters"

#: The four commands that stay in `scripts/` (D1, the 10-03 "stays" row).
STAYING_COMMANDS = (
    "defender/scripts/tenant.py",
    "defender/scripts/policy_cli.py",
    "defender/scripts/box_image.py",
    "defender/scripts/tacit_cli.py",
)

#: The two shims whose exec targets are the wrappers that stay (M-H (a): shims unchanged).
WRAPPER_SHIMS = ("defender-sql", "defender-lessons")


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
    """The census's importer scope: tracked `.py` under `defender/` and the repo's `scripts/`,
    minus junk directories (even force-added: s154), the test exemption and `defender/scripts/`."""
    return [r for r in tracked_files(root, "defender", "scripts")
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
                and (S.under(r, "defender") or S.under(r, "scripts")):
            files.add(r)
    edges = {Edge(st.path, st.line, t) for st in imports(root, sorted(files), overlay)
             for t in targets_of(st, root) if is_scripts_target(t)}
    return sorted(edges)


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1165 (the ticket_writer -> _stub_transport edge).
def o1_exceptions(root: Path = S.REPO_ROOT) -> tuple[tuple[str, str, str], ...]:
    """O1's named exceptions (M-A (a) with H4 (i)): (importer, target, retiring ticket). The
    write-back importer is wherever `record_case_ticket` is defined (found by symbol); before
    the write-back has moved it names no file, so it excuses nothing and reads as stale."""
    try:
        write_back = S.home_of("record_case_ticket", root=root)
    except AssertionError:
        write_back = "<record_case_ticket has no home outside defender/scripts/>"
    return (
        ("defender/learning/branch/staging.py", STUB_TRANSPORT, "#1121"),
        ("defender/skills/connect/examples/example_adapter.py", STUB_TRANSPORT, "#1172"),
        (write_back, STUB_TRANSPORT, "#1165 or #1172"),
    )


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
    """The repo-relative file a `bin/` shim of the tree at `root` execs."""
    text = (root / "defender" / "bin" / shim).read_text(encoding="utf-8")
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("exec ") and ".py" in s:
            for tok in s.split():
                tok = tok.strip('"')
                if tok.endswith(".py"):
                    tail = tok.split("}", 1)[-1] if "}" in tok else tok.split("/", 1)[-1]
                    return "defender/" + tail.lstrip("/")
    raise AssertionError(f"bin/{shim} names no `exec ... <file>.py` line")


def wrappers(root: Path = S.REPO_ROOT) -> tuple[str, ...]:
    return tuple(shim_target(root, s) for s in WRAPPER_SHIMS)


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1172 (confinement, esql_text and faults leaving scripts/adapters/).
def adapters_expected() -> tuple[str, ...]:
    """The files `scripts/adapters/` keeps until #1172 (M-A (a)): the eight `*_adapter.py`,
    `_stub_transport.py` and `README.md` — the adapters named off the base inventory."""
    base = S.base_inventory()["files"]
    eight = [f for f in base if S.under(f, ADAPTERS) and f.endswith("_adapter.py")]
    assert len(eight) == 8, eight
    return tuple(sorted([*eight, f"{ADAPTERS}/_stub_transport.py", f"{ADAPTERS}/README.md"]))


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1105, #1165, #1172 and the case_ticket follow-up.
def placement_findings(root: Path = S.REPO_ROOT) -> list[str]:
    """Every tracked file under `defender/scripts/` that is none of: a staying command, a
    shim's wrapper, or one of the files `scripts/adapters/` keeps (any file type: [6])."""
    allowed = {*STAYING_COMMANDS, *wrappers(root), *adapters_expected()}
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
    keep = {r for r in tracked_files(src, "defender", "scripts", *also)
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
