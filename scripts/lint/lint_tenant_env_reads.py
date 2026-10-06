#!/usr/bin/env python3
"""Tenant settings out of the environment — no read of the process environment, or of a verb
context's `env`, in the code that addresses a tenant's systems (#1107 O7).

A tenant's settings are its `settings/` folder, resolved ONCE when a run begins into the run's
record (`RunTenant`). An adapter, the estate, the case-history writer and lead-zero take what a
system's address, container, docker context or secret is from that record — never from whatever
the process happens to have exported, which differs between the shell that launched the run, the
box and the CI job, and which a model-writable tree can influence. This lint is the net under
that rule: in the four swept trees an environment LOOKUP is a finding.

THE FOUR TREES (repo-relative): `defender/scripts/adapters/`, `defender/learning/branch/estate/`
with `defender/learning/branch/staging.py`, `defender/scripts/case_history/` with
`defender/runtime/case_ticket.py`, and
`defender/runtime/lead_zero/` with `defender/runtime/lead_zero_config.py`. The allow-list is EMPTY
— there is no baseline file and no suppression comment; a read that is genuinely not a setting
moves out of the tree or is handed in by the caller.

WHAT IS A LOOKUP (resolved by the shared resolver `_astlib`, so an alias is seen: `import os as
_os`, `from os import environ as e`, `os.path.os.environ`):
  * `os.environ` in ANY use — a subscript, `.get`, a bare reference, `dict(os.environ)`;
  * `os.getenv`;
  * `env_str`, `env_int`, `env_bool` and `env_choice` (the platform's typed accessors);
  * on any expression ending in `.env` (`ctx.env`, `deps.ctx.env`), on a name bound from one
    (`env = ctx.env`, annotated, or walrus), on a function parameter named `env` (the run's
    environment handed in: `record_case_ticket(env=...)`, `resolve_lead_zero(env=...)`), and on
    a direct copy of any of these (`dict(ctx.env)`, a
    lone `{**ctx.env}`): `.get(...)` and the other mapping reads, a subscript, an `in` test, and
    iteration. Not followed: tuple-unpacked bindings, `.copy()`, `list(...)`/`sorted(...)`,
    `|`, `getattr(ctx, "env")`, a `{**env, ...}` with extra keys.
Reads at module scope are flagged too. The ONE exemption is a module-level `def main`: a command
line entry point is the process boundary where an environment belongs. A nested or method `main`
is flagged.

WHAT IS NOT: `dict(ctx.env)` and `env=ctx.env` handed to a child process (the run's cleaned
environment passes through untouched — the child is not a lookup), and anything outside the four
trees (platform settings — the data root, log format, provider keys, budgets — stay in the
environment). A lookup made through a shared helper outside the trees is out of reach by design
(direct lookups only); the run-level tests are the net for it.

Run from repo root:  python scripts/lint/lint_tenant_env_reads.py
                     python scripts/lint/lint_tenant_env_reads.py --root <repo-shaped tree>
Exit 0 = clean, 1 = findings, 2 = the scan saw none of the four trees (a root that holds nothing
to sweep is a scan that proved nothing, never a clean result), or — over this repo itself — a
swept entry no longer exists. A move that takes swept code elsewhere must carry its entry along;
otherwise the moved code leaves the sweep while the lint still passes. Under `--root <tree>` a
missing entry is simply not scanned, so a planted or partial layout is still checked.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

# Standalone program: its sibling `_astlib` is reached by bare name, and a caller that loads this
# file by path (the spec's tests do) has not put this directory on the path for us.
if (_here := str(Path(__file__).resolve().parent)) not in sys.path:
    sys.path.insert(0, _here)

from _astlib import ModuleEnv, ScanBlind, callee, module_env, origin, read_and_parse  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The four swept trees, repo-relative: a directory is walked, a file is taken as it is.
SWEPT: tuple[str, ...] = (
    "defender/scripts/adapters",
    "defender/learning/branch/estate",
    "defender/learning/branch/staging.py",
    "defender/scripts/case_history",
    "defender/runtime/case_ticket.py",
    "defender/runtime/lead_zero",
    "defender/runtime/lead_zero_config.py",
)

#: The platform's typed environment accessors — a lookup by another name.
ACCESSORS = frozenset({"env_str", "env_int", "env_bool", "env_choice"})
#: The mapping methods that read out of an environment (`copy` and the like are not reads).
READ_METHODS = frozenset({"get", "items", "keys", "values", "pop", "setdefault", "__getitem__"})
EXCLUDED_DIRS = frozenset({"__pycache__", ".venv"})


def _swept_files(root: Path) -> list[Path]:
    """Every module in the four trees under `root`. `ScanBlind` when NONE of them is there, or
    when `root` is this repo and ANY of them is missing."""
    found: list[Path] = []
    seen_a_tree = False
    for rel in SWEPT:
        target = root / rel
        if target.is_file():
            seen_a_tree = True
            found.append(target)
        elif target.is_dir():
            seen_a_tree = True
            found.extend(p for p in sorted(target.rglob("*.py"))
                         if not EXCLUDED_DIRS.intersection(p.relative_to(target).parts))
    if not seen_a_tree:
        raise ScanBlind(f"none of the four swept trees is under {root} — the lint swept nothing")
    if root.resolve() == REPO_ROOT.resolve():
        missing = [rel for rel in SWEPT if not (root / rel).exists()]
        if missing:
            raise ScanBlind(f"swept entries missing from this repo: {missing} — whatever lived "
                            "there left the sweep; point SWEPT at where it moved")
    return found


def _main_ranges(tree: ast.Module) -> list[tuple[int, int]]:
    """The line ranges of the MODULE-LEVEL `def main` — the only exempt scope."""
    return [(n.lineno, n.end_lineno or n.lineno) for n in tree.body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == "main"]


class _Reads(ast.NodeVisitor):
    """The lookups in one module, as `(line, what)` — scope-aware only as far as it must be: the
    names bound from an env expression are tracked per function, and a nested function sees its
    enclosing functions' bindings."""

    def __init__(self, env: ModuleEnv) -> None:
        self.env = env
        self.hits: list[tuple[int, str]] = []
        self._bound: list[set[str]] = [set()]

    # -- what an env expression is ---------------------------------------------------------
    def _is_env(self, node: ast.expr | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Attribute):
            return node.attr == "env"
        if isinstance(node, ast.NamedExpr):
            return self._is_env(node.value)
        if isinstance(node, ast.Name):
            return any(node.id in names for names in self._bound)
        if isinstance(node, ast.Call):
            return (callee(node, self.env) == "builtins.dict" and len(node.args) == 1
                    and not node.keywords and self._is_env(node.args[0]))
        if isinstance(node, ast.Dict):
            return len(node.keys) == 1 and node.keys[0] is None and self._is_env(node.values[0])
        return False

    def _hit(self, node: ast.AST, what: str) -> None:
        self.hits.append((getattr(node, "lineno", 0), what))

    # -- scopes ----------------------------------------------------------------------------
    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        a = node.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs, *filter(None, (a.vararg, a.kwarg))]
        self._bound.append({p.arg for p in params if p.arg == "env"})
        self.generic_visit(node)
        self._bound.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_env(node.value):
            self._bound[-1].update(t.id for t in node.targets if isinstance(t, ast.Name))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self._is_env(node.value) and isinstance(node.target, ast.Name):
            self._bound[-1].add(node.target.id)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        if self._is_env(node.value):
            self._bound[-1].add(node.target.id)
        self.generic_visit(node)

    # -- the lookups -----------------------------------------------------------------------
    def _origin_hit(self, node: ast.expr) -> bool:
        dotted = origin(node, self.env)
        if dotted is None:
            return False
        head, _, tail = dotted.partition(".")
        last = dotted.rsplit(".", 1)[-1]
        if head == "os" and last == "environ":
            self._hit(node, "reads os.environ")
            return True
        if head == "os" and last == "getenv":
            self._hit(node, "calls os.getenv")
            return True
        if last in ACCESSORS and tail:
            self._hit(node, f"calls the environment accessor {last}")
            return True
        return False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not self._origin_hit(node):
            self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self._origin_hit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in READ_METHODS and self._is_env(
                func.value):
            self._hit(node, f"reads the environment with .{func.attr}(...)")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_env(node.value):
            self._hit(node, "subscripts the environment")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, right in zip(node.ops, node.comparators, strict=True):
            if isinstance(op, ast.In | ast.NotIn) and self._is_env(right):
                self._hit(node, "tests membership in the environment")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if self._is_env(node.iter):
            self._hit(node, "iterates the environment")
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        if self._is_env(node.iter):
            self._hit(node.iter, "iterates the environment")
        self.generic_visit(node)


def scan_file(path: Path, rel: str) -> list[str]:
    """`rel:line: what` for every lookup in `path` outside a module-level `def main`."""
    _text, tree = read_and_parse(path, rel)
    visitor = _Reads(module_env(tree))
    visitor.visit(tree)
    exempt = _main_ranges(tree)
    seen: set[tuple[int, str]] = set()
    out: list[str] = []
    for line, what in sorted(visitor.hits):
        if any(lo <= line <= hi for lo, hi in exempt) or (line, what) in seen:
            continue
        seen.add((line, what))
        out.append(f"{rel}:{line}: {what}")
    return out


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    findings: list[str] = []
    for path in _swept_files(root):
        findings.extend(scan_file(path, path.relative_to(root).as_posix()))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = REPO_ROOT
    if "--root" in args:
        at = args.index("--root")
        if at + 1 >= len(args):
            print("usage: lint_tenant_env_reads.py [--root <tree>]", file=sys.stderr)
            return 2
        root = Path(args[at + 1])
    try:
        findings = scan(root)
    except ScanBlind as blind:
        print(f"[lint_tenant_env_reads] {blind}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print(
            f"\n[lint_tenant_env_reads] {len(findings)} environment read(s) in the tenant-settings "
            "trees. A tenant's settings come from the run's record (`ctx.tenant`), never the "
            "process environment; a value that is not a setting is handed in by the caller.")
        return 1
    print("[lint_tenant_env_reads] 0 findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
