#!/usr/bin/env python3
"""Adapters are replay-blind — no adapter, nor the adapter kit's interface, reads the branch
point, the run state or the run clock, and host-state stamps no time of its own (#1385 L1).

An adapter knows only its target system (the #1172 ruling). A branched replay's cut at the branch
point is the oracle's, and the time a reply is observed is the platform's stamp (`received_at`),
so neither reaches an adapter: not on the call context, not in the kit's protocol, not through the
call-scoped carrier the query tool sets for the platform (`CALL_RUN_STATE`). This lint is the net
under that rule; a replay guarantee that rested in each adapter would hold only for the adapters
we wrote.

WHAT IS A FINDING (paths are relative to the `defender/` tree):
  * in `integrations/` and in the adapter template `skills/connect/examples/`: an attribute read
    of `.as_of` or `.run_state`, `getattr(x, "as_of" | "run_state", ...)`, and any reference to
    `CALL_RUN_STATE` (a name, an attribute, an import);
  * in `kit/verbs.py` and `systems/verbs.py`: the call context class (`VerbContext`) declaring
    `as_of` or `run_state`;
  * in `kit/verbs.py`: any protocol offering a `now()` — a clock under whatever name it is given;
  * in `integrations/host_state_adapter.py`: the string `"captured_at"`, and a wall-clock read
    (`now`, `utcnow`, `today`, `time.time`) that is the value, or feeds a name that reaches,
    a `return`. Reading a clock for a deadline or an age check, with no path into the reply, is
    not a finding; the finding is at the line of the read.

WHAT IS NOT: tests and the platform side (`systems/`, `learning/`, `investigation/`) naming the
carrier or the run state, and any other adapter putting a date in its reply (tacit-knowledge judges
against today until #1390). There is no baseline and no suppression comment.

Run from repo root:  python tooling/lint/lint_adapter_replay_blind.py
Exit 0 = clean, 1 = findings, 2 = the tree holds none of what it sweeps (a scan that saw nothing
proved nothing).
"""
from __future__ import annotations

import ast
import sys
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The attributes that carry a replay input to an adapter.
_REPLAY_ATTRS = frozenset({"as_of", "run_state"})
#: The platform-only carrier of the run state around a call.
_CARRIER = "CALL_RUN_STATE"
#: Calls that read a wall clock (or the run's own clock) for a value.
_CLOCK_READS = frozenset({"now", "utcnow", "today", "time", "time_ns"})
_HOST_STATE = "integrations/host_state_adapter.py"
_KIT = "kit/verbs.py"
_PLATFORM_CONTEXT = "systems/verbs.py"
_CONTEXT_CLASS = "VerbContext"
_ADAPTER_TREES = ("integrations/", "skills/connect/examples/")


def _python_files(root: Path, prefix: str) -> Iterator[tuple[str, Path]]:
    """`(relative path, file)` for each module under `root/prefix`, tests excluded."""
    for path in sorted((root / prefix).rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if "tests" not in path.relative_to(root).parts:
            yield rel, path


def _parsed(path: Path, rel: str) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=rel)


def _replay_input_use(node: ast.AST) -> str | None:
    """What replay input `node` reads, if it does: the attribute, the `getattr` name or the
    carrier."""
    if isinstance(node, ast.Attribute):
        if node.attr in _REPLAY_ATTRS:
            return f"reads `.{node.attr}`"
        if node.attr == _CARRIER:
            return f"reaches `{_CARRIER}`"
    if isinstance(node, ast.Name) and node.id == _CARRIER:
        return f"reaches `{_CARRIER}`"
    if isinstance(node, ast.alias) and node.name.split(".")[-1] == _CARRIER:
        return f"imports `{_CARRIER}`"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
            and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _REPLAY_ATTRS):
        return f"reads `{node.args[1].value}` by `getattr`"
    return None


def _adapter_findings(rel: str, tree: ast.Module) -> list[str]:
    """Each line of an adapter (or the template) that reads a replay input; one per line."""
    seen: dict[int, str] = {}
    for node in ast.walk(tree):
        what = _replay_input_use(node)
        line = getattr(node, "lineno", None)
        if what is not None and line is not None:
            seen.setdefault(line, what)
    return [f"{rel}:{line}: an adapter {what} — adapters are replay-blind (#1385 O1)"
            for line, what in sorted(seen.items())]


def _declared_names(cls: ast.ClassDef) -> Iterator[tuple[str, int]]:
    """The `(name, line)` of each field, method or property a class declares."""
    for stmt in cls.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            yield stmt.target.id, stmt.lineno
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield stmt.name, stmt.lineno
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    yield target.id, stmt.lineno


def _is_protocol(cls: ast.ClassDef) -> bool:
    return any((isinstance(b, ast.Name) and b.id == "Protocol")
               or (isinstance(b, ast.Attribute) and b.attr == "Protocol") for b in cls.bases)


def _context_findings(rel: str, tree: ast.Module) -> list[str]:
    """`VerbContext` declaring a replay input, in the kit's protocol or the platform's class."""
    out: list[str] = []
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        if cls.name != _CONTEXT_CLASS:
            continue
        out += [f"{rel}:{line}: `{_CONTEXT_CLASS}` declares `{name}` — an adapter must receive "
                "neither the branch point nor the run clock (#1385 O1)"
                for name, line in _declared_names(cls) if name in _REPLAY_ATTRS]
    return out


def _kit_clock_findings(rel: str, tree: ast.Module) -> list[str]:
    """A protocol in the kit offering a `now()`: a clock handed to adapters, whatever its name."""
    return [f"{rel}:{line}: protocol `{cls.name}` offers a clock (`now`) — the kit's interface "
            "carries no run clock (#1385 O1)"
            for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef) and _is_protocol(cls)
            for name, line in _declared_names(cls) if name == "now"]


def _is_clock_read(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _CLOCK_READS)


def _reads_in(node: ast.AST | None) -> list[ast.Call]:
    return [n for n in ast.walk(node) if _is_clock_read(n)] if node is not None else []


def _names_in(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node is not None else set()


def _assigned(stmt: ast.AST) -> tuple[list[str], ast.AST | None]:
    """`(names bound, value)` of a simple assignment statement, else `([], None)`."""
    if isinstance(stmt, ast.Assign):
        return [t.id for t in stmt.targets if isinstance(t, ast.Name)], stmt.value
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)) and isinstance(stmt.target, ast.Name):
        return [stmt.target.id], stmt.value
    if isinstance(stmt, ast.NamedExpr):
        return [stmt.target.id], stmt.value
    return [], None


def _function_stamps(func: ast.AST) -> set[int]:
    """The lines of the clock reads in `func` whose value reaches a `return`: read inline in the
    returned expression, or bound to a name (directly or through other names) the return uses."""
    stamped_lines: set[int] = set()
    origins: dict[str, set[int]] = {}
    for stmt in ast.walk(func):
        targets, value = _assigned(stmt)
        if value is not None:
            lines = {c.lineno for c in _reads_in(value)}
            for used in _names_in(value):
                lines |= origins.get(used, set())
            for name in targets:
                origins.setdefault(name, set()).update(lines)
    for ret in (n for n in ast.walk(func) if isinstance(n, (ast.Return, ast.Yield))):
        stamped_lines |= {c.lineno for c in _reads_in(ret.value)}
        for used in _names_in(ret.value):
            stamped_lines |= origins.get(used, set())
    return stamped_lines


def _host_state_findings(rel: str, tree: ast.Module) -> list[str]:
    """Host-state putting a time stamp in its reply: a `captured_at` key, or a clock read that
    reaches a returned value."""
    lines = {n.lineno for n in ast.walk(tree)
             if isinstance(n, ast.Constant) and n.value == "captured_at"}
    for func in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        lines |= _function_stamps(func)
    return [f"{rel}:{line}: host-state stamps a time in its reply — the platform stamps every "
            "reply (#1385 O7)" for line in sorted(lines)]


def scan(root: Path) -> list[str]:
    """Every finding under the `defender/` tree at `root`, sorted."""
    root = Path(root)
    findings: list[str] = []
    for prefix in _ADAPTER_TREES:
        for rel, path in _python_files(root, prefix):
            tree = _parsed(path, rel)
            findings += _adapter_findings(rel, tree)
            if rel == _HOST_STATE:
                findings += _host_state_findings(rel, tree)
    for rel in (_KIT, _PLATFORM_CONTEXT):
        if (root / rel).is_file():
            tree = _parsed(root / rel, rel)
            findings += _context_findings(rel, tree)
            if rel == _KIT:
                findings += _kit_clock_findings(rel, tree)
    return sorted(set(findings))


def _sees_nothing(root: Path) -> bool:
    return not any(_python_files(root, "integrations")) and not (root / _KIT).is_file()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = REPO_ROOT / "defender"
    if "--root" in args:
        at = args.index("--root")
        if at + 1 >= len(args):
            print("usage: lint_adapter_replay_blind.py [--root <defender tree>]", file=sys.stderr)
            return 2
        root = Path(args[at + 1])
    if _sees_nothing(root):
        print(f"[lint_adapter_replay_blind] {root} holds no adapters and no kit: nothing was "
              "scanned", file=sys.stderr)
        return 2
    findings = scan(root)
    for finding in findings:
        print(finding)
    if findings:
        print(f"\n[lint_adapter_replay_blind] {len(findings)} finding(s). An adapter receives "
              "neither the branch point nor the run clock: the oracle applies the cut and the "
              "platform stamps each reply (#1385).")
        return 1
    print("[lint_adapter_replay_blind] 0 findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
