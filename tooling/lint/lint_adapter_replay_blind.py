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
  * in `kit/verbs.py`: any class declaring `as_of` or `run_state` (a field, method, property or
    `self.` store); in `systems/verbs.py`: the call context class (`VerbContext`) declaring them;
  * in `kit/verbs.py`: any protocol (`Protocol` or `typing.Protocol`, subscripted or aliased,
    or a subclass of a protocol here) offering a `now()` — a clock under whatever name it is given;
  * in `integrations/host_state_adapter.py`: the string `"captured_at"`, and a wall-clock read
    that is the value, or feeds a name that reaches, a `return` or `yield`. A clock read is a
    stdlib current-time reader (`now`, `utcnow`, `today`, `time`, `time_ns`, `gmtime`,
    `localtime`, `ctime`, `asctime`, and `strftime` given no time tuple), called as an attribute
    or as a bare name through the module's `from X import Y [as Z]` / `import X as Y`, or through
    a name bound to one (`f = dt.datetime.now; f()`, a parameter defaulting to one, a `partial`).
    Origins flow to a fixpoint over every binding: assignments (tuple/list targets, and the base
    name of a subscript or attribute target), loop and `with` targets, comprehensions, walrus,
    and `.append/.extend/.add/.insert/.update/.setdefault` calls on a name; module-level
    bindings seed each function. Reading a clock for a deadline or an age check, with no path
    into the reply, is not a finding; the finding is at the line of the read.

WHAT IS NOT: tests and the platform side (`systems/`, `learning/`, `investigation/`) naming the
carrier or the run state, and any other adapter putting a date in its reply (tacit-knowledge judges
against today until #1390). There is no baseline and no suppression comment.

WHAT THE LINT CANNOT SEE: a clock handed under an arbitrary protocol name (a kit protocol whose
method is `utc()` or `wall()`, not `now`); flows across modules (a clock read in one module and
returned from another, or stamped into an argument by a helper the caller then returns); dynamic
names (`getattr(ctx, "as_" + "of")`, a key built from strings, `captured_at` spelled in
pieces); and control flow (a clock read that only decides a branch). The runtime context-contents
test is the net for what actually reaches an adapter; this lint is the cheap early read of the
shapes we can name.

Run from repo root:  python tooling/lint/lint_adapter_replay_blind.py
Exit 0 = clean, 1 = findings, 2 = the tree holds none of what it sweeps (a scan that saw nothing
proved nothing).
"""
from __future__ import annotations

import ast
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from _astlib import ModuleEnv, callee, module_env, origin

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The attributes that carry a replay input to an adapter.
_REPLAY_ATTRS = frozenset({"as_of", "run_state"})
#: The platform-only carrier of the run state around a call.
_CARRIER = "CALL_RUN_STATE"
#: Calls that read a wall clock (or the run's own clock) for a value, by name.
_CLOCK_READS = frozenset({"now", "utcnow", "today", "time", "time_ns"})
#: `time` module readers that read the clock only when given no time (tuple or seconds) to render.
_TIME_READS = frozenset({"gmtime", "localtime", "ctime", "asctime", "strftime"})
#: Calls on a name that put their arguments into it.
_MUTATORS = frozenset({"append", "extend", "add", "insert", "update", "setdefault",
                       "appendleft", "extendleft"})
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


def _constant_strings(call: ast.Call) -> Iterator[str]:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            yield arg.value


def _replay_input_use(node: ast.AST) -> str | None:  # noqa: PLR0911 — one arm per spelling
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
    if isinstance(node, ast.MatchClass):
        for attr in node.kwd_attrs:
            if attr in _REPLAY_ATTRS:
                return f"matches `{attr}` by a class pattern"
    if isinstance(node, ast.Call):
        fn = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else None)
        strings = list(_constant_strings(node))
        if fn == "getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                and node.args[1].value in _REPLAY_ATTRS:
            return f"reads `{node.args[1].value}` by `getattr`"
        if fn in ("attrgetter", "__getattribute__"):
            for text in strings:
                if _REPLAY_ATTRS & set(text.split(".")):
                    return f"reads `{text}` by `{fn}`"
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
    """The `(name, line)` of each field, method, property or `self.` store a class declares."""
    for stmt in cls.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            yield stmt.target.id, stmt.lineno
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield stmt.name, stmt.lineno
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                        and isinstance(node.value, ast.Name) and node.value.id in ("self", "cls")):
                    yield node.attr, node.lineno
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        yield name.id, stmt.lineno


def _spelled(node: ast.AST, env: ModuleEnv) -> str | None:
    """`node` as a dotted name: its import origin where the scope binds its root to an import (so
    `import typing as t` gives `t.Protocol` as `typing.Protocol`), else the name as written (a
    class of this module); None for anything but a `Name.attr` chain."""
    resolved = origin(node, env) if isinstance(node, ast.expr) else None
    if resolved is not None:
        return resolved
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _spelled(node.value, env)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _is_protocol(cls: ast.ClassDef, env: ModuleEnv, local: frozenset[str] = frozenset()
                 ) -> bool:
    """A `Protocol` subclass: `Protocol`, `typing.Protocol`, `typing_extensions.Protocol`,
    subscripted or imported under another name, or a subclass of a protocol in this module."""
    for base in cls.bases:
        node = base.value if isinstance(base, ast.Subscript) else base
        qual = _spelled(node, env)
        if qual is not None and (qual.split(".")[-1] == "Protocol" or qual in local):
            return True
    return False


def _protocols(tree: ast.AST) -> list[ast.ClassDef]:
    env = module_env(tree)
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    local: set[str] = set()
    grew = True
    while grew:
        grew = False
        for cls in classes:
            if cls.name not in local and _is_protocol(cls, env, frozenset(local)):
                local.add(cls.name)
                grew = True
    return [cls for cls in classes if cls.name in local]


def _context_findings(rel: str, tree: ast.Module) -> list[str]:
    """A class declaring a replay input: any class in the kit's interface, `VerbContext` in the
    platform's."""
    out: list[str] = []
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        if rel != _KIT and cls.name != _CONTEXT_CLASS:
            continue
        out += [f"{rel}:{line}: `{cls.name}` declares `{name}` — an adapter must receive "
                "neither the branch point nor the run clock (#1385 O1)"
                for name, line in _declared_names(cls) if name in _REPLAY_ATTRS]
    return out


def _kit_clock_findings(rel: str, tree: ast.Module) -> list[str]:
    """A protocol in the kit offering a `now()`: a clock handed to adapters, whatever its name."""
    return [f"{rel}:{line}: protocol `{cls.name}` offers a clock (`now`) — the kit's interface "
            "carries no run clock (#1385 O1)"
            for cls in _protocols(tree) for name, line in _declared_names(cls) if name == "now"]


class _Clock:
    """What a module calls a clock read: the stdlib readers by attribute or bare name, through the
    module's import aliases and the names it binds to one (`f = dt.datetime.now`)."""

    def __init__(self, tree: ast.AST) -> None:
        self.env = module_env(tree)
        #: local name -> the `(root, last)` clock reader it is bound to.
        self.bound: dict[str, tuple[str | None, str]] = {}
        grew = True
        while grew:
            grew = False
            for name, value in self._bindings(tree):
                kind = self._reader(value)
                if kind is not None and self.bound.get(name) != kind:
                    self.bound[name] = kind
                    grew = True

    def _bindings(self, tree: ast.AST) -> Iterator[tuple[str, ast.AST]]:
        """`(name, value)` for each name bound to a bare callable, or a `partial` of one."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        yield target.id, node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None \
                    and isinstance(node.target, ast.Name):
                yield node.target.id, node.value
            elif isinstance(node, ast.arguments):
                pos = [*node.posonlyargs, *node.args]
                for arg, default in zip(pos[len(pos) - len(node.defaults):], node.defaults):
                    yield arg.arg, default
                for arg, kw_default in zip(node.kwonlyargs, node.kw_defaults):
                    if kw_default is not None:
                        yield arg.arg, kw_default

    def _reader(self, node: ast.AST) -> tuple[str | None, str] | None:
        """`(root module, reader name)` of the clock reader `node` is, uncalled, else None."""
        if isinstance(node, ast.Call):  # functools.partial(<reader>, ...)
            qual = callee(node, self.env)
            if qual is not None and qual.split(".")[-1] == "partial" and node.args:
                return self._reader(node.args[0])
            return None
        if isinstance(node, ast.Name):
            if node.id in self.bound:
                return self.bound[node.id]
            qual = origin(node, self.env)
            if qual is None or "." not in qual:
                return None
            root, last = qual.split(".")[0], qual.split(".")[-1]
            if qual != "datetime.time" and (
                    (root == "datetime" and last in ("now", "utcnow", "today"))
                    or (root == "time" and last in _CLOCK_READS | _TIME_READS)):
                return root, last
            return None
        if isinstance(node, ast.Attribute):
            qual = origin(node, self.env)
            if qual == "datetime.time":  # the time-of-day class, not a read
                return None
            base = qual.split(".")[0] if qual is not None else None
            if node.attr in _CLOCK_READS or (base == "time" and node.attr in _TIME_READS):
                return base, node.attr
        return None

    def is_read(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        kind = self._reader(node.func)
        if kind is None:
            return False
        last = kind[1]
        if last in _CLOCK_READS:
            return True
        # a `time` renderer reads the clock only with no time to render: `strftime(fmt)`
        given = [*node.args, *(k.value for k in node.keywords)]
        if last == "strftime":
            return len(given) <= 1
        return all(isinstance(a, ast.Constant) and a.value is None for a in given)


def _reads_in(node: ast.AST | None, clock: _Clock) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call) and clock.is_read(n)
            ] if node is not None else []


def _names_in(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node is not None else set()


def _bound_names(target: ast.AST) -> Iterator[str]:
    """The names an assignment target binds or fills: a name, each name in a tuple or list, and
    the base name of a subscript or attribute (`d[k] = v` fills `d`)."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _bound_names(elt)
    elif isinstance(target, ast.Starred):
        yield from _bound_names(target.value)
    elif isinstance(target, (ast.Subscript, ast.Attribute)):
        yield from _bound_names(target.value)


def _assigned(stmt: ast.AST, env: ModuleEnv) -> tuple[list[str], list[ast.AST]]:  # noqa: C901 — one arm per binding form
    """`(names bound, the expressions their values come from)` of a binding node, else
    `([], [])`: assignments, loop and `with` targets, comprehension targets, walrus, and a call
    that puts its arguments into a name (`xs.append(v)`, `d.update(v)`, `d.setdefault(k, v)`)."""
    if isinstance(stmt, ast.Assign):
        slices = [t.slice for t in stmt.targets if isinstance(t, ast.Subscript)]
        return [n for t in stmt.targets for n in _bound_names(t)], [stmt.value, *slices]
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        value = stmt.value
        return (list(_bound_names(stmt.target)), [value] if value is not None else [])
    if isinstance(stmt, (ast.For, ast.AsyncFor, ast.comprehension)):
        return list(_bound_names(stmt.target)), [stmt.iter]
    if isinstance(stmt, ast.withitem) and stmt.optional_vars is not None:
        return list(_bound_names(stmt.optional_vars)), [stmt.context_expr]
    # a method on a value, not a function an import names (`callee` is None for the former)
    if (isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute)
            and callee(stmt, env) is None and stmt.func.attr in _MUTATORS):
        return list(_bound_names(stmt.func.value)), [*stmt.args, *(k.value for k in stmt.keywords)]
    return [], []


def _origins(nodes: Iterable[ast.AST], clock: _Clock,
             seed: dict[str, set[int]]) -> dict[str, set[int]]:
    """For each name, the lines of the clock reads that may reach it, propagated to a fixpoint over
    every binding in `nodes` — in any statement order, inside any `try`/`with`/`if`."""
    binds = [(names, deps) for names, deps in (_assigned(n, clock.env) for n in nodes) if names]
    origins = {name: set(lines) for name, lines in seed.items()}
    grew = True
    while grew:
        grew = False
        for names, deps in binds:
            lines: set[int] = set()
            for dep in deps:
                lines |= {c.lineno for c in _reads_in(dep, clock)}
                for used in _names_in(dep):
                    lines |= origins.get(used, set())
            for name in names:
                held = origins.setdefault(name, set())
                if not lines <= held:
                    held |= lines
                    grew = True
    return origins


def _module_level(tree: ast.Module) -> Iterator[ast.AST]:
    """The nodes of a module outside any function body."""
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node)
                     if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)))


def _function_stamps(func: ast.AST, clock: _Clock, seed: dict[str, set[int]]) -> set[int]:
    """The lines of the clock reads in `func` whose value reaches a `return` or `yield`: read
    inline in the returned expression, or bound to a name (directly, or through other names, or
    through the module's own bindings in `seed`) the return uses."""
    nodes = list(ast.walk(func))
    origins = _origins(nodes, clock, seed)
    stamped: set[int] = set()
    for ret in (n for n in nodes if isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom))):
        stamped |= {c.lineno for c in _reads_in(ret.value, clock)}
        for used in _names_in(ret.value):
            stamped |= origins.get(used, set())
    return stamped


def _host_state_findings(rel: str, tree: ast.Module) -> list[str]:
    """Host-state putting a time stamp in its reply: a `captured_at` key, or a clock read that
    reaches a returned value."""
    lines = {n.lineno for n in ast.walk(tree)
             if isinstance(n, ast.Constant) and n.value == "captured_at"}
    clock = _Clock(tree)
    seed = _origins(_module_level(tree), clock, {})
    for func in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        lines |= _function_stamps(func, clock, seed)
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
