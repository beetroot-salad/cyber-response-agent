"""Deterministic seed extractor for a single Python module.

Step 1 scope — everything here is mechanical, no LLM. It produces, rooted at
a chosen entry function:

  * `calls`        edges between functions defined in the module (ast)
  * `dispatches`   edges for `_run_claude(<CONST>, ...)` where CONST resolves
                   to a `*.md` agent prompt   (via=run_claude)
  * `runs_command` edges for `subprocess.*([... <CONST> ...])` where CONST
                   resolves to a `*.py` script (via=subprocess)

Constant resolution is intentionally narrow and honest: it evaluates only the
`Path(__file__).resolve().parents[k]` anchor + `<Path> / "literal"` chains that
this codebase actually uses for its prompt/script constants, against the real
on-disk location of the module. Anything it cannot resolve becomes a `Gap`
rather than a guess — including the genuinely dynamic `__import__(var)` site.

Node identity is canonical and path-derived:
  py-func       ->  "py:<relpath>::<func>"
  agent-prompt  ->  "agent-prompt:<relpath-of-md>"
  script        ->  "script:<relpath-of-py>"
"""
from __future__ import annotations

import ast
from pathlib import Path

from .model import Edge, Gap, Graph, Node


# --------------------------------------------------------------------------- #
# Constant resolution
# --------------------------------------------------------------------------- #


class ConstResolver:
    """Resolve module-level `NAME = <path-expr>` constants to real paths.

    Handles exactly the shapes the defender learning loop uses:
      REPO_ROOT   = Path(__file__).resolve().parents[2]
      LEARNING_DIR = REPO_ROOT / "defender" / "learning"
      ACTOR_PROMPT = LEARNING_DIR / "actor.md"
    Returns None for anything else (caller turns that into a Gap).
    """

    def __init__(self, module_path: Path) -> None:
        self.module_path = module_path.resolve()
        self.values: dict[str, Path] = {}

    def load(self, tree: ast.Module) -> None:
        # Two passes so forward references between constants resolve regardless
        # of source order (they are top-to-bottom here, but cheap to be safe).
        for _ in range(2):
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    tgt = stmt.targets[0]
                    if isinstance(tgt, ast.Name):
                        val = self._eval(stmt.value)
                        if val is not None:
                            self.values[tgt.id] = val

    def _eval(self, node: ast.AST) -> Path | None:
        # <left> / "literal"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self._eval(node.left)
            right = node.right
            if left is not None and isinstance(right, ast.Constant) and isinstance(right.value, str):
                return left / right.value
            return None
        # NAME -> previously resolved constant
        if isinstance(node, ast.Name):
            return self.values.get(node.id)
        # Path(__file__).resolve().parents[k]
        if isinstance(node, ast.Subscript):
            return self._eval_parents(node)
        return None

    def _eval_parents(self, node: ast.Subscript) -> Path | None:
        # node.value should be `Path(__file__).resolve().parents`
        val = node.value
        if not (isinstance(val, ast.Attribute) and val.attr == "parents"):
            return None
        if not self._is_path_file_resolve(val.value):
            return None
        idx = node.slice
        if isinstance(idx, ast.Constant) and isinstance(idx.value, int):
            try:
                return self.module_path.parents[idx.value]
            except IndexError:
                return None
        return None

    @staticmethod
    def _is_path_file_resolve(node: ast.AST) -> bool:
        # matches `Path(__file__).resolve()`
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "resolve"):
            return False
        inner = node.func.value
        return (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
                and inner.func.id == "Path"
                and len(inner.args) == 1 and isinstance(inner.args[0], ast.Name)
                and inner.args[0].id == "__file__")


# --------------------------------------------------------------------------- #
# Call/dispatch extraction
# --------------------------------------------------------------------------- #


def _called_name(call: ast.Call) -> str | None:
    """Best-effort callable name for an ast.Call."""
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def _is_subprocess_call(call: ast.Call) -> bool:
    fn = call.func
    return (isinstance(fn, ast.Attribute) and fn.attr in
            {"run", "Popen", "call", "check_call", "check_output"}
            and isinstance(fn.value, ast.Name) and fn.value.id == "subprocess")


def _names_in(node: ast.AST) -> list[ast.Name]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Name)]


def _kind_for_path(p: Path) -> str | None:
    if p.suffix == ".md":
        return "agent-prompt"
    if p.suffix == ".py":
        return "script"
    return None


def seed_python_module(file: Path, root: Path, entry: str = "run_one") -> Graph:
    """Build a deterministic call+dispatch graph rooted at `entry`."""
    file = file.resolve()
    root = root.resolve()
    src = file.read_text()
    tree = ast.parse(src, filename=str(file))

    def rel(p: Path) -> str:
        try:
            return str(p.resolve().relative_to(root))
        except ValueError:
            return str(p)

    relfile = rel(file)

    # Collect top-level function defs (module functions; loop.py has no methods
    # in the traced subflow).
    funcs: dict[str, ast.FunctionDef] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[stmt.name] = stmt

    consts = ConstResolver(file)
    consts.load(tree)

    g = Graph(built_from={"root": str(root), "module": relfile, "entry": entry})

    def func_id(name: str) -> str:
        return f"py:{relfile}::{name}"

    def ensure_func_node(name: str) -> str:
        nid = func_id(name)
        if nid not in g.nodes:
            fn = funcs[name]
            doc = ast.get_docstring(fn)
            label = (doc.strip().splitlines()[0] if doc else "")
            g.add_node(Node(
                id=nid, kind="py-func",
                label=label, label_source="harvested" if label else "",
                ref=f"{relfile}:{fn.lineno}",
                signals={"decision_density": _decision_density(fn)},
            ))
        return nid

    # BFS from entry over local calls; record dispatch/subprocess edges per func.
    if entry not in funcs:
        raise SystemExit(f"entry function {entry!r} not found in {relfile}")

    seen: set[str] = set()
    queue = [entry]
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        src_id = ensure_func_node(name)
        fn = funcs[name]
        _extract_func(fn, src_id, name, funcs, consts, g, rel, relfile,
                      func_id, ensure_func_node, queue)

    return g


def _decision_density(fn: ast.AST) -> int:
    return sum(1 for n in ast.walk(fn)
               if isinstance(n, (ast.If, ast.For, ast.While, ast.Try, ast.Match)))


def _extract_func(fn, src_id, name, funcs, consts, g, rel, relfile,
                  func_id, ensure_func_node, queue) -> None:
    relpath = relfile

    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        cname = _called_name(call)
        site = f"{relpath}:{getattr(call, 'lineno', fn.lineno)}"

        # --- local call edge ------------------------------------------------
        if cname in funcs:
            dst = ensure_func_node(cname)
            g.add_edge(Edge(src_id, dst, "calls", ref=site, via="ast"))
            if cname not in queue:
                queue.append(cname)

        # --- claude -p dispatch: _run_claude(<CONST prompt>, ...) -----------
        if cname == "_run_claude" and call.args:
            arg0 = call.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in consts.values:
                p = consts.values[arg0.id]
                if p.suffix == ".md":
                    nid = f"agent-prompt:{rel(p)}"
                    g.add_node(Node(id=nid, kind="agent-prompt",
                                    label=p.stem, label_source="harvested",
                                    ref=f"{rel(p)}:1"))
                    g.add_edge(Edge(src_id, nid, "dispatches",
                                    label=arg0.id, ref=site, via="run_claude"))
                else:
                    g.gaps.append(Gap("unresolved-const", site,
                                      f"_run_claude prompt arg {arg0.id!r} -> {p} (not .md)"))
            elif call.args:
                g.gaps.append(Gap("unresolved-const", site,
                                  f"_run_claude prompt arg is not a resolvable constant: "
                                  f"{ast.dump(arg0)[:80]}"))

        # --- subprocess of a resolvable .py script --------------------------
        if _is_subprocess_call(call):
            script_consts = {
                nm.id for nm in _names_in(fn)
                if nm.id in consts.values and consts.values[nm.id].suffix == ".py"
            }
            if script_consts:
                for cnm in sorted(script_consts):
                    p = consts.values[cnm]
                    nid = f"script:{rel(p)}"
                    g.add_node(Node(id=nid, kind="script",
                                    label=p.name, label_source="harvested",
                                    ref=f"{rel(p)}:1"))
                    g.add_edge(Edge(src_id, nid, "runs_command",
                                    label=cnm, ref=site, via="subprocess"))
            else:
                # subprocess whose target is a literal binary (e.g. "claude")
                # is not a script edge; only flag if it looks like it should be.
                pass

        # --- dynamic import: __import__(var) -> GAP (proves the protocol) ----
        if cname == "__import__" and call.args:
            a0 = call.args[0]
            if not isinstance(a0, ast.Constant):
                g.gaps.append(Gap(
                    "dynamic-dispatch", site,
                    f"__import__({ast.unparse(a0)}) in {name}() — target is a runtime "
                    "value; resolve by tracing the literal kwargs at call sites of "
                    f"{name}() (deterministic dataflow) or via a haiku worker.",
                ))
