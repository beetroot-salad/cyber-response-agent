"""Deterministic gap-closure: cross-module in-process dispatch.

The seed reports two things it cannot resolve from a single call expression:

  * dynamic:  ``mod = __import__(param)`` then ``mod.attr(...)`` — the module
              name is a runtime parameter (reported as a ``dynamic-dispatch`` gap).
  * static:   ``import X as Y`` then ``Y.attr(...)`` — a cross-module call the
              per-expression seed pass does not emit at all (a silent drop).

Both are the same phenomenon — an in-process call into a sibling module — and
both are recoverable *deterministically*, no LLM:

  1. Bind aliases: module-level + function-scoped ``import`` statements, and
     ``name = __import__("literal")``.
  2. For ``name = __import__(param)``, recover the concrete module names by
     reading the literal ``param`` kwargs/args at every call site of the
     enclosing function (call-site dataflow).
  3. For each ``<binding>.<attr>(...)`` call, resolve ``binding`` → module name
     → a *sibling* ``.py`` file (same dir as the analysed module). Only sibling
     modules become edges; stdlib / third-party (no sibling file) are skipped,
     not guessed.
  4. Emit cross-module ``calls`` edges to the target ``FunctionDef`` and drop
     the matching reported gap.

This is the "promote a gap into a deterministic seed resolver" path: the schema
is unchanged, the edges gain ``via=dynamic-import|module-attr`` +
``confidence=deterministic`` so they are indistinguishable from any other
trusted edge.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .model import Edge, Graph, Node


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(p)


def _find_func(tree: ast.Module, attr: str) -> ast.FunctionDef | None:
    for d in ast.walk(tree):
        if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef)) and d.name == attr:
            return d
    return None


def _recover_param_literals(tree: ast.Module, fn: ast.FunctionDef, pname: str) -> set[str]:
    """Literal strings passed as `pname` at every call site of `fn` in module."""
    pos_params = [a.arg for a in (fn.args.posonlyargs + fn.args.args)]
    lits: set[str] = set()
    for call in (c for c in ast.walk(tree) if isinstance(c, ast.Call)):
        if not (isinstance(call.func, ast.Name) and call.func.id == fn.name):
            continue
        for kw in call.keywords:
            if kw.arg == pname and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, str):
                lits.add(kw.value.value)
        if pname in pos_params:
            idx = pos_params.index(pname)
            if idx < len(call.args):
                a = call.args[idx]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    lits.add(a.value)
    return lits


def resolve_module_dispatch(g: Graph, module: Path, root: Path) -> dict:
    """Close cross-module dispatch on the reachable subflow already in `g`.

    Mutates `g` (adds nodes/edges, drops resolved gaps). Returns a summary.
    """
    module = module.resolve()
    root = root.resolve()
    tree = ast.parse(module.read_text(), filename=str(module))
    relfile = _rel(module, root)
    funcs = {s.name: s for s in tree.body
             if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}

    module_aliases: dict[str, str] = {}
    for s in tree.body:
        if isinstance(s, ast.Import):
            for a in s.names:
                module_aliases[a.asname or a.name] = a.name

    resolved_funcs: set[str] = set()
    edges_added = 0

    # cache: parsed target trees so each sibling is read once
    _tree_cache: dict[Path, ast.Module] = {}

    def add_target(modname: str, attr: str, src_id: str, via: str, site: str) -> bool:
        target_file = module.parent / f"{modname}.py"
        if not target_file.is_file():
            return False  # stdlib / third-party — no sibling, not an app edge
        ttree = _tree_cache.get(target_file)
        if ttree is None:
            ttree = ast.parse(target_file.read_text(), filename=str(target_file))
            _tree_cache[target_file] = ttree
        tfn = _find_func(ttree, attr)
        if tfn is None:
            return False
        trel = _rel(target_file, root)
        doc = ast.get_docstring(tfn)
        label = doc.strip().splitlines()[0] if doc else ""
        tid = f"py:{trel}::{attr}"
        g.add_node(Node(id=tid, kind="py-func", label=label,
                        label_source="harvested" if label else "",
                        ref=f"{trel}:{tfn.lineno}"))
        before = len(g.edges)
        # label reflects the RESOLVED module, not the binding name — so a
        # dynamic __import__(param) edge reads e.g. "author_actor.run_batch".
        g.add_edge(Edge(src_id, tid, "calls", label=f"{modname}.{attr}",
                        ref=site, via=via, confidence="deterministic",
                        resolved_by="seed"))
        return len(g.edges) > before

    for fname, fn in funcs.items():
        src_id = f"py:{relfile}::{fname}"
        if src_id not in g.nodes:
            continue  # only resolve dispatch on the reachable subflow

        aliases = dict(module_aliases)
        dyn_bindings: dict[str, str] = {}   # binding -> param name
        for n in ast.walk(fn):
            if isinstance(n, ast.Import):
                for a in n.names:
                    aliases[a.asname or a.name] = a.name
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name):
                v = n.value
                if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) \
                        and v.func.id == "__import__" and v.args:
                    a0 = v.args[0]
                    if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                        aliases[n.targets[0].id] = a0.value
                    elif isinstance(a0, ast.Name):
                        dyn_bindings[n.targets[0].id] = a0.id

        param_literals = {
            p: _recover_param_literals(tree, fn, p)
            for p in set(dyn_bindings.values())
        }

        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            f = call.func
            if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)):
                continue
            binding, attr = f.value.id, f.attr
            site = f"{relfile}:{getattr(call, 'lineno', fn.lineno)}"
            if binding in aliases:
                if add_target(aliases[binding], attr, src_id, "module-attr", site):
                    edges_added += 1
                    resolved_funcs.add(fname)
            elif binding in dyn_bindings:
                for modname in sorted(param_literals.get(dyn_bindings[binding], set())):
                    if add_target(modname, attr, src_id, "dynamic-import", site):
                        edges_added += 1
                        resolved_funcs.add(fname)

    # drop dynamic-dispatch gaps for functions we successfully resolved
    kept_gaps = []
    dropped = 0
    for gp in g.gaps:
        if gp.kind == "dynamic-dispatch" and any(
            f"in {fn}()" in gp.detail for fn in resolved_funcs
        ):
            dropped += 1
            continue
        kept_gaps.append(gp)
    g.gaps = kept_gaps

    return {"edges_added": edges_added, "gaps_dropped": dropped,
            "resolved_funcs": sorted(resolved_funcs)}
