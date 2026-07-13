"""Shared AST resolution for the lint gates — answer "where does this call COME FROM",
not "how was it SPELLED".

Three gates used to identify a banned call by its spelled dotted name:
``_receiver_root(call) == "re"`` (frontmatter), ``call.func.value.id == "json"``
(jsonl), a ``subprocess.`` prefix and an opener-root skip-list (text-io). Each asked
*"is this call written as ``re.something(...)``?"* rather than *"does this call land in
the ``re`` module?"*, so an alias (``import re as regex``) or a from-import
(``from re import search``) made all three blind — the same hole, re-derived three times
(#602, #594).

Spelling-based identification fails a second, worse way: it cannot know the callee's
ARITY. ``lint_unpinned_text_io._open_mode`` read ``call.args[0]`` as the mode of any
``<x>.open(...)`` — right for ``Path.open(mode)``, wrong for every path-first module
opener (``codecs.open(file, mode)``, ``io.open(file, mode)``, ``gzip.open(file, mode)``),
so the gate read the FILE PATH as the mode string and every verdict on that family turned
on whether the path was a literal containing the letter ``b``. The mode's positional slot
and its default are properties of the CALLEE. Resolving the callee is what supplies them:
the resolver is not a patch for the alias hole, it is what makes such a check correct at
all.

``callee()`` returning None is a first-class signal, NOT a failure: it means the receiver
is a value rather than a module (``p.open("r")``, ``zf.open(n)``). A gate that wants the
duck-typed case must key on the attribute NAME and skip only via a POSITIVE table of
origins — "skip whatever resolves" would turn every resolvable receiver into a false
negative. ``zf.open(n)`` and ``p.open("r")`` are indistinguishable here by construction;
telling them apart needs local-binding tracking, which this module deliberately does not do.

The one unsound hole — ``from re import *`` — is closed outside the gates: ruff runs
``--select E,F`` repo-wide, so F403 already makes a star-import unmergeable. That is why
this resolver can be sound without dataflow.
"""
from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass

_BUILTIN_NAMES = frozenset(dir(builtins))


@dataclass(frozen=True)
class ModuleEnv:
    """What a module binds at import time.

    ``imports`` — bound name -> dotted ORIGIN::

        import re                   -> {"re": "re"}
        import re as regex          -> {"regex": "re"}
        import os.path              -> {"os": "os"}        # `import a.b` binds `a`
        import os.path as osp       -> {"osp": "os.path"}
        from re import search       -> {"search": "re.search"}
        from re import search as s  -> {"s": "re.search"}
        from .mod import y          -> {"y": ".mod.y"}     # leading dot: never collides
                                                           # with a stdlib origin
    ``consts``  — module-level ``NAME = "<str literal>"`` bindings.
    ``defines`` — module-level def/class/assign names, i.e. the names that are therefore
    NOT the builtin of the same name.
    """

    imports: dict[str, str]
    consts: dict[str, str]
    defines: frozenset[str]


def module_env(tree: ast.AST) -> ModuleEnv:
    """Build the import/const/define environment for one module.

    Imports are collected from the WHOLE tree, not just ``tree.body``: a function-local
    ``import re as regex`` is a plausible evasion, and a module-level-only resolver would
    reproduce the exact blind spot this module exists to close. Colliding aliases are
    last-write-wins — the failure mode is a false positive, and the shape does not occur.

    ``consts`` stays MODULE-LEVEL only, deliberately asymmetric: an import unambiguously
    binds a name to a module, a local string assignment does not, and widening it is a
    detector-semantics change with real false-positive risk on live code.
    """
    imports: dict[str, str] = {}
    consts: dict[str, str] = {}
    defines: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    # `import a.b.c` binds only `a`, and `a` refers to package `a`.
                    root = alias.name.split(".")[0]
                    imports[root] = root
        elif isinstance(node, ast.ImportFrom):
            # `level` > 0 is a relative import; keep the leading dots so a relative
            # `.re` can never be mistaken for the stdlib `re`.
            prefix = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    continue  # unresolvable — but ruff F403 makes it unmergeable
                imports[alias.asname or alias.name] = f"{prefix}.{alias.name}"

    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defines.add(node.name)
            continue
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        else:
            continue
        if not isinstance(target, ast.Name):
            continue
        defines.add(target.id)
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            consts[target.id] = node.value.value

    return ModuleEnv(imports=imports, consts=consts, defines=frozenset(defines))


def origin(node: ast.expr, env: ModuleEnv) -> str | None:
    """The dotted origin of a PURE ``Name.attr.attr`` chain rooted at an imported name.

    ``os`` -> ``"os"``; ``regex`` -> ``"re"``; ``re.error`` -> ``"re.error"``.
    ``p`` -> None (a local value). ``zipfile.ZipFile(p)`` -> None: a Call in the chain
    makes it a VALUE, not an attribute path — never walk through one, or the value's
    origin gets confused with its constructor's.
    """
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    base = env.imports.get(cur.id)
    if base is None:
        return None
    return ".".join([base, *reversed(parts)])


def callee(call: ast.Call, env: ModuleEnv) -> str | None:
    """The dotted origin of the called FUNCTION, or None when the receiver is a value
    rather than a module.

        re.search(...) / regex.search(...) / search(...)   -> "re.search"
        subprocess.run(...) / run(...)                     -> "subprocess.run"
        open(...)      [not imported, not shadowed]        -> "builtins.open"
        p.open("r") / p.read_text() / zf.open(n)           -> None   <- DUCK-TYPED

    The ``builtins.<id>`` fallback fires ONLY in call position, and only for a Name that
    is in neither ``env.imports`` nor ``env.defines`` — so a parameter named ``input`` or
    a module-level ``def open(...)`` cannot fabricate an origin.
    """
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in env.imports:
            return env.imports[func.id]
        if func.id in env.defines:
            return None
        if func.id in _BUILTIN_NAMES:
            return f"builtins.{func.id}"
        return None
    if isinstance(func, ast.Attribute):
        return origin(func, env)
    return None


def root_name(node: ast.expr) -> str | None:
    """The LOOSE root Name of an attribute/call/subscript chain, walking THROUGH calls:
    ``line.strip()`` -> ``"line"``; ``zipfile.ZipFile(p).open`` -> ``"zipfile"``.

    This identifies a NAME for value-derivation tracking (which local a value came from);
    it is NOT module resolution and must not be used as one. Distinct from ``origin`` on
    purpose — the three gates each had a private copy of this walker under a different
    name (``_receiver_root`` / ``_open_receiver_root`` / ``_root_name``).
    """
    cur: ast.expr = node
    while True:
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return cur.id if isinstance(cur, ast.Name) else None


def str_args(call: ast.Call, env: ModuleEnv) -> list[str]:
    """The string args of a call — positional AND keyword (so ``re.compile(pattern=…)``
    is seen), tuple elements flattened (so ``startswith(("a", "b"))`` is), and Names
    resolved through ``env.consts``.

    The const resolution matters: hoisting a literal to a module constant
    (``FENCE = "---\\n"`` … ``text.startswith(FENCE)``) is GOOD style, and a detector that
    reads inline Constants only makes the tidiest way to write the banned idiom the one
    way to evade the gate.
    """
    out: list[str] = []

    def resolve(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return env.consts.get(node.id)
        return None

    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(arg, ast.Tuple):
            out.extend(v for el in arg.elts if (v := resolve(el)) is not None)
        elif (v := resolve(arg)) is not None:
            out.append(v)
    return out


def arg_at(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    """The argument in positional slot ``index`` or passed as ``keyword=``, whichever is
    present. The positional slot is a property of the CALLEE — ``builtins.open(file, mode)``
    puts mode at 1, ``Path.open(mode)`` at 0, ``tempfile.NamedTemporaryFile(mode)`` at 0 —
    so the caller must pass the index it resolved, never guess one."""
    if index >= 0 and len(call.args) > index:
        return call.args[index]
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def str_value(node: ast.expr | None, env: ModuleEnv) -> str | None:
    """A single expression's string value — an inline literal or a module constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return env.consts.get(node.id)
    return None


def has_kw(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def kw_is_true(call: ast.Call, name: str) -> bool:
    """True only for a literal ``name=True``, or a module const bound to it."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
