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

Names resolve against the SCOPE they are used in, not against one flat module map (#607).
Collecting function-local imports is necessary — a local ``import re as regex`` is a
plausible evasion — but binding them module-wide makes any local of the same name resolve
to a module, which is how a real ``Path.open`` in ``judge/compare.py`` came to resolve as
``…invlang.parser.open`` and got skipped. ``module_env`` therefore builds a scope tree, and
a local binding shadows an import exactly as far as Python says it does.

The one unsound hole — ``from re import *`` — is closed outside the gates: ruff runs
``--select E,F`` repo-wide, so F403 already makes a star-import unmergeable. That is why
this resolver can be sound without dataflow.
"""
from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, field
from pathlib import Path

_BUILTIN_NAMES = frozenset(dir(builtins))


class ScanBlind(RuntimeError):
    """A file inside a gate's own scan scope could not be read or parsed, so the gate never
    examined it. The gate cannot report on what it did not read, and must not report clean."""


def read_and_parse(path: Path, rel: str) -> tuple[str, ast.Module]:
    """Read and parse one file of a gate's scan scope, or raise ScanBlind.

    Eight gates each carried their own copy of::

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue

    — the swallow-to-clean shape (#618/#621/#652): the file drops out of the corpus, the gate
    scans the remainder, prints ``0 finding(s)`` and exits 0. A ban this gate exists to enforce
    could sit in the skipped file and nothing would say so.

    Raising (rather than the WARN-and-continue tier ``check_actors`` uses for its census) is
    right *here* because the scope is this project's own first-party source. There is no
    vendored or fixture population to tolerate: an unparseable file under ``defender/`` or
    ``spec-flow/scripts/`` means ruff, mypy and pytest are already failing on it, so this
    raises approximately never — and when it does, silence would be the wrong answer.

    ``errors="replace"`` is preserved from the copies it replaces, so decoding still cannot
    raise; a ``UnicodeDecodeError`` (a ``ValueError``, never an ``OSError`` — see
    ``lint_unpinned_text_io``'s docstring) is therefore not a live case, and is not caught
    here on the pretence that it is.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ScanBlind(
            f"{rel}: could not be read ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so skipping it would shrink the scanned corpus silently."
        ) from exc
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ScanBlind(
            f"{rel}: could not be parsed ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so it was never examined. Fix the syntax and re-run; a file "
            f"this gate cannot parse is a file it cannot clear."
        ) from exc
    return text, tree


def read_source(path: Path, rel: str) -> str:
    """The text-only twin of `read_and_parse`, for a gate that scans lines rather than an AST."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ScanBlind(
            f"{rel}: could not be read ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so skipping it would shrink the scanned corpus silently."
        ) from exc


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


@dataclass(frozen=True)
class ModuleEnv:
    """What one SCOPE binds — the module's, or a function's.

    ``imports`` — bound name -> dotted ORIGIN::

        import re                   -> {"re": "re"}
        import re as regex          -> {"regex": "re"}
        import os.path              -> {"os": "os"}        # `import a.b` binds `a`
        import os.path as osp       -> {"osp": "os.path"}
        from re import search       -> {"search": "re.search"}
        from re import search as s  -> {"s": "re.search"}
        from .mod import y          -> {"y": ".mod.y"}     # leading dot: never collides
                                                           # with a stdlib origin
    ``consts``  — module-level ``NAME = "<str literal>"`` bindings, minus any the scope
    rebinds (a function that reassigns ``FENCE`` no longer carries the module's value).
    ``defines`` — the names bound to something OTHER than an import: def/class names,
    assignments, parameters, loop and ``with`` targets. These are the names that are
    therefore NOT the builtin, and NOT the import, of the same name.

    ``scope_of`` maps every node of the tree to the env of the scope it sits in. It is
    keyed by the node OBJECT (AST nodes hash by identity), so the map both resolves
    correctly and keeps the nodes alive — an ``id()``-keyed map would be a
    use-after-free waiting to alias a recycled address onto the wrong scope.
    """

    imports: dict[str, str]
    consts: dict[str, str]
    defines: frozenset[str]
    scope_of: dict[ast.AST, ModuleEnv] = field(
        default_factory=dict, compare=False, repr=False
    )


def _scope_bindings(scope: ast.AST) -> tuple[dict[str, str], set[str]]:
    """``(imports, other bindings)`` made DIRECTLY in one scope.

    Walks the scope's own statements and stops at every nested function/lambda/class: a
    name bound inside a nested scope belongs to THAT scope, not this one. The nested def's
    NAME, however, is bound here — so it is collected before the descent is cut off.
    """
    imports: dict[str, str] = {}
    bound: set[str] = set()

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(child.name)  # the def binds its name HERE; its body is elsewhere
                continue
            if isinstance(child, ast.Lambda):
                continue  # params + body are a scope of their own
            if isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.asname:
                        imports[alias.asname] = alias.name
                    else:
                        # `import a.b.c` binds only `a`, and `a` refers to package `a`.
                        root = alias.name.split(".")[0]
                        imports[root] = root
                continue
            if isinstance(child, ast.ImportFrom):
                # `level` > 0 is a relative import; keep the leading dots so a relative
                # `.re` can never be mistaken for the stdlib `re`.
                prefix = "." * child.level + (child.module or "")
                for alias in child.names:
                    if alias.name == "*":
                        continue  # unresolvable — but ruff F403 makes it unmergeable
                    imports[alias.asname or alias.name] = f"{prefix}.{alias.name}"
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                bound.add(child.id)          # assign, augassign, for/with target, walrus
            elif isinstance(child, ast.arg):
                bound.add(child.arg)         # a parameter
            elif isinstance(child, ast.ExceptHandler) and child.name:
                bound.add(child.name)        # `except E as name`
            walk(child)

    walk(scope)
    return imports, bound


def _module_consts(tree: ast.AST) -> dict[str, str]:
    """Top-level ``NAME = "<str literal>"`` bindings.

    MODULE-LEVEL only, deliberately asymmetric with ``imports``: an import unambiguously
    binds a name to a module, a function-local string assignment does not, and widening it
    is a detector-semantics change with real false-positive risk on live code (#605).
    """
    consts: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if (
            isinstance(target, ast.Name)
            and isinstance(getattr(node, "value", None), ast.Constant)
            and isinstance(node.value.value, str)  # type: ignore[attr-defined]
        ):
            consts[target.id] = node.value.value  # type: ignore[attr-defined]
    return consts


def _child_env(func: ast.AST, parent: ModuleEnv) -> ModuleEnv:
    """The env INSIDE one function: the enclosing env, with this scope's own bindings
    applied. A local (non-import) binding SHADOWS an inherited import — that is the whole
    point — and a local import rebinds on top of it."""
    local_imports, bound = _scope_bindings(func)
    imports = {n: o for n, o in parent.imports.items() if n not in bound}
    imports.update(local_imports)
    return ModuleEnv(
        imports=imports,
        consts={n: v for n, v in parent.consts.items() if n not in bound},
        defines=frozenset((set(parent.defines) | bound) - set(local_imports)),
        scope_of=parent.scope_of,
    )


def _tag(node: ast.AST, env: ModuleEnv, scope_of: dict[ast.AST, ModuleEnv]) -> None:
    """Record, for every node, the env of the scope it sits in."""
    for child in ast.iter_child_nodes(node):
        scope_of[child] = env
        # A ClassDef is NOT in the chain: Python does not close methods over the class
        # body, so a method's enclosing scope is the module (or the enclosing function).
        # Recursing with the same env is exactly that. Class-body bindings are therefore
        # invisible — accepted, and vanishingly rare in this tree.
        _tag(child, _child_env(child, env) if isinstance(child, _SCOPES) else env, scope_of)


def module_env(tree: ast.AST) -> ModuleEnv:
    """Build the SCOPE TREE for one module and return its root (module-level) env.

    Every node is tagged with the env of the scope it sits in, so ``callee``/``origin``/
    ``str_value`` resolve a name the way Python would — against the innermost scope that
    binds it — while callers keep passing the one env this returns.

    Scope-awareness is what makes collecting function-local imports SAFE. A local
    ``import re as regex`` is a plausible evasion, so it must be seen; but binding it
    module-wide (the pre-#607 resolver did) makes any local of the same name resolve to a
    module. That is not hypothetical: ``learning/pipeline/judge/compare.py`` binds ``p`` to
    a module inside ``_invlang()`` while ``write_comparison_files()`` uses ``p`` as a
    ``Path``, so ``p.write_text(...)`` resolved to ``…invlang.parser.write_text``. Scoped,
    the local ``p`` shadows the import in the function that rebinds it, and nowhere else.

    Note the two directions of "unresolvable", which is why a bail-out was never an option
    here: for ``lint_unpinned_text_io`` a None callee means FLAG (the duck-typed
    ``p.open()``), while for the jsonl and frontmatter gates it means SKIP. Only real
    scoping is safe for all three at once.
    """
    scope_of: dict[ast.AST, ModuleEnv] = {}
    imports, bound = _scope_bindings(tree)
    root = ModuleEnv(
        imports=imports,
        consts=_module_consts(tree),
        defines=frozenset(bound),
        scope_of=scope_of,
    )
    _tag(tree, root, scope_of)
    return root


def _env_at(node: ast.AST, env: ModuleEnv) -> ModuleEnv:
    """The env of the scope ``node`` sits in. Falls back to ``env`` for a node that was
    not tagged — a synthetic node, or one from a different tree."""
    return env.scope_of.get(node, env)


def origin(node: ast.expr, env: ModuleEnv) -> str | None:
    """The dotted origin of a PURE ``Name.attr.attr`` chain rooted at an imported name,
    resolved against the scope ``node`` sits in.

    ``os`` -> ``"os"``; ``regex`` -> ``"re"``; ``re.error`` -> ``"re.error"``.
    ``p`` -> None (a local value — including one that merely SHARES a name with an import
    bound in some other function). ``zipfile.ZipFile(p)`` -> None: a Call in the chain
    makes it a VALUE, not an attribute path — never walk through one, or the value's
    origin gets confused with its constructor's.
    """
    return _origin(node, _env_at(node, env))


def _origin(node: ast.expr, env: ModuleEnv) -> str | None:
    """``origin`` against an ALREADY-resolved scope env."""
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    if cur.id in env.defines:
        return None  # a local/param of that name shadows the import
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

    Everything resolves against the scope the CALL sits in, so a function-local import is
    seen inside that function and nowhere else, and a local that merely shares a name with
    an import elsewhere in the file stays a local (#607).

    ``env.defines`` — the names bound to something that is not an import — is consulted
    BEFORE ``env.imports``, so a shadowing local wins over an ambiguous module-level
    binding. The ``builtins.<id>`` fallback fires ONLY in call position, and only for a
    Name in neither map, so a parameter named ``input`` or a ``def open(...)`` cannot
    fabricate an origin.
    """
    env = _env_at(call, env)
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in env.defines:
            return None
        if func.id in env.imports:
            return env.imports[func.id]
        if func.id in _BUILTIN_NAMES:
            return f"builtins.{func.id}"
        return None
    if isinstance(func, ast.Attribute):
        return origin(func, env)  # re-resolves func's scope — the same one, by construction
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
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(arg, ast.Tuple):
            out.extend(v for el in arg.elts if (v := str_value(el, env)) is not None)
        elif (v := str_value(arg, env)) is not None:
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
    """A single expression's string value — an inline literal, or a module constant that
    the node's own scope has not rebound to something else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return _env_at(node, env).consts.get(node.id)
    return None


# Openers that DO take `encoding=`, keyed by resolved origin -> (mode's positional slot,
# mode's default). Both facts are properties of the CALLEE, and both used to be guessed:
# the old `_open_mode` read args[0] as the mode for every `<x>.open(...)`, which is right
# only for `Path.open(mode)`. Every module-level opener is path-FIRST, so the gate read the
# file path as the mode string (#594/#602). Verified against inspect.signature.
OPENERS = {
    "builtins.open": (1, "r"),
    "io.open": (1, "r"),                          # io.open IS builtins.open
    "codecs.open": (1, "r"),
    "os.fdopen": (1, "r"),                        # wraps an fd — still decodes under the locale
    "gzip.open": (1, "rb"),                       # binary by default, but takes encoding= in text mode
    "bz2.open": (1, "rb"),
    "lzma.open": (1, "rb"),
    "tempfile.NamedTemporaryFile": (0, "w+b"),
    "tempfile.TemporaryFile": (0, "w+b"),
    "tempfile.SpooledTemporaryFile": (1, "w+b"),  # max_size comes FIRST — mode is slot 1
}
# `Path.open(mode)` and friends: the receiver is a VALUE, so the callee never resolves.
# Duck-typed on purpose — this is the case the gates most exist to catch.
DUCK_OPENER = (0, "r")
# Genuinely encoding-less: `os.open` returns an fd (its third arg is the PERMISSION bits,
# not a text mode); `tarfile.open` has no `encoding` parameter.
NO_ENCODING_OPENERS = ("os.open", "tarfile.open")


def opener_slot(call: ast.Call, env: ModuleEnv) -> tuple[int, str] | None:
    """``(mode's positional slot, mode's default)`` for an opener call, or None if this
    call is not an opener at all.

    An origin is skipped only via the POSITIVE ``NO_ENCODING_OPENERS`` table — never
    because it merely resolved. "It resolved, so the receiver is a module, so it is not a
    duck-typed opener" is FALSE: the receiver may be an imported OBJECT, and
    ``PATHS.lessons_dir.open()`` duly resolves to
    ``defender._paths.PATHS.lessons_dir.open``. Reading that as "not an opener" silently
    drops the Path-like text open these gates most exist to catch, and the empty baseline
    would stay green while it happened. Scoping (#607) does not close this — ``PATHS`` is
    a genuine import, never rebound — so the positive table is what carries it.

    So: a tabled origin gets the callee's real slot/default; any OTHER ``.open`` on a
    receiver falls back to the duck opener. The cost is a possible false alarm on an
    untabled module opener called with a literal path — a false alarm the suppression
    marker answers, where the reverse error is a violation that ships.
    """
    o = callee(call, env)
    if o in NO_ENCODING_OPENERS:
        return None
    if o in OPENERS:
        return OPENERS[o]
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return DUCK_OPENER
    return None


def open_mode(call: ast.Call, env: ModuleEnv) -> str | None:
    """The mode an opener call opens in — the CALLEE's own default when no mode is passed.

    None means "no mode this checker can read": either the call is not an opener, or the
    mode is an expression rather than a literal/module-const. Both mean the same thing to
    every caller (there is nothing to decide on), so they share the return.
    """
    slot = opener_slot(call, env)
    if slot is None:
        return None
    index, default = slot
    arg = arg_at(call, index, "mode")
    return default if arg is None else str_value(arg, env)


def has_kw(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def kw_is_true(call: ast.Call, name: str) -> bool:
    """True only for a literal ``name=True``, or a module const bound to it."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
