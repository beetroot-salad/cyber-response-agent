"""The three production-code censuses #1078 pass (A) pins — O1 (no tenant literal, no
`DEFAULT_TENANT_ID`), O2 (one writer of the tenant row) and U6 (no tenant data written into the
box-mounted `defender/` tree) — each as ONE scanner function.

Each scanner is driven TWICE by its tests: over the real tree (the negative: nothing is found
that should not be) and over a planted synthetic module (the positive control: the same
function, fed the violation, reports it). Sharing one function is what makes the control prove
the observation channel — a scanner that saw nothing would be green on the real tree and red
on the plant.

GREP FLOORS, recorded rather than hidden (the census's honest limit, C55-style):
* O1 sees a tenant id only where it reaches the AST as a string constant at a tenant-shaped
  position (a `tenant`/`tenant_id` keyword or parameter default, the tenant slot of an owner
  call, the element after `--tenant` in an argv list, an argparse `--tenant` default, an
  f-string spelling `--tenant <id>`, a `*TENANT*` name bound to a grammar-shaped id). A literal
  that reaches a tenant slot through an unrelated variable is below the floor.
* O2 attributes a write to the top-level function holding the write call; a write through a
  path value another function returned sits below the floor (dropped premise #99).
* U6 traces a path only through names bound in the same module or function to a defender-tree
  anchor; a path built in another file is not seen (C55's own floor).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFENDER = REPO_ROOT / "defender"
LINT_DIR = REPO_ROOT / "scripts" / "lint"

_SKIP_PARTS = {".venv", "__pycache__", "node_modules"}
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")
_TENANT_FLAG_IN_TEXT = re.compile(r"--tenant(?:=|\s+)([a-z][a-z0-9-]{0,62})\b")


def _py_under(root: Path, *, exclude_top: tuple[str, ...] = ()) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if _SKIP_PARTS & set(rel.parts):
            continue
        if rel.parts and rel.parts[0] in exclude_top:
            continue
        out.append(p)
    return out


# ======================================================================================
# O1 — no tenant literal and no DEFAULT_TENANT_ID in production code (F7's scope)
# ======================================================================================

def o1_scope(repo: Path = REPO_ROOT) -> tuple[list[Path], list[Path]]:
    """`(python files, shell shims)` of O1's census scope (§7 F7, auto): `defender/**/*.py`
    minus `defender/tests` and `defender/evals`, plus `scripts/lint/`, plus every shell shim
    under a `bin/` directory (the repo-root `bin/` does not exist, C-R18; `defender/bin/` does).
    `experiments/` is outside `defender/` and excluded (N10)."""
    defender = repo / "defender"
    py = _py_under(defender, exclude_top=("tests", "evals"))
    py += _py_under(repo / "scripts" / "lint") if (repo / "scripts" / "lint").is_dir() else []
    shims = []
    for bin_dir in (repo / "bin", defender / "bin"):
        if bin_dir.is_dir():
            shims += [p for p in sorted(bin_dir.iterdir())
                      if p.is_file() and p.suffix not in (".md", ".py")]
    return py, shims


#: The owner calls whose tenant id sits at a known position (D1/D2's signatures).
_TENANT_ARG_POS = {"TenantPaths": 1, "create_tenant": 1, "require_tenant": 1,
                   "ensure_runs_base_record": 1, "runs_base_for": 0, "for_tenant": 0}
_TENANT_KW = {"tenant", "tenant_id"}


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _callee_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _is_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def o1_python_findings(path: Path, rel: str) -> list[str]:  # noqa: C901, PLR0912 — one flat dispatch over the census's node shapes, read top to bottom
    """Every place `path` holds `DEFAULT_TENANT_ID` or passes a string literal as a tenant."""
    text = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(text, filename=rel)
    docs = _docstring_ids(tree)
    found: list[str] = []

    def hit(node: ast.AST, what: str) -> None:
        found.append(f"{rel}:{getattr(node, 'lineno', 0)}: {what}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "DEFAULT_TENANT_ID":
            hit(node, "names DEFAULT_TENANT_ID")
        elif isinstance(node, ast.Attribute) and node.attr == "DEFAULT_TENANT_ID":
            hit(node, "reads .DEFAULT_TENANT_ID")
        elif isinstance(node, ast.alias) and "DEFAULT_TENANT_ID" in (node.name, node.asname):  # lint-ast-resolve: ok — a census over-reports on purpose: ANY import spelling of the constant is a finding, bound or shadowed
            hit(node, "imports DEFAULT_TENANT_ID")
        elif (isinstance(node, ast.Constant) and node.value == "DEFAULT_TENANT_ID"
              and id(node) not in docs):
            hit(node, "spells 'DEFAULT_TENANT_ID'")
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _TENANT_KW and _is_str(kw.value):
                    hit(kw.value, f"passes {kw.arg}={kw.value.value!r}")  # type: ignore[union-attr]
            pos = _TENANT_ARG_POS.get(_callee_name(node))
            if pos is not None and len(node.args) > pos and _is_str(node.args[pos]):
                hit(node, f"passes {node.args[pos].value!r} to {_callee_name(node)}")  # type: ignore[union-attr]
            if (_callee_name(node) == "add_argument" and node.args and _is_str(node.args[0])
                    and node.args[0].value == "--tenant"):  # type: ignore[union-attr]
                for kw in node.keywords:
                    if kw.arg == "default" and _is_str(kw.value):
                        hit(kw.value, f"defaults --tenant to {kw.value.value!r}")  # type: ignore[union-attr]
        elif isinstance(node, (ast.List, ast.Tuple)):
            elts = node.elts
            for a, b in zip(elts, elts[1:], strict=False):
                if _is_str(a) and a.value == "--tenant" and _is_str(b):  # type: ignore[union-attr]
                    hit(b, f"argv '--tenant {b.value}'")  # type: ignore[union-attr]
            for e in elts:
                if _is_str(e) and e.value.startswith("--tenant="):  # type: ignore[union-attr]
                    hit(e, f"argv {e.value!r}")  # type: ignore[union-attr]
        elif isinstance(node, ast.JoinedStr):
            literal = "".join(v.value for v in node.values if _is_str(v))  # type: ignore[union-attr]
            m = _TENANT_FLAG_IN_TEXT.search(literal)
            if m:
                hit(node, f"f-string spells --tenant {m.group(1)}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for t in targets:
                if (isinstance(t, ast.Name) and "tenant" in t.id.lower() and _is_str(value)
                        and _ID.fullmatch(value.value)):  # type: ignore[union-attr]
                    hit(t, f"binds {t.id} = {value.value!r}")  # type: ignore[union-attr]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            for arg, default in zip(positional[len(positional) - len(args.defaults):],
                                    args.defaults, strict=True):
                if arg.arg in _TENANT_KW and _is_str(default):
                    hit(default, f"defaults parameter {arg.arg} to {default.value!r}")  # type: ignore[union-attr]
            for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
                if arg.arg in _TENANT_KW and _is_str(default):
                    hit(default, f"defaults parameter {arg.arg} to {default.value!r}")  # type: ignore[union-attr]
    return found


def o1_shim_findings(path: Path, rel: str) -> list[str]:
    """A shell shim that holds `DEFAULT_TENANT_ID` or spells a tenant literal on a command
    line or in a TENANT variable."""
    found = []
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        code = line.split("#", 1)[0]
        if "DEFAULT_TENANT_ID" in code:
            found.append(f"{rel}:{n}: names DEFAULT_TENANT_ID")
        m = _TENANT_FLAG_IN_TEXT.search(code)
        if m:
            found.append(f"{rel}:{n}: spells --tenant {m.group(1)}")
        m = re.search(r"\b\w*TENANT\w*=['\"]?([a-z][a-z0-9-]{0,62})\b", code)
        if m:
            found.append(f"{rel}:{n}: binds a tenant variable to {m.group(1)!r}")
    return found


def o1_census(py: Iterable[Path], shims: Iterable[Path], *, root: Path) -> list[str]:
    out: list[str] = []
    for p in py:
        out += o1_python_findings(p, p.relative_to(root).as_posix())
    for p in shims:
        out += o1_shim_findings(p, p.relative_to(root).as_posix())
    return out


# ======================================================================================
# O2 — the tenant row's writers
# ======================================================================================

ROW_NAME = "tenant.json"
_WRITE_ATTRS = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to", "rename",
                "replace"}
_WRITEISH = re.compile(r"(write|create|link|replace|rename|copy|move|dump|save|store|mint)",
                       re.IGNORECASE)
_READISH = re.compile(r"(read|parse|load|present|exist|stat|refuse|check|is_|require)",
                      re.IGNORECASE)


def _row_like(node: ast.AST, tainted: set[str]) -> bool:
    for n in ast.walk(node):
        if _is_str(n) and (n.value == ROW_NAME or n.value.endswith("/" + ROW_NAME)):  # type: ignore[union-attr]
            return True
        if isinstance(n, ast.Attribute) and n.attr == "row":
            return True
        if isinstance(n, ast.Name) and n.id in tainted:
            return True
    return False


def _walk_scope(node: ast.AST, *, module: bool) -> Iterator[ast.AST]:
    """`ast.walk`, except that at MODULE scope it does not descend into a function or class
    body — a local of one function is not a module-level name."""
    if module and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        if module and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _walk_scope(child, module=module)


def _taint(stmts: Iterable[ast.AST], seed: set[str], predicate, *,
           module: bool = False) -> set[str]:
    """Names bound (in these statements) to a value `predicate` accepts, to a fixed point."""
    tainted = set(seed)
    assigns = [n for s in stmts for n in _walk_scope(s, module=module)
               if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and n.value is not None]
    changed = True
    while changed:
        changed = False
        for a in assigns:
            targets = (a.targets if isinstance(a, ast.Assign)
                       else [a.target])
            if predicate(a.value, tainted):
                for t in targets:
                    for name in ast.walk(t):
                        if isinstance(name, ast.Name) and name.id not in tainted:
                            tainted.add(name.id)
                            changed = True
    return tainted


def _top_level_units(tree: ast.Module) -> Iterator[tuple[str, list[ast.AST]]]:
    """`(qualname, statements)` per top-level function, per method of a top-level class, and
    `<module>` for the rest."""
    loose: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, [node]
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{item.name}", [item]
        else:
            loose.append(node)
    yield "<module>", loose


def _write_calls(stmts: list[ast.AST], is_target) -> Iterator[ast.Call]:
    for s in stmts:
        for n in ast.walk(s):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr in _WRITE_ATTRS and is_target(f.value):
                yield n
                continue
            name = _callee_name(n)
            args = [*n.args, *(k.value for k in n.keywords)]
            if name == "open" and n.args and is_target(n.args[0]):
                mode = n.args[1] if len(n.args) > 1 else next(
                    (k.value for k in n.keywords if k.arg == "mode"), None)
                if _is_str(mode) and set(mode.value) & set("wax+"):  # type: ignore[union-attr]
                    yield n
                continue
            if isinstance(f, ast.Attribute) and f.attr == "open" and is_target(f.value):
                mode = n.args[0] if n.args else next(
                    (k.value for k in n.keywords if k.arg == "mode"), None)
                if _is_str(mode) and set(mode.value) & set("wax+"):  # type: ignore[union-attr]
                    yield n
                continue
            if name and _WRITEISH.search(name) and not _READISH.search(name) and any(
                    is_target(a) for a in args):
                yield n


def o2_row_writers(files: Iterable[Path], *, root: Path) -> list[str]:
    """`rel::function` for every production site that writes the row by its name or through a
    `.row` accessor."""
    out: list[str] = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=rel)
        module_taint = _taint(tree.body, set(), _row_like, module=True)
        for qual, stmts in _top_level_units(tree):
            tainted = _taint(stmts, module_taint, _row_like)
            for call in _write_calls(stmts, lambda e, t=tainted: _row_like(e, t)):
                out.append(f"{rel}::{qual}:{call.lineno}")
    return out


def o2_scope(repo: Path = REPO_ROOT) -> list[Path]:
    """Production Python: `defender/**` minus the tests, plus the lint gates."""
    return _py_under(repo / "defender", exclude_top=("tests",))


def private_helpers_only_called_from(path: Path, caller: str) -> set[str]:
    """The `_private` top-level functions of `path` whose EVERY call site in the module sits
    inside `caller` — a write inside one of those is `caller`'s own write, split out."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    callers: dict[str, set[str]] = {}
    for qual, stmts in _top_level_units(tree):
        for s in stmts:
            for n in ast.walk(s):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                    callers.setdefault(n.func.id, set()).add(qual)
    changed = True
    only = {caller}
    while changed:
        changed = False
        for name, who in callers.items():
            if name.startswith("_") and name not in only and who and who <= only:
                only.add(name)
                changed = True
    return only - {caller}


# ======================================================================================
# U6 — writes into the box-mounted defender/ tree
# ======================================================================================

#: The names and spellings that anchor a path at the checkout's `defender/` tree (C55's anchor
#: list: `_DEFENDER_DIR`, `DEFENDER_DIR`, `PATHS.defender_dir`, `HERE.parent`, `REPO_ROOT /
#: 'defender'`, plus `Path(__file__)`, which every module-relative anchor is built from).
_ANCHOR_NAMES = {"_DEFENDER_DIR", "DEFENDER_DIR", "DEFENDER"}
_ANCHOR_ATTRS = {"defender_dir"}
_REPO_ROOT_NAMES = {"REPO_ROOT", "_REPO_ROOT", "ROOT", "REPO"}


def _anchored(node: ast.AST, tainted: set[str]) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and (n.id in _ANCHOR_NAMES or n.id in tainted
                                        or n.id == "__file__"):
            return True
        if isinstance(n, ast.Attribute) and n.attr in _ANCHOR_ATTRS:
            return True
        if (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div) and _is_str(n.right)
                and n.right.value == "defender"  # type: ignore[union-attr]
                and isinstance(n.left, ast.Name) and n.left.id in _REPO_ROOT_NAMES):
            return True
    return False


_U6_WRITE_NAMES = re.compile(r"^(copy|copy2|copyfile|copytree|move|write_atomic|write_guarded|"
                             r"atomic_write|dump)$")


def _u6_writes(stmts: list[ast.AST], tainted: set[str]) -> Iterator[tuple[ast.Call, ast.AST]]:  # noqa: C901 — one flat dispatch over the write shapes
    """`(call, destination expression)` for every write in `stmts` whose destination is traced
    to a defender-tree anchor."""
    for s in stmts:
        for n in ast.walk(s):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if (isinstance(f, ast.Attribute) and f.attr in _WRITE_ATTRS | {"mkdir"}
                    and _anchored(f.value, tainted)):
                yield n, f.value
            elif isinstance(f, ast.Attribute) and f.attr == "open" and _anchored(f.value, tainted):
                mode = n.args[0] if n.args else next(
                    (k.value for k in n.keywords if k.arg == "mode"), None)
                if _is_str(mode) and set(mode.value) & set("wax+"):  # type: ignore[union-attr]
                    yield n, f.value
            elif _callee_name(n) == "open" and n.args and _anchored(n.args[0], tainted):
                mode = n.args[1] if len(n.args) > 1 else next(
                    (k.value for k in n.keywords if k.arg == "mode"), None)
                if _is_str(mode) and set(mode.value) & set("wax+"):  # type: ignore[union-attr]
                    yield n, n.args[0]
            elif _U6_WRITE_NAMES.match(_callee_name(n)):
                # the DESTINATION: the second positional for copy/move, the first otherwise
                dest = (n.args[1] if _callee_name(n) in {"copy", "copy2", "copyfile", "copytree",
                                                         "move"} and len(n.args) > 1
                        else n.args[0] if n.args else None)
                if dest is not None and _anchored(dest, tainted):
                    yield n, dest


def _bindings(stmts: Iterable[ast.AST], *, module: bool) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for s in stmts:
        for n in _walk_scope(s, module=module):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(
                    n.targets[0], ast.Name):
                out.setdefault(n.targets[0].id, n.value)
    return out


def u6_defender_tree_writes(files: Iterable[Path], *, root: Path) -> list[str]:
    """`rel::function::<destination>` for every production write whose destination is traced
    to a defender-tree anchor within its own module or function. `<destination>` is the
    destination expression, with a bare local name replaced by the expression it was bound to,
    so a site reads as the file it writes (`HERE.parent / 'queues.json'`)."""
    out: list[str] = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=rel)
        module_taint = _taint(tree.body, set(), _anchored, module=True)
        module_binds = _bindings(tree.body, module=True)
        for qual, stmts in _top_level_units(tree):
            tainted = _taint(stmts, module_taint, _anchored)
            binds = {**module_binds, **_bindings(stmts, module=False)}
            for _call, dest in _u6_writes(stmts, tainted):
                shown = binds.get(dest.id, dest) if isinstance(dest, ast.Name) else dest
                out.append(f"{rel}::{qual}::{ast.unparse(shown)}")
    return sorted(set(out))


def u6_scope(repo: Path = REPO_ROOT) -> list[Path]:
    """Production Python under `defender/`, minus the tests (C55's census population)."""
    return _py_under(repo / "defender", exclude_top=("tests",))
