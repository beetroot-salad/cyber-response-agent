#!/usr/bin/env python3
"""Private-import fence (#1315): an underscore means "private to its area", and code outside the
area does not reach it.

An area is a node of `lint_import_order.ORDER` (`records`, `tenancy`, `investigation`, ...). A
segment of a dotted name that starts with one `_`, BELOW the area's own segment, makes the name
private to that area: `defender.tenancy._tenant`, `defender.investigation.tools._deps`,
`defender.execution.box_codec._BOX_MARK_ENV`. The area segment itself never counts. The root-level
seams — the flat `_*.py` modules (`_io`, `_git`, `_log`, ...) and `_filesystem` — form one root
area: any area may import them (the import order still decides direction), and their own
underscore names are private to the root area. Dunder names are not private.

What is flagged, in non-test code under `defender/`:

* an import that names another area's private module or name — `import a._b`, `from a._b import
  x`, `from a import _b`, a relative import resolving outside the area, anywhere in the file
  (function bodies, `try`, `if TYPE_CHECKING:`);
* an attribute read `mod._x` where `mod` statically resolves to another area's module.

A public module meets a cross-area need: either the name moves out of the underscore, or the
area's **door** serves it. A door is a public module with a literal `_HOMES` dict (each served
name -> the submodule, relative to the door's package, that defines it), a `TYPE_CHECKING` block
that imports every served name from its home (so the type checker and the re-export-resolving
gates see real origins), and `__getattr__ = lazy_door(globals(), _HOMES)`. Doors are checked too:

* the map and the `TYPE_CHECKING` mirror list the same names, each from the same home;
* every home is a module of the door's package that binds the name at module level;
* every `from <door> import X` (and `door.X` read) names something the door serves or binds.

A door may serve its own area's private modules' names; serving another area's is flagged at the
door's own import. No baseline and no inline suppression: a cross-area use is resolved by making
the thing public. Recorded gaps: strings (`importlib.import_module`, `getattr(mod, "_x")`).

Sweep: `defender/` minus `tests/`, `evals/`, venvs and `__pycache__`. A file that does not parse is
exit 2.

Run from anywhere:  python tooling/lint/lint_private_imports.py [--root DIR]
"""
from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import _astlib
from lint_import_order import node_of

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"
LABEL = "lint_private_imports"

_EXCLUDED = ("tests", "evals", ".venv", "venv", "__pycache__")
#: The import-order nodes that make up the shared root area.
_ROOT_NODES = frozenset({"_flat", "_filesystem"})
_ROOT = "root"
_HOMES = "_HOMES"  # the door map's name, as `_astlib.homes_of` reads it


def _private(segment: str) -> bool:
    return segment.startswith("_") and not segment.startswith("__")


@dataclass(frozen=True)
class _Door:
    module: str                  # dotted door module
    package: str                 # the package its homes are relative to
    homes: dict[str, str]        # served name -> home submodule (relative)
    mirror: dict[str, str]       # TYPE_CHECKING-imported name -> dotted source module
    bound: frozenset[str]        # every module-level binding of the door


class _Tree:
    """The scanned files and the area of any dotted `defender` name."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files = {_astlib.module_and_package(rel)[0]: rel
                      for rel in _astlib.source_files(root, _EXCLUDED)}
        self.parsed: dict[str, ast.Module] = {}
        self.bound: dict[str, frozenset[str]] = {}

    def tree(self, rel: str) -> ast.Module:
        if rel not in self.parsed:
            self.parsed[rel] = _astlib.read_and_parse(self.root / rel, rel)[1]
        return self.parsed[rel]

    def bindings(self, rel: str) -> frozenset[str]:
        if rel not in self.bound:
            self.bound[rel] = _module_bindings(self.tree(rel).body)
        return self.bound[rel]

    def is_module(self, dotted: str) -> bool:
        """A scanned module, or a package holding one."""
        return dotted in self.files or any(m.startswith(f"{dotted}.") for m in self.files)

    def area_of(self, dotted: str) -> str | None:
        parts = dotted.split(".")
        if parts[0] != "defender" or len(parts) < 2:
            return None
        head = f"defender.{parts[1]}"
        if head in self.files and not self.files[head].endswith("__init__.py"):
            node = node_of(self.files[head])
        elif self.is_module(head):
            node = node_of(f"{parts[1]}/__init__.py")
        else:
            return None
        return _ROOT if node in _ROOT_NODES else node


def _area_of_file(rel: str) -> str:
    node = node_of(rel)
    return _ROOT if node in _ROOT_NODES else node


def _breach(target: str, importer_area: str, tree: _Tree) -> str | None:
    """The private prefix of `target` another area owns, or None."""
    parts = target.split(".")
    owner = tree.area_of(target)
    if owner is None or owner == importer_area:
        return None
    for i in range(2, len(parts)):
        if _private(parts[i]):
            return ".".join(parts[:i + 1])
    return None


def _imported(node: ast.Import | ast.ImportFrom, package: str) -> Iterator[str]:
    if isinstance(node, ast.Import):
        yield from (a.name for a in node.names)
        return
    source = _astlib.import_source(node, package)
    yield from (f"{source}.{a.name}" for a in node.names if a.name != "*")


def _type_checking_imports(tree: ast.Module, package: str) -> dict[str, str]:
    mirror: dict[str, str] = {}
    for stmt in tree.body:
        if _astlib.type_checking_block(stmt):
            for node in stmt.body:
                if isinstance(node, ast.ImportFrom):
                    source = _astlib.import_source(node, package)
                    mirror.update({a.asname or a.name: source for a in node.names})
    return mirror


def _module_bindings(body: list[ast.stmt]) -> frozenset[str]:
    """The names `body`'s statements bind in the module: through `if`/`try`/`with`/loops, never
    into a function's or class's own body."""
    bound: set[str] = set()
    for stmt in body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            bound.add(stmt.name)
        elif isinstance(stmt, ast.Import | ast.ImportFrom):
            bound.update((a.asname or a.name).split(".")[0] for a in stmt.names)
        elif isinstance(stmt, ast.If | ast.Try | ast.TryStar | ast.With | ast.AsyncWith
                        | ast.For | ast.AsyncFor | ast.While):
            nested = [*getattr(stmt, "body", []), *getattr(stmt, "orelse", []),
                      *getattr(stmt, "finalbody", []),
                      *(s for h in getattr(stmt, "handlers", []) for s in h.body)]
            bound |= _module_bindings(nested)
            heads = [getattr(stmt, "target", None), *(i.optional_vars for i in getattr(stmt, "items", []))]
            bound.update(n.id for h in heads if h is not None for n in ast.walk(h) if isinstance(n, ast.Name))
            bound.update(h.name for h in getattr(stmt, "handlers", []) if h.name)
        else:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    bound.add(node.id)
    return frozenset(bound)


def _doors(tree: _Tree) -> dict[str, _Door]:
    doors: dict[str, _Door] = {}
    for module, rel in tree.files.items():
        parsed = tree.tree(rel)
        homes = _astlib.homes_of(parsed, rel)
        if homes is None:
            continue
        _m, package = _astlib.module_and_package(rel)
        doors[module] = _Door(module, package, homes,
                              _type_checking_imports(parsed, package), tree.bindings(rel))
    return doors


def _door_faults(door: _Door, tree: _Tree) -> Iterator[str]:
    rel = tree.files[door.module]
    for name in sorted(door.homes.keys() - door.mirror.keys()):
        yield f"{rel}: door serves `{name}` but its TYPE_CHECKING block does not import it"
    for name in sorted(door.mirror.keys() - door.homes.keys()):
        yield f"{rel}: TYPE_CHECKING imports `{name}` but the door's {_HOMES} does not serve it"
    for name, home in sorted(door.homes.items()):
        home_module = f"{door.package}.{home}"
        if name in door.mirror and door.mirror[name] != home_module:
            yield (f"{rel}: `{name}` is served from `{home}` but mirrored from "
                   f"`{door.mirror[name]}`")
        if home_module not in tree.files:
            yield f"{rel}: `{name}`'s home `{home_module}` is not a module"
        elif name not in tree.bindings(tree.files[home_module]):
            yield f"{rel}: `{name}` is not bound at module level in its home `{home_module}`"


def _served(door: _Door, name: str) -> bool:
    return name in door.homes or name in door.bound


def _file_findings(rel: str, tree: _Tree, doors: dict[str, _Door]) -> Iterator[str]:
    module, package = _astlib.module_and_package(rel)
    area = _area_of_file(rel)
    parsed = tree.tree(rel)
    with _astlib.scan_guard(rel):
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import | ast.ImportFrom):
                for target in _imported(node, package):
                    if not target.startswith("defender."):
                        continue
                    private = _breach(target, area, tree)
                    if private is not None:
                        yield f"{rel}:{node.lineno}: reaches `{private}`, private to `{tree.area_of(target)}`"
                    head, _, name = target.rpartition(".")
                    if isinstance(node, ast.ImportFrom) and head in doors and head != module \
                            and not _served(doors[head], name) and not tree.is_module(target):
                        yield f"{rel}:{node.lineno}: `{head}` is a door that does not serve `{name}`"
        env = _astlib.module_env(parsed, module, package)
        for node in ast.walk(parsed):
            if not isinstance(node, ast.Attribute):
                continue
            base = _astlib.origin(node.value, env)
            if base is None or not base.startswith("defender.") or not tree.is_module(base):
                continue
            if _private(node.attr):
                private = _breach(f"{base}.{node.attr}", area, tree)
                if private is not None:
                    yield f"{rel}:{node.lineno}: reads `{private}`, private to `{tree.area_of(base)}`"
            elif base in doors and base != module and not _served(doors[base], node.attr) \
                    and not tree.is_module(f"{base}.{node.attr}"):
                yield f"{rel}:{node.lineno}: `{base}` is a door that does not serve `{node.attr}`"


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    tree = _Tree(root)
    doors = _doors(tree)
    findings: list[str] = []
    for door in doors.values():
        findings.extend(_door_faults(door, tree))
    for rel in sorted(tree.files.values()):
        findings.extend(dict.fromkeys(_file_findings(rel, tree, doors)))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[{LABEL}] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[{LABEL}] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
