#!/usr/bin/env python3
"""Record id columns (#1382): a column that holds a record id is an `IdColumn` of its family.

A record id the system mints is canonical UUID text, stored as PostgreSQL `uuid` and read back as
its family's type (`TenantId`, `AlertId`, ...). A column declared otherwise (`Text`, `String`, a
bare `Uuid`) brings back free-text ids that read back unchecked as plain `str`.

In every production module under `defender/` (tests excluded), in a class that sets `__tablename__`,
a column whose `Mapped[...]` annotation names an id family (`X`, `X | None` or `Optional[X]`), a
column with a `ForeignKey` (every reference in the schema is to a record id), and the table's own
`id`, whatever their annotation, must be `mapped_column(IdColumn(<family>), ...)`, of the annotated
family when there is one. The families are
read from `defender/records/`: every class there descending from `UuidId`. A tree with no such
column, or no family, is a finding (the rule moved), never a pass. A file that does not parse is
exit 2. No baseline, no suppression.

Run from anywhere:  python tooling/lint/lint_record_id_columns.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

EXCLUDED_DIRS = ("tests", ".venv", "__pycache__")
_COLUMN = "IdColumn"
_ROOT_FAMILY = "UuidId"


def _families(root: Path) -> set[str]:
    """Every class under `records/` descending from `UuidId` (by base-class name, transitively)."""
    bases: dict[str, set[str]] = {}
    records = root / "records"
    for rel in _astlib.source_files(records, EXCLUDED_DIRS) if records.is_dir() else ():
        _text, tree = _astlib.read_and_parse(records / rel, rel)
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            bases[cls.name] = {ast.unparse(b).split(".")[-1] for b in cls.bases}
    found: set[str] = set()
    grew = True
    while grew:
        grew = False
        for name, parents in bases.items():
            if name not in found and parents & (found | {_ROOT_FAMILY}):
                found.add(name)
                grew = True
    return found


def _is_table(cls: ast.ClassDef) -> bool:
    return any(isinstance(stmt, ast.Assign | ast.AnnAssign)
               and any(isinstance(t, ast.Name) and t.id == "__tablename__"
                       for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]))
               for stmt in cls.body)


def _annotated_family(annotation: ast.expr, families: set[str]) -> str | None:
    """The id family `Mapped[F]` or `Mapped[F | None]` names, if any."""
    if not (isinstance(annotation, ast.Subscript) and ast.unparse(annotation.value).split(".")[-1] == "Mapped"):
        return None
    inner = annotation.slice
    names = [inner]
    if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.BitOr):
        names = [inner.left, inner.right]
    elif isinstance(inner, ast.Subscript) and ast.unparse(inner.value).split(".")[-1] == "Optional":
        names = [inner.slice]
    for node in names:
        name = ast.unparse(node).split(".")[-1]
        if name in families:
            return name
    return None


def _has_foreign_key(call: ast.Call) -> bool:
    return any(isinstance(a, ast.Call) and ast.unparse(a.func).split(".")[-1] == "ForeignKey" for a in call.args)


def _column_family(call: ast.Call) -> str | None:
    """`F` when the call's first argument is `IdColumn(F)`, else None."""
    first = call.args[0] if call.args else None
    if isinstance(first, ast.Call) and ast.unparse(first.func).split(".")[-1] == _COLUMN and first.args:
        return ast.unparse(first.args[0]).split(".")[-1]
    return None


def _columns(cls: ast.ClassDef) -> list[tuple[str, ast.expr | None, ast.Call]]:
    """(name, annotation, `mapped_column(...)` call) of every column the class declares."""
    out = []
    for stmt in cls.body:
        target = stmt.target if isinstance(stmt, ast.AnnAssign) else (
            stmt.targets[0] if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 else None)
        if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Call) \
                and ast.unparse(stmt.value.func).split(".")[-1] == "mapped_column":
            out.append((target.id, stmt.annotation if isinstance(stmt, ast.AnnAssign) else None, stmt.value))
    return out


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    families = _families(root)
    if not families:
        return [f"no class under records/ descends from `{_ROOT_FAMILY}`; re-site the rule"]
    findings: list[str] = []
    checked = 0
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and _is_table(n)):
            for name, annotation, call in _columns(cls):
                family = _annotated_family(annotation, families) if annotation is not None else None
                if family is None and name != "id" and not _has_foreign_key(call):
                    continue
                checked += 1
                declared = _column_family(call)
                if declared is None or (family is not None and declared != family):
                    want = family or "<family>"
                    got = ast.unparse(call.args[0]) if call.args else "(no type)"
                    findings.append(f"{rel}:{call.lineno}: table class `{cls.name}` declares `{name}` as "
                                    f"`{got}`; a record id is `{_COLUMN}({want})` (PostgreSQL uuid, read back "
                                    f"as its id type)")
    if not checked:
        findings.append("no table class declares an id column; re-site the rule")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_record_id_columns] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_record_id_columns] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
