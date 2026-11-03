#!/usr/bin/env python3
"""Record id columns (#1382): every ORM table's own `id` is an `IdColumn`.

A record id the system mints is canonical UUID text, stored as PostgreSQL `uuid` and read back as
its family's type (`TenantId`, `AlertId`, ...). A table whose primary key `id` is declared `Text`
(or anything but `IdColumn(<family>)`) brings back free-text ids and the store guards they needed.
A column that refers to an id needs no rule here: PostgreSQL refuses a foreign key from `text` to
`uuid`, and the catalog comparison of #1339 holds the migration to the model.

In every production module under `defender/` (tests excluded), a class that sets `__tablename__`
and declares `id = mapped_column(...)` must pass `IdColumn(...)` as its first argument. A tree
with no such table is a finding (the rule moved), never a pass. A file that does not parse is
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


def _is_table(cls: ast.ClassDef) -> bool:
    return any(isinstance(stmt, ast.Assign | ast.AnnAssign)
               and any(isinstance(t, ast.Name) and t.id == "__tablename__"
                       for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]))
               for stmt in cls.body)


def _id_column(cls: ast.ClassDef) -> ast.Call | None:
    """The `mapped_column(...)` call the class assigns to `id`, if any."""
    for stmt in cls.body:
        target = stmt.target if isinstance(stmt, ast.AnnAssign) else (
            stmt.targets[0] if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 else None)
        if isinstance(target, ast.Name) and target.id == "id" and isinstance(stmt.value, ast.Call) \
                and ast.unparse(stmt.value.func).split(".")[-1] == "mapped_column":
            return stmt.value
    return None


def _is_id_column(call: ast.Call) -> bool:
    first = call.args[0] if call.args else None
    return isinstance(first, ast.Call) and ast.unparse(first.func).split(".")[-1] == _COLUMN


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    tables = 0
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and _is_table(n)):
            call = _id_column(cls)
            if call is None:
                continue
            tables += 1
            if not _is_id_column(call):
                findings.append(f"{rel}:{call.lineno}: table class `{cls.name}` declares its `id` as "
                                f"`{ast.unparse(call.args[0]) if call.args else '(no type)'}`; a record id is "
                                f"`{_COLUMN}(<family>)` (PostgreSQL uuid, read back as its id type)")
    if not tables:
        findings.append("no table class declares an `id` column; re-site the rule")
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
