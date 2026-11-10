#!/usr/bin/env python3
"""The catalog's declarations, read cold (#1366 K2, K8, C1).

Every catalog adapter (`defender/integrations/*_adapter.py`) and connect's example adapter
(`defender/skills/connect/examples/example_adapter.py`) declare, at module level and readable without running the
module, `PREFIX` (text), `REQUIRED_CONFIG_KEYS` and `PATH_KEYS` (tuples of key names, prefix stripped; empty where
none), `DISPLAY_NAME` (non-blank text) and `EXAMPLE` (a bool: a lab stub). The operator's catalog listing and the record
judgement read them so. Accepted spellings: a literal, an alias of another module-level declaration
(`PATH_KEYS = REQUIRED_CONFIG_KEYS`), an annotation (`X: tuple[str, ...] = ()`), and a keys tuple that splats a shared
template beside literals (`(*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "TABLE")`). A call, an expression or a definition
under a condition is a finding.

An adapter offering the host's comment action (`add_case_comment`) also declares `comment_route` (C1, K5): the route
the store's cover rule judges a record against.

K8: no declared settings key is named like a secret (`TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `CREDENTIAL`, `API_KEY`,
`APIKEY`, or a `*_SECRET_REF` reference): a secret is a credential in the secret store, never a setting. This replaces
connect's validator scan of a tenant's `config.env` values.

Run from repo root:  python tooling/lint/lint_catalog_declarations.py [--root <repo-shaped tree>]
Exit 0 = clean, 1 = findings (each line names the module's repo-relative path and the constant or key), 2 = the scan
saw no adapter (a root holding none proves nothing).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTERS = "defender/integrations"
EXAMPLE_ADAPTER = "defender/skills/connect/examples/example_adapter.py"
ADAPTER_SUFFIX = "_adapter.py"

TEXT, FLAG, KEYS = "text", "flag", "keys"
#: Each declaration and the kind of literal it must be.
DECLARATIONS = {"PREFIX": TEXT, "REQUIRED_CONFIG_KEYS": KEYS, "PATH_KEYS": KEYS, "DISPLAY_NAME": TEXT, "EXAMPLE": FLAG}
COMMENT_ACTION, COMMENT_ROUTE = "add_case_comment", "comment_route"
#: A secret-named key (K8): the name ends in a secret word, or is a reference to a secret.
SECRET_NAMED = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)(_REF)?$", re.I)

_UNREAD = object()
_SPLAT = object()  # a splat of something outside the module (the shared template): keys not knowable here


def _adapters(root: Path) -> list[Path]:
    found = sorted((root / ADAPTERS).glob(f"*{ADAPTER_SUFFIX}")) if (root / ADAPTERS).is_dir() else []
    example = root / EXAMPLE_ADAPTER
    return found + ([example] if example.is_file() else [])


def _module_level(tree: ast.Module) -> tuple[dict[str, ast.expr], set[str]]:
    """The module-level assignments by name, and the module-level names defined (functions and assignments)."""
    assigned: dict[str, ast.expr] = {}
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = node.value
                    defined.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
            if node.value is not None:
                assigned[node.target.id] = node.value
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            defined.add(node.name)
    return assigned, defined


def _value(node: ast.expr, assigned: dict[str, ast.expr], depth: int = 0) -> object:
    """`node` as a literal: a constant, a tuple/list of literals and splats, or an alias; `_UNREAD` otherwise."""
    if depth > 8:
        return _UNREAD
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return _value(assigned[node.id], assigned, depth + 1) if node.id in assigned else _UNREAD
    if isinstance(node, ast.Tuple | ast.List):
        items: list[object] = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                if isinstance(element.value, ast.Attribute):
                    items.append(_SPLAT)
                    continue
                inner = _value(element.value, assigned, depth + 1)
                if not isinstance(inner, tuple):
                    return _UNREAD
                items.extend(inner)
                continue
            value = _value(element, assigned, depth + 1)
            if value is _UNREAD:
                return _UNREAD
            items.append(value)
        return tuple(items)
    return _UNREAD


def _shaped(kind: str, value: object) -> bool:
    if kind == TEXT:
        return isinstance(value, str) and bool(value.strip())
    if kind == FLAG:
        return isinstance(value, bool)
    return isinstance(value, tuple) and all(isinstance(v, str) or v is _SPLAT for v in value)


def scan_file(path: Path, rel: str) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError) as e:
        return [f"{rel}: cannot be read cold ({type(e).__name__}): its declarations are unknown"]
    assigned, defined = _module_level(tree)
    findings: list[str] = []
    for name, kind in DECLARATIONS.items():
        if name not in assigned:
            findings.append(f"{rel}: declares no module-level {name} (every catalog adapter declares {name}, read "
                            "without running it)")
            continue
        value = _value(assigned[name], assigned)
        if value is _UNREAD or not _shaped(kind, value):
            findings.append(f"{rel}: {name} is not readable without running the module: declare it as a {kind} "
                            "literal (or an alias of one) at module level")
            continue
        if kind == KEYS:
            assert isinstance(value, tuple)
            findings.extend(f"{rel}: {name} declares {key}, a settings key named like a secret — a secret is a "
                            "credential in the secret store, never a setting"
                            for key in value if isinstance(key, str) and SECRET_NAMED.search(key))
    if COMMENT_ACTION in defined and COMMENT_ROUTE not in defined:
        findings.append(f"{rel}: offers {COMMENT_ACTION} but declares no {COMMENT_ROUTE}(settings): the route the "
                        "comment is sent on must be declared")
    return findings


def scan(root: Path) -> tuple[int, list[str]]:
    root = Path(root).resolve()
    modules = _adapters(root)
    findings: list[str] = []
    for path in modules:
        findings.extend(scan_file(path, path.relative_to(root).as_posix()))
    return len(modules), findings


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = REPO_ROOT
    if "--root" in args:
        at = args.index("--root")
        if at + 1 >= len(args):
            print("usage: lint_catalog_declarations.py [--root <tree>]", file=sys.stderr)
            return 2
        root = Path(args[at + 1])
    seen, findings = scan(root)
    if not seen:
        print(f"[lint_catalog_declarations] no adapter under {ADAPTERS}/ or at {EXAMPLE_ADAPTER}: the scan proved "
              "nothing", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print(f"\n[lint_catalog_declarations] {len(findings)} finding(s): the catalog is read cold, so each adapter "
              "declares its settings and display constants as module-level literals.")
        return 1
    print(f"[lint_catalog_declarations] 0 findings over {seen} adapter(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
