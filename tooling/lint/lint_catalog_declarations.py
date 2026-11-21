#!/usr/bin/env python3
"""The catalog's declarations, read cold (#1366 K2, K8, C1).

Every catalog adapter (`defender/integrations/*_adapter.py`) and connect's example adapter
(`defender/skills/connect/examples/example_adapter.py`) declare, at module level and readable without running the
module, `PREFIX` (text), `REQUIRED_CONFIG_KEYS` and `PATH_KEYS` (tuples of key names, prefix stripped; empty where
none), `DISPLAY_NAME` (non-blank text), `EXAMPLE` (a bool: a lab stub) and `READ_ROUTES` (#1504 O1: the non-GET
`(method, path)` routes its tools send, an explicit `()` for none). The operator's catalog listing and the record
judgement read them so. Accepted spellings: a literal, an alias of another module-level declaration
(`PATH_KEYS = REQUIRED_CONFIG_KEYS`), an annotation (`X: tuple[str, ...] = ()`), and a keys tuple that splats a shared
template beside literals (`(*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "TABLE")`). A call, an expression or a definition
under a condition is a finding.

An adapter offering the host's comment action (`add_case_comment`, defined or imported at module level) also declares
`comment_route` (C1, K5): the route the store's cover rule judges a record against; such an adapter declares no
`READ_ROUTES` (a case system takes no non-GET read, the proxy's one-ticket write rule).

#1504 O5, O6: a reference `<module stem>.md` sits beside each adapter module (connect's example, the seed a generated
adapter is copied from, included) with a non-empty `## Credential` and a non-empty `## Pitfalls` section.

An adapter imports no `proxy_client` (#1504 O2): every request leaves through the transport's capture seam.

K8: no declared settings key is named like a secret (`TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `CREDENTIAL`, `API_KEY`,
`APIKEY`, or a `*_SECRET_REF` reference, each also under a trailing `_ENV`, as connect's retired scan read it): a
secret is a credential in the secret store, never a setting. This replaces connect's validator scan of a tenant's
`config.env` values.

Run from repo root:  python tooling/lint/lint_catalog_declarations.py [--root <repo-shaped tree>]
Exit 0 = clean, 1 = findings (each line names the module's repo-relative path and the constant or key), 2 = the scan
saw no adapter (a root holding none proves nothing).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import _astlib

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTERS = "defender/integrations"
EXAMPLE_ADAPTER = "defender/skills/connect/examples/example_adapter.py"
ADAPTER_SUFFIX = "_adapter.py"
READS = "READ_ROUTES"
#: The reference's two sections, each a level-2 heading (O5).
SECTIONS = ("Credential", "Pitfalls")
#: The route shape the access declaration's parser requires (`tenancy/_access.py` `_routes`, C17): an upper-case method,
#: a path from `/` with no `?` or `#`. GET and HEAD need no declared route at the proxy, so they are never listed.
_METHOD = re.compile(r"[A-Z]+\Z")
_PROXY_READ_METHODS = ("GET", "HEAD")

TEXT, FLAG, KEYS = "text", "flag", "keys"
#: Each declaration and the kind of literal it must be.
DECLARATIONS = {"PREFIX": TEXT, "REQUIRED_CONFIG_KEYS": KEYS, "PATH_KEYS": KEYS, "DISPLAY_NAME": TEXT, "EXAMPLE": FLAG,
                READS: "routes"}
COMMENT_ACTION, COMMENT_ROUTE = "add_case_comment", "comment_route"
#: A secret-named key (K8): the name ends in a secret word, or is a reference to a secret, either one optionally
#: under the retired `_ENV` suffix (connect's old rule judged the key with `_ENV` stripped: `API_TOKEN_ENV` is a secret).
SECRET_NAMED = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)(_REF)?(_ENV)?$", re.I)

_UNREAD = object()
_SPLAT = object()  # a splat of something outside the module (the shared template): keys not knowable here


def _adapters(root: Path) -> list[Path]:
    """The catalog's adapter modules (`integrations/*_adapter.py`, top level only), through the shared listing, then the
    connect example."""
    folder = root / ADAPTERS
    listed = _astlib.source_files(folder, (), suffixes=(ADAPTER_SUFFIX,)) if folder.is_dir() else []
    found = [folder / rel for rel in listed if "/" not in rel]
    example = root / EXAMPLE_ADAPTER
    return found + ([example] if example.is_file() else [])


def _module_level(tree: ast.Module) -> tuple[dict[str, ast.expr], set[str]]:
    """The module-level assignments by name, and the module-level names the module has (functions, assignments and
    imported names: an adapter offers an action it imports as surely as one it defines)."""
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
    # The names its imports bind, by the scope-aware resolver (an alias included).
    defined.update(_astlib.module_env(tree).imports)
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


def _route_faults(value: object) -> list[str]:
    """Why a `READ_ROUTES` value is not a tuple of `(method, path)` routes of the access declaration's shape, each a
    non-GET/HEAD method, none repeated (O1); empty when it is."""
    if not isinstance(value, tuple):
        return ["is not a tuple of (method, path) routes"]
    faults: list[str] = []
    seen: set[object] = set()
    for route in value:
        if not (isinstance(route, tuple) and len(route) == 2 and all(isinstance(part, str) for part in route)):
            faults.append(f"holds {route!r}, which is not a (method, path) pair of text")
            continue
        method, path = route
        if not _METHOD.match(method):
            faults.append(f"holds {route!r}, whose method is not upper-case letters")
        elif method in _PROXY_READ_METHODS:
            faults.append(f"holds {route!r}: the proxy passes a {method} without a declared route")
        if not path.startswith("/") or "?" in path or "#" in path:
            faults.append(f"holds {route!r}, whose path does not start with `/` or holds `?` or `#`")
        if route in seen:
            faults.append(f"holds {route!r} twice")
        seen.add(route)
    return faults


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
        if value is not _UNREAD and kind == "routes":
            findings.extend(f"{rel}: {name} {why}" for why in _route_faults(value))
            if COMMENT_ROUTE in defined and value:
                findings.append(f"{rel}: {name} is not empty, but the adapter declares a {COMMENT_ROUTE}: a case system "
                                "takes no non-GET read")
            continue
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
    findings.extend(_bypass_findings(tree, rel))
    return findings + _reference_findings(path, rel)


def _bypass_findings(tree: ast.Module, rel: str) -> list[str]:
    """#1504 O2: an adapter sends through the transport's capture seam, never through the proxy client directly, so the
    test that matches the sent requests with the declared list sees every request."""
    out: list[str] = []
    for node in ast.walk(tree):
        names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                 else [node.module or "", *(a.name for a in node.names)] if isinstance(node, ast.ImportFrom) else [])
        if any("proxy_client" in name.split(".") for name in names):
            out.append(f"{rel}:{node.lineno}: imports the proxy client; send through `defender.kit.transport`, whose "
                       "capture seam the declared-reads test watches")
    return out


def _reference_findings(path: Path, rel: str) -> list[str]:
    """O5, O6: the reference `<module stem>.md` beside the module exists and holds a non-empty section per heading."""
    shown = Path(rel).with_suffix(".md").as_posix()
    try:
        text = path.with_suffix(".md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return [f"{shown}: the adapter's reference cannot be read ({type(e).__name__}): every adapter ships one beside "
                f"its module, with a `## {SECTIONS[0]}` and a `## {SECTIONS[1]}` section"]
    bodies: dict[str, list[str]] = {}
    current: list[str] | None = None
    fence: str | None = None
    for line in text.splitlines():
        opens = re.match(r"\s{0,3}(`{3,}|~{3,})", line)
        if fence is not None:
            if opens and opens.group(1)[0] == fence[0] and len(opens.group(1)) >= len(fence):
                fence = None
        elif opens:
            fence = opens.group(1)
        heading = None if fence is not None or opens else re.match(r"(#{1,6})\s+(.*?)\s*\Z", line)
        if heading and len(heading.group(1)) <= 2:
            # A level-1 or level-2 heading opens the next section; a deeper one stays inside the enclosing one.
            current = bodies.setdefault(heading.group(2), []) if len(heading.group(1)) == 2 else None
        elif current is not None and not heading:
            current.append(line)
    return [f"{shown}: has no non-empty `## {name}` section (write `None known.` when there is nothing to say)"
            for name in SECTIONS if not any(line.strip() for line in bodies.get(name, []))]


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
