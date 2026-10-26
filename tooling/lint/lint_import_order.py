#!/usr/bin/env python3
"""Import-order fence (#1080): `defender/`'s top-level packages form one declared order, bottom to
top, and no import points up it unless the baseline lists it with an owner issue.

The order (`ORDER`) is declared here and nowhere else. A node is a top-level package, or a
top-level module: every flat `_*.py` counts as one node (`_flat`), and `run.py`, `run_common.py`
and `agents.py` each count as their own. Every import statement counts — at module load, inside
a function, and under `if TYPE_CHECKING:` — since an indented import is still a dependency and the
usual way a loop is hidden. Relative imports are resolved. An import's fingerprint is the importing
file plus the fully resolved module it names (`from defender.runtime import session_store` keys
as `defender.runtime.session_store`), so a listed entry never covers a second import.

Besides the order, three per-package rules (#1080 O4):

* `integrations/` (the adapters) imports only `kit`, the flat tier, `knowledge` and itself;
* only the files in `INTEGRATIONS_IMPORTERS` import `integrations/` (#1172 owns those reach-ins);
* `api/` loads no `runtime` or `learning` module: the load-time imports reachable from any `api`
  module (not inside a function, not type-only) are followed transitively (#1131).

It fails (exit 1) on an unlisted finding, on a baseline entry no finding matches (the list only
shrinks), on an entry whose reason names no owner issue (`#<n>`), and on a top-level package the
order does not name — that one has no baseline: place the package. A file that does not parse is
exit 2. Not seen (#1080 N4): imports through strings or `importlib`.

Run from anywhere:  python tooling/lint/lint_import_order.py [--root DIR] [--update-baseline]
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import _astlib
from _baseline import Finding, _load_entries, gate

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"
BASELINE = Path(__file__).with_name("lint_import_order_baseline.json")
LABEL = "lint_import_order"

#: Bottom to top. A pair with no imports either way is ordered arbitrarily; swap it when an import
#: first needs the other direction.
ORDER = (
    "kit", "configuration", "execution", "_filesystem", "_flat", "records", "episodes",
    "tenancy", "knowledge", "box", "integrations", "hooks", "skills",
    "runtime", "learning", "presentation", "run_common", "agents", "run", "cli", "api",
)
_RANK = {node: rank for rank, node in enumerate(ORDER)}

_EXCLUDED = ("tests", ".venv", "__pycache__")
_ADAPTERS = "integrations"
#: What the adapters may import besides themselves.
_ADAPTER_IMPORTS = frozenset({"kit", "_flat", "knowledge"})
#: The files outside `integrations/` that may import it (#1080 N2; #1172 removes each).
INTEGRATIONS_IMPORTERS = frozenset({
    "cli/tacit_cli.py",                          # the tacit adapter's private helpers
    "runtime/ticket_writer.py",                  # the shared transport
    "skills/connect/examples/example_adapter.py",  # the connect skill's example adapter
})
_API = "api"
_API_FORBIDDEN = frozenset({"runtime", "learning"})
_OWNER = re.compile(r"#\d+")

_HEADER = (
    "lint_import_order baseline (#1080): upward imports and per-package breaches accepted until "
    "their owner issue resolves them. Each reason names that owner (#<n>). The list only "
    "shrinks: an entry no import matches fails. Regenerate with "
    "`python tooling/lint/lint_import_order.py --update-baseline`."
)


class Unplaced(Exception):
    """A top-level package or module the order does not name."""


def node_of(rel: str) -> str:
    """The order node a `defender/`-relative path belongs to."""
    first = rel.split("/", 1)[0]
    if "/" in rel:
        return first
    stem = first.removesuffix(".py")
    return "_flat" if stem.startswith("_") else stem


def _node_of_module(module: str, modules: dict[str, str]) -> str | None:
    """The node of a dotted `defender.` module, or None for anything outside `defender`."""
    parts = module.split(".")
    if parts[0] != "defender" or len(parts) < 2:
        return None
    head = parts[1]
    if f"defender.{head}" in modules:
        return node_of(modules[f"defender.{head}"])
    if any(m.startswith(f"defender.{head}.") for m in modules):  # a folder without __init__.py
        return head
    return "_flat" if head.startswith("_") else head


@dataclass(frozen=True)
class _Import:
    rel: str
    line: int
    module: str     # fully resolved `defender.` module
    load_time: bool


def _resolved(node: ast.Import | ast.ImportFrom, package: str,
              modules: dict[str, str]) -> Iterator[str]:
    """Each `defender.` module an import statement names; a from-import of a submodule names the
    submodule."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name == "defender" or alias.name.startswith("defender."):
                yield alias.name
        return
    source = _astlib.import_source(node, package)
    if source != "defender" and not source.startswith("defender."):
        return
    for alias in node.names:
        sub = f"{source}.{alias.name}"
        yield sub if sub in modules else source


def _imports(rel: str, tree: ast.Module, modules: dict[str, str]) -> Iterator[_Import]:
    _module, package = _astlib.module_and_package(rel)

    def walk(node: ast.AST, load_time: bool) -> Iterator[_Import]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                yield from walk(child, False)
            elif isinstance(child, ast.If) and "TYPE_CHECKING" in ast.unparse(child.test):
                for stmt in child.body:
                    yield from walk(ast.Module(body=[stmt], type_ignores=[]), False)
                for stmt in child.orelse:
                    yield from walk(ast.Module(body=[stmt], type_ignores=[]), load_time)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for module in _resolved(child, package, modules):
                    yield _Import(rel, child.lineno, module, load_time)
            else:
                yield from walk(child, load_time)

    with _astlib.scan_guard(rel):
        yield from walk(tree, True)


def _files(root: Path) -> dict[str, str]:
    """Dotted module -> `defender/`-relative file, for every scanned file."""
    rels = _astlib.source_files(root, _EXCLUDED)
    return {_astlib.module_and_package(rel)[0]: rel for rel in rels}


def _loaded_by(module: str, modules: dict[str, str]) -> list[str]:
    """`module` and the packages a Python import of it executes first."""
    parts = module.split(".")
    return [m for i in range(2, len(parts) + 1) if (m := ".".join(parts[:i])) in modules]


def _api_findings(imports: dict[str, list[_Import]], modules: dict[str, str]) -> list[Finding]:
    start = [m for m, rel in modules.items() if node_of(rel) == _API]
    seen = set(start)
    via: dict[str, str] = {}
    queue = list(start)
    found: list[Finding] = []
    while queue:
        current = queue.pop()
        for imp in imports.get(modules[current], ()):
            if not imp.load_time:
                continue
            for loaded in _loaded_by(imp.module, modules):
                if loaded in seen:
                    continue
                seen.add(loaded)
                via[loaded] = current
                if node_of(modules[loaded]) in _API_FORBIDDEN:
                    chain = [loaded]
                    while chain[-1] in via:
                        chain.append(via[chain[-1]])
                    found.append(Finding(
                        f"api-loads:{loaded}",
                        f"api loads `{loaded}` at import time: {' <- '.join(chain)}"))
                else:
                    queue.append(loaded)
    return found


def scan(root: Path) -> list[Finding]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    modules = _files(root)
    unplaced = sorted({node_of(rel) for rel in modules.values()} - _RANK.keys())
    if unplaced:
        raise Unplaced(", ".join(unplaced))
    imports: dict[str, list[_Import]] = {}
    for rel in modules.values():
        imports[rel] = list(_imports(rel, _astlib.read_and_parse(root / rel, rel)[1], modules))

    findings: list[Finding] = []
    for rel, found in imports.items():
        source = node_of(rel)
        for imp in found:
            target = _node_of_module(imp.module, modules)
            if target is None or target == source:
                continue
            if target not in _RANK:
                raise Unplaced(target)
            where = f"{rel}:{imp.line}"
            if _RANK[target] > _RANK[source]:
                findings.append(Finding(f"{rel}:{imp.module}",
                                        f"{where}: `{source}` imports up into `{imp.module}`"))
            if source == _ADAPTERS and target not in _ADAPTER_IMPORTS:
                findings.append(Finding(
                    f"adapter-imports:{rel}:{imp.module}",
                    f"{where}: an adapter imports `{imp.module}`; adapters import only "
                    f"{', '.join(sorted(_ADAPTER_IMPORTS))} and themselves"))
            if target == _ADAPTERS and rel not in INTEGRATIONS_IMPORTERS:
                findings.append(Finding(
                    f"imports-adapters:{rel}:{imp.module}",
                    f"{where}: imports adapter code `{imp.module}`; only the files in "
                    "INTEGRATIONS_IMPORTERS may"))
    findings.extend(_api_findings(imports, modules))
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return list(unique.values())


def _baseline_faults(findings: list[Finding], baseline: Path) -> list[str]:
    """Entries no finding matches, and entries whose reason names no owner issue."""
    entries = _load_entries(baseline)
    current = {f.fingerprint for f in findings}
    out = [f"stale: {fp} — no import matches it; delete the entry"
           for fp in sorted(entries.keys() - current)]
    out += [f"ownerless: {fp} — its reason names no owner issue (#<n>)"
            for fp, reason in sorted(entries.items()) if fp in current and not _OWNER.search(reason)]
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--update-baseline", action="store_true")
    args = parser.parse_args(argv)
    try:
        findings = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[{LABEL}] {exc}", file=sys.stderr)
        return 2
    except Unplaced as exc:
        print(f"[{LABEL}] not in the order: {exc}. Place it in ORDER in "
              "tooling/lint/lint_import_order.py.")
        return 1
    gate_argv = ["--update-baseline"] if args.update_baseline else []
    status = gate(findings, args.baseline, gate_argv, label=LABEL, header=_HEADER,
                  require_reasons=True)
    if args.update_baseline:
        return status
    faults = _baseline_faults(findings, args.baseline)
    for line in faults:
        print(f"[{LABEL}] {line}")
    return 1 if status or faults else 0


if __name__ == "__main__":
    sys.exit(main())
