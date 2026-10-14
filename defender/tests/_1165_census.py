"""#1165's counted architectural contract, sharing #1133's I/O resolver.

This is test machinery, not a production I/O substitute. Every vocabulary occurrence is
retained; unknown targets remain findings. Explicit residue is compared by counts, never
line numbers, so adding a second bypass in an approved function does not disappear.
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from defender.tests import test_1133_census as vocabulary
from defender.tests._by_path import import_lint_lib

ROOTS = ("runtime", "hooks", "scripts/gather_tools", "scripts/case_history")
READERS = frozenset({
    "read_jsonl_rows", "read_jsonl_rows_report", "read_text_soft", "read_text_utf8",
    "locked_for_read", "locked_json_read", "read_bytes_capped", "iter_plain_jsonl_rows",
})
READ_KEYS = READERS | frozenset({"read_guarded", "read_bytes_guarded", "read_plain",
                                "read_plain_bytes", "Path.read_text", "Path.read_bytes",
                                ".read_text", ".read_bytes"})
WORKING = frozenset({"investigation", "gather_summary", "gather_summaries", "payload",
                     "gather_raw", "alert"})


@dataclass(frozen=True)
class Hit:
    module: str
    scope: str
    callee: str
    target: str
    expression: str = "<reference>"

    @property
    def key(self) -> tuple[str, str, str]:
        return self.module, self.scope, self.callee


def _reader(node: ast.expr, scan) -> str | None:
    origin = scan.origin(node)
    if origin is None:
        return None
    name = origin.rsplit(".", 1)[-1]
    return name if origin.startswith("defender._io.") and name in READERS else None


def _typed(node: ast.expr, scan, wanted: str, seen: frozenset[str] = frozenset()) -> bool:
    """Resolve a local parameter/alias through the shared scan, never its variable spelling."""
    if not isinstance(node, ast.Name) or node.id in seen:
        return False
    fn = scan.innermost_def(node)
    if fn is None:
        return False
    for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
        if arg.arg == node.id and arg.annotation is not None:
            annotation = scan._annotation(arg.annotation)
            origin = scan.origin(annotation) if annotation is not None else None
            if origin in {f"defender.run_repository.{wanted}",
                          f"defender.run_repository._handle.{wanted}"}:
                return True
    bindings = scan.bindings(fn).get(node.id, [])
    return bool(bindings) and all(binding.value is not None and
        (_typed(binding.value, scan, wanted, seen | {node.id}) or
         (wanted == "RecordHandle" and _record_receiver(binding.value, scan, seen | {node.id})))
        for binding in bindings)


def _record_receiver(node: ast.expr, scan, seen: frozenset[str] = frozenset()) -> bool:
    if _typed(node, scan, "RecordHandle", seen):
        return True
    member = node.func if isinstance(node, ast.Call) else node
    if not isinstance(member, ast.Attribute) or not isinstance(member.value, ast.Attribute):
        return False
    group = member.value
    return (group.attr in {"tables", "facts", "documents", "observability", "session"}
            and _typed(group.value, scan, "Run", seen))


def _target(node: ast.expr | None, scan, seen: frozenset[str] = frozenset()) -> str:
    if node is None:
        return "unresolved"
    astlib = import_lint_lib("_astlib")
    attributes = {part.attr for part in ast.walk(node) if isinstance(part, ast.Attribute)}
    if "tool_trace" in attributes:
        return "tool_trace"
    if "box_sentinel" in attributes:
        return "probe"
    owned = any(isinstance(part, ast.expr) and astlib.owner_derived(part, scan.env)
                for part in ast.walk(node))
    if owned:
        return "working_file" if attributes & WORKING else "record"
    if isinstance(node, ast.Name) and node.id not in seen:
        fn = scan.innermost_def(node)
        if fn is not None:
            bindings = scan.bindings(fn).get(node.id, [])
            kinds = {_target(binding.value, scan, seen | {node.id}) for binding in bindings
                     if binding.value is not None}
            if kinds and kinds != {"unresolved"}:
                return next(iter(kinds)) if len(kinds) == 1 else "unresolved"
    if any(isinstance(part, ast.Name) and part.id.endswith("run_dir")
           for part in ast.walk(node)):
        return "record"
    if "path" in attributes:
        return "record"
    return "unresolved"


def census_source(rel: str, source: str) -> list[Hit]:
    tree = ast.parse(source)
    scan = vocabulary._scan(rel, tree)
    aliases = vocabulary.module_aliases(tree, scan)
    visitor = vocabulary._Scoped()
    visitor.visit(tree)
    module = vocabulary._module_name(rel)
    out = []
    for scope, call in visitor.calls:
        key = vocabulary._call_key(call, scan, aliases) or _reader(call.func, scan)
        if key is None:
            continue
        if (key in {".read_bytes", "Path.read_bytes", ".replace", "Path.replace"} and isinstance(call.func, ast.Attribute)
                and _record_receiver(call.func.value, scan)):
            continue
        # A method's receiver is the target; a resolved module/static primitive uses its
        # first positional argument. Pure load_json_artifact is deliberately not I/O.
        target = call.args[0] if call.args else None
        if key.startswith(("Path.", ".")) and isinstance(call.func, ast.Attribute):
            target = call.func.value
        out.append(Hit(module, scope, key, _target(target, scan),
                       ast.unparse(target) if target is not None else "<no target>"))
    for scope, node in visitor.refs:
        key = vocabulary._ref_key(node, scan, aliases) or _reader(node, scan)
        if (key in {".read_bytes", "Path.read_bytes", ".replace", "Path.replace"} and isinstance(node, ast.Attribute)
                and _record_receiver(node.value, scan)):
            continue
        if key is not None:
            out.append(Hit(module, scope, key, "unresolved"))
    return out


def collect(package: Path) -> list[Hit]:
    out = []
    for name in ROOTS:
        root = package / name
        if not root.is_dir():
            raise ValueError(f"missing swept directory: {name}")
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            out.extend(census_source(path.relative_to(package).as_posix(),
                                     path.read_text(encoding="utf-8")))
    return out


def deviations(hits: list[Hit], residue: dict) -> list[str]:
    counts = Counter(hit.key for hit in hits)
    expected = Counter({key: value[0] for key, value in residue.items()})
    out = [f"new or duplicate I/O {key}: {count}" for key, count in (counts - expected).items()]
    out.extend(f"stale residue {key}: {count}" for key, count in (expected - counts).items())
    for hit in hits:
        entry = residue.get(hit.key)
        if entry is None:
            continue
        category = entry[1]
        # An opaque parameter is allowed only by a documented exact target declaration.
        # An unknown expression substituted into an otherwise exempt scope is a finding.
        if hit.target == "unresolved" and (len(entry) < 3 or hit.expression not in entry[2]):
            out.append(f"unclassified residue target {hit}")
        if category == "m_read" and (hit.target != "working_file" or hit.callee not in READ_KEYS):
            out.append(f"working-file read exemption does not cover {hit}")
        if category == "nonrecord" and hit.target in {"record", "working_file", "tool_trace"}:
            out.append(f"nonrecord exemption does not cover {hit}")
        if category == "retiring" and hit.target not in {"tool_trace", "unresolved"}:
            out.append(f"retiring exemption does not cover {hit}")
    return out
