#!/usr/bin/env python3
"""Working-investigation I/O fence (#1165): every file I/O occurrence on a run's records, in the
runtime, hooks and box code and the ticket writer, is a handled record operation or a named,
counted residue.

It shares the episode-paths lint's resolver (`lint_episode_paths`): the same I/O vocabulary, the
same scope walk, the same owner tracking. A call to a guarded writer, an opener, a reader, a
path method or a `shutil`/`os` primitive is classified by what it targets (a record, a working
file, a tool trace, a probe, or unresolved); the residue below lists the approved occurrences by
module, function and callee with an exact count, a category and, where the target is an opaque
parameter, the exact target expressions allowed. Counts, never line numbers: a second bypass in an
approved function is a new occurrence, and a residue entry nothing matches is stale.

There is no baseline and no suppression: migrate the I/O to a record handle, or add a categorised
residue entry with its reason. A file that does not parse or decode is a finding of exit 2.

Run from anywhere:  python tooling/lint/lint_working_io.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import _astlib
import _census1134
import lint_episode_paths as vocabulary

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

# Runtime includes the former gather_tools; only ticket_writer belonged to case_history.
# Box I/O moved out of runtime and retains the same counted coverage.
ROOTS = ("runtime", "hooks", "box", "runtime/ticket_writer.py")
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
    return name if origin.rpartition(".")[0] in vocabulary._IO_MODULES and name in READERS else None


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
    astlib = _astlib
    attributes = {part.attr for part in ast.walk(node) if isinstance(part, ast.Attribute)}
    if "tool_trace" in attributes:
        return "tool_trace"
    if "box_sentinel" in attributes:
        return "probe"
    if isinstance(node, ast.Name) and node.id not in seen:
        fn = scan.innermost_def(node)
        if fn is not None:
            bindings = scan.bindings(fn).get(node.id, [])
            kinds = {_target(binding.value, scan, seen | {node.id}) for binding in bindings
                     if binding.value is not None}
            if kinds and kinds != {"unresolved"}:
                return next(iter(kinds)) if len(kinds) == 1 else "unresolved"
    owned = any(isinstance(part, ast.expr) and astlib.owner_derived(part, scan.env)
                for part in ast.walk(node))
    if owned:
        return "working_file" if attributes & WORKING else "record"
    if any(isinstance(part, ast.Name) and part.id.endswith("run_dir")
           for part in ast.walk(node)):
        return "record"
    if "path" in attributes:
        return "record"
    return "unresolved"


def census_source(rel: str, source: str, view=None) -> list[Hit]:
    """The hits of `source` scanned as `rel`, resolved against `view` (default: this checkout)."""
    tree = ast.parse(source)
    scan = vocabulary._scan(view or _census1134.tree_of(DEFENDER.parent), rel, tree)
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
    for name in ROOTS:
        if not (package / name).exists():
            raise ValueError(f"missing swept directory: {name}")
    view = _census1134.tree_of(package.parent)
    out = []
    for name in ROOTS:
        root = package / name
        paths = ([root] if root.is_file() else
                 [root / r for r in _astlib.source_files(root, ("__pycache__",))])
        for path in paths:
            rel = path.relative_to(package).as_posix()
            out.extend(census_source(rel, _astlib.read_source(path, rel), view))
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


# Exact residual occurrences are intentionally small, categorized, and not regenerated from
# implementation. The live-state files and durable record writers are not exemptions.
RESIDUE = {
    ("runtime.driver._build", "_fold_decision", "read_text_utf8"): (1, "m_read"),
    ("hooks.inject_system_skill_description", "read_description", "read_text_soft"): (1, "nonrecord", ('skill_path',)),
    ("runtime.bash_policy", "_load_policy", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("box._docker", "_own_container_ids", "read_text_soft"): (2, "nonrecord", ('hostname_path', 'mountinfo_path')),
    # #1205: send the request frame to the Docker client's stdin pipe, not a run record.
    ("box._output", "_send", "os.write"): (1, "nonrecord", ("fd",)),
    ("box._clock", "write_clock", "write_guarded"): (1, "job_state", ('clock_file',)),
    ("box._clock", "prepare_clock", "guarded_mkdir"): (1, "job_state", ('where',)),
    ("box._clock", "prepare_clock", "write_guarded"): (1, "job_state", ('clock_file',)),
    ("box._clock", "remove_clock", "shutil.rmtree"): (1, "job_state", ('clock_file.parent',)),
    ("box._stage", "_remove", "shutil.rmtree"): (1, "model_view", ('entry',)),
    ("box._stage", "_remove", ".unlink"): (1, "model_view", ('entry',)),
    ("box._stage", "_same_bytes", "builtins.open"): (2, "model_view", ('a', 'b')),
    ("box._stage", "_carry_file", "shutil.copy2"): (1, "model_view", ('entry.path',)),
    ("box._stage", "_mirror_tree", "guarded_mkdir"): (1, "model_view", ('target',)),
    ("box._stage", "make_staging_tree", "guarded_mkdir"): (1, "model_view", ('tree.run_view',)),
    ("box._stage", "make_staging_tree", ".symlink_to"): (
        2, "model_view", ("root / MODEL_DEFENDER.relative_to('/')", "root / MODEL_AGENT.relative_to('/')")),
    # The finalizer holds this cleanup callable; the census records that reference.
    ("box._stage", "staged_executor", "shutil.rmtree"): (1, "model_view", ('<reference>',)),
    ("box._image", "_read", ".read_bytes"): (1, "nonrecord", ('tree / name',)),
    # #1108 P3 (D7): a read-only mount is verified by reading an existing host file back
    # (a code mount's `MOUNT_CHECK` or a data mount's first regular file) — never a run record.
    ("box._lifecycle", "_check_mount_sentinel", "read_text_utf8"): (1, "probe", ('source / relative',)),
    ("box._lifecycle", "_plant", "write_guarded"): (1, "probe", ('sentinel',)),
    ("box._lifecycle", "_probe_sentinel", ".unlink"): (2, "probe", ('sentinel',)),
    ("box._lifecycle", "stop_and_scrub", "sweep_staged"): (1, "cleanup", ('tree',)),
    ("box._oracle", "_make_runner", "guarded_mkdir"): (1, "nonrecord", ('dest.parent',)),
    ("box._oracle", "_make_runner", "read_bytes_capped"): (1, "nonrecord", ('CHECKOUT / rel',)),
    ("box._oracle", "_make_runner", "shutil.rmtree"): (1, "nonrecord", ('runner',)),
    ("box._oracle", "_make_runner", "write_guarded"): (1, "nonrecord", ('dest',)),
    ("box._oracle", "start_oracle_box", "shutil.rmtree"): (1, "nonrecord", ('runner',)),
    ("box._oracle", "start_oracle_box.discard", "shutil.rmtree"): (2, "nonrecord", ('runner', 'scratch')),
    ("box._oracle", "stop_oracle_box", "shutil.rmtree"): (1, "nonrecord", ('folder',)),
    # #1108 P4: the run copy's host-side lifecycle (`<tenant>/run-knowledge/<run_id>/`, outside any
    # run dir): built as a dot-named temporary whose name carries its owner, renamed into place
    # (removed by name through `tenancy._exports.remove_entry`); and the host-held
    # knowledge-source record beside the run dir (U12). None is a run-dir record, so each is
    # non-record I/O.
    ("runtime.run_knowledge", "copy_for_run", "hold_new"): (1, "nonrecord", ('copies',)),
    ("runtime.run_knowledge", "copy_for_run", ".mkdir"): (1, "nonrecord", ('held',)),
    ("runtime.run_knowledge", "copy_for_run", "os.rename"): (1, "nonrecord", ('copies / temporary',)),
    ("runtime.run_knowledge", "write_host_record", "write_guarded"): (1, "nonrecord", ('path',)),
    ("runtime.driver", "_stop_before_main", "write_guarded"): (1, "retiring"),
    # #1255 extracted the existing empty tool-trace fallback; #1165 N-c still
    # retires this projection separately. Its record target and count are unchanged.
    ("runtime.driver", "_write_trace_or_empty", "write_guarded"): (
        1, "retiring", ('RunPaths(run_dir).tool_trace',)),
    ("runtime.driver._build", "_gather_instructions", "read_text_utf8"): (1, "nonrecord", ("defender_dir / 'skills' / 'gather' / 'SKILL.md'",)),
    ("runtime.driver._prompts", "_main_instructions", "read_text_utf8"): (1, "nonrecord", ("defender_dir / 'SKILL.md'",)),
    ("runtime.lead_zero", "run_correlation", "read_text_utf8"): (1, "m_read"),
    ("runtime.lessons_engine.lessons_fm", "cmd_show", "read_text_utf8"): (1, "nonrecord", ('lesson',)),
    ("runtime.lessons_engine.lessons_frontier", "main", "read_text_soft"): (1, "nonrecord", ('Path(ns.investigation)',)),
    # Explicit non-run backend paths: learning loggers and worktree scrubs share these
    # utilities. Run integrations are separately driven with the handed record handles.
    ("runtime.observe", "RequestLogger.__init__", "open_guarded"): (1, "non_run", ('path',)),
    ("runtime.observe", "stage_trace_path", "guarded_mkdir"): (1, "non_run"),
    ("runtime.observe", "write_trace", "write_guarded"): (1, "retiring"),
    ("runtime.orient", "_invlang_grammar", "read_text_soft"): (1, "nonrecord", ("defender_dir / 'skills' / 'invlang' / 'SKILL.md'",)),
    ("runtime.review", "role_prompt", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("box._scrub", "_write_verdict", "write_guarded"): (1, "non_run", ('verdict_path(tree)',)),
    ("box._scrub", "mark_unsandboxed", "read_text_utf8"): (1, "non_run", ('p',)),
    ("box._scrub", "tree_unsandboxed", "read_text_utf8"): (1, "non_run", ('verdict_path(tree)',)),
    ("box._scrub", "tree_verified", "read_text_utf8"): (1, "non_run", ('p',)),
    # Extracted from session_store.py; the count, target and classification are unchanged.
    ("runtime.session_store._write", "open_store", "guarded_mkdir"): (1, "session_store", ('path.parent',)),
    # The SQL shim reads the model's file operands and operates only inside the box.
    ("runtime.sql_engine.sql", "_inferred_load", "builtins.open"): (1, "model_tools"),
    ("runtime.sql_engine.sql", "_load_rows", "builtins.open"): (1, "model_tools"),
    ("runtime.sql_engine.sql", "_run", "shutil.rmtree"): (1, "nonrecord", ('scratch',)),
    ("runtime.tenant_settings", "read_regular_bytes", "getattr(os)"): (1, "nonrecord", ('os',)),
    ("runtime.tenant_settings", "read_regular_bytes", "os.open"): (1, "nonrecord", ('path',)),
    ("runtime.tools._files", "_write_operand", "hold"): (1, "model_tools", ('root',)),
    ("runtime.verb_roster", "audit_read_surfaces", "read_text_utf8"): (1, "nonrecord", ('path',)),
    ("runtime.verbs", "read_roster", "read_bytes_capped"): (1, "nonrecord", ('path',)),
}


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    try:
        return deviations(collect(root), RESIDUE)
    except ValueError as exc:
        raise _astlib.ScanBlind(str(exc)) from exc
    except SyntaxError as exc:
        raise _astlib.ScanBlind(f"does not parse: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_working_io] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_working_io] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
