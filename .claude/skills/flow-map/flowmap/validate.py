"""End-to-end deterministic validation of a seeded graph.

The seed builds the graph one way (BFS, per-function visitor). This validator
re-derives the facts a *different* way (fresh AST pass, independent traversal)
and asserts they agree — so a bug in the extractor cannot silently pass. Four
checks, all mechanical:

  R) ref integrity     — every node.ref points at a real file:line, and for
                         py-func the symbol at that line is a FunctionDef with
                         the matching name; for agent-prompt/script the file
                         exists on disk.
  E) edge integrity    — every edge endpoint id exists in nodes.
  C) call consistency  — re-parse the module; for every `calls` edge assert the
                         call truly appears in the source function, AND every
                         in-graph local call in the source appears as an edge
                         (no missing, no invented).
  G) golden subflow    — a hand-traced expected edge set for the load-bearing
                         learning-loop path must be present (the human-checked
                         anchor).

Exit 0 = all pass. Exit 1 = any failure (prints every failure).
"""
from __future__ import annotations

import ast
from pathlib import Path

from .model import Graph


def _resolve_ref(root: Path, ref: str) -> tuple[Path, int] | None:
    if ":" not in ref:
        return None
    path_part, _, line_part = ref.rpartition(":")
    try:
        line = int(line_part)
    except ValueError:
        return None
    p = (root / path_part)
    return (p, line) if p.is_file() else None


def check_refs(g: Graph, root: Path) -> list[str]:
    errs: list[str] = []
    for nid, n in g.nodes.items():
        if not n.ref:
            errs.append(f"[R] node {nid} has empty ref")
            continue
        resolved = _resolve_ref(root, n.ref)
        if resolved is None:
            errs.append(f"[R] node {nid} ref {n.ref!r} does not resolve to a real file")
            continue
        path, line = resolved
        if n.kind == "py-func":
            tree = ast.parse(path.read_text(), filename=str(path))
            funcname = nid.split("::", 1)[1]
            hit = any(
                isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef))
                and d.name == funcname and d.lineno == line
                for d in ast.walk(tree)
            )
            if not hit:
                errs.append(f"[R] py-func {nid}: no FunctionDef {funcname!r} at {n.ref}")
        # agent-prompt / script: file existence already confirmed by _resolve_ref
    return errs


def check_edges(g: Graph) -> list[str]:
    errs: list[str] = []
    for e in g.edges:
        if e.src not in g.nodes:
            errs.append(f"[E] edge src {e.src!r} not a node ({e.kind} -> {e.dst})")
        if e.dst not in g.nodes:
            errs.append(f"[E] edge dst {e.dst!r} not a node ({e.src} {e.kind} ->)")
    return errs


def check_call_consistency(g: Graph, module: Path, root: Path) -> list[str]:
    """Independent re-derivation of intra-module call edges from a fresh AST pass.

    Identity is read back from the GRAPH (node ids + their ref files), never
    re-derived as a path-prefix string — so there is no way for the seed's
    notion of a node id to diverge from the check's. Cross-module edges (added
    by the dispatch resolver) point at a dst in another file; they are validated
    by check_refs (dst must be a real FunctionDef at its ref), not here.
    """
    errs: list[str] = []
    tree = ast.parse(module.read_text(), filename=str(module))
    funcs = {s.name: s for s in tree.body
             if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}

    mod_real = module.resolve()

    def _ref_file(ref: str) -> Path | None:
        if not ref or ":" not in ref:
            return None
        return root / ref.rsplit(":", 1)[0]

    # py-func nodes whose ref resolves to THIS module — identified by file,
    # not by string-prefixing a recomputed relative path.
    local_ids = {
        nid for nid, n in g.nodes.items()
        if n.kind == "py-func" and (lf := _ref_file(n.ref)) is not None
        and lf.resolve() == mod_real
    }
    name2id = {nid.split("::", 1)[1]: nid for nid in local_ids}

    recomputed: dict[str, set[str]] = {nid: set() for nid in local_ids}
    for nid in local_ids:
        fname = nid.split("::", 1)[1]
        if fname not in funcs:
            errs.append(f"[C] graph func {nid} absent from module source")
            continue
        for c in (n for n in ast.walk(funcs[fname]) if isinstance(n, ast.Call)):
            fn = c.func
            nm = fn.id if isinstance(fn, ast.Name) else None
            if nm in name2id:
                recomputed[nid].add(name2id[nm])

    graph_calls: dict[str, set[str]] = {nid: set() for nid in local_ids}
    for e in g.edges:
        if e.kind == "calls" and e.src in local_ids and e.dst in local_ids:
            graph_calls[e.src].add(e.dst)

    for nid in local_ids:
        want, got = recomputed[nid], graph_calls[nid]
        for missing in want - got:
            errs.append(f"[C] missing calls edge: {nid} -> {missing} (present in source)")
        for invented in got - want:
            errs.append(f"[C] invented calls edge: {nid} -> {invented} (not in source)")
    return errs


# The hand-traced load-bearing subflow of loop.py. If the extractor stops
# finding these, the map has drifted from the code and the build must fail.
GOLDEN_EDGES = [
    # (src_func, kind, dst_suffix)
    ("run_one", "calls", "::normalize_disposition"),
    ("run_one", "calls", "::_directions_for"),
    ("run_one", "calls", "::_run_adversarial"),
    ("run_one", "calls", "::_run_benign"),
    ("run_one", "calls", "::_maybe_trigger_author"),
    ("run_one", "calls", "::derive_alert_rule_key"),
    ("_run_adversarial", "calls", "::project_actor_input"),
    ("_run_adversarial", "calls", "::invoke_actor"),
    ("_run_adversarial", "calls", "::_run_oracle"),
    ("_run_adversarial", "calls", "::invoke_judge"),
    ("_run_adversarial", "calls", "::persist_run"),
    ("_run_adversarial", "calls", "::append_findings"),
    ("invoke_actor", "dispatches", "agent-prompt:") ,        # -> actor.md
    ("invoke_oracle", "dispatches", "agent-prompt:"),        # -> oracle.md
    ("invoke_judge", "dispatches", "agent-prompt:"),         # -> judge.md
    ("project_actor_input", "runs_command", "script:"),      # -> project_lead_sequence.py
]

GOLDEN_DISPATCH_TARGETS = {
    "invoke_actor": "actor.md",
    "invoke_oracle": "oracle.md",
    "invoke_judge": "judge.md",
    "invoke_actor_benign": "actor_benign.md",
    "invoke_judge_benign": "judge_benign.md",
}

GOLDEN_GAP_SUBSTR = "__import__"  # the dynamic dispatch must be reported, not silently dropped

# After deterministic resolution, _maybe_trigger_author's __import__(module_name)
# must become concrete cross-module edges to each curator's run_batch — recovered
# from the literal module_name= kwargs at its three call sites in run_one.
GOLDEN_RESOLVED_CURATORS = ("author", "author_actor", "author_actor_benign")


def check_golden(g: Graph, relfile: str) -> list[str]:
    errs: list[str] = []

    def src_id(fname: str) -> str:
        return f"py:{relfile}::{fname}"

    for src_func, kind, dst_suffix in GOLDEN_EDGES:
        sid = src_id(src_func)
        hit = any(
            e.src == sid and e.kind == kind and dst_suffix in e.dst
            for e in g.edges
        )
        if not hit:
            errs.append(f"[G] golden edge missing: {src_func} -{kind}-> *{dst_suffix}*")

    # dispatch targets must resolve to the right prompt file
    for src_func, want_md in GOLDEN_DISPATCH_TARGETS.items():
        sid = src_id(src_func)
        targets = [e.dst for e in g.edges if e.src == sid and e.kind == "dispatches"]
        if targets and not any(t.endswith(want_md) for t in targets):
            errs.append(f"[G] {src_func} dispatch target {targets} != expected *{want_md}")

    # Resolution-aware: the dynamic __import__ dispatch is EITHER reported as a
    # gap (no-resolve) OR closed into concrete curator edges (resolved). Never
    # silently dropped with nothing in its place.
    gap_present = any(GOLDEN_GAP_SUBSTR in gap.detail for gap in g.gaps)
    trigger_id = src_id("_maybe_trigger_author")
    resolved_edges = {
        e.dst.rsplit("::", 1)[-1]
        for e in g.edges
        if e.src == trigger_id and e.via == "dynamic-import"
    }
    if resolved_edges:
        # resolved mode: gap must be gone AND all three curators linked
        if gap_present:
            errs.append("[G] resolved curator edges exist but the __import__ gap "
                        "was not dropped")
        for curator in GOLDEN_RESOLVED_CURATORS:
            if f"run_batch" not in {r for r in resolved_edges} or \
                    not any(e.src == trigger_id and e.via == "dynamic-import"
                            and f"py:defender/learning/{curator}.py::run_batch" == e.dst
                            for e in g.edges):
                errs.append(f"[G] resolved curator edge missing: "
                            f"_maybe_trigger_author -> {curator}.run_batch")
    elif not gap_present:
        errs.append(f"[G] expected EITHER a reported __import__ gap OR resolved "
                    f"curator edges; found neither (silent drop)")
    return errs


# The golden subflow is a hand-traced anchor for ONE specific real module. It
# is a fixture, not a generic rule — so it only fires when validating that file.
GOLDEN_MODULE_SUFFIX = "defender/learning/loop.py"


def validate(g: Graph, module: Path, root: Path) -> list[str]:
    relfile = str(module.resolve().relative_to(root.resolve()))
    errs = []
    errs += check_refs(g, root)        # generic: applies to any module
    errs += check_edges(g)             # generic
    errs += check_call_consistency(g, module, root)  # generic
    if relfile.endswith(GOLDEN_MODULE_SUFFIX):       # fixture: loop.py only
        errs += check_golden(g, relfile)
    return errs
