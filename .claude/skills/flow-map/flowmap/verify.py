"""Differential verifier — surrogate-fidelity check for a built graph.

Two tiers, in cost order:

  1. STRUCTURAL (free, always, hard gate). Reuses validate(): every node ref
     resolves, no dangling edges, intra-module calls are consistent, the golden
     subflow is intact. If structural fails, the differential never runs — a
     graph that isn't even internally consistent has nothing to be faithful to.

  2. DIFFERENTIAL (paid, opt-in, 1-2 load-bearing sub-flows). Two independent
     haiku tracers answer the SAME trace question — one reading the raw source
     of the sub-flow's functions, the other reading only the constructed
     subgraph. Their answers (ordered target names) are compared deterministically:
       * agreement  → the graph is a faithful surrogate FOR THIS sub-flow.
       * disagreement → the graph dropped/added something load-bearing; reported
         as a `surrogate-fidelity` gap (NOT a silent pass). This is the
         high-value signal — it localizes drift between code and map.

This is intentionally probabilistic and scoped: it certifies the sub-flows
traced, not the whole graph, and two tracers can share a blind spot — so a
clean differential raises confidence, it does not prove completeness. The
structural tier is the deterministic backstop.

The model call is injected (`tracer=`) so tests run with zero live calls.
"""
from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .model import Gap, Graph
from .validate import validate

# Differential verification is the only PAID tier (two haiku tracers per
# sub-flow). It is OFF by default and opt-in via this env var, so a normal
# build pays nothing. Set FLOWMAP_DIFFERENTIAL=1 (or true/yes/on) to enable.
_DIFFERENTIAL_ENV = "FLOWMAP_DIFFERENTIAL"


def differential_enabled() -> bool:
    return os.environ.get(_DIFFERENTIAL_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# Sub-flow specification
# --------------------------------------------------------------------------- #


@dataclass
class SubflowSpec:
    """A load-bearing sub-flow to verify.

    seed_func   the function the trace starts from (e.g. "_run_adversarial")
    question    the trace question, phrased identically to both tracers
    """
    seed_func: str
    question: str = (
        "List, in order, every function, agent-prompt, or script this code "
        "directly invokes to do its work. Use the bare callable/file name "
        "(e.g. invoke_actor, actor.md, project_lead_sequence.py). Do not "
        "include the seed itself, control-flow keywords, logging, or builtins."
    )


@dataclass
class DiffResult:
    spec: SubflowSpec
    raw_steps: list[str]
    graph_steps: list[str]
    only_in_raw: list[str]
    only_in_graph: list[str]

    @property
    def agree(self) -> bool:
        return not self.only_in_raw and not self.only_in_graph


@dataclass
class VerifyResult:
    structural: list[str]
    differentials: list[DiffResult] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.structural and all(d.agree for d in self.differentials)


# --------------------------------------------------------------------------- #
# Views handed to the two tracers (deterministic construction)
# --------------------------------------------------------------------------- #


def source_view(module: Path, seed_func: str) -> str:
    """Raw source of the seed function (what the code-side tracer reads)."""
    tree = ast.parse(module.read_text(), filename=str(module))
    for d in ast.walk(tree):
        if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef)) and d.name == seed_func:
            seg = ast.get_source_segment(module.read_text(), d)
            if seg:
                return seg
    raise ValueError(f"seed function {seed_func!r} not found in {module}")


def graph_view(g: Graph, module_rel: str, seed_func: str) -> str:
    """The subgraph's outgoing edges from the seed (what the map-side tracer reads).

    Deliberately renders ONLY direct out-edges of the seed with their target
    labels — the same scope the trace question asks about — so the two tracers
    are answering a comparable question from comparable surface area.
    """
    seed_id = f"py:{module_rel}::{seed_func}"
    lines = [f"# direct out-edges of {seed_func}"]
    for e in g.edges:
        if e.src != seed_id:
            continue
        dst = g.nodes.get(e.dst)
        target = _bare_name(e.dst)
        label = f" ({dst.label})" if dst and dst.label else ""
        lines.append(f"- {e.kind}: {target}{label}")
    return "\n".join(lines)


def _bare_name(node_id: str) -> str:
    """py:rel::fn -> fn ; agent-prompt:dir/x.md -> x.md ; script:dir/y.py -> y.py"""
    tail = node_id.split("::")[-1]
    return tail.split("/")[-1]


# --------------------------------------------------------------------------- #
# Comparison (deterministic)
# --------------------------------------------------------------------------- #


def _normalize(steps: list[str]) -> set[str]:
    return {s.strip().lower() for s in steps if isinstance(s, str) and s.strip()}


def compare_traces(raw: list[str], graph: list[str]) -> tuple[list[str], list[str]]:
    r, gset = _normalize(raw), _normalize(graph)
    return sorted(r - gset), sorted(gset - r)


def expected_steps_from_graph(g: Graph, module_rel: str, seed_func: str) -> list[str]:
    """Ground-truth step set straight from the graph (no LLM) — the oracle the
    graph-side tracer SHOULD reproduce. Used by tests and as a sanity anchor."""
    seed_id = f"py:{module_rel}::{seed_func}"
    return sorted(_bare_name(e.dst) for e in g.edges if e.src == seed_id)


# Edge kinds that make a sub-flow "load-bearing" — the ones worth the paid
# differential because they are where a parser is most likely to drift.
_LOAD_BEARING_KINDS = {"dispatches", "runs_command"}


def select_load_bearing_subflows(g: Graph, module_rel: str, entry: str,
                                 k: int = 2) -> list[SubflowSpec]:
    """Deterministically pick the <=k most load-bearing sub-flows to verify.

    A sub-flow is a function whose out-edges include dispatch/subprocess work
    (the semantically interesting boundaries). Ranked by count of such edges,
    then by total out-degree, then by name for stability. The entry function is
    always included first so the top-level flow is always verified.
    """
    seed_prefix = f"py:{module_rel}::"
    out_by_src: dict[str, list] = {}
    for e in g.edges:
        if e.src.startswith(seed_prefix):
            out_by_src.setdefault(e.src, []).append(e)

    def fname(nid: str) -> str:
        return nid.split("::", 1)[1]

    def score(nid: str) -> tuple:
        edges = out_by_src.get(nid, [])
        lb = sum(1 for e in edges if e.kind in _LOAD_BEARING_KINDS)
        return (lb, len(edges))

    entry_id = f"{seed_prefix}{entry}"
    ranked = sorted(
        (nid for nid in out_by_src if nid != entry_id),
        key=lambda nid: (-score(nid)[0], -score(nid)[1], fname(nid)),
    )
    chosen = [entry] + [fname(nid) for nid in ranked if score(nid)[0] > 0]
    # dedup preserving order, cap at k
    seen: set[str] = set()
    out: list[SubflowSpec] = []
    for name in chosen:
        if name in seen:
            continue
        seen.add(name)
        out.append(SubflowSpec(name))
        if len(out) >= k:
            break
    return out


# --------------------------------------------------------------------------- #
# Tracer (model-backed, injectable)
# --------------------------------------------------------------------------- #

_TRACE_SYSTEM = """You trace control flow. You are given ONE artifact (either a
code snippet or a graph edge list) and a question. Answer ONLY from the artifact.

Output STRICT JSON, no prose, no code fence:
{"steps":["name1","name2",...]}
Use bare names (invoke_actor, actor.md, project_lead_sequence.py). Preserve the
order they appear. Omit the seed itself, control-flow keywords, logging calls,
and language builtins."""


def _default_tracer(artifact: str, question: str) -> list[str]:
    # imported lazily so the module loads without the model wiring present
    from .haiku import _parse_obj, _run_haiku
    user = f"{question}\n\n<artifact>\n{artifact}\n</artifact>"
    raw = _run_haiku(_TRACE_SYSTEM, user)
    doc = _parse_obj(raw)
    steps = doc.get("steps")
    if not isinstance(steps, list):
        raise ValueError(f"tracer output missing 'steps' list: {raw[:160]!r}")
    return [s for s in steps if isinstance(s, str)]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def differential_verify(
    g: Graph,
    module: Path,
    root: Path,
    specs: list[SubflowSpec],
    *,
    tracer=_default_tracer,
    run_differential: bool | None = None,
) -> VerifyResult:
    """Structural gate (always) + differential on `specs` (opt-in).

    The differential (the paid tier) runs only when enabled. `run_differential`
    resolves as: explicit True/False wins; when None (default) it reads the
    FLOWMAP_DIFFERENTIAL env var (off unless set) — so callers pay for haiku
    tracing only by deliberate opt-in.

    `tracer(artifact, question) -> list[str]` is injected so the differential is
    testable with zero live calls. On structural failure the differential is
    skipped entirely (a non-faithful graph has nothing to be a surrogate of).
    """
    do_diff = differential_enabled() if run_differential is None else run_differential
    structural = validate(g, module, root)
    result = VerifyResult(structural=structural)
    if structural or not do_diff:
        return result

    module_rel = str(module.resolve().relative_to(root.resolve()))
    for spec in specs:
        raw_view = source_view(module, spec.seed_func)
        gview = graph_view(g, module_rel, spec.seed_func)
        raw_steps = tracer(raw_view, spec.question)
        graph_steps = tracer(gview, spec.question)
        only_raw, only_graph = compare_traces(raw_steps, graph_steps)
        d = DiffResult(spec, raw_steps, graph_steps, only_raw, only_graph)
        result.differentials.append(d)
        if not d.agree:
            detail = (
                f"sub-flow {spec.seed_func}: code-trace and graph-trace disagree. "
                f"only-in-code={only_raw} only-in-graph={only_graph} — the map may "
                "be dropping or inventing a load-bearing step here."
            )
            gap = Gap("surrogate-fidelity", f"{module_rel}::{spec.seed_func}", detail)
            result.gaps.append(gap)
            g.gaps.append(gap)
    return result
