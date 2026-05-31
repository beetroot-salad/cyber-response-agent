"""Control-flow (logic) view of a single function — branch-aware + sequential.

The seed builds a CALL graph (unordered "A calls B"). This builds a CONTROL-FLOW
graph of one function body: statements in execution order, with `if`/`for`/
`while`/`try`/`return`/`raise` rendered as real branches and loop-backs. Edge
labels are the RAW condition source (`ast.unparse(test)`), so they are
source-traceable and need no per-codebase recognizers.

Node kinds (reusing model.Node):
  terminal  — start / end / return / raise
  decision  — an `if` (label = the test source); out-edges "yes"/"no"
  loop      — a `for`/`while` (label = the header source); "loop"/"done" edges
  agent     — a call to a function that DIRECTLY dispatches a claude -p agent
              (carries the prompt name); the non-deterministic steps
  code      — any other tracked call (local function / subprocess / cross-module)

"Tracked" calls are calls to functions defined in the same module (the altitude
of this function) plus its resolved dispatch/subprocess/cross-module edges. A
call to a direct-dispatcher renders as `agent`; everything else as `code`.
Builtins and untracked names are skipped. Nothing is hidden silently — the
companion `agent_table()` lists each agent's goal + input context.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .model import Edge, Graph, Node

_MAXLABEL = 60


def _trunc(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= _MAXLABEL else s[: _MAXLABEL - 1] + "…"


@dataclass
class _Builder:
    relfile: str
    local_funcs: set[str]
    dispatchers: dict[str, str]   # funcname -> prompt bare-name it dispatches
    g: Graph = field(default_factory=Graph)
    _seq: int = 0

    def nid(self, lineno: int) -> str:
        self._seq += 1
        return f"cfg:{self.relfile}:{lineno}#{self._seq}"

    def add(self, lineno: int, kind: str, label: str, **signals) -> str:
        nid = self.nid(lineno)
        self.g.add_node(Node(id=nid, kind=kind, label=label,
                             ref=f"{self.relfile}:{lineno}", signals=signals))
        return nid

    def link(self, srcs: list[str], dst: str, label: str = "") -> None:
        for s in srcs:
            self.g.add_edge(Edge(s, dst, "flow", label=label, via="cfg"))

    # ----- tracked-call discovery within one statement -------------------- #

    def _calls_in(self, node: ast.AST) -> list[tuple[str, int]]:
        """(callee_name, lineno) for tracked calls in source order."""
        out = []
        for c in ast.walk(node):
            if isinstance(c, ast.Call):
                fn = c.func
                name = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None)
                if name in self.local_funcs or name in self.dispatchers:
                    out.append((name, getattr(c, "lineno", 0)))
        return out

    def _emit_call_chain(self, names: list[tuple[str, int]], preds: list[str],
                         label: str) -> list[str]:
        """Emit one node per tracked call (source order); thread sequentially."""
        cur, lbl = preds, label
        for name, lineno in names:
            if name in self.dispatchers:
                nid = self.add(lineno, "agent", name,
                               prompt=self.dispatchers[name])
            else:
                nid = self.add(lineno, "code", name)
            self.link(cur, nid, lbl)
            cur, lbl = [nid], ""
        return cur

    # ----- statement walker ----------------------------------------------- #

    def emit(self, stmts: list[ast.stmt], preds: list[str],
             label: str = "") -> list[str]:
        cur, lbl = preds, label
        for st in stmts:
            cur, lbl = self._emit_stmt(st, cur, lbl)
            if not cur:           # path terminated (return/raise)
                break
        return cur

    def _emit_stmt(self, st: ast.stmt, preds: list[str], label: str):
        if isinstance(st, ast.If):
            d = self.add(st.lineno, "decision", _trunc(ast.unparse(st.test)))
            self.link(preds, d, label)
            true_tails = self.emit(st.body, [d], "yes")
            if st.orelse:
                false_tails = self.emit(st.orelse, [d], "no")
                return true_tails + false_tails, ""
            return true_tails + [d], ""   # 'no' falls through from the decision

        if isinstance(st, (ast.For, ast.While)):
            hdr = (f"for {ast.unparse(st.target)} in {ast.unparse(st.iter)}"
                   if isinstance(st, ast.For) else f"while {ast.unparse(st.test)}")
            ln = self.add(st.lineno, "loop", _trunc(hdr))
            self.link(preds, ln, label)
            body_tails = self.emit(st.body, [ln], "loop")
            self.link(body_tails, ln, "↺")     # loop-back
            return [ln], "done"

        if isinstance(st, ast.Return):
            t = self.add(st.lineno, "terminal", "return")
            self.link(preds, t, label)
            return [], ""

        if isinstance(st, ast.Raise):
            t = self.add(st.lineno, "terminal", "raise")
            self.link(preds, t, label)
            return [], ""

        if isinstance(st, ast.Try):
            tails = self.emit(st.body, preds, label)
            for h in st.handlers:
                tails += self.emit(h.body, preds, "except")
            if st.finalbody:
                tails = self.emit(st.finalbody, tails, "")
            return tails, ""

        # plain statement: emit any tracked calls it contains, in order
        names = self._calls_in(st)
        if names:
            return self._emit_call_chain(names, preds, label), ""
        return preds, label


def _dispatchers(g: Graph, relfile: str) -> dict[str, str]:
    """funcname -> prompt bare-name, for funcs in `relfile` that directly dispatch."""
    out: dict[str, str] = {}
    for e in g.edges:
        if e.kind == "dispatches" and e.src.startswith(f"py:{relfile}::"):
            out[e.src.split("::", 1)[1]] = e.dst.split("/")[-1]
    return out


def build_control_flow(call_graph: Graph, module: Path, root: Path,
                       entry: str) -> Graph:
    """CFG of `entry`'s body. `call_graph` is the seeded+resolved call graph
    (used only to know which local funcs are agent-dispatchers)."""
    module = module.resolve(); root = root.resolve()
    relfile = str(module.relative_to(root))
    tree = ast.parse(module.read_text(), filename=str(module))
    funcs = {s.name: s for s in tree.body
             if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if entry not in funcs:
        raise ValueError(f"entry {entry!r} not a top-level function in {relfile}")

    b = _Builder(relfile=relfile, local_funcs=set(funcs),
                 dispatchers=_dispatchers(call_graph, relfile))
    start = b.add(funcs[entry].lineno, "terminal", entry)
    tails = b.emit(funcs[entry].body, [start], "")
    if tails:
        end = b.add(funcs[entry].lineno, "terminal", "end")
        b.link(tails, end, "")
    b.g.built_from = {"root": str(root), "module": relfile, "entry": entry,
                      "view": "control-flow"}
    return b.g


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

_SHAPE = {
    "terminal": ("([", "])"),
    "decision": ("{", "}"),
    "loop": ("[/", "/]"),
    "agent": ("{{", "}}"),
    "code": ("[", "]"),
}

# Dark text on light fills — readable across GitHub + VS Code light/dark.
_CLASSDEFS = [
    "classDef terminal fill:#e2e8f0,stroke:#475569,color:#0f172a;",
    "classDef decision fill:#fef9c3,stroke:#a16207,color:#1c1917;",
    "classDef loop fill:#e0e7ff,stroke:#3730a3,color:#1e1b4b;",
    "classDef agent fill:#dcfce7,stroke:#15803d,color:#14532d,stroke-width:2px;",
    "classDef code fill:#ffffff,stroke:#334155,color:#0f172a;",
]

# Calls treated as render-noise (logging / pure side-effect). Collapsed by
# default — they are still in the underlying graph, just spliced out of the view.
NOISE_NAMES = {"_log", "log", "logger", "print", "_debug", "debug"}


def _sid(nid: str) -> str:
    import re
    return "N" + re.sub(r"[^A-Za-z0-9]", "_", nid)


def collapse_noise(g: Graph, names: set[str] = NOISE_NAMES) -> Graph:
    """Return a copy of `g` with noise `code` nodes spliced out (in→out joined),
    preserving branch labels on the incoming edge. Render-only; the input graph
    is untouched."""
    nodes = dict(g.nodes)
    edges = list(g.edges)
    noise = [nid for nid, n in nodes.items()
             if n.kind == "code" and n.label in names]
    for nid in noise:
        ins = [e for e in edges if e.dst == nid]
        outs = [e for e in edges if e.src == nid]
        edges = [e for e in edges if e.src != nid and e.dst != nid]
        for i in ins:
            for o in outs:
                edges.append(Edge(i.src, o.dst, "flow",
                                  label=i.label or o.label, via="cfg"))
        nodes.pop(nid, None)
    out = Graph(built_from=dict(g.built_from))
    out.nodes = nodes
    # de-dup spliced edges
    for e in edges:
        out.add_edge(e)
    return out


def render_logic_mermaid(g: Graph, title: str = "") -> str:
    lines = ["```mermaid", "flowchart TD"]
    if title:
        lines.append(f"  %% {title}")
    for nid, n in g.nodes.items():
        o, c = _SHAPE.get(n.kind, ("[", "]"))
        lines.append(f'  {_sid(nid)}{o}"{n.label}"{c}:::{n.kind}')
    for e in g.edges:
        if e.label:
            lines.append(f"  {_sid(e.src)} -->|{e.label}| {_sid(e.dst)}")
        else:
            lines.append(f"  {_sid(e.src)} --> {_sid(e.dst)}")
    lines += ["  " + cd for cd in _CLASSDEFS]
    lines.append("```")
    return "\n".join(lines)


def agent_table(g: Graph, call_graph: Graph, module: Path, root: Path) -> str:
    """Companion table: each agent step's goal (prompt description first line) +
    input context (the <tags> assembled at the dispatch site)."""
    root = root.resolve()
    agents = sorted({n.label for n in g.nodes.values() if n.kind == "agent"})
    if not agents:
        return ""
    rows = ["| agent | goal | input context |", "|---|---|---|"]
    for a in agents:
        # prefer an LLM-represented goal stamped onto the node; else the
        # deterministic first-line fallback.
        node = next((n for n in g.nodes.values()
                     if n.kind == "agent" and n.label == a), None)
        goal = (node.signals.get("goal") if node else None) \
            or _prompt_goal(call_graph, a, root) or "—"
        ctx = _dispatch_context(module, a) or "—"
        rows.append(f"| **{a}** | {goal} | {ctx} |")
    return "\n".join(rows)


def _prompt_goal(g: Graph, funcname: str, root: Path) -> str | None:
    """First sentence of the dispatched prompt file's opening paragraph."""
    dst = next((e.dst for e in g.edges
                if e.kind == "dispatches" and e.src.endswith(f"::{funcname}")), None)
    if not dst:
        return None
    path = root / dst.split(":", 1)[1] if dst.startswith("agent-prompt:") else None
    if not path or not path.is_file():
        return None
    text = path.read_text().lstrip()
    # skip a leading **Output contract.** style bolded preamble; take first
    # sentence of the first paragraph that starts with "You are"/"Your".
    for para in text.split("\n\n"):
        p = para.strip()
        if p.lower().startswith(("you are", "your job", "you ")):
            first = p.split(". ")[0].rstrip(".")
            return _trunc_md(first)
    first = text.split(". ")[0].strip()
    return _trunc_md(first)


def _trunc_md(s: str, n: int = 90) -> str:
    s = " ".join(s.split()).replace("|", "/")
    return s if len(s) <= n else s[: n - 1] + "…"


def render_logic_view(call_graph: Graph, module: Path, root: Path, funcname: str,
                      *, representer=None, collapse: bool = True) -> tuple[str, dict]:
    """Full subsystem-map render for one driving function: build the control-flow
    graph, re-phrase its branch/agent labels (LLM seam), collapse render-noise,
    and emit the Mermaid chart + the agent companion table as one markdown string.

    `representer` is the injectable LLM seam (default: the live haiku representer).
    Degrades to the deterministic raw labels on any representer failure — the flow
    you read is always the located one; only its wording is model-authored. Returns
    (markdown, summary) where summary reports requested/applied label counts."""
    from .represent import _default_representer, represent_logic

    if representer is None:
        representer = _default_representer
    cfg = build_control_flow(call_graph, module, root, funcname)
    try:
        summary = represent_logic(cfg, call_graph, root, representer=representer)
    except Exception as e:  # noqa: BLE001 — degrade to raw labels, never crash the view
        from .represent import collect_requests
        summary = {"requested": len(collect_requests(cfg, call_graph, root)),
                   "applied": 0, "error": str(e)}

    view = collapse_noise(cfg) if collapse else cfg
    chart = render_logic_mermaid(view, title=funcname)
    table = agent_table(view, call_graph, module, root)
    md = chart + ("\n\n" + table if table else "")
    return md, summary


def _dispatch_context(module: Path, funcname: str) -> str | None:
    """The XML-ish <tag> names in the user-prompt f-string at the dispatch site."""
    tree = ast.parse(module.read_text(), filename=str(module))
    fn = next((d for d in ast.walk(tree)
               if isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef))
               and d.name == funcname), None)
    if fn is None:
        return None
    import re
    tags: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for m in re.finditer(r"<([a-z][a-z0-9_]*)>", node.value):
                t = m.group(1)
                if t not in tags:
                    tags.append(t)
    return " · ".join(tags) if tags else None
