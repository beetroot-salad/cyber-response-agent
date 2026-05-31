#!/usr/bin/env python3
"""flow-map CLI.

Commands:
  map      "<question>" <module.py> --root DIR [--entry FN]
           natural-language query: build (+verify) the graph, parse the question
           to an intent (haiku), resolve the seed deterministically, and render
           the view — a contract card (component-card) or the branch-aware logic
           view of the driving function + agent table (subsystem-map).
  build    <module.py> --root DIR [--entry FN] [--out graph.json] [--mermaid]
           full pipeline: seed -> resolve -> VERIFY -> render. Verification is
           integral, not a separate step: structural checks ALWAYS run and gate
           the build (exit 1 on failure); the paid differential runs when
           FLOWMAP_DIFFERENTIAL is set (or --differential), reporting fidelity
           gaps on the graph it just built.
  seed     <module.py> --root DIR [--entry FN] [--out graph.json] [--mermaid]
           extraction only (seed + resolve), no verification — for inspecting
           the raw graph / reported gaps.
  validate <module.py> --root DIR [--entry FN] [--graph graph.json]
           structural re-derivation of a graph (exit 1 on any discrepancy).

Prefer `build` for normal use — it is the only path that guarantees the graph
you get has been verified.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# allow running as a plain script (no package install)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flowmap.model import Graph          # noqa: E402
from flowmap.seed import seed_python_module  # noqa: E402
from flowmap.resolve import resolve_module_dispatch  # noqa: E402
from flowmap.render import render_mermaid     # noqa: E402
from flowmap.validate import validate         # noqa: E402
from flowmap.verify import (              # noqa: E402
    differential_enabled,
    differential_verify,
    select_load_bearing_subflows,
)
from flowmap.intent import resolve_question  # noqa: E402
from flowmap.scope import component_card, render_card_markdown  # noqa: E402
from flowmap.logic import render_logic_view  # noqa: E402


def _build(module: Path, root: Path, entry: str, *, resolve: bool) -> Graph:
    g = seed_python_module(module, root, entry=entry)
    if resolve:
        resolve_module_dispatch(g, module, root)
    return g


def _cmd_seed(args) -> int:
    root = Path(args.root).resolve()
    module = Path(args.module).resolve()
    g = _build(module, root, args.entry, resolve=not args.no_resolve)
    if args.out:
        Path(args.out).write_text(g.to_json())
        print(f"wrote {args.out}: {len(g.nodes)} nodes, {len(g.edges)} edges, "
              f"{len(g.gaps)} gap(s)", file=sys.stderr)
    if args.mermaid or not args.out:
        print(render_mermaid(g, title=f"{module.name} · entry={args.entry}"))
    return 0


def _cmd_build(args) -> int:
    """Full pipeline with integral verification.

    The graph is produced AND verified in one step so a built graph is never
    unverified. Structural verification always runs and gates the build. The
    differential runs only when opted in (env var or --differential), and its
    disagreements are surfaced as gaps on the emitted graph — never silently.
    """
    root = Path(args.root).resolve()
    module = Path(args.module).resolve()
    module_rel = str(module.relative_to(root))

    g = _build(module, root, args.entry, resolve=not args.no_resolve)

    # run_differential: --differential forces on; --no-differential forces off;
    # otherwise the env var governs (off by default).
    if args.differential:
        run_diff = True
    elif args.no_differential:
        run_diff = False
    else:
        run_diff = None  # -> verify reads FLOWMAP_DIFFERENTIAL

    specs = select_load_bearing_subflows(g, module_rel, args.entry, k=args.subflows)
    result = differential_verify(g, module, root, specs, run_differential=run_diff)

    # structural is the hard gate
    if result.structural:
        print(f"BUILD FAILED — {len(result.structural)} structural error(s):",
              file=sys.stderr)
        for e in result.structural:
            print(f"  {e}", file=sys.stderr)
        return 1

    diff_state = ("ran" if result.differentials else
                  ("enabled-but-no-subflows" if (run_diff or
                   (run_diff is None and differential_enabled())) else "skipped"))
    print(f"OK — built + verified: {len(g.nodes)} nodes, {len(g.edges)} edges, "
          f"{len(g.gaps)} gap(s); structural=pass differential={diff_state}",
          file=sys.stderr)
    for d in result.differentials:
        verdict = "agree" if d.agree else "DISAGREE"
        print(f"  differential[{d.spec.seed_func}]: {verdict}"
              + ("" if d.agree else
                 f" only-in-code={d.only_in_raw} only-in-graph={d.only_in_graph}"),
              file=sys.stderr)

    if args.out:
        Path(args.out).write_text(g.to_json())
        print(f"wrote {args.out}", file=sys.stderr)
    if args.mermaid or not args.out:
        print(render_mermaid(g, title=f"{module.name} · entry={args.entry}"))
    # differential disagreement is advisory (probabilistic) -> exit 2, distinct
    # from a clean build (0) and a structural failure (1), so CI can choose.
    return 2 if any(not d.agree for d in result.differentials) else 0


def _cmd_map(args) -> int:
    """Natural-language query: build (+verify) the graph, then render the view the
    question asks for.

    The graph is produced with the same structural gate as `build`. The question
    is parsed to an Intent by haiku (mode + target), the seed is resolved
    deterministically against real node ids, and the view is rendered:

      * component-card — a source-faithful contract card + its call neighborhood.
      * subsystem-map  — the branch-aware logic view of the driving function: its
        control flow (decisions, loops, agent vs code steps) with branch/agent
        labels re-phrased by haiku, plus the agent companion table.
    """
    root = Path(args.root).resolve()
    module = Path(args.module).resolve()

    g = _build(module, root, args.entry, resolve=not args.no_resolve)
    structural = validate(g, module, root)
    if structural:
        print(f"MAP FAILED — graph not faithful ({len(structural)} error(s)):",
              file=sys.stderr)
        for e in structural:
            print(f"  {e}", file=sys.stderr)
        return 1

    try:
        intent, seed_id = resolve_question(g, args.question)
    except Exception as e:  # IntentError or parser failure -> actionable message
        print(f"could not answer {args.question!r}: {e}", file=sys.stderr)
        return 1

    bare = seed_id.split("::")[-1].split("/")[-1]
    print(f"intent: mode={intent.mode} target={bare}", file=sys.stderr)

    if intent.mode == "component-card":
        scoped = component_card(g, seed_id)
        print(render_card_markdown(g, seed_id))
        print()
        print(render_mermaid(scoped.graph, title=f"{bare} — component"))
        return 0

    # subsystem-map: the driving function's logic view. The seed must be a
    # function (its body sequences the flow); anything else is a clean error.
    if not (seed_id.startswith("py:") and "::" in seed_id):
        print(f"subsystem-map needs a function target; {bare!r} is not a "
              f"function (resolved to {seed_id!r}). Ask about the function that "
              f"drives the flow.", file=sys.stderr)
        return 1
    relfile, funcname = seed_id[len("py:"):].split("::", 1)
    view_module = root / relfile
    try:
        md, summary = render_logic_view(g, view_module, root, funcname)
    except Exception as e:
        print(f"could not render logic view for {funcname!r}: {e}", file=sys.stderr)
        return 1
    note = (f"; represented {summary.get('applied', 0)}/"
            f"{summary.get('requested', 0)} labels"
            + (f" (representer error: {summary['error']})"
               if summary.get("error") else ""))
    print(f"logic view: {funcname} in {relfile}{note}", file=sys.stderr)
    print(f"## {funcname}\n")
    print(md)
    return 0


def _cmd_validate(args) -> int:
    root = Path(args.root).resolve()
    module = Path(args.module).resolve()
    if args.graph:
        import json
        g = Graph.from_dict(json.loads(Path(args.graph).read_text()))
    else:
        g = _build(module, root, args.entry, resolve=not args.no_resolve)
    errs = validate(g, module, root)
    if errs:
        print(f"FAIL — {len(errs)} validation error(s):", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"OK — graph faithful: {len(g.nodes)} nodes, {len(g.edges)} edges, "
          f"{len(g.gaps)} reported gap(s) (all checks passed)", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="seed + resolve + verify (integral) + render")
    b.add_argument("module")
    b.add_argument("--root", required=True)
    b.add_argument("--entry", default="run_one")
    b.add_argument("--out")
    b.add_argument("--mermaid", action="store_true")
    b.add_argument("--no-resolve", action="store_true",
                   help="skip deterministic cross-module dispatch resolution")
    b.add_argument("--differential", action="store_true",
                   help="force the paid differential verifier on (overrides env)")
    b.add_argument("--no-differential", action="store_true",
                   help="force the differential off (overrides FLOWMAP_DIFFERENTIAL)")
    b.add_argument("--subflows", type=int, default=2,
                   help="max load-bearing sub-flows to differentially verify")
    b.set_defaults(fn=_cmd_build)

    s = sub.add_parser("seed")
    s.add_argument("module")
    s.add_argument("--root", required=True)
    s.add_argument("--entry", default="run_one")
    s.add_argument("--out")
    s.add_argument("--mermaid", action="store_true")
    s.add_argument("--no-resolve", action="store_true",
                   help="skip deterministic cross-module dispatch resolution")
    s.set_defaults(fn=_cmd_seed)

    m = sub.add_parser("map", help="natural-language query -> scoped flow view")
    m.add_argument("question")
    m.add_argument("module")
    m.add_argument("--root", required=True)
    m.add_argument("--entry", default="run_one")
    m.add_argument("--no-resolve", action="store_true",
                   help="skip deterministic cross-module dispatch resolution")
    m.set_defaults(fn=_cmd_map)

    v = sub.add_parser("validate")
    v.add_argument("module")
    v.add_argument("--root", required=True)
    v.add_argument("--entry", default="run_one")
    v.add_argument("--graph")
    v.add_argument("--no-resolve", action="store_true",
                   help="skip deterministic cross-module dispatch resolution")
    v.set_defaults(fn=_cmd_validate)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
