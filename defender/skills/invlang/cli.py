"""Minimal CLI over the cross-case query helpers + advisory adapter.

Primitive queries:
  python -m defender.skills.invlang.cli <corpus_root> sequence [--contains S] [--disposition D] [--signature SIG]
  python -m defender.skills.invlang.cli <corpus_root> hypotheses <pattern> [--final-weight W] [--disposition D] [--signature SIG]
  python -m defender.skills.invlang.cli <corpus_root> branch-effects [--hyp PATTERN ...] [--min-support N]
  python -m defender.skills.invlang.cli <corpus_root> hypothesis-vocabulary --signature SIG [--top-k N] [--json]
  python -m defender.skills.invlang.cli <corpus_root> hypothesis-shape [--parent-type T] [--parent-class CLASS] [--rel R] [--attached-to-type T] [--json]

Composed PLAN-time advisory recall:
  python -m defender.skills.invlang.cli <corpus_root> advisory --signature SIG [--frontier ?H ...] [--class C ...] [--top-k 3] [--json]

Controlled-vocabulary lookup (no corpus needed):
  python -m defender.skills.invlang.cli <corpus_root> enum            # list slot names
  python -m defender.skills.invlang.cli <corpus_root> enum <slot>      # list values for a slot (e.g. types, relations, compute.role)
  python -m defender.skills.invlang.cli <corpus_root> enum [<slot>] --json

Primitives emit JSON; `advisory` emits rendered markdown by default with
a `--json` toggle for the harness. `hypothesis-vocabulary` and
`hypothesis-shape` emit markdown by default with a `--json` toggle.
`enum` emits plain newline-delimited values by default with a `--json`
toggle.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .advisory import VALID_CLASSES, advisory_recall
from .corpus import load_corpus
from .queries import (
    hypothesis_name_wildcard,
    hypothesis_shape_match,
    lead_branch_effects,
    lead_sequence_pattern,
)
from . import vocab

# Weight buckets best -> worst with the unassessed (None) bucket keyed "null",
# derived from the vocab ladder so the shape-lookup histogram order can't drift.
_WEIGHT_DISPLAY: tuple[str, ...] = tuple(
    b if b is not None else "null"
    for b in sorted(vocab.WEIGHT_ORDER, key=lambda w: vocab.WEIGHT_ORDER[w], reverse=True)
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="defender.skills.invlang.cli")
    p.add_argument("corpus_root", type=Path)
    p.add_argument("--quiet", action="store_true", help="Suppress LoadReport summary on stderr.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p5 = sub.add_parser("sequence", help="Class 5: lead sequence pattern")
    p5.add_argument("--contains")
    p5.add_argument("--disposition")
    p5.add_argument("--signature")

    p6 = sub.add_parser("hypotheses", help="Class 6: hypothesis name wildcard")
    p6.add_argument("pattern")
    p6.add_argument("--final-weight", choices=list(vocab.WEIGHT_BUCKETS))
    p6.add_argument("--disposition")
    p6.add_argument("--signature")

    p8 = sub.add_parser("branch-effects", help="Class 8: per-lead per-hypothesis effect")
    p8.add_argument("--hyp", action="append", default=[], help="Hypothesis fnmatch pattern (repeatable).")
    p8.add_argument("--min-support", type=int, default=1)
    p8.add_argument("--max-hypotheses-per-lead", type=int, default=5)

    pv = sub.add_parser(
        "hypothesis-vocabulary",
        help="Unique ?hypothesis names in the corpus for one signature, "
             "with counts + example case_ids. Use before authoring :H to "
             "align fresh hypothesis names with corpus vocabulary so that "
             "frontier-matched advisory recall returns precedent instead "
             "of a loud-empty banner.",
    )
    pv.add_argument("--signature", required=True)
    pv.add_argument("--top-k", type=int, default=20,
                    help="Cap on rows shown (default 20).")
    pv.add_argument("--json", dest="as_json", action="store_true",
                    help="Emit JSON instead of rendered markdown.")

    ps = sub.add_parser(
        "hypothesis-shape",
        help="Cross-case ?hypothesis-names used for a given discovery "
             "topology (parent_type, parent_class, rel, attached_to_type). "
             ":H is discovery-only: anchors are v-* ids. Class-refinement "
             "questions use `??` / `{...}` on the prologue entry and don't "
             "surface here. Cross-signature: same shape recurs across rules.",
    )
    ps.add_argument("--parent-type",
                    help="Exact match on :H parent_type (closed vocab).")
    ps.add_argument("--parent-class",
                    help="fnmatch pattern on :H parent_class "
                         "(e.g. 'bastion/*', '*/internal/*').")
    ps.add_argument("--rel",
                    help="Exact match on :H rel.")
    ps.add_argument("--attached-to-type",
                    help="Exact match on the type of the v-* vertex named "
                         "as the anchor on :H rows.")
    ps.add_argument("--json", dest="as_json", action="store_true",
                    help="Emit JSON instead of rendered markdown.")

    pe = sub.add_parser(
        "enum",
        help="List controlled-vocabulary slots, or values for a named "
             "slot. No corpus load. Use before authoring :V/:E/:H rows "
             "to pick from closed catalogs.",
    )
    pe.add_argument(
        "slot", nargs="?",
        help="Slot name (e.g. types, relations, compute.role). "
             "If omitted, lists available slot names.",
    )
    pe.add_argument("--json", dest="as_json", action="store_true",
                    help="Emit JSON instead of newline-delimited values.")

    pa = sub.add_parser("advisory", help="Composed PLAN-time advisory recall")
    pa.add_argument("--signature", required=True)
    pa.add_argument(
        "--frontier", action="append", default=[],
        help="Current ?hypothesis name (repeatable).",
    )
    pa.add_argument(
        "--class", dest="classes", action="append", default=[],
        choices=list(VALID_CLASSES),
        help="Subset of advisory classes (repeatable). Default: all.",
    )
    pa.add_argument("--top-k", type=int, default=3)
    pa.add_argument("--json", dest="as_json", action="store_true",
                    help="Emit JSON instead of rendered markdown.")

    return p


def _handle_enum_cmd(args) -> int:
    if args.slot is None:
        slots = vocab.list_slots()
        if args.as_json:
            json.dump({"slots": slots}, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            for s in slots:
                print(s)
        return 0
    try:
        values = vocab.get_enum(args.slot)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.as_json:
        json.dump({"slot": args.slot, "values": list(values)},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for v in values:
            print(v)
    return 0


def _handle_advisory_cmd(args) -> int:
    # The adapter does its own (cached) corpus load + telemetry; skip
    # the upfront load + summary print so its own banner isn't shadowed.
    result = advisory_recall(
        args.corpus_root,
        signature_id=args.signature,
        frontier=tuple(args.frontier),
        classes=tuple(args.classes) if args.classes else VALID_CLASSES,
        top_k=args.top_k,
    )
    sys.stdout.write(result.as_json() if args.as_json else result.as_markdown())
    sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "enum":
        return _handle_enum_cmd(args)
    if args.cmd == "advisory":
        return _handle_advisory_cmd(args)

    corpus, report = load_corpus(args.corpus_root)
    if not args.quiet:
        print(
            f"loaded {len(corpus)}/{report.scanned} cases "
            f"(skipped={len(report.skipped)} partial={len(report.partial)} "
            f"warnings={report.total_warnings})",
            file=sys.stderr,
        )

    if args.cmd == "sequence":
        out = lead_sequence_pattern(
            corpus,
            contains=args.contains,
            disposition=args.disposition,
            signature_id=args.signature,
        )
    elif args.cmd == "hypotheses":
        out = hypothesis_name_wildcard(
            corpus,
            args.pattern,
            final_weight=args.final_weight,
            disposition=args.disposition,
            signature_id=args.signature,
        )
    elif args.cmd == "branch-effects":
        out = lead_branch_effects(
            corpus,
            hypothesis_patterns=tuple(args.hyp),
            min_support=args.min_support,
            max_hypotheses_per_lead=args.max_hypotheses_per_lead,
        )
    elif args.cmd == "hypothesis-vocabulary":
        return _handle_hypothesis_vocabulary_cmd(args, corpus)
    elif args.cmd == "hypothesis-shape":
        return _handle_hypothesis_shape_cmd(args, corpus)
    else:
        raise AssertionError(args.cmd)

    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _handle_hypothesis_vocabulary_cmd(args, corpus) -> int:
    out = _hypothesis_vocabulary(corpus, args.signature, args.top_k)
    if args.as_json:
        json.dump(out, sys.stdout, indent=2)
    else:
        sys.stdout.write(_render_vocab(out, args.signature))
    sys.stdout.write("\n")
    return 0


def _handle_hypothesis_shape_cmd(args, corpus) -> int:
    if not (args.parent_type or args.parent_class or args.rel
            or args.attached_to_type):
        print(
            "error: hypothesis-shape requires at least one of "
            "--parent-type, --parent-class, --rel, --attached-to-type",
            file=sys.stderr,
        )
        return 2
    out = hypothesis_shape_match(
        corpus,
        parent_type=args.parent_type,
        parent_class=args.parent_class,
        rel=args.rel,
        attached_to_type=args.attached_to_type,
    )
    if args.as_json:
        json.dump(out, sys.stdout, indent=2)
    else:
        sys.stdout.write(_render_shape(out))
    sys.stdout.write("\n")
    return 0


def _hypothesis_vocabulary(corpus, signature_id: str, top_k: int) -> dict:
    """Aggregate unique ?hypothesis names for one signature.

    Returns {signature, n_cases, vocabulary: [{name, count, example_case_id}]}.
    Sorted by count desc, then alphabetical.
    """
    from collections import Counter

    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}
    n_cases = 0
    for c in corpus:
        if signature_id and c.signature_id != signature_id:
            continue
        n_cases += 1
        seen_in_case: set[str] = set()
        for h in c.hypotheses:
            name = (h.get("name") or "").strip()
            if not name or name in seen_in_case:
                continue
            seen_in_case.add(name)
            counts[name] += 1
            examples.setdefault(name, c.case_id)
        for lead in c.leads:
            for h in lead.get("new_hypotheses", []) or []:
                if not isinstance(h, dict):
                    continue
                name = (h.get("name") or "").strip()
                if not name or name in seen_in_case:
                    continue
                seen_in_case.add(name)
                counts[name] += 1
                examples.setdefault(name, c.case_id)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
    return {
        "signature": signature_id,
        "n_cases": n_cases,
        "vocabulary": [
            {"name": n, "count": c, "example_case_id": examples[n]}
            for n, c in ranked
        ],
    }


def _render_vocab(out: dict, signature: str) -> str:
    rows = out["vocabulary"]
    header = (
        f"## HYPOTHESIS VOCABULARY — signature {signature}\n"
        f"Corpus: {out['n_cases']} cases for this signature\n"
    )
    if not rows:
        return header + "\n_no hypotheses in corpus for this signature_\n"
    body = ["", "| ?name | count | example case |", "|---|---:|---|"]
    for r in rows:
        body.append(f"| `{r['name']}` | {r['count']} | `{r['example_case_id']}` |")
    body.append("")
    body.append(
        "Use these names verbatim where the semantics match. Frontier-matched "
        "advisory recall returns precedent only when the `--frontier '?name'` "
        "values match corpus vocabulary."
    )
    return header + "\n".join(body) + "\n"


def _render_shape(out: dict) -> str:
    shape = out["shape"]
    shape_parts = [f"{k}={v!r}" for k, v in shape.items() if v]
    header = (
        "## HYPOTHESIS SHAPE LOOKUP\n"
        f"Shape: {', '.join(shape_parts) if shape_parts else '(none)'}\n"
        f"Hits: {out['count']} distinct ?name(s)\n"
    )
    if not out["hits"]:
        return header + "\n_no past hypotheses match this shape_\n"
    body = [
        "",
        f"| ?name | n | weights ({'/'.join(_WEIGHT_DISPLAY)}) | dispositions | example case(s) |",
        "|---|---:|---|---|---|",
    ]
    for h in out["hits"]:
        w = h["final_weight_distribution"]
        wstr = "/".join(str(w.get(b, 0)) for b in _WEIGHT_DISPLAY)
        dstr = ", ".join(f"{k}:{v}" for k, v in h["dispositions"].items())
        cases = h["cases"][:3]
        if len(h["cases"]) > 3:
            cases = cases + [f"+{len(h['cases']) - 3} more"]
        cstr = ", ".join(f"`{c}`" if not c.startswith("+") else c
                          for c in cases)
        body.append(f"| `{h['name']}` | {h['n']} | {wstr} | {dstr} | {cstr} |")
    body.append("")
    body.append(
        "Use these names verbatim when the semantics match. Names with "
        "broad disposition spread (benign+malicious) carry no inherent "
        "verdict — they're shape labels, not conclusions."
    )
    return header + "\n".join(body) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
