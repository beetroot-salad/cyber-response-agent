#!/usr/bin/env python3
"""Score an oracle projection against the telemetry it was projecting (#711 §4).

`y'` vs `y`: the oracle emits telemetry, so this grades telemetry against telemetry
rather than projecting both sides down to a four-way class. Two things run first, in
code, and never reach the model:

1. **Lead-set integrity.** A projection missing leads, carrying leads the case does not
   have, or repeating a `lead_id` is not a result. It is reported and nothing is scored
   — the judge is not paid to grade a truncated document.
2. **Grammar.** The oracle's output grammar is closed (`oracle/prompt.md` §"Output"):
   event mappings, or exactly one of the two marker strings, never mixed. `case-005
   l-002` emitted a prose paragraph whose *content* was correct; that scores as a
   failure, deterministically, because a judge would be tempted to be generous about it.
3. **Leak check.** For mutation cases, the pre-mutation entities must appear nowhere in
   the projection. Deterministic, whole-value-or-token containment.

Everything downstream is the judge's, in two passes (`judge.py`):

* the **label** pass reads the telemetry alone — never the story, never the projection —
  and returns the `delta_kind` this envelope actually carried;
* the **verdict** pass grades the projection against that measurement.

A lead the label pass calls `undecidable` never reaches the verdict pass: there is
nothing to grade against. It is recorded with `faithful: null`, excluded from every
denominator, and counted in the abstention tally.

**The label pass is a function of (case, lead) and nothing else** — it is the one part
of this that does not depend on which projection is being scored. Its output is cached
per case under `labels/<judge-suffix>.json`, so two oracle tags are graded against the
same measurement instead of two independent readings of the same telemetry, and a
re-score costs the verdict pass only. Editing either prompt changes the suffix and
invalidates the cache by construction.

**Derived cases (`mutation`, `negative-control`) never reach the judge.** They reuse
their base's envelopes and change only the story, so no telemetry was ever captured for
the story they tell — there is no `y`. They are scored by the mechanical checks alone
and contribute no judged rows; `report.py` reports their mechanical results separately
rather than folding a definitional truth into a measured rate.

Because the judge runs here, THIS IS NOT DETERMINISTIC, and the judge is part of the
tag: `<oracle-tag>__judge-<model>-<effort>_<prompts-sha8>`.

Usage: score.py <case_dir> <projections/<tag>.yaml> [--json <out>] [--jobs N] [--relabel]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.evals.oracle_golden import judge  # noqa: E402

# The closed marker vocabulary. Anything else is malformed model output and must not be
# folded into a real answer — a degraded model emitting prose would otherwise be graded
# on its prose.
_SUPPRESSED_PREFIX = "<suppressed"
_NOISE_MARKER = "<standard environment noise>"

#: Kinds whose story was never fired, so nothing was ever measured for it. They are
#: graded against `expectation:` in the manifest instead — see `expectation_failures`.
DERIVED_KINDS = ("mutation", "negative-control", "spec-probe", "contradiction")

#: Causes decided in code, never by the judge. They are disjoint from `judge.CAUSES` on
#: purpose: a mechanical failure is a property of the document, needs no measurement to
#: establish, and must not be confused with a graded one when the report tallies causes.
C_MALFORMED = "C-MALFORMED"
C_NOT_PROJECTED = "C-NOT-PROJECTED"
MECHANICAL_CAUSES = frozenset({C_MALFORMED, C_NOT_PROJECTED})

#: Punctuation trimmed off a token before a leak comparison — `<`/`>` included, so the
#: closing bracket of a marker ("…on office-ws-1>") does not hide a real leak. A whole
#: `<placeholder>` is exempt (see `_tokens`): trimming those would turn the placeholder
#: vocabulary into bare words and let `<port>` collide with `port`.
_TOKEN_TRIM = "\"'`,;:()[]{}<>"

_PLACEHOLDER = re.compile(r"<[^<>]+>")


def _norm(value: object) -> str:
    """One coercion for both sides of a value comparison (YAML ints/bools vs strings)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# ------------------------------------------------------------------ mechanical checks

def _marker_kind(marker: str) -> str | None:
    text = marker.strip()
    if text.startswith(_SUPPRESSED_PREFIX):
        return "suppressed-marker"
    if text == _NOISE_MARKER:
        return "noise-marker"
    return None


def grammar_problem(events: object) -> str | None:
    """`None` when a lead's events parse as the oracle's closed grammar, else why not.

    Repeated markers of the SAME kind still read as that kind — unambiguous in meaning,
    even though `prompt.md` asks for a single marker item.
    """
    if not isinstance(events, list):
        return f"events is {type(events).__name__}, not a list"
    if not events:
        return None                                    # an empty list is "nothing here"
    if all(isinstance(e, dict) for e in events):
        return None
    if not all(isinstance(e, str) for e in events):
        type_names = sorted({type(e).__name__ for e in events})
        return f"a marker mixed with {'/'.join(type_names)} — prompt.md forbids mixing"
    kinds = {_marker_kind(m) for m in events}
    if None in kinds:
        unknown = [m for m in events if _marker_kind(m) is None]
        return f"not in the marker vocabulary: {unknown[0]!r}"
    if len(kinds) > 1:
        return f"two different markers in one list: {sorted(set(events))}"
    return None


def emitted_values(events: Iterable) -> list[str]:
    """Every value a projection emits — mapping values and marker strings.

    Keys are excluded on purpose: they are schema field names (`user.name`), never the
    mutated entities a mutation case forbids, so scanning them only invents false leaks.
    """
    out: list[str] = []
    for e in events:
        if isinstance(e, dict):
            out.extend(_norm(v) for v in e.values())
        elif isinstance(e, str):
            out.append(e)
    return out


def _tokens(value: str) -> set[str]:
    """Whitespace-delimited, punctuation-trimmed tokens of an emitted value.

    A whole `<placeholder>` survives intact — it names a value the story did not state,
    and reducing it to a bare word would let it collide with a real one.
    """
    out = set()
    for token in value.split():
        out.add(token if token.startswith("<") and token.endswith(">")
                else token.strip(_TOKEN_TRIM))
    return out


def leaks(forbidden: list, preds: dict[str, list]) -> list[str]:
    """Forbidden pre-mutation values a projection actually emitted.

    Matches a forbidden value against a whole emitted value or one of its
    whitespace-delimited, punctuation-trimmed tokens — never as a bare substring.
    Substring matching cannot tell `user.name: root` (a real leak) from
    `file.path: /root/.ssh/authorized_keys` (an unrelated path that merely contains the
    token), and case-002 in this very suite emits the latter.
    """
    return [f for f in forbidden if _norm(f) in _emitted_index(preds)]


def _emitted_index(preds: dict[str, list]) -> set[str]:
    """Every emitted value plus its tokens — the surface `must_not_emit` and `must_emit`
    both match against, so the forbidden and required directions cannot drift apart."""
    seen: set[str] = set()
    for events in preds.values():
        for value in emitted_values(events):
            seen.add(value)
            seen |= _tokens(value)
    seen.discard("")
    return seen


def has_concrete_value(events: Iterable) -> bool:
    """Did the projection commit to any fully concrete value?

    `prompt.md` mandates `<angle-placeholder>` for anything the story does not state, so
    a wholly-placeholdered event is an abstention, not a claim. Reported for the derived
    cases, where it is the only thing distinguishing "declined to invent" from "invented".
    """
    return any(not _PLACEHOLDER.search(v) for v in emitted_values(events))


# ---------------------------------------------------------- definitional expectations

def _requested(spec: str | list[str] | None, lead_ids: list[str]) -> list[str]:
    """`all`, or an explicit lead list, resolved against the case's own lead ids.

    Resolving against the case's own ids is what stops a clause that names a lead the
    case does not have from passing silently — it asserts nothing, and a contract that
    quietly asserts nothing is the failure this whole mechanism exists to prevent.
    """
    if spec == "all":
        return list(lead_ids)
    return [lead_id for lead_id in (spec or []) if lead_id in lead_ids]


def expectation_failures(expectation: dict, preds: dict[str, list],
                         lead_ids: list[str]) -> list[str]:
    """Rules the story settles by itself, and the projection broke anyway.

    A derived case has no telemetry, so the judge cannot grade it — and until this
    existed, NOTHING did. A forged `neg-001` projection copying the brute-force burst
    into all nine leads (exactly the window-copying the negative control exists to
    catch) scored clean and exited 0: its ground truth sat inert in `expected.yaml`
    after the redesign moved the contract to "the judge's measurement of the telemetry".
    A case with no telemetry has no such measurement, so derived cases fell through.

    These need no `y`. `oracle/prompt.md` is a specification and much of it is decidable
    from the story alone — an unrelated story touches nothing, suppression is earned by
    an explicit blinding action, a value the story never states must stay a placeholder.
    Each failure names the rule, so it reads as a spec violation and not as a diff.
    """
    out: list[str] = []
    for lead_id in _requested(expectation.get("empty_leads"), lead_ids):
        if emitted := preds.get(lead_id):
            # A marker is a different error from a fabricated event: `+ noise` asserts the
            # activity IS here and merely looks routine, which is a claim of presence, not
            # a quantity. Name it, or the failure reads as "emitted 1 item" and hides that.
            markers = [e for e in emitted if isinstance(e, str)]
            what = (f"the {_marker_kind(markers[0])} {markers[0]!r}" if markers
                    else f"{len(emitted)} fabricated event(s)")
            out.append(f"{lead_id}: must be empty — the story's activity never touches "
                       f"this envelope, but it emitted {what}")
    for lead_id in _requested(expectation.get("no_suppression"), lead_ids):
        if any(isinstance(e, str) and _marker_kind(e) == "suppressed-marker"
               for e in preds.get(lead_id) or []):
            out.append(f"{lead_id}: must not claim suppression — the story performs no "
                       f"action that blinds this stream")
    for lead_id in _requested(expectation.get("no_noise_marker"), lead_ids):
        if any(isinstance(e, str) and _marker_kind(e) == "noise-marker"
               for e in preds.get(lead_id) or []):
            out.append(f"{lead_id}: must not claim indistinguishability — this envelope "
                       f"carries a delta the queries surface")
    emitted_index = _emitted_index(preds)
    for value in expectation.get("must_emit") or []:
        if _norm(value) not in emitted_index:
            out.append(f"must_emit: {_norm(value)!r} is the story's own value and "
                       f"appears nowhere in the projection")
    return out


# ------------------------------------------------------------------------ lead framing

def system_of(lead: dict) -> str:
    """The stratification axis, derived from the lead's own `query_id` prefixes.

    `query_id` is `{system}.{kebab-name}` (defender/CLAUDE.md), so this is a property of
    the envelope rather than an attribution someone made. A lead spanning systems keeps
    both, `+`-joined: it really is a mixed lead, and flattening it to the majority system
    would file a cross-system result under a single-system slice. Checked against the 47
    hand-assigned systems in the seed `expected.yaml` files — 46 agree, and the one that
    does not (case-005 l-005) is a cmdb+elastic lead the hand label had flattened.
    """
    systems = sorted(judge.lead_systems(lead) - {""})
    return "+".join(systems) if systems else "?"


def load_predictions(proj: dict) -> tuple[dict[str, list], list[str]]:
    """Projection rows as {lead_id: events}, plus any lead_id repeated in the doc."""
    preds: dict[str, list] = {}
    duplicates: list[str] = []
    for row in proj.get("projections") or []:
        lead_id = row["lead_id"]
        if lead_id in preds:
            duplicates.append(lead_id)
        preds[lead_id] = row["events"]
    return preds, duplicates


def integrity(lead_ids: list[str], preds: dict[str, list],
              duplicates: list[str]) -> dict[str, list[str]]:
    return {
        "missing_leads": [x for x in lead_ids if x not in preds],
        "unscored_leads": [x for x in preds if x not in lead_ids],
        "duplicate_leads": duplicates,
    }


# ----------------------------------------------------------------------- the label pass

def labels_path(case_dir: Path, model: str, effort: str) -> Path:
    return case_dir / "labels" / f"{judge.tag_suffix(model, effort)}.json"


def measure_case(case_dir: Path, lead_ids: list[str], *, model: str, effort: str,
                 jobs: int = 4, relabel: bool = False,
                 call: judge.CallFn = judge.call_model) -> dict:
    """The label pass over a case's leads, read from or written to the label cache.

    Projection-independent by construction — see the module docstring. A cached entry is
    reused verbatim; only leads absent from the cache are measured, so adding a lead to a
    case does not re-measure the rest of it.
    """
    path = labels_path(case_dir, model, effort)
    cached: dict = {}
    if path.is_file() and not relabel:
        doc = json.loads(path.read_text(encoding="utf-8"))
        cached = doc.get("leads") or {}

    todo = [x for x in lead_ids if x not in cached]
    if todo:
        with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(todo)))) as pool:
            fresh = list(pool.map(
                lambda lead_id: judge.label_lead(
                    judge.load_lead_inputs(case_dir, lead_id),
                    model=model, effort=effort, call=call),
                todo))
        cached.update(dict(zip(todo, fresh, strict=True)))
        # Read the judge back from the calls rather than echoing the request: a run that
        # silently fell back must not be filed under the tag we asked for.
        resolved = {x["judge_model"] for x in fresh}
        if len(resolved) != 1:
            raise RuntimeError(f"the label pass ran on more than one judge: {sorted(resolved)}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "judge": {"model": resolved.pop(), "effort": effort,
                      "prompts_sha8": judge.prompts_sha8()},
            "leads": {k: cached[k] for k in sorted(cached)},
        }, indent=2) + "\n", encoding="utf-8")
    return cached


# --------------------------------------------------------------------------- the score

def _mechanical_row(lead_id: str, system: str, label: dict, cause: str, note: str) -> dict:
    """A row failed in code. It carries the measurement's `delta_kind` anyway, so the
    lead still lands in its own slice — a malformed projection is not evidence about the
    envelope, and hiding it from the slice would flatter the slices it belongs to.

    A mechanical failure wins over an `undecidable` measurement: it is established by the
    document alone and needs no telemetry to settle.
    """
    return {
        "lead": lead_id, "system": system,
        "delta_kind": label.get("delta_kind", "undecidable"),
        "faithful": False, "cause": cause,
        "heterogeneous": label.get("heterogeneous"),
        "undecidable_reason": None, "form_notes": note,
        "rationale": "mechanical pre-check; the judge was not called",
        "evidence": label.get("evidence"),
    }


def score_case(case_dir: Path, proj_path: Path, *, model: str, effort: str, jobs: int = 4,
               relabel: bool = False, call: judge.CallFn = judge.call_model) -> dict:
    """The whole measurement, as the dict written to `scores/<tag>.json`."""
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    proj = yaml.safe_load(proj_path.read_text(encoding="utf-8")) or {}
    leads = {row["lead_id"]: row for row in judge.load_case_leads(case_dir)}
    preds, duplicates = load_predictions(proj)

    summary: dict = {
        "tag": score_tag(proj_path.stem, model, effort),
        "projection": proj_path.name,
        "case": case_dir.name,
        "kind": manifest.get("kind"),
        "judge": {"model": model, "effort": effort, "prompts_sha8": judge.prompts_sha8()},
        "n_leads": len(leads),
    }
    summary["mechanical"] = {
        **integrity(list(leads), preds, duplicates),
        "malformed_leads": {}, "forbidden_emitted": [], "concrete_value_leads": [],
        "expectation_failures": [],
    }

    forbidden = _forbidden_values(case_dir, manifest)
    summary["mechanical"]["forbidden_emitted"] = leaks(forbidden, preds)
    summary["mechanical"]["expectation_failures"] = expectation_failures(
        manifest.get("expectation") or {}, preds, list(leads))
    summary["mechanical"]["malformed_leads"] = {
        lead_id: problem
        for lead_id, events in preds.items()
        if (problem := grammar_problem(events)) is not None
    }
    summary["mechanical"]["concrete_value_leads"] = sorted(
        lead_id for lead_id, events in preds.items()
        if isinstance(events, list) and has_concrete_value(events))

    # A lead set that does not match is not a result. Report it and stop before paying
    # for a single judge call — grading a truncated document produces a number that
    # looks like a score and is not one.
    if any(summary["mechanical"][k] for k in
           ("missing_leads", "unscored_leads", "duplicate_leads")):
        summary.update({"judged": False, "rows": [],
                        "why_unjudged": "the projection's lead set does not match the case's"})
        return summary

    if manifest.get("defective"):
        # A case whose leads cannot contain the activity they were gathered for. Scoring
        # it would report a projection as correctly-quiet and file that under a unit
        # nothing was ever measured for — which reads as coverage.
        summary.update({
            "judged": False, "rows": [],
            "why_unjudged": f"the case is marked defective: {manifest['defective']}",
        })
        return summary

    if manifest.get("kind") in DERIVED_KINDS:
        summary.update({
            "judged": False, "rows": [],
            "why_unjudged": (
                f"a {manifest.get('kind')} case reuses its base's envelopes and changes only "
                f"the story, so the story it tells was never fired and no telemetry was ever "
                f"captured for it. There is nothing to grade a projection against; it is "
                f"scored by the mechanical checks alone."),
        })
        return summary

    lead_ids = sorted(leads)
    measured = measure_case(case_dir, lead_ids, model=model, effort=effort, jobs=jobs,
                            relabel=relabel, call=call)

    to_judge = [
        lead_id for lead_id in lead_ids
        if measured[lead_id]["delta_kind"] != "undecidable"
        and lead_id not in summary["mechanical"]["malformed_leads"]
    ]
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(to_judge) or 1))) as pool:
        verdicts = dict(zip(to_judge, pool.map(
            lambda lead_id: judge.verdict_lead(
                judge.load_lead_inputs(case_dir, lead_id), preds[lead_id],
                _measurement(measured[lead_id]),
                model=model, effort=effort, call=call),
            to_judge), strict=True))

    rows = []
    for lead_id in lead_ids:
        system = system_of(leads[lead_id])
        label = measured[lead_id]
        problem = summary["mechanical"]["malformed_leads"].get(lead_id)
        if problem is not None:
            rows.append(_mechanical_row(lead_id, system, label, C_MALFORMED, problem))
            continue
        if lead_id not in verdicts:          # the measurement could not settle the lead
            rows.append({
                "lead": lead_id, "system": system, "delta_kind": "undecidable",
                "faithful": None, "cause": None,
                "heterogeneous": label.get("heterogeneous"),
                "undecidable_reason": label.get("undecidable_reason"),
                "form_notes": None,
                "rationale": "the label pass could not measure this envelope; not graded",
                "evidence": label.get("evidence"),
            })
            continue
        verdict = verdicts[lead_id]
        rows.append({
            "lead": lead_id, "system": system,
            "delta_kind": label["delta_kind"],
            "faithful": verdict["faithful"], "cause": verdict["cause"],
            "heterogeneous": label.get("heterogeneous"),
            "undecidable_reason": verdict["undecidable_reason"],
            "form_notes": verdict["form_notes"],
            "rationale": verdict["rationale"],
            "evidence": label.get("evidence"),
        })

    decided = [r for r in rows if r["faithful"] is not None]
    faithful = sum(1 for r in decided if r["faithful"] is True)
    costs = [x.get("cost_usd") for x in list(measured.values()) + list(verdicts.values())
             if x.get("cost_usd") is not None]
    summary.update({
        "judged": True,
        "faithful": f"{faithful}/{len(decided)}",
        "abstentions": len(rows) - len(decided),
        "by_system": _by_system(rows),
        "cost_usd": round(sum(costs), 4) if costs else None,
        "rows": rows,
    })
    return summary


def _measurement(label: dict) -> dict:
    """The label pass's reading, as the verdict pass is shown it. Provenance and cost are
    ours, not the judge's business, and feeding them back would put the label pass's
    price tag inside the grading prompt."""
    return {k: label[k] for k in ("delta_kind", "heterogeneous", "evidence") if k in label}


def _forbidden_values(case_dir: Path, manifest: dict) -> list:
    """`must_not_emit` for a mutation case: the pre-mutation entities.

    Read from `expected.yaml` where the seed cases keep it, falling back to the manifest —
    `expected.yaml` is the label pass's calibration set now, and a case recruited without
    hand labels declares its mutation in its manifest instead.
    """
    expectation = manifest.get("expectation") or {}
    if expectation.get("must_not_emit"):
        return list(expectation["must_not_emit"])
    calibration = case_dir / "expected.yaml"
    if calibration.is_file():
        doc = yaml.safe_load(calibration.read_text(encoding="utf-8")) or {}
        if doc.get("must_not_emit"):
            return list(doc["must_not_emit"])
    return list(manifest.get("must_not_emit") or [])


def _by_system(rows: list[dict]) -> dict[str, str]:
    out: dict[str, list[int]] = {}
    for r in rows:
        if r["faithful"] is None:
            continue
        bucket = out.setdefault(r["system"], [0, 0])
        bucket[0] += r["faithful"] is True
        bucket[1] += 1
    return {s: f"{k}/{n}" for s, (k, n) in sorted(out.items())}


def score_tag(projection_stem: str, model: str, effort: str) -> str:
    """`<oracle-model>_<oracle-prompt>__judge-<model>-<effort>_<prompts-sha8>` (#711 §6).

    The judge runs at score time, so it is part of the tag: editing either prompt is a
    new tag requiring a full re-score, exactly like an oracle change.
    """
    return f"{projection_stem}__{judge.tag_suffix(model, effort)}"


# ---------------------------------------------------------------------------- reporting

def print_report(summary: dict) -> None:
    mech = summary["mechanical"]
    j = summary["judge"]
    print(f"== score: {summary['projection']} vs {summary['case']} ==")
    print(f"judge: {j['model']} effort={j['effort']} prompts={j['prompts_sha8']}")
    for label, key in (("MISSING from projection", "missing_leads"),
                       ("projected but NOT IN THE CASE", "unscored_leads"),
                       ("DUPLICATED in projection", "duplicate_leads")):
        if mech[key]:
            print(f"!! lead-set integrity — {label}: {mech[key]}")
    if mech["malformed_leads"]:
        for lead_id, problem in sorted(mech["malformed_leads"].items()):
            print(f"!! malformed grammar — {lead_id}: {problem}")
    if mech["forbidden_emitted"]:
        print(f"!! mutation — LEAKED pre-mutation values: {mech['forbidden_emitted']}")
    for failure in mech.get("expectation_failures") or []:
        print(f"!! expectation — {failure}")

    if not summary["judged"]:
        print(f"\nnot judged: {summary['why_unjudged']}")
        return

    print(f"\nfaithful: {summary['faithful']} of the DECIDED leads   "
          f"abstentions: {summary['abstentions']}/{summary['n_leads']}   "
          f"cost: ${summary['cost_usd']}")
    print(f"by system: {summary['by_system']}\n")
    for r in summary["rows"]:
        mark = "?? " if r["faithful"] is None else ("ok " if r["faithful"] else "!! ")
        tail = f"  {r['cause']}" if r["cause"] else (
            f"  ({r['undecidable_reason']})" if r["undecidable_reason"] else "")
        het = " het" if r["heterogeneous"] else ""
        print(f"  {mark}{r['lead']:<6} {r['system']:<16} {r['delta_kind']:<18}{het}{tail}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path, help="golden case directory")
    p.add_argument("projection", type=Path, help="projections/<tag>.yaml to score")
    p.add_argument("--json", type=Path, default=None, dest="json_out",
                   help="write the score here (default: <case_dir>/scores/<tag>.json)")
    p.add_argument("--jobs", type=int, default=4, help="concurrent judge calls")
    p.add_argument("--relabel", action="store_true",
                   help="re-run the label pass instead of reading labels/<judge-suffix>.json")
    p.add_argument("--dry-run", action="store_true",
                   help="run the mechanical checks only; call no model and write nothing")
    ns = p.parse_args(argv)

    model, effort = judge.judge_model(), judge.judge_effort()
    if ns.dry_run:
        summary = _dry_run(ns.case_dir, ns.projection, model=model, effort=effort)
    else:
        summary = score_case(ns.case_dir, ns.projection, model=model, effort=effort,
                             jobs=ns.jobs, relabel=ns.relabel, call=judge.call_model)
    print_report(summary)

    # `expectation_failures` and `forbidden_emitted` join the lead-set checks rather than
    # merely reporting. A derived case IS its contract, so a violated one is a failed
    # score and not a note — and `forbidden_emitted` was the same hole one layer down: a
    # mutation case that leaked a pre-mutation entity printed the leak and still exited 0,
    # so a script driving the suite read it as a pass. No committed score leaks, so this
    # changes no existing result.
    broken = any(summary["mechanical"][k] for k in
                 ("missing_leads", "unscored_leads", "duplicate_leads",
                  "expectation_failures", "forbidden_emitted"))
    if not ns.dry_run:
        out = ns.json_out if ns.json_out is not None else (
            ns.case_dir / "scores" / f"{summary['tag']}.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {out}")
    # Non-zero on a lead-set mismatch: a partial projection is not a result, and a caller
    # scripting the suite must not read it as one.
    return 1 if broken else 0


def _dry_run(case_dir: Path, proj_path: Path, *, model: str, effort: str) -> dict:
    """The mechanical half, with no model in the loop — what `--dry-run` reports."""
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    proj = yaml.safe_load(proj_path.read_text(encoding="utf-8")) or {}
    leads = {row["lead_id"]: row for row in judge.load_case_leads(case_dir)}
    preds, duplicates = load_predictions(proj)
    return {
        "tag": score_tag(proj_path.stem, model, effort),
        "projection": proj_path.name, "case": case_dir.name, "kind": manifest.get("kind"),
        "judge": {"model": model, "effort": effort, "prompts_sha8": judge.prompts_sha8()},
        "n_leads": len(leads),
        "mechanical": {
            **integrity(list(leads), preds, duplicates),
            "malformed_leads": {lead_id: problem for lead_id, events in preds.items()
                                if (problem := grammar_problem(events)) is not None},
            "forbidden_emitted": leaks(_forbidden_values(case_dir, manifest), preds),
            "expectation_failures": expectation_failures(
                manifest.get("expectation") or {}, preds, list(leads)),
            "concrete_value_leads": sorted(lead_id for lead_id, events in preds.items()
                                           if isinstance(events, list)
                                           and has_concrete_value(events)),
        },
        "judged": False, "rows": [], "why_unjudged": "--dry-run: no model was called",
    }


if __name__ == "__main__":
    sys.exit(main())
