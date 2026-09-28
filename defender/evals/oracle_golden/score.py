#!/usr/bin/env python3
"""Score an oracle projection against the telemetry it was projecting.

`y'` vs `y`: the oracle emits telemetry, so this grades telemetry against telemetry rather
than projecting both sides down to a four-way class. Three checks run first, in code, and
never reach the model:

1. **Lead-set integrity.** A projection missing leads, carrying leads the case does not
   have, or repeating a `lead_id` is not a result: it is reported and nothing is scored.
2. **Grammar.** The oracle's output grammar is closed (`oracle/prompt.md` §"Output"):
   event mappings, or exactly one of the two marker strings, never mixed. Prose output
   fails deterministically, even when its content is right.
3. **Leak check.** For mutation cases, the pre-mutation entities must appear nowhere in
   the projection (whole-value or token containment).

The containment checks compare text, but `yaml.safe_load` types unquoted scalars (an
unquoted timestamp becomes a `datetime` with a different `str()`). So the projection is
parsed once via `defender._yaml.safe_load_typed_and_spelled` into two same-shaped
readings: `typed` for structure (integrity, grammar, expectation clauses, what the judge
sees) and `spelled` (every value scalar as written) for text questions (`must_not_emit`,
`must_emit`, the concrete-value check). The author's side is text by rule: each
`must_emit` / `must_not_emit` entry must be a quoted string, or the clause is refused.

Everything downstream is the judge's, in two passes (`judge.py`):

* the **label** pass reads the telemetry alone and returns the `delta_kind` this envelope
  actually carried;
* the **verdict** pass grades the projection against that measurement.

A lead labelled `undecidable` is not graded: it is recorded with `faithful: null`,
excluded from every denominator, and counted as an abstention.

The label pass depends only on (case, lead), so it is cached per case under
`labels/<judge-suffix>.json`: two oracle tags are graded against the same measurement, and
a re-score pays for the verdict pass only. Editing either prompt changes the suffix.

**Derived cases** (`mutation`, `negative-control`, ...) never reach the judge. They reuse
their base's envelopes with a changed story, so there is no `y`; they are scored by the
mechanical checks alone, chiefly the manifest's `expectation:` clauses.

The judge makes this non-deterministic, so it is part of the tag:
`<oracle-tag>__judge-<model>-<effort>_<prompts-sha8>`.

Usage: score.py <case_dir> <projections/<tag>.yaml> [--json <out>] [--jobs N] [--relabel]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Set
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender._model import model  # noqa: E402
from defender._yaml import safe_load, safe_load_typed_and_spelled  # noqa: E402
from defender.evals.oracle_golden import judge  # noqa: E402

# The closed marker vocabulary; anything else is malformed output, not an answer.
_SUPPRESSED_PREFIX = "<suppressed"
_NOISE_MARKER = "<standard environment noise>"

#: Kinds whose story was never fired, so nothing was measured for it; they are graded against
#: the manifest's `expectation:` instead. `validate_cases` reads this too (a missing `hidden/`
#: is expected for these kinds).
DERIVED_KINDS = ("mutation", "negative-control", "spec-probe", "contradiction",
                 "corrupted")


def is_derived(kind: object) -> bool:
    """Was this case's story never fired, so nothing was ever measured for it?

    Lives beside the vocabulary so callers ask this rather than re-deriving membership.
    """
    return kind in DERIVED_KINDS


#: Causes decided in code, never by the judge. Disjoint from `judge.CAUSES` so the report
#: never tallies a document-level failure as a graded one.
C_MALFORMED = "C-MALFORMED"
C_NOT_PROJECTED = "C-NOT-PROJECTED"
MECHANICAL_CAUSES = frozenset({C_MALFORMED, C_NOT_PROJECTED})

#: Punctuation trimmed off a token before a leak comparison. `<`/`>` are included so a marker's
#: closing bracket ("…on office-ws-1>") does not hide a leak; a whole `<placeholder>` is exempt
#: (see `_tokens`) so `<port>` cannot collide with `port`.
_TOKEN_TRIM = "\"'`,;:()[]{}<>"

_PLACEHOLDER = re.compile(r"<[^<>]+>")


# mechanical checks

def _marker_kind(marker: str) -> str | None:
    text = marker.strip()
    if text.startswith(_SUPPRESSED_PREFIX):
        return "suppressed-marker"
    if text == _NOISE_MARKER:
        return "noise-marker"
    return None


def grammar_problem(events: object) -> str | None:
    """`None` when a lead's events parse as the oracle's closed grammar, else why not.

    Repeated markers of the same kind are accepted: unambiguous, though `prompt.md` asks
    for one.
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


def emitted_values(events: object) -> list[str]:
    """Every value a projection emits under one lead's `events`: mapping values, marker
    strings, and scalars inside nested collections. Order is not preserved.

    Keys are excluded: they are schema field names, never mutated entities, so scanning
    them only invents false leaks. Callers pass the spelled reading; `str()` covers the
    scalars it leaves typed (`!!omap`/`!!pairs`/`!!set` members) and in-memory test input.
    `seen` is identity-keyed because a self-referencing anchor (`&e [{self: *e}]`) loads
    as a cyclic object.
    """
    out: list[str] = []
    stack: list[object] = [events]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if isinstance(current, (dict, list)):
            if id(current) in seen:
                continue
            seen.add(id(current))
            stack.extend(current.values() if isinstance(current, dict) else current)
        elif current is not None:
            out.append(str(current))
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


def leaks(forbidden: list[str], emitted: Set[str]) -> list[str]:
    """Forbidden pre-mutation values a projection emitted (`emitted` is its `emitted_index`).

    Matches whole values or tokens, never bare substrings: a substring match cannot tell
    `user.name: root` (a leak) from `file.path: /root/.ssh/authorized_keys` (not one).
    """
    return [f for f in forbidden if f in emitted]


def emitted_index(preds: Mapping[str, object]) -> frozenset[str]:
    """Every value the projection emits, across every lead, plus its tokens. Shared by
    `must_not_emit` and `must_emit` so the two directions match against the same surface."""
    seen: set[str] = set()
    for events in preds.values():
        for value in emitted_values(events):
            seen.add(value)
            seen |= _tokens(value)
    seen.discard("")
    return frozenset(seen)


def has_concrete_value(events: object) -> bool:
    """Did the projection commit to any fully concrete value?

    `prompt.md` mandates `<angle-placeholder>` for anything the story does not state, so a
    wholly-placeholdered event is an abstention. For derived cases this is what separates
    "declined to invent" from "invented". Pass the spelled reading.
    """
    return any(not _PLACEHOLDER.search(v) for v in emitted_values(events))


# definitional expectations

def _requested(spec: str | list[str] | None, lead_ids: list[str]) -> list[str]:
    """`all`, or an explicit lead list, resolved against the case's own lead ids."""
    if spec == "all":
        return list(lead_ids)
    return [lead_id for lead_id in (spec or []) if lead_id in lead_ids]


def expectation_failures(expectation: dict, preds: dict[str, list], lead_ids: list[str],
                         emitted: Set[str]) -> list[str]:
    """Rules the story settles by itself, and the projection broke anyway.

    `preds` is the projection, for the per-lead clauses; `emitted` is its `emitted_index`,
    for `must_emit`. These are the only grading a derived case gets (it has no telemetry),
    and each is decidable from the story alone. Each failure names the rule it breaks.
    """
    out: list[str] = []
    for lead_id in _requested(expectation.get("empty_leads"), lead_ids):
        if events := preds.get(lead_id):
            # Name a marker explicitly: `+ noise` claims the activity is present, which is a
            # different error from fabricating events.
            markers = [e for e in events if isinstance(e, str)]
            what = (f"the {_marker_kind(markers[0])} {markers[0]!r}" if markers
                    else f"{len(events)} fabricated event(s)")
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
    for value in required_values(expectation):
        if value not in emitted:
            out.append(f"must_emit: {value!r} is the story's own value and "
                       f"appears nowhere in the projection")
    return out


# lead framing

def system_of(lead: dict) -> str:
    """The stratification axis, from the lead's `query_id` prefixes (`{system}.{name}`).

    A lead spanning systems keeps all of them, `+`-joined, rather than being filed under one.
    """
    systems = sorted(judge.lead_systems(lead) - {""})
    return "+".join(systems) if systems else "?"


def load_predictions(proj: object) -> tuple[dict[str, list], list[str]]:
    """Projection rows as {lead_id: events}, plus any lead_id repeated in the doc.

    A non-mapping document has no rows, so every lead reports as missing rather than crashing."""
    preds: dict[str, list] = {}
    duplicates: list[str] = []
    rows = proj.get("projections") if isinstance(proj, dict) else None
    for row in rows or []:
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


# the label pass

def labels_path(case_dir: Path, model: str, effort: str) -> Path:
    return case_dir / "labels" / f"{judge.tag_suffix(model, effort)}.json"


def measure_case(case_dir: Path, lead_ids: list[str], *, model: str, effort: str,
                 jobs: int = 4, relabel: bool = False,
                 call: judge.CallFn = judge.call_model) -> dict:
    """The label pass over a case's leads, read from or written to the label cache.

    Independent of the projection. Only leads absent from the cache are measured.
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
        # Record the model the calls actually used: a silent fallback must not be filed
        # under the requested tag.
        resolved = judge.sole_judge(fresh, what="the label pass")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "judge": {"model": resolved, "effort": effort,
                      "prompts_sha8": judge.prompts_sha8()},
            "leads": {k: cached[k] for k in sorted(cached)},
        }, indent=2) + "\n", encoding="utf-8")
    return cached


# the score

def _mechanical_row(lead_id: str, system: str, label: dict, cause: str, note: str) -> dict:
    """A row failed in code. It keeps the measurement's `delta_kind` so the failure still
    counts against its own slice, and it wins over an `undecidable` measurement.
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


@model(frozen=True)
class _Mechanical:
    """The score as far as it goes with no model, plus the inputs the judged half reuses."""

    summary: dict
    manifest: dict
    leads: dict
    preds: dict


def _measured(case_dir: Path, proj_path: Path, *, model: str, effort: str) -> _Mechanical:
    """Load one case-and-projection pair and run every check that needs no model.

    Shared by `--dry-run` and `score_case` so the dry run cannot disagree with the score.
    """
    manifest = safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    # Typed reading for structure and the judge; spelled reading (same shape) for text checks.
    readings = safe_load_typed_and_spelled(proj_path.read_text(encoding="utf-8"))
    leads = {row["lead_id"]: row for row in judge.load_case_leads(case_dir)}
    preds, duplicates = load_predictions(readings.typed)
    spelled_preds, _ = load_predictions(readings.spelled)
    emitted = emitted_index(spelled_preds)

    summary: dict = {
        "tag": score_tag(proj_path.stem, model, effort),
        "projection": proj_path.name,
        "case": case_dir.name,
        "kind": manifest.get("kind"),
        "judge": {"model": model, "effort": effort, "prompts_sha8": judge.prompts_sha8()},
        "n_leads": len(leads),
        "mechanical": {
            **integrity(list(leads), preds, duplicates),
            "malformed_leads": {
                lead_id: problem for lead_id, events in preds.items()
                if (problem := grammar_problem(events)) is not None
            },
            "forbidden_emitted": leaks(forbidden_values(case_dir, manifest), emitted),
            "expectation_failures": expectation_failures(
                manifest.get("expectation") or {}, preds, list(leads), emitted),
            "concrete_value_leads": sorted(
                lead_id for lead_id, events in spelled_preds.items()
                if isinstance(events, list) and has_concrete_value(events)),
        },
    }
    return _Mechanical(summary=summary, manifest=manifest, leads=leads, preds=preds)


def score_case(case_dir: Path, proj_path: Path, *, model: str, effort: str, jobs: int = 4,
               relabel: bool = False, call: judge.CallFn = judge.call_model) -> dict:
    """The whole measurement, as the dict written to `scores/<tag>.json`."""
    mech = _measured(case_dir, proj_path, model=model, effort=effort)
    summary, manifest, leads, preds = mech.summary, mech.manifest, mech.leads, mech.preds

    # A mismatched lead set is not a result; stop before paying for any judge call.
    if any(summary["mechanical"][k] for k in
           ("missing_leads", "unscored_leads", "duplicate_leads")):
        summary.update({"judged": False, "rows": [],
                        "why_unjudged": "the projection's lead set does not match the case's"})
        return summary

    if manifest.get("defective"):
        # Its leads cannot contain the activity they were gathered for; scoring it would
        # record a correctly-quiet projection as coverage.
        summary.update({
            "judged": False, "rows": [],
            "why_unjudged": f"the case is marked defective: {manifest['defective']}",
        })
        return summary

    if is_derived(manifest.get("kind")):
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
                measurement(measured[lead_id]),
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
        if lead_id not in verdicts:          # labelled undecidable
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
    summary.update({
        "judged": True,
        "faithful": f"{faithful}/{len(decided)}",
        "abstentions": len(rows) - len(decided),
        "by_system": _by_system(rows),
        "cost_usd": judge.total_cost([*measured.values(), *verdicts.values()]),
        "rows": rows,
    })
    return summary


def measurement(label: dict) -> dict:
    """The label pass's reading as the verdict pass is shown it, without provenance or cost.

    Public so `audit_judge.verdict_set` shows the verdict pass the same reading a real score
    does."""
    return {k: label[k] for k in ("delta_kind", "heterogeneous", "evidence") if k in label}


def forbidden_values(case_dir: Path, manifest: dict) -> list[str]:
    """`must_not_emit` for a mutation case: the pre-mutation entities.

    Read from the manifest's `expectation:`, else `expected.yaml` (seed cases), else the
    manifest's top level; the first non-empty clause wins. Every present clause is validated,
    including shadowed ones, so a mis-typed clause is refused wherever it sits. Public
    because `validate_cases` applies the same check at commit time.
    """
    sources: list[tuple[dict, str]] = [
        (manifest.get("expectation") or {}, "manifest.yaml expectation")]
    calibration = case_dir / "expected.yaml"
    if calibration.is_file():
        sources.append((safe_load(calibration.read_text(encoding="utf-8")) or {},
                        "expected.yaml"))
    sources.append((manifest, "manifest.yaml"))
    clauses = [_text_clause(doc, "must_not_emit", where=where) for doc, where in sources]
    return next((clause for clause in clauses if clause), [])


def required_values(expectation: dict) -> list[str]:
    """`must_emit`: the story's own values the projection has to carry."""
    return _text_clause(expectation, "must_emit", where="manifest.yaml expectation")


class ClauseError(ValueError):
    """A `must_emit` / `must_not_emit` clause that is not a list of quoted strings: an
    authoring error in the case. Its own class so `main` can report it as a refusal rather
    than a traceback."""


def _text_clause(doc: dict, key: str, *, where: str) -> list[str]:
    """`doc[key]` as a list of string literals, or `ClauseError` saying what it is.

    Only a string carries a spelling to compare: an unquoted timestamp arrives as a
    `datetime`, `0755` as `493`, `yes` as `True`, and would never match. A bare scalar would
    be iterated character by character. Both are refused rather than coerced.
    """
    entries = doc.get(key)
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ClauseError(f"{where}: `{key}` must be a list of quoted strings, not "
                          f"{type(entries).__name__} {entries!r}")
    for entry in entries:
        if not isinstance(entry, str):
            raise ClauseError(
                f"{where}: `{key}` entry {entry!r} is a YAML {type(entry).__name__}, and the "
                f"check compares text — quote it as the literal the projection would carry")
    return list(entries)


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
    """`<oracle-model>_<oracle-prompt>__judge-<model>-<effort>_<prompts-sha8>`.

    Editing either judge prompt yields a new tag, requiring a full re-score.
    """
    return f"{projection_stem}__{judge.tag_suffix(model, effort)}"


# reporting

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
    try:
        if ns.dry_run:
            summary = _dry_run(ns.case_dir, ns.projection, model=model, effort=effort)
        else:
            summary = score_case(ns.case_dir, ns.projection, model=model, effort=effort,
                                 jobs=ns.jobs, relabel=ns.relabel, call=judge.call_model)
    except ClauseError as e:
        # An authoring error: one `!!` line, so a sweep over many cases keeps going.
        print(f"== score: {ns.projection.name} vs {ns.case_dir.name} ==")
        print(f"!! clause — {e}")
        return 1
    print_report(summary)

    # A violated expectation or a leak fails the score, since derived cases are graded by
    # nothing else. Some committed scores do leak and exit 1 by design; a sweeping caller
    # should read `mechanical.forbidden_emitted` rather than treat exit 1 as "re-score me".
    broken = any(summary["mechanical"][k] for k in
                 ("missing_leads", "unscored_leads", "duplicate_leads",
                  "expectation_failures", "forbidden_emitted"))
    if not ns.dry_run:
        out = ns.json_out if ns.json_out is not None else (
            ns.case_dir / "scores" / f"{summary['tag']}.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {out}")
    return 1 if broken else 0


def _dry_run(case_dir: Path, proj_path: Path, *, model: str, effort: str) -> dict:
    """The mechanical half, with no model in the loop — what `--dry-run` reports."""
    summary = _measured(case_dir, proj_path, model=model, effort=effort).summary
    summary.update({"judged": False, "rows": [],
                    "why_unjudged": "--dry-run: no model was called"})
    return summary


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main())
