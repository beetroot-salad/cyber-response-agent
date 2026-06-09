#!/usr/bin/env python3
"""Retrieve environment lessons relevant to a case, by classification.

Discovery primitive for the benign (ops-teamer) actor — see ``--help`` for
the retrieval model, when/how to use it, and examples.

A plain corpus scan (NO PERSISTENT INDEX) — fine at the current scale;
revisit (duckdb / a built index) when a per-call directory scan hurts.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv so PyYAML resolves regardless of which python
# the caller invoked us with (the actor's Bash tool uses system python3).
# Gated on __main__ so importing this module as a library never os.execv's
# the importing process away.
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO_ROOT / "defender" / "lessons-environment"


def _parse_frontmatter(text: str) -> dict | None:
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    try:
        data = yaml.safe_load(text[4:end])
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _as_str_set(v) -> set[str]:
    return {str(x) for x in _as_list(v)}


def iter_lessons(corpus: Path):
    if not corpus.is_dir():
        return
    for path in sorted(corpus.glob("*.md")):
        if path.name.startswith("_"):
            continue
        fm = _parse_frontmatter(path.read_text())
        if fm is None:
            print(f"warn: skipping {path.name} (malformed frontmatter)", file=sys.stderr)
            continue
        yield path, fm


def _csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {t.strip() for t in value.split(",") if t.strip()}


def _parse_case_entities(value: str | None) -> list[tuple[str, str]]:
    """`identity:service-account/known-corp,socket:ssh` → [(type, class), ...]."""
    out: list[tuple[str, str]] = []
    for tok in (value or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        typ, _, cls = tok.partition(":")
        out.append((typ.strip(), cls.strip()))
    return out


def _class_match(selector_class: str, case_class: str) -> bool:
    sel = (selector_class or "").split("/")
    case = (case_class or "").split("/")
    if len(sel) > len(case):
        return False
    return all(s == "*" or s == case[i] for i, s in enumerate(sel))


def _selector_satisfied(selector: dict, case_entities: list[tuple[str, str]]) -> bool:
    if not isinstance(selector, dict):
        return False
    s_type = str(selector.get("type") or "")
    s_class = str(selector.get("class") or "")
    return any(
        s_type == c_type and _class_match(s_class, c_class)
        for c_type, c_class in case_entities
    )


def _lesson_applies(
    fm: dict,
    case_entities: list[tuple[str, str]],
    entities_provided: bool,
    want_rule_ids: set[str],
) -> bool:
    # Entity selectors are enforced only when the caller supplies case
    # entities; otherwise this axis is unfiltered (whole-corpus listing).
    if entities_provided:
        for selector in _as_list(fm.get("entities")):
            if not _selector_satisfied(selector, case_entities):
                return False
    # Rule-anchored retrieval: a lesson must declare a matching anchor. Every
    # environment lesson is required to carry a non-empty alert_rule_ids (the
    # template + observation enforce it); a lesson with an empty/disjoint anchor
    # is malformed and matches NOTHING here, rather than matching everything —
    # otherwise an unanchored lesson would surface for every unrelated alert
    # rule. (Whole-corpus listing passes no rule ids and is unfiltered.)
    if want_rule_ids:
        lesson_rules = _as_str_set(fm.get("alert_rule_ids"))
        if not lesson_rules or lesson_rules.isdisjoint(want_rule_ids):
            return False
    return True


_HELP_DESCRIPTION = """\
Retrieve the environment lessons relevant to a case, by classification.

The benign (ops-teamer) actor runs this once, before constructing a benign
story, to pull the standing deployment facts that ground it — what a senior
engineer checks in the runbook.

Retrieval model: --alert-rule-ids is the ANCHOR (always present,
discriminating); --entities REFINE. A lesson applies when every constraint
it declares is satisfied by the case:
  * entities — conjunctive invlang {type,class} selectors; each must be met
    by some case entity. Class match is slot-wise on '/': a selector slot of
    '*' matches anything, and a selector with fewer slots matches more
    ('web-server' matches 'web-server/internal/container').
  * rule ids — the anchor. A rule-anchored query returns only lessons whose
    anchor includes the case rule; a lesson with no/disjoint anchor is skipped
    (every env lesson is required to carry an anchor). A whole-corpus listing
    with no --alert-rule-ids is unfiltered on this axis.
A lesson that declares no entities applies regardless of entities."""

_HELP_EPILOG = """\
when:
  Run once before writing the story. Anchor on the alert's rule id; add the
  case entities to narrow the match. No output = nothing matched: reason from
  the alert and general operations knowledge.

entities:
  Pass only what the prologue actually classifies — process, socket, file,
  credential, compute. Do NOT pass an identity unless the alert names a
  principal: in a false positive the investigation never grounded the
  identity, so it is not an observable selector.

output:
  One <path>\\t<relevance_criteria> line per matching lesson. Scan the
  criteria, then Read the files that fit. Stale lessons are hidden by default.

examples:
  # anchor on the rule, refine with the case's observable entities:
  lessons_env_retrieve.py --alert-rule-ids v2-falco-suspicious-network-tool --entities process:nc,socket:tcp
  # rule-only (no entity refinement):
  lessons_env_retrieve.py --alert-rule-ids v2-off-hours-sudo
  # by subject (the fold key) — e.g. to find an existing lesson to update:
  lessons_env_retrieve.py --subject svc.monitoring
  # whole corpus (live only):
  lessons_env_retrieve.py"""


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="lessons_env_retrieve.py",
        description=_HELP_DESCRIPTION,
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--entities", help="Case entities (prologue-observable) as comma-separated invlang type:class tokens; refine the rule-anchored match")
    ap.add_argument("--alert-rule-ids", help="Alert rule id(s) for the case — the retrieval anchor; comma-separated, OR within the list")
    ap.add_argument("--subject", help="Exact subject match (single value — subject is the equivalence key / fold key)")
    ap.add_argument("--include-stale", action="store_true", help="Include lessons with status: stale (author-only; the runtime actor must never see stale claims)")
    ap.add_argument("--corpus", help="Corpus directory (default: defender/lessons-environment)")
    ns = ap.parse_args(argv[1:])

    corpus = Path(ns.corpus) if ns.corpus else DEFAULT_CORPUS
    case_entities = _parse_case_entities(ns.entities)
    entities_provided = ns.entities is not None
    want_rule_ids = _csv_set(ns.alert_rule_ids)
    want_subject = ns.subject.strip() if ns.subject else None

    for path, fm in iter_lessons(corpus):
        if not ns.include_stale and str(fm.get("status") or "live").strip() == "stale":
            continue
        if want_subject is not None and str(fm.get("subject") or "").strip() != want_subject:
            continue
        if not _lesson_applies(fm, case_entities, entities_provided, want_rule_ids):
            continue
        criteria = str(fm.get("relevance_criteria") or "").strip().replace("\t", " ").replace("\n", " ")
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        print(f"{rel}\t{criteria}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
