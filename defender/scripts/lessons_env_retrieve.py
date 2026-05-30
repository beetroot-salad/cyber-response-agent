#!/usr/bin/env python3
"""Retrieve environment lessons relevant to a case, by classification.

Cheap discovery primitive for the benign (ops-teamer) actor: prints one
`<path>\\t<relevance_criteria>` line per lesson that applies to the case,
so the actor scans descriptions before deciding which files to Read.

Retrieval is **classification-first**. The caller passes the case's
classified entities (invlang `type:class` tokens from the prologue) and
the alert rule id(s); a lesson applies when every constraint it *declares*
is satisfied by the case:

  * `entities:` — a conjunctive list of invlang `{type, class}` selectors.
    Each selector must be satisfied by some case entity (same `type`, and
    a `class` slot-match). Class match is slot-wise on `/`: a selector slot
    of `*` matches anything, and a selector may name fewer slots than the
    case entity (it only constrains the slots it names). So selector
    `service-account/*` matches case `service-account/known-corp`, and
    `web-server` matches `web-server/internal/container`.
  * `alert_rule_ids:` — if the lesson names rule ids, the case rule must be
    among them. A lesson with no rule ids applies regardless of rule.

A lesson that declares no `entities` applies regardless of entities (e.g.
a pure rule-FP lesson). This is a NO PERSISTENT INDEX scan — fine at the
current corpus scale; revisit (duckdb / a built yaml index) when the
corpus is large enough that a per-call directory scan hurts.

Usage:
    lessons_env_retrieve.py                                  # whole corpus (live only)
    lessons_env_retrieve.py --entities identity:service-account/known-corp,socket:ssh \\
                            --alert-rule-ids v2-falco-suspicious-network-tool
    lessons_env_retrieve.py --subject svc.monitoring
    lessons_env_retrieve.py --include-stale                  # author-only

Lessons with `status: stale` are hidden by default; the runtime actor must
never see stale claims. `--corpus DIR` overrides the corpus location.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv so PyYAML resolves regardless of which python
# the caller invoked us with (the actor's Bash tool uses system python3).
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
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
    # A lesson that names rule ids must include the case rule; a lesson
    # with no rule ids applies regardless of rule.
    lesson_rules = _as_str_set(fm.get("alert_rule_ids"))
    if want_rule_ids and lesson_rules and lesson_rules.isdisjoint(want_rule_ids):
        return False
    return True


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--entities", help="Case entities as comma-separated invlang type:class tokens")
    ap.add_argument("--alert-rule-ids", help="Comma-separated SIEM rule IDs for the case; OR within the list")
    ap.add_argument("--subject", help="Exact subject match (single value — subject is the equivalence key)")
    ap.add_argument("--include-stale", action="store_true", help="Include lessons with status: stale (author-only)")
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
