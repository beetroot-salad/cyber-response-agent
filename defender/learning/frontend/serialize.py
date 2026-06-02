#!/usr/bin/env python3
"""Serialize the three lesson corpora into one uniform view contract.

This is the *api* layer of the lessons frontend: it reads the
filesystem (the backend) and normalizes the three corpora — which have
*different* frontmatter schemas — into a single schema-agnostic
contract. The view (``build.py`` + its template) renders only from this
contract and never sees raw frontmatter or file layout. The same
contract is written to ``lessons.json`` so a real HTTP api could later
serve it to the identical frontend untouched.

The three corpora (authored by distinct learning-loop curators):

    defender     defender/lessons/             author.py
    actor        defender/lessons-actor/       author_actor.py
    environment  defender/lessons-environment/ author_actor_benign.py

Reuses the existing discovery primitives — ``iter_lessons`` from
``lessons_actor_index`` / ``lessons_env_retrieve`` — for actor/env
enumeration (underscore-skip, stale handling, malformed warnings). The
defender corpus has no indexer, so we enumerate it locally with the
same frontmatter shape.

Usage:
    serialize.py            # write defender/learning/frontend/lessons.json
    serialize.py --stdout   # print the contract to stdout (api preview)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]
DEFENDER = REPO_ROOT / "defender"

# Re-exec into defender/.venv so PyYAML resolves regardless of which
# python the caller used (mirrors the indexer scripts). No-op when the
# venv is absent (e.g. a worktree) or we are already inside it.
_VENV_PY = DEFENDER / ".venv" / "bin" / "python3"
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(HERE), *sys.argv[1:]])

# defender/scripts holds the reusable enumerators + yaml frontmatter parse.
sys.path.insert(0, str(DEFENDER / "scripts"))

import datetime as _dt
import json

import yaml

import lessons_actor_index
import lessons_env_retrieve


def _json_safe(obj):
    """Coerce YAML-parsed values (e.g. dates) into JSON-serializable form."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (_dt.date, _dt.datetime)):
        return obj.isoformat()
    return obj


def _read_lesson(path: Path) -> tuple[dict, str]:
    """Return (frontmatter dict, markdown body) for a lesson file.

    Mirrors the ``_parse_frontmatter`` shape used by both indexers,
    plus the body split they don't need.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text.strip()
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text.strip()
    try:
        fm = yaml.safe_load(text[4:end]) or {}
    except yaml.YAMLError:
        fm = {}
    if not isinstance(fm, dict):
        fm = {}
    nl = text.find("\n", end + 1)  # newline ending the closing '---' line
    body = text[nl + 1 :] if nl != -1 else ""
    return fm, body.strip()


def _iter_defender():
    """Enumerate defender/lessons/*.md (no existing indexer)."""
    corpus = DEFENDER / "lessons"
    if not corpus.is_dir():
        return
    for path in sorted(corpus.glob("*.md")):
        if path.name.startswith("_"):
            continue
        fm, _ = _read_lesson(path)
        if not fm:
            print(f"warn: skipping {path.name} (malformed frontmatter)", file=sys.stderr)
            continue
        yield path, fm


def _normalize(path: Path, fm: dict, *, group: str, title_keys: list[str], desc_key: str) -> dict:
    title = next((str(fm[k]).strip() for k in title_keys if fm.get(k)), path.stem)
    status = str(fm.get("status") or "live").strip()
    _, body = _read_lesson(path)
    return {
        "group": group,
        "title": title,
        "description": str(fm.get(desc_key) or "").strip(),
        "status": status,
        "source_path": str(path.relative_to(REPO_ROOT)),
        "metadata": _json_safe(fm),
        "body": body,
    }


# Per-group: where the title/description live, and which metadata fields the
# view renders as chips/badges. `kind` tells the view how to render the value.
GROUPS = {
    "defender": {
        "label": "Defender lessons",
        "blurb": "Pitfalls the runtime defender agent learned to avoid — folded from judged findings.",
        "title_keys": ["name"],
        "desc_key": "description",
        "fields": [
            {"label": "Source findings", "key": "source_finding_ids", "kind": "count"},
            {"label": "Created", "key": "created_at", "kind": "date"},
        ],
    },
    "actor": {
        "label": "Actor lessons",
        "blurb": "Tradecraft and detector facts the adversarial actor learned — what cover holds and what trips the defender.",
        "title_keys": ["subject"],
        "desc_key": "relevance_criteria",
        "fields": [
            {"label": "Techniques", "key": "techniques", "kind": "chips"},
            {"label": "Alert rules", "key": "alert_rule_ids", "kind": "chips"},
            {"label": "Lead tags", "key": "defender_lead_tags", "kind": "chips"},
            {"label": "Recorded", "key": "recorded_at", "kind": "text"},
        ],
    },
    "environment": {
        "label": "Environment lessons",
        "blurb": "Standing deployment facts the benign ops-teamer actor uses to ground routine activity.",
        "title_keys": ["subject"],
        "desc_key": "relevance_criteria",
        "fields": [
            {"label": "Alert rules", "key": "alert_rule_ids", "kind": "chips"},
            {"label": "Entities", "key": "entities", "kind": "chips"},
            {"label": "Recorded", "key": "recorded_at", "kind": "text"},
        ],
    },
}


def build_view() -> dict:
    """Pure: read the corpora → the view contract (no timestamp inside)."""
    enumerators = {
        "defender": _iter_defender(),
        "actor": lessons_actor_index.iter_lessons(),
        "environment": lessons_env_retrieve.iter_lessons(DEFENDER / "lessons-environment"),
    }
    groups: dict[str, dict] = {}
    for name, spec in GROUPS.items():
        lessons = [
            _normalize(path, fm, group=name, title_keys=spec["title_keys"], desc_key=spec["desc_key"])
            for path, fm in enumerators[name]
        ]
        lessons.sort(key=lambda l: l["title"].lower())
        groups[name] = {
            "label": spec["label"],
            "blurb": spec["blurb"],
            "fields": spec["fields"],
            "lessons": lessons,
        }
    return {"groups": groups}


def main(argv: list[str]) -> int:
    from datetime import datetime, timezone

    view = build_view()
    view["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = json.dumps(view, indent=2, ensure_ascii=False)
    if "--stdout" in argv[1:]:
        print(payload)
    else:
        out = HERE.parent / "lessons.json"
        out.write_text(payload + "\n", encoding="utf-8")
        counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
        print(f"wrote {out.relative_to(REPO_ROOT)} — {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
