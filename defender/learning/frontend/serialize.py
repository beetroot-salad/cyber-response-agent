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
    environment  defender/lessons-environment/ author_actor_benign.py (FP)
                                               + author_actor_env.py (adversarial, #298)

Each corpus is enumerated through the shared walk (``defender._corpus.iter_lessons`` — the same
reader the lesson CLIs and the curators go through), so the view cannot drift from the rest of the
codebase about what a lesson *is*: sorted ``*.md``, underscore-skip, warn+skip on a malformed
*or unreadable* file. Stale lessons are *surfaced* (with a badge), not hidden: this is an
author-facing posture view, not the runtime retrieval path the actors use.

Usage:
    serialize.py            # write defender/learning/frontend/lessons.json
    serialize.py --stdout   # print the contract to stdout (api preview)
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path
from typing import TypedDict

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]
DEFENDER = REPO_ROOT / "defender"

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (sys.path[0] is this
# script's dir, not the workspace root). Must precede the shared import.
if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender.scripts._venv import reexec_into_venv  # noqa: E402

# Switch to defender/.venv (for PyYAML) only when run as a script — gated on
# __main__ so that *importing* this module (pytest, uv, build.py) never replaces
# the caller's process. ``build_view`` is an importable api; an import-time
# ``os.execv`` would silently hijack the importing interpreter.
if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender._corpus import iter_lessons
from defender._io import use_utf8_stdio


def _json_safe(obj):
    """Coerce YAML-parsed values into JSON-serializable form.

    Dates/datetimes → ISO strings; sets/tuples → lists; anything else
    YAML can produce that ``json`` cannot (``datetime.time``, ``bytes``,
    ``!!set`` members, …) → ``str`` so a build can never crash on an
    exotic frontmatter scalar.
    """
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        return [_json_safe(v) for v in sorted(obj, key=str)]
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (_dt.date, _dt.datetime)):
        return obj.isoformat()
    if obj is None or isinstance(obj, (str, bool, int, float)):
        return obj
    return str(obj)


def _normalize(
    path: Path, fm: dict, body: str, *, group: str, title_keys: list[str], desc_key: str,
    root: Path = REPO_ROOT,
) -> dict:
    """One lesson → one view record.

    ``source_path`` is rendered relative to ``root`` — the parent of the corpus root
    ``build_view`` was pointed at, which for the real tree IS ``REPO_ROOT`` (so the value is
    unchanged). Keying it off the module constant instead would make the injection seam unusable
    rather than merely imprecise: ``relative_to(REPO_ROOT)`` raises ``ValueError`` on the first
    record from any tree outside the repo.

    A lesson whose frontmatter is a valid EMPTY MAPPING renders like any other: no ``title_keys``
    hit, so the title falls back to the stem (which is what keeps the record's title truthy), an
    empty description, and the default ``live`` status. It is *shown*, not silently dropped — the
    shared walk treats ``{}`` as the successful parse it is.
    """
    title = next((str(fm[k]).strip() for k in title_keys if fm.get(k)), path.stem)
    status = str(fm.get("status") or "live").strip()
    return {
        "group": group,
        "title": title,
        "description": str(fm.get(desc_key) or "").strip(),
        "status": status,
        "source_path": str(path.relative_to(root)),
        "metadata": _json_safe(fm),
        "body": body,
    }


class GroupSpec(TypedDict):
    label: str
    dir: str
    blurb: str
    title_keys: list[str]
    desc_key: str
    fields: list[dict[str, str]]


# Per-group: the corpus dir (under defender/), where the title/description
# live, and which metadata fields the view renders. `kind` tells the view
# how to render the value. This dict is the single source of group order
# and identity — the view derives both from the contract it produces.
GROUPS: dict[str, GroupSpec] = {
    "defender": {
        "label": "Defender lessons",
        "dir": "lessons",
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
        "dir": "lessons-actor",
        "blurb": "Pattern/tradecraft lessons the adversarial actor learned — what cover holds and what trips the defender. Standing deployment facts now live in the shared environment corpus (issue #298).",
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
        "dir": "lessons-environment",
        "blurb": "Standing deployment facts both actors retrieve to ground their stories — fed by the benign (FP) and adversarial directions alike (issue #298).",
        "title_keys": ["subject"],
        "desc_key": "relevance_criteria",
        "fields": [
            {"label": "Alert rules", "key": "alert_rule_ids", "kind": "chips"},
            {"label": "Entities", "key": "entities", "kind": "chips"},
            {"label": "Recorded", "key": "recorded_at", "kind": "text"},
        ],
    },
}


def build_view(defender_dir: Path = DEFENDER) -> dict:
    """Pure: read the corpora under ``defender_dir`` → the view contract (no timestamp inside).

    ``defender_dir`` defaults to the real ``defender/``, so every existing caller is unchanged;
    it exists so the view can be built against a fixture corpus at all (the group dirs are
    resolved beneath it, and ``source_path`` is rendered relative to its parent).
    """
    groups: dict[str, dict] = {}
    for name, spec in GROUPS.items():
        lessons = [
            _normalize(lesson.path, lesson.fm, lesson.body, group=name,
                       title_keys=spec["title_keys"], desc_key=spec["desc_key"],
                       root=defender_dir.parent)
            for lesson in iter_lessons(defender_dir / spec["dir"])
        ]
        lessons.sort(key=lambda rec: rec["title"].lower())
        groups[name] = {
            "label": spec["label"],
            "blurb": spec["blurb"],
            "fields": spec["fields"],
            "lessons": lessons,
        }
    return {"groups": groups}


def stamped_view() -> dict:
    """``build_view()`` plus the CLI-layer ``generated_at`` stamp (UTC).

    The single place the timestamp is applied — both ``serialize`` and
    ``build`` go through here so the contract's wall-clock field cannot
    drift between the two entry points.
    """
    from datetime import datetime

    view = build_view()
    view["generated_at"] = datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return view


def dump_contract(view: dict) -> str:
    """The canonical on-disk ``lessons.json`` form (indented + trailing newline)."""
    return json.dumps(view, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    # The file writes below pin utf-8; --stdout dumps the same ensure_ascii=False payload, so it
    # needs the stream pinned too or an accented lesson kills the api preview under a C locale.
    use_utf8_stdio()
    view = stamped_view()
    if "--stdout" in argv[1:]:
        sys.stdout.write(dump_contract(view))
    else:
        out = HERE.parent / "lessons.json"
        out.write_text(dump_contract(view), encoding="utf-8")
        counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
        print(f"wrote {out.relative_to(REPO_ROOT)} — {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
