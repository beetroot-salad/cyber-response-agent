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

Each corpus is enumerated locally with one read per file
(``_iter_corpus`` → ``_read_lesson``), matching the indexer discovery
rules (sorted ``*.md``, underscore-skip, warn+skip on malformed
frontmatter). Stale lessons are *surfaced* (with a badge), not hidden:
this is an author-facing posture view, not the runtime retrieval path
the actors use.

Usage:
    serialize.py            # write defender/learning/frontend/lessons.json
    serialize.py --stdout   # print the contract to stdout (api preview)
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]
DEFENDER = REPO_ROOT / "defender"


def _reexec_into_venv() -> None:
    """Switch to defender/.venv (for PyYAML) — only when run as a script.

    Guarded by ``__name__ == "__main__"`` at the call site so that
    *importing* this module (pytest, uv, build.py) never replaces the
    caller's process. ``build_view`` is an importable api; an
    import-time ``os.execv`` would silently hijack the importing
    interpreter (a test runner would exec into the CLI and exit). No-op
    when the venv is absent or we are already inside it.
    """
    venv_py = DEFENDER / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(HERE), *sys.argv[1:]])


if __name__ == "__main__":
    _reexec_into_venv()

# Put the workspace root on sys.path so the `defender.*` namespace import below
# resolves whether this file is imported or run directly (after the venv re-exec
# above, sys.path[0] is this script's dir, not the workspace root).
if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender._frontmatter import FrontmatterError, parse_frontmatter


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


def _read_lesson(path: Path) -> tuple[dict, str]:
    """Return (frontmatter dict, markdown body) for a lesson file — one read.

    A tolerant wrapper over the shared ``parse_frontmatter``: a file with no
    parseable frontmatter yields ``({}, whole-body)`` rather than raising, so a
    malformed lesson is surfaced/skipped upstream instead of crashing the build.
    """
    text = path.read_text(encoding="utf-8")
    try:
        return parse_frontmatter(text)
    except FrontmatterError:
        return {}, text.strip()


def _iter_corpus(corpus: Path):
    """Yield (path, frontmatter, body) for each lesson in a corpus dir.

    One read per file. Skips ``_``-prefixed files and warns+skips any
    file whose frontmatter is missing or malformed (the indexer
    discovery rules). Stale lessons are yielded — the view badges them.
    """
    if not corpus.is_dir():
        return
    for path in sorted(corpus.glob("*.md")):
        if path.name.startswith("_"):
            continue
        fm, body = _read_lesson(path)
        if not fm:
            print(f"warn: skipping {path.name} (malformed frontmatter)", file=sys.stderr)
            continue
        yield path, fm, body


def _normalize(path: Path, fm: dict, body: str, *, group: str, title_keys: list[str], desc_key: str) -> dict:
    title = next((str(fm[k]).strip() for k in title_keys if fm.get(k)), path.stem)
    status = str(fm.get("status") or "live").strip()
    return {
        "group": group,
        "title": title,
        "description": str(fm.get(desc_key) or "").strip(),
        "status": status,
        "source_path": str(path.relative_to(REPO_ROOT)),
        "metadata": _json_safe(fm),
        "body": body,
    }


# Per-group: the corpus dir (under defender/), where the title/description
# live, and which metadata fields the view renders. `kind` tells the view
# how to render the value. This dict is the single source of group order
# and identity — the view derives both from the contract it produces.
GROUPS = {
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


def build_view() -> dict:
    """Pure: read the corpora → the view contract (no timestamp inside)."""
    groups: dict[str, dict] = {}
    for name, spec in GROUPS.items():
        lessons = [
            _normalize(path, fm, body, group=name, title_keys=spec["title_keys"], desc_key=spec["desc_key"])
            for path, fm, body in _iter_corpus(DEFENDER / spec["dir"])
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
    from datetime import datetime, timezone

    view = build_view()
    view["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return view


def dump_contract(view: dict) -> str:
    """The canonical on-disk ``lessons.json`` form (indented + trailing newline)."""
    return json.dumps(view, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
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
