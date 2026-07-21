#!/usr/bin/env python3
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path
from typing import TypedDict

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]
DEFENDER = REPO_ROOT / "defender"

if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender.scripts._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender._corpus import iter_lessons
from defender._io import use_utf8_stdio


def _json_safe(obj):
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


def _skipped_record(path: Path, *, group: str, root: Path) -> dict:
    return {
        "group": group,
        "title": path.stem,
        "description": "(malformed or unreadable lesson — frontmatter unavailable)",
        "status": "malformed",
        "source_path": str(path.relative_to(root)),
        "metadata": {},
        "body": "",
    }


class GroupSpec(TypedDict):
    label: str
    dir: str
    blurb: str
    title_keys: list[str]
    desc_key: str
    fields: list[dict[str, str]]


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
    groups: dict[str, dict] = {}
    for name, spec in GROUPS.items():
        skipped: list[Path] = []
        lessons = [
            _normalize(lesson.path, lesson.fm, lesson.body, group=name,
                       title_keys=spec["title_keys"], desc_key=spec["desc_key"],
                       root=defender_dir.parent)
            for lesson in iter_lessons(defender_dir / spec["dir"], on_skip=skipped.append)
        ]
        lessons += [
            _skipped_record(path, group=name, root=defender_dir.parent) for path in skipped
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
    from datetime import datetime

    view = build_view()
    view["generated_at"] = datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return view


def dump_contract(view: dict) -> str:
    return json.dumps(view, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
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
