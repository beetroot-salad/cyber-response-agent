#!/usr/bin/env python3
from __future__ import annotations

import datetime as _dt
import json
import math
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
        # KEYS too: YAML types a bare `2026-01-01:` as a `datetime.date` and `!!binary` as
        # `bytes`, either of which json.dumps rejects — so one such key in one lesson's
        # frontmatter would abort the whole build instead of degrading that lesson.
        return {(k if isinstance(k, str) else str(_json_safe(k))): _json_safe(v)
                for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        return [_json_safe(v) for v in sorted(obj, key=str)]
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (_dt.date, _dt.datetime)):
        return obj.isoformat()
    if isinstance(obj, float) and not math.isfinite(obj):
        # `json.dumps` ACCEPTS these and emits bare `NaN`/`Infinity`, which is not JSON — a
        # YAML `.nan` in one lesson's frontmatter would poison `lessons.json` for every strict
        # reader. Same degrade-this-lesson rule as the exotic types above.
        return None
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
    #: Has this corpus lost its PRODUCER while its files remain? A reader cannot tell that
    #: from one nothing has written to lately, and "the loop's current output" is what this
    #: page claims. Per group, not inferred from a lesson's `status: stale` — staleness is
    #: one lesson's property, retirement is the channel's. `retired_note` says why, beside
    #: the badge; a retired group without one renders a badge nobody can act on.
    retired: bool
    retired_note: str
    title_keys: list[str]
    desc_key: str
    fields: list[dict[str, str]]


GROUPS: dict[str, GroupSpec] = {
    "defender": {
        "label": "Defender lessons",
        "dir": "lessons",
        "blurb": "Pitfalls the runtime defender agent learned to avoid — folded from the "
                 "branched episode's judged findings, and read at PLAN time.",
        "retired": False,
        "retired_note": "",
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
        "blurb": "Pattern/tradecraft lessons the adversarial actor learned — what cover held "
                 "and what tripped the defender.",
        "retired": True,
        "retired_note": "Frozen archive. The adversarial actor that authored these, and the "
                        "curator that folded them, were deleted with the four-role pipeline "
                        "(#922). Nothing writes this corpus and nothing reads it; the lessons "
                        "are kept so what was learned stays findable.",
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
        "blurb": "Standing deployment facts the two actors retrieved to ground their stories, "
                 "fed by the benign and adversarial directions alike (issue #298).",
        "retired": True,
        "retired_note": "Frozen archive. Both directions that fed it were deleted with the "
                        "four-role pipeline (#922), and no live role retrieves it. Kept "
                        "readable; environment knowledge the runtime uses lives in "
                        "defender/skills/ instead.",
        "title_keys": ["subject"],
        "desc_key": "relevance_criteria",
        "fields": [
            {"label": "Alert rules", "key": "alert_rule_ids", "kind": "chips"},
            # The display label for an environment lesson's own `entities` frontmatter key
            # (the retired environment-observation validator's own `entities` selectors), not the
            # `Entities` dataclass — same word, unrelated domain. Renaming it would change a
            # user-visible chip label and a corpus schema key. The suppression marker must sit
            # on the REFERENCING line: lint_stale_refs reads it off the matched line only.
            {"label": "Entities", "key": "entities", "kind": "chips"},  # lint-stale-ref: ok — display label, not the retired dataclass
            {"label": "Recorded", "key": "recorded_at", "kind": "text"},
        ],
    },
    "questioner": {
        "label": "Questioner lessons",
        "dir": "lessons-questioner",
        "blurb": "Pitfalls about the WORLDS the questioner authors — an invented field shape, "
                 "an under-scoped story, a family that failed to discriminate — folded from "
                 "the family judge's own world findings (#1007) and read back at the "
                 "questioner's call 1.",
        "retired": False,
        "retired_note": "",
        "title_keys": ["name"],
        "desc_key": "description",
        "fields": [
            {"label": "Pattern", "key": "pattern", "kind": "text"},
            {"label": "Holding system", "key": "holding_system", "kind": "text"},
            {"label": "Bucket", "key": "bucket", "kind": "text"},
            {"label": "Source findings", "key": "source_finding_ids", "kind": "count"},
            {"label": "Created", "key": "created_at", "kind": "date"},
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
            "retired": spec["retired"],
            "retired_note": spec["retired_note"],
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
