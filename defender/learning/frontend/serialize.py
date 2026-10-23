#!/usr/bin/env python3
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path
from typing import TypedDict

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]

if (_root := str(REPO_ROOT)) not in sys.path:
    sys.path.insert(0, _root)

from defender.execution._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender._clock import z_seconds
from defender.knowledge._corpus import iter_lessons
from defender._io import json_safe, use_utf8_stdio
from defender.knowledge._knowledge import LESSONS, LESSONS_QUESTIONER, KnowledgePaths


def _json_safe(obj):
    # `null` for a non-finite float: `lessons.json` is data a page computes over, and bare
    # `NaN` from one lesson's YAML `.nan` would poison it for every strict reader. The rest —
    # dates and `!!binary` as keys or values, sets — is the shared rule.
    return json_safe(obj, non_finite="null")


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
    #: Has this corpus lost its producer while its files remain? Not inferable from the files.
    #: Per group (retirement is the channel's property, staleness a lesson's); `retired_note`
    #: says why, beside the badge.
    retired: bool
    retired_note: str
    title_keys: list[str]
    desc_key: str
    fields: list[dict[str, str]]


GROUPS: dict[str, GroupSpec] = {
    "defender": {
        "label": "Defender lessons",
        "dir": LESSONS,
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
    "questioner": {
        "label": "Questioner lessons",
        "dir": LESSONS_QUESTIONER,
        "blurb": "Pitfalls about the WORLDS the questioner authors — a fact placed where no "
                 "served system could show it, an under-scoped story, a family that failed to "
                 "discriminate — folded from the family judge's own world findings (#1007) and "
                 "read back at the questioner's call 1 for a tenant serving one of the "
                 "lesson's systems.",
        "retired": False,
        "retired_note": "",
        "title_keys": ["name"],
        "desc_key": "description",
        "fields": [
            {"label": "Systems", "key": "systems", "kind": "chips"},
            {"label": "Bucket", "key": "bucket", "kind": "text"},
            {"label": "Source findings", "key": "source_finding_ids", "kind": "count"},
            {"label": "Created", "key": "created_at", "kind": "date"},
        ],
    },
}


def build_view(agent_root: Path | None) -> dict:
    """The posture page's contract over the tenant knowledge at `agent_root` (an export's
    `agent/`, #1108 P4): each group's lessons, spelled relative to the tenant repo. `None` (no
    tenant selected, or nothing published for it) is every group with no lesson."""
    groups: dict[str, dict] = {}
    for name, spec in GROUPS.items():
        lessons = [] if agent_root is None else _group_lessons(Path(agent_root), name, spec)
        groups[name] = {
            "label": spec["label"],
            "blurb": spec["blurb"],
            "retired": spec["retired"],
            "retired_note": spec["retired_note"],
            "fields": spec["fields"],
            "lessons": lessons,
        }
    return {"groups": groups}


def _group_lessons(agent_root: Path, name: str, spec: dict) -> list[dict]:
    knowledge = KnowledgePaths(agent_root)
    root = knowledge.agent_root.parent
    skipped: list[Path] = []
    lessons = [
        _normalize(lesson.path, lesson.fm, lesson.body, group=name,  # lint-lesson-text: ok — the HTML view escapes every value it renders (build.py escHtml)
                   title_keys=spec["title_keys"], desc_key=spec["desc_key"],
                   root=root)
        for lesson in iter_lessons(knowledge.corpus_dir(spec["dir"]), on_skip=skipped.append)
    ]
    lessons += [
        _skipped_record(path, group=name, root=root) for path in skipped
    ]
    lessons.sort(key=lambda rec: rec["title"].lower())
    return lessons


def published_agent_root(tenant) -> Path:
    """The `agent/` of the export the tenant's `current` names: the knowledge the page shows.
    `DeliveryRefused` when nothing is published for the tenant."""
    from defender.tenancy._exports import current_export

    return current_export(tenant).path / "agent"


def stamped_view(agent_root: Path | None) -> dict:
    view = build_view(agent_root=agent_root)
    view["generated_at"] = z_seconds(_dt.datetime.now(_dt.UTC))
    return view


def dump_contract(view: dict) -> str:
    return json.dumps(view, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    import argparse

    use_utf8_stdio()
    parser = argparse.ArgumentParser(description="The lessons posture page's contract")
    parser.add_argument("--stdout", action="store_true")
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument("--tenant", help="show the tenant's published knowledge")
    where.add_argument("--agent-root", type=Path, help="show the knowledge at this agent root")
    args = parser.parse_args(argv[1:])
    if args.agent_root is not None:
        agent_root = args.agent_root
    else:
        from defender.tenancy import _tenant
        from defender.tenancy._exports import DeliveryRefused

        try:
            tenant = _tenant.requested_tenant(_tenant.resolve_data_root(), args.tenant)
            agent_root = published_agent_root(tenant)
        except (_tenant.TenantRefused, DeliveryRefused) as refused:
            parser.error(str(refused))
    view = stamped_view(agent_root)
    if args.stdout:
        sys.stdout.write(dump_contract(view))
    else:
        out = HERE.parent / "lessons.json"
        out.write_text(dump_contract(view), encoding="utf-8")
        counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
        print(f"wrote {out.relative_to(REPO_ROOT)} — {counts}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
