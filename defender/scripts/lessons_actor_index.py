#!/usr/bin/env python3
"""List actor lessons by relevance_criteria.

Cheap discovery primitive for the actor stage: prints one
`<path>\\t<relevance_criteria>` line per lesson that passes the filters,
so the actor scans descriptions before deciding which files to Read.

Usage:
    lessons_actor_index.py --channel tradecraft --actor-type internal \\
        --techniques T1078.004,T1550.001
    lessons_actor_index.py --channel environment --actor-type external

Filters are AND-combined. `--techniques` is OR within the list.
Lessons missing a filtered field are skipped silently.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv so PyYAML resolves regardless of which
# python the caller invoked us with (the actor's Bash tool uses the
# system ``python3`` on PATH; the defender's venv carries pyyaml).
_VENV_PY = Path(__file__).resolve().parents[2] / "defender" / ".venv" / "bin" / "python3"
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
LESSONS_ROOT = REPO_ROOT / "defender" / "lessons-actor"
CHANNELS = ("tradecraft", "environment")


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
    if isinstance(v, list):
        return v
    return [v]


def iter_lessons(channel: str):
    chan_dir = LESSONS_ROOT / channel
    if not chan_dir.is_dir():
        return
    for path in sorted(chan_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        fm = _parse_frontmatter(path.read_text())
        if fm is None:
            print(f"warn: skipping {path.relative_to(REPO_ROOT)} (malformed frontmatter)", file=sys.stderr)
            continue
        yield path, fm


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--channel", required=True, choices=CHANNELS)
    ap.add_argument("--actor-type", choices=("internal", "external"))
    ap.add_argument("--techniques", help="Comma-separated MITRE T-IDs; matches if any appear in the lesson's techniques: list")
    ns = ap.parse_args(argv[1:])

    want_techniques = set()
    if ns.techniques:
        want_techniques = {t.strip() for t in ns.techniques.split(",") if t.strip()}

    for path, fm in iter_lessons(ns.channel):
        if ns.actor_type:
            if ns.actor_type not in _as_list(fm.get("actor_type")):
                continue
        if want_techniques:
            have = set(_as_list(fm.get("techniques")))
            if have.isdisjoint(want_techniques):
                continue
        criteria = fm.get("relevance_criteria") or ""
        criteria = str(criteria).strip().replace("\t", " ").replace("\n", " ")
        rel = path.relative_to(REPO_ROOT)
        print(f"{rel}\t{criteria}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
