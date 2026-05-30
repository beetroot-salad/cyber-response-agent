#!/usr/bin/env python3
"""Deterministic forward-check for a single candidate environment lesson.

Usage: ``verify_forward_env.py [--corpus DIR] [--pending FILE] <lesson_path> <observation_id>``

The environment-lesson analog of ``verify_forward_actor.py`` — but where
the actor check is a Haiku judgment, this one is deterministic and free.
The failure mode that matters for an environment lesson is **mis-keying**:
a lesson the benign actor cannot retrieve for the case it bears on is dead
weight. So the check re-runs the environment retrieval with the source
observation's OWN ``alert_rule_ids`` + ``entities`` and confirms the lesson
file is returned. A correctly-keyed lesson MUST come back; an empty/wrong
rule anchor, an ``identity`` selector (absent from an FP prologue), or a
``class`` slot narrower than the case entity drops it.

Resolves the observation row from the active pending queue (default
``_pending/environment_observations.jsonl`` — the row is still present
during the author run; the queue rotates only on AUTHOR_RESULT
post-flight). Prints exactly ``GOOD`` or ``BAD`` on its last line.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
RETRIEVE = REPO_ROOT / "defender" / "scripts" / "lessons_env_retrieve.py"
DEFAULT_PENDING = HERE / "_pending" / "environment_observations.jsonl"
DEFAULT_CORPUS = REPO_ROOT / "defender" / "lessons-environment"


def load_observation(observation_id: str, pending: Path) -> dict:
    if not pending.is_file():
        raise SystemExit(f"verify_forward_env: pending queue not found at {pending}")
    with pending.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("observation_id") == observation_id:
                return row
    raise SystemExit(
        f"verify_forward_env: observation_id {observation_id!r} not found in {pending}"
    )


def _entities_arg(entities: object) -> str:
    """[{type, class}, ...] -> 'type:class,type:class' for the retrieval CLI."""
    out: list[str] = []
    for sel in entities or []:
        if not isinstance(sel, dict):
            continue
        typ = str(sel.get("type") or "").strip()
        cls = str(sel.get("class") or "").strip()
        if typ:
            out.append(f"{typ}:{cls}")
    return ",".join(out)


def _rule_ids_arg(rule_ids: object) -> str:
    if isinstance(rule_ids, list):
        return ",".join(str(r).strip() for r in rule_ids if str(r).strip())
    return str(rule_ids or "").strip()


def run_retrieval(rule_ids: str, entities: str, corpus: Path) -> list[str]:
    """Return the list of repo-relative lesson paths the retrieval emits."""
    cmd = [sys.executable, str(RETRIEVE), "--corpus", str(corpus)]
    if rule_ids:
        cmd += ["--alert-rule-ids", rule_ids]
    if entities:
        cmd += ["--entities", entities]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"verify_forward_env: retrieval failed (rc={proc.returncode}): "
            f"{proc.stderr[-2000:]}"
        )
    paths: list[str] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        paths.append(line.split("\t", 1)[0])
    return paths


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="verify_forward_env.py")
    ap.add_argument("--corpus", help="corpus dir the lesson was written to (default: defender/lessons-environment)")
    ap.add_argument("--pending", help="pending queue jsonl (default: _pending/environment_observations.jsonl)")
    ap.add_argument("lesson_path")
    ap.add_argument("observation_id")
    ns = ap.parse_args(argv[1:])

    corpus = Path(ns.corpus) if ns.corpus else DEFAULT_CORPUS
    pending = Path(ns.pending) if ns.pending else DEFAULT_PENDING
    lesson_path = Path(ns.lesson_path).resolve()
    if not lesson_path.is_file():
        print(f"verify_forward_env: lesson not found: {lesson_path}", file=sys.stderr)
        return 1

    row = load_observation(ns.observation_id, pending)
    rule_ids = _rule_ids_arg(row.get("alert_rule_ids"))
    entities = _entities_arg(row.get("entities"))

    returned = run_retrieval(rule_ids, entities, corpus)
    try:
        rel = str(lesson_path.relative_to(REPO_ROOT))
    except ValueError:
        rel = str(lesson_path)
    # The retrieval prints repo-relative paths; match on basename too in case
    # the corpus dir sits outside the repo root (e.g. a validation tmp dir).
    target_names = {rel, lesson_path.name}
    hit = any(p in target_names or Path(p).name == lesson_path.name for p in returned)
    print("GOOD" if hit else "BAD")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
