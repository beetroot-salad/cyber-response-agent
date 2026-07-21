#!/usr/bin/env python3
"""Thin one-shot actor-stage entrypoint for the secondary-metric replay.

The secondary harness (``defender/evals/secondary.py``) needs
to invoke the actor stage *inside a worktree pinned to gen-{N-K}* —
where the worktree's ``loop.py`` ships the actor.md / mitre_corpus /
lessons-actor / model-pin state of that older generation. The full
``loop.run_one`` runs oracle + judge + persist + queue, which the
harness explicitly does *not* want from the frozen worktree (those
stages must run at HEAD). This script exposes just the actor stage:
project the HEAD-produced two tables (executed_queries.jsonl +
gather_raw/) to an actor-facing view via ``lead_repository``, invoke
the actor, write ``actor_story.md``.

This script is the **replay compatibility boundary**. Generations
whose worktree does not ship ``replay_actor.py`` (or ``lead_repository.py``)
are reported by the secondary harness as ``replay-incompatible``;
pre-migration archives carrying ``lead_sequence.yaml`` (not the tables)
are likewise incompatible. The metric is meaningful starting at the
first generation that ships both.

Usage:
  python3 defender/learning/replay_actor.py <staging_dir>

Required inputs in ``<staging_dir>``:
  - alert.json
  - gather_raw/          (the leads table; queries table optional)

Outputs in ``<staging_dir>``:
  - actor_input.yaml     (actor-facing, queries-only projection)
  - actor_archetype.txt
  - actor_menu.txt
  - actor_story.md
  - actor_trace.jsonl    (if a transcript was captured)

Exit codes:
  0  story written (any content — including SKIP)
  2  invocation failed (missing inputs, projection error, model/timeout error)
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import yaml

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._run_paths import RunPaths  # noqa: E402 — after the sys.path bootstrap
from defender.learning.core.config import source_first_party_key  # noqa: E402 — after bootstrap


def _load_sibling(modname: str, path: Path):
    spec = importlib.util.spec_from_file_location(modname, path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("staging_dir", help="dir containing alert.json + gather_raw/")
    p.add_argument("--case-id", default=None,
                   help="stable case id for actor seed/menu/archetype "
                        "(defaults to staging_dir.name). The harness should "
                        "pass a value that does NOT include per-attempt "
                        "suffixes so reruns sample the same menu.")
    ns = p.parse_args(argv)

    staging = Path(ns.staging_dir).resolve()
    staging_paths = RunPaths(staging)
    alert = staging_paths.alert
    if not alert.is_file():
        print(f"missing {alert}", file=sys.stderr)
        return 2
    if not staging_paths.gather_raw.is_dir() and not staging_paths.executed_queries.is_file():
        print(f"missing the lead/query tables under {staging} "
              f"({staging_paths.gather_raw.name}/ + {staging_paths.executed_queries.name})",
              file=sys.stderr)
        return 2

    here = Path(__file__).resolve().parent
    learning = here.parent
    sub = _load_sibling(
        "_defender_learning_subagents_replay",
        learning / "pipeline" / "malicious_actor" / "run.py",
    )
    lr = _load_sibling("_defender_learning_lead_repository_replay", learning / "lead_repository.py")

    source_first_party_key(sub.ACTOR_MODEL, label="actor")

    case_id = ns.case_id or staging.name
    view = lr.actor_view(staging)
    view["case_id"] = case_id
    view.setdefault("alert_ref", "alert.json")

    actor_input = staging / "actor_input.yaml"
    actor_input.write_text(yaml.safe_dump(view, sort_keys=False), encoding="utf-8")

    original_seed = sub._actor_seed
    sub._actor_seed = lambda _run_id, _stable=case_id: original_seed(_stable)
    try:
        story = sub.invoke_actor(alert, actor_input, staging)
    except sub.RunUnprocessable as e:
        print(f"actor invocation failed: {e}", file=sys.stderr)
        return 2
    finally:
        sub._actor_seed = original_seed

    (staging / "actor_story.md").write_text(story, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
