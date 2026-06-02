#!/usr/bin/env python3
"""Thin one-shot actor-stage entrypoint for the secondary-metric replay.

The secondary harness (``defender/learning/eval_secondary.py``) needs
to invoke the actor stage *inside a worktree pinned to gen-{N-K}* —
where the worktree's ``loop.py`` ships the actor.md / mitre_corpus /
lessons-actor / model-pin state of that older generation. The full
``loop.run_one`` runs oracle + judge + persist + queue, which the
harness explicitly does *not* want from the frozen worktree (those
stages must run at HEAD). This script exposes just the actor stage:
project the HEAD-produced ``lead_sequence.yaml`` to an actor-facing
view, invoke the actor, write ``actor_story.md``.

This script is the **replay compatibility boundary**. Generations
whose worktree does not ship ``replay_actor.py`` are reported by the
secondary harness as ``replay-incompatible``; the metric becomes
meaningful starting at the first generation that includes it.

Usage:
  python3 defender/learning/replay_actor.py <staging_dir>

Required inputs in ``<staging_dir>``:
  - alert.json
  - lead_sequence.yaml   (HEAD-produced; schema must parse here)

Outputs in ``<staging_dir>``:
  - actor_input.yaml     (actor-facing projection of lead_sequence)
  - actor_archetype.txt
  - actor_menu.txt
  - actor_story.md
  - actor_trace.jsonl    (if a transcript was captured)

Exit codes:
  0  story written (any content — including SKIP)
  2  invocation failed (missing inputs, projection error, claude rc!=0)
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import yaml


def _load_sibling(modname: str, path: Path):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("staging_dir", help="dir containing alert.json + lead_sequence.yaml")
    p.add_argument("--case-id", default=None,
                   help="stable case id for actor seed/menu/archetype "
                        "(defaults to staging_dir.name). The harness should "
                        "pass a value that does NOT include per-attempt "
                        "suffixes so reruns sample the same menu.")
    ns = p.parse_args(argv)

    staging = Path(ns.staging_dir).resolve()
    alert = staging / "alert.json"
    lead_seq = staging / "lead_sequence.yaml"
    if not alert.is_file():
        print(f"missing {alert}", file=sys.stderr)
        return 2
    if not lead_seq.is_file():
        print(f"missing {lead_seq}", file=sys.stderr)
        return 2

    here = Path(__file__).resolve().parent
    repo_root = here.parents[1]
    # Load the actor stage + projector from *this worktree* so all sibling refs
    # (actor.md, mitre_corpus.py, lessons-actor/) resolve to the pinned generation,
    # not HEAD. The actor lives in _loop_subagents.py (loop.py is a thin facade).
    sub = _load_sibling("_defender_learning_subagents_replay", here / "_loop_subagents.py")
    pls = _load_sibling(
        "_defender_scripts_project_lead_sequence_replay",
        repo_root / "defender" / "scripts" / "project_lead_sequence.py",
    )

    try:
        full_doc = yaml.safe_load(lead_seq.read_text())
    except yaml.YAMLError as e:
        print(f"lead_sequence.yaml parse failed: {e}", file=sys.stderr)
        return 2
    if not isinstance(full_doc, dict) or "entries" not in full_doc:
        print("lead_sequence.yaml missing top-level entries list", file=sys.stderr)
        return 2

    # Re-stamp case_id to the caller-supplied stable id so the actor's
    # seed/menu/archetype is keyed on (generation, alert) — independent
    # of the staging dir name, which carries a per-attempt suffix so
    # filesystem dirs don't collide across reruns. Without this split,
    # retry identity would perturb catch rate.
    case_id = ns.case_id or staging.name
    full_doc = dict(full_doc)
    full_doc["case_id"] = case_id
    full_doc.setdefault("alert_ref", "alert.json")

    actor_input = staging / "actor_input.yaml"
    actor_input.write_text(pls.dump_actor_yaml(pls.project_actor(full_doc)))

    # invoke_actor seeds menu/archetype from learning_run_dir.name —
    # but in replay we want the seed keyed on the stable case_id
    # (independent of any per-attempt suffix in the staging dir name).
    # Pin the seed by overriding _actor_seed for the duration of the
    # call; all other actor artifacts (archetype, menu, story,
    # transcript) still land in `staging` as the harness expects.
    original_seed = sub._actor_seed
    sub._actor_seed = lambda _run_id, _stable=case_id: original_seed(_stable)
    try:
        story = sub.invoke_actor(alert, actor_input, staging)
    except sub.LoopError as e:
        print(f"actor invocation failed: {e}", file=sys.stderr)
        return 2
    finally:
        sub._actor_seed = original_seed

    (staging / "actor_story.md").write_text(story)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
