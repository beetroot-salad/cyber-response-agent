#!/usr/bin/env python3
"""Tabulate fold/new/skip outcomes per probe across trials.

Reads each trial's snapshot under ``runs-out/trial-{i}/``:
  - ``lessons-actor-final/`` — final state of the corpus
  - ``_pending-final/actor_observations.consumed.jsonl`` — per-row
    consumed records with the disposition the author emitted
    (``fold`` / ``new`` / ``skip`` / ``consumed_skip``)

For each probe (uf-P1..uf-P4) we classify the outcome:
  - fold       — observation_id appears in some existing seed's
                 source_observation_ids (true fold into a pre-existing
                 seed slug)
  - fold-into-new — observation_id is in a non-seed file's
                 source_observation_ids (the author created a new file
                 and the same lesson got grouped with another probe)
  - new        — observation_id is the only id on a new file
  - skip       — consumed with skip / consumed_skip reason
  - other      — unaccounted (e.g., trial errored out)

Per-probe target seed (from README):
  uf-P1 → tradecraft/credential-spray-stagger
  uf-P2 → environment/docker-exec-args-not-in-audit
  uf-P3 → (no target — should be new)
  uf-P4 → tradecraft/credential-spray-stagger (fold-extends)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SEED_SLUGS = {
    "credential-spray-stagger",
    "dev-container-label-cover",
    "docker-exec-args-not-in-audit",
}

PROBE_TARGETS = {
    "uf-P1/0": ("fold", "credential-spray-stagger"),
    "uf-P2/0": ("fold", "docker-exec-args-not-in-audit"),
    "uf-P3/0": ("new", None),
    "uf-P4/0": ("fold", "credential-spray-stagger"),
}

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_frontmatter(path: Path) -> dict:
    """Tiny YAML-ish parser: list values via [a,b], scalars otherwise."""
    text = path.read_text()
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    fm: dict = {}
    for line in m.group(1).splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            fm[k] = [s.strip() for s in inner.split(",") if s.strip()]
        else:
            fm[k] = v
    return fm


def classify_probe(trial_dir: Path, observation_id: str) -> dict:
    """Return {outcome, target_slug, target_channel, body_touched}."""
    lessons_root = trial_dir / "lessons-actor-final"
    found: list[tuple[str, str, list[str]]] = []  # (channel, slug, ids)
    if lessons_root.exists():
        for channel in ("tradecraft", "environment"):
            cdir = lessons_root / channel
            if not cdir.exists():
                continue
            for path in sorted(cdir.glob("*.md")):
                fm = parse_frontmatter(path)
                ids = fm.get("source_observation_ids") or []
                if isinstance(ids, str):
                    ids = [ids]
                # Strip [] residue
                ids = [i.strip("[],") for i in ids if i.strip("[],")]
                if observation_id in ids:
                    found.append((channel, path.stem, ids))

    # Consult consumed.jsonl for skip detection
    consumed_path = trial_dir / "_pending-final" / "actor_observations.consumed.jsonl"
    consumed_action = None
    if consumed_path.exists():
        for line in consumed_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("observation_id") == observation_id:
                consumed_action = row.get("consumed_category") or row.get("action") or row.get("status")
                break

    if not found:
        if consumed_action and "skip" in str(consumed_action).lower():
            return {"outcome": "skip", "target_slug": None, "target_channel": None,
                    "consumed_action": consumed_action}
        return {"outcome": "other", "target_slug": None, "target_channel": None,
                "consumed_action": consumed_action}

    # If id is in a seed slug → fold-into-seed
    seed_hits = [(c, s, ids) for (c, s, ids) in found if s in SEED_SLUGS]
    if seed_hits:
        c, s, ids = seed_hits[0]
        outcome = "fold" if len(ids) > 1 else "fold-solo"
        return {"outcome": outcome, "target_slug": s, "target_channel": c,
                "other_ids": [i for i in ids if i != observation_id]}

    # Non-seed file → new (or grouped-into-new)
    c, s, ids = found[0]
    outcome = "new" if len(ids) == 1 else "fold-into-new"
    return {"outcome": outcome, "target_slug": s, "target_channel": c,
            "other_ids": [i for i in ids if i != observation_id]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--runs-out", default=str(Path(__file__).parent / "runs-out"),
        help="Directory containing trial-* subdirs.",
    )
    args = ap.parse_args()

    runs_out = Path(args.runs_out).resolve()
    trials = sorted([p for p in runs_out.glob("trial-*") if p.is_dir()])
    if not trials:
        print(f"No trial dirs found under {runs_out}", file=sys.stderr)
        return 1

    # Per-probe rollup
    rollup: dict[str, dict[str, int]] = {pid: {} for pid in PROBE_TARGETS}
    detail: dict[str, list] = {pid: [] for pid in PROBE_TARGETS}

    for trial in trials:
        for pid in PROBE_TARGETS:
            res = classify_probe(trial, pid)
            outcome = res["outcome"]
            rollup[pid][outcome] = rollup[pid].get(outcome, 0) + 1
            detail[pid].append({"trial": trial.name, **res})

    n = len(trials)
    print(f"# Underfold stress test — n={n} trials\n")
    print("## Per-probe rollup\n")
    print("| Probe | Expected | Outcomes |")
    print("|---|---|---|")
    for pid, (exp_outcome, exp_slug) in PROBE_TARGETS.items():
        exp = f"{exp_outcome}" + (f" → {exp_slug}" if exp_slug else "")
        breakdown = ", ".join(f"{k}={v}/{n}" for k, v in sorted(rollup[pid].items()))
        print(f"| {pid} | {exp} | {breakdown} |")
    print()
    print("## Per-trial detail\n")
    for pid in PROBE_TARGETS:
        print(f"### {pid}")
        for d in detail[pid]:
            slug = d.get("target_slug") or "—"
            channel = d.get("target_channel") or "—"
            other = d.get("other_ids") or []
            ca = d.get("consumed_action")
            note = f" (consumed_action={ca})" if ca else ""
            other_note = f" other_ids={other}" if other else ""
            print(f"- {d['trial']}: **{d['outcome']}** → {channel}/{slug}{other_note}{note}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
