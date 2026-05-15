#!/usr/bin/env python3
"""Tabulate v2 underfold outcomes per probe across trials.

Reads each trial's snapshot under ``runs-out/trial-{i}/``:
  - ``lessons-actor-final/`` — final v2 flat corpus
  - ``_pending-final/actor_observations.consumed.jsonl`` — per-row
    consumed records with the disposition the author emitted

For each probe we collect every lesson file referencing the
observation_id (decomposition produces multiple), then classify:
  - fold        — id lands on >=1 seed file (existing v2 seed slug)
  - new         — id lands on >=1 new file, no seed touched
  - decomposed  — id lands on >=2 files (mix of seed + new, or 2 new);
                  flag in addition to fold/new
  - skip        — consumed with skip / consumed_skip reason
  - other       — unaccounted (trial errored out)

Per-probe target (v2):
  uf-P1 → fold credential-spray-stagger (5712 volume detector)
          decomposition may add wazuh-rule-5712-threshold env-fact
  uf-P2 → fold container-side-execve-omits-argv (host-side argv fork)
  uf-P3 → new (5701 banner fetch — no seed covers this)
  uf-P4 → fold-or-decompose: extends credential-spray-stagger and/or
          new auth-pipeline-breach-enricher env-fact
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
    "container-side-execve-omits-argv",
}

PROBE_TARGETS = {
    "uf-P1/0": ("fold", ["credential-spray-stagger"]),
    "uf-P2/0": ("fold", ["container-side-execve-omits-argv"]),
    "uf-P3/0": ("new", []),
    "uf-P4/0": ("fold|decompose", ["credential-spray-stagger"]),
}

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_frontmatter(path: Path) -> dict:
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
    lessons_root = trial_dir / "lessons-actor-final"
    found: list[dict] = []
    if lessons_root.exists():
        candidates = list(lessons_root.glob("*.md"))
        for sub in ("tradecraft", "environment"):
            if (lessons_root / sub).exists():
                candidates += list((lessons_root / sub).glob("*.md"))
        for path in sorted(candidates):
            if path.name.startswith("_"):
                continue
            fm = parse_frontmatter(path)
            ids = fm.get("source_observation_ids") or []
            if isinstance(ids, str):
                ids = [ids]
            ids = [i.strip("[],\"' ") for i in ids if i.strip("[],\"' ")]
            if observation_id in ids:
                found.append({
                    "slug": path.stem,
                    "subject": fm.get("subject"),
                    "techniques": fm.get("techniques") or [],
                    "applies_to": fm.get("applies_to") or [],
                    "mutable": fm.get("mutable"),
                    "ids": ids,
                })

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
                consumed_action = (
                    row.get("consumed_category")
                    or row.get("action")
                    or row.get("status")
                )
                break

    if not found:
        if consumed_action and "skip" in str(consumed_action).lower():
            return {"outcome": "skip", "consumed_action": consumed_action, "files": []}
        return {"outcome": "other", "consumed_action": consumed_action, "files": []}

    seed_hits = [f for f in found if f["slug"] in SEED_SLUGS]
    new_hits = [f for f in found if f["slug"] not in SEED_SLUGS]
    decomposed = len(found) >= 2
    outcome = "fold" if seed_hits else "new"

    return {
        "outcome": outcome,
        "decomposed": decomposed,
        "n_files": len(found),
        "n_seed_files": len(seed_hits),
        "n_new_files": len(new_hits),
        "files": [
            {"slug": f["slug"], "subject": f["subject"],
             "techniques": f["techniques"], "applies_to": f["applies_to"]}
            for f in found
        ],
        "consumed_action": consumed_action,
    }


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

    rollup: dict[str, dict[str, int]] = {pid: {} for pid in PROBE_TARGETS}
    decomp_counts: dict[str, int] = {pid: 0 for pid in PROBE_TARGETS}
    detail: dict[str, list] = {pid: [] for pid in PROBE_TARGETS}

    for trial in trials:
        for pid in PROBE_TARGETS:
            res = classify_probe(trial, pid)
            outcome = res["outcome"]
            rollup[pid][outcome] = rollup[pid].get(outcome, 0) + 1
            if res.get("decomposed"):
                decomp_counts[pid] += 1
            detail[pid].append({"trial": trial.name, **res})

    n = len(trials)
    print(f"# Underfold v2 stress test — n={n} trials\n")
    print("## Per-probe rollup\n")
    print("| Probe | Expected | Outcomes | Decomposed |")
    print("|---|---|---|---|")
    for pid, (exp_outcome, exp_slugs) in PROBE_TARGETS.items():
        exp = exp_outcome + (f" → {','.join(exp_slugs)}" if exp_slugs else "")
        breakdown = ", ".join(f"{k}={v}/{n}" for k, v in sorted(rollup[pid].items()))
        print(f"| {pid} | {exp} | {breakdown} | {decomp_counts[pid]}/{n} |")
    print()
    print("## Per-trial detail\n")
    for pid in PROBE_TARGETS:
        print(f"### {pid}")
        for d in detail[pid]:
            files = d.get("files") or []
            file_summary = ", ".join(
                f"{f['slug']}"
                + (f" [subject={f['subject']}]" if f.get('subject') else "")
                + (f" [techniques={f['techniques']}]" if f.get('techniques') else "")
                + (f" [applies_to={f['applies_to']}]" if f.get('applies_to') else "")
                for f in files
            ) or "—"
            decomp_tag = " (decomposed)" if d.get("decomposed") else ""
            ca = d.get("consumed_action")
            ca_note = f" consumed_action={ca}" if ca else ""
            print(f"- {d['trial']}: **{d['outcome']}**{decomp_tag} → {file_summary}{ca_note}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
