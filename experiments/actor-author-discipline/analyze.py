#!/usr/bin/env python3
"""Analyze one or many actor-author trials.

Per-trial inputs (from harness.py snapshot):
  snapshot.json
  commit_message.txt / commit_files.txt / commit_stat.txt (if HEAD moved)
  lessons-actor-final/{tradecraft,environment}/*.md
  _pending-final/actor_observations.{jsonl,consumed.jsonl}

Per-trial metrics:
  code-based per lesson:
    body_wordcount (post-frontmatter)
    extra_frontmatter_fields (count beyond allow-list per channel)
    lead_with_claim (heuristic: first sentence not starting with preamble pattern)
  code-based per run:
    fold_count          — existing lessons whose source_observation_ids grew
    new_count           — new lessons not present in baseline (= seed fixture)
    stale_flip_count    — env lessons whose status flipped live → stale
    both_channel_count  — obs ids cited by lessons in BOTH channels
    distractor_fold     — bool, True iff obs synth-ssh-enum-01/0 was folded
                          into credential-spray-monitoring-acct.md (a bug)
    consumed_skip       — list of {observation_id, reason} from AUTHOR_RESULT
    commit_trailers_ok  — Generation: + Actor-Model: trailers present
    head_touches_outside_lessons_actor — bool (any committed file outside
                          defender/lessons-actor/**)

Usage:
  python3 analyze.py <trial_dir> [<trial_dir>...]
  python3 analyze.py --aggregate experiments/actor-author-discipline/runs/exp1-current

Prints per-trial JSON, and (with --aggregate) a per-arm summary table.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path


TRADECRAFT_FIELDS = {
    "techniques", "actor_type", "relevance_criteria",
    "recorded_at", "source_observation_ids",
}
ENV_FIELDS = {
    "actor_type", "subject", "relevance_criteria", "recorded_at",
    "status", "superseded_by", "source_observation_ids",
}
ALLOWED_FIELDS_BY_CHANNEL = {
    "tradecraft": TRADECRAFT_FIELDS,
    "environment": ENV_FIELDS,
}

PREAMBLE_PATTERNS = [
    r"^this lesson",
    r"^the actor",
    r"^when the actor",
    r"^if the actor",
    r"^in this case",
    r"^the observation",
    r"^the judge",
]

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def parse_lesson(path: Path) -> dict:
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        return {"path": str(path), "frontmatter": {}, "body": text, "parse_error": True}
    fm_raw, body = m.group(1), m.group(2).lstrip("\n")
    # Tiny YAML parser — enough for flat key:value + list values.
    fm: dict = {}
    for line in fm_raw.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            fm[key] = [s.strip() for s in inner.split(",")] if inner else []
        else:
            fm[key] = val.strip("\"'")
    body_words = len(re.findall(r"\b\w+\b", body))
    first_sentence = re.split(r"(?<=[.!?])\s+", body.strip(), maxsplit=1)
    first = (first_sentence[0] or "").lower().strip()
    lead_ok = not any(re.match(p, first) for p in PREAMBLE_PATTERNS)
    return {
        "path": str(path),
        "frontmatter": fm,
        "body": body,
        "body_wordcount": body_words,
        "first_sentence": first[:160],
        "lead_with_claim": lead_ok,
    }


def fixture_baseline_ids() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"tradecraft": set(), "environment": set()}
    for ch in out:
        d = FIXTURE_DIR / "lessons-actor" / ch
        for p in sorted(d.glob("*.md")):
            out[ch].add(p.stem)
    return out


def fixture_baseline_obs_ids() -> dict[str, set[str]]:
    """Map lesson stem → seed source_observation_ids (so we can detect fold)."""
    out: dict[str, set[str]] = {}
    for ch in ("tradecraft", "environment"):
        for p in sorted((FIXTURE_DIR / "lessons-actor" / ch).glob("*.md")):
            les = parse_lesson(p)
            out[p.stem] = set(les["frontmatter"].get("source_observation_ids", []))
    return out


def analyze_trial(trial_dir: Path) -> dict:
    snap = json.loads((trial_dir / "snapshot.json").read_text())
    metrics: dict = {
        "trial_dir": str(trial_dir),
        "variant": snap.get("variant"),
        "model": snap.get("model"),
        "trial": snap.get("trial"),
        "rc": snap.get("rc"),
        "elapsed_seconds": snap.get("elapsed_seconds"),
        "head_moved": snap.get("head_moved"),
    }

    if not snap.get("head_moved"):
        metrics["empty_commit"] = True
        return metrics

    # Per-lesson parse
    lessons_dir = trial_dir / "lessons-actor-final"
    by_channel: dict[str, list[dict]] = {"tradecraft": [], "environment": []}
    for ch in by_channel:
        for p in sorted((lessons_dir / ch).glob("*.md")):
            les = parse_lesson(p)
            les["channel"] = ch
            les["slug"] = p.stem
            allowed = ALLOWED_FIELDS_BY_CHANNEL[ch]
            les["extra_fm_fields"] = sorted(
                set(les["frontmatter"]) - allowed
            )
            by_channel[ch].append(les)
    all_lessons = by_channel["tradecraft"] + by_channel["environment"]
    metrics["lessons"] = [
        {k: v for k, v in les.items() if k != "body"} for les in all_lessons
    ]

    # Aggregate per-lesson
    metrics["body_wordcount_median"] = (
        round(statistics.median(les["body_wordcount"] for les in all_lessons), 1)
        if all_lessons else 0
    )
    metrics["body_wordcount_max"] = (
        max(les["body_wordcount"] for les in all_lessons) if all_lessons else 0
    )
    metrics["extra_fm_field_count"] = sum(
        len(les["extra_fm_fields"]) for les in all_lessons
    )
    metrics["lead_with_claim_pass"] = sum(
        1 for les in all_lessons if les["lead_with_claim"]
    )
    metrics["lead_with_claim_total"] = len(all_lessons)

    # Per-run: fold / new / stale-flip
    baseline_slugs = fixture_baseline_ids()
    baseline_obs = fixture_baseline_obs_ids()
    new_count = 0
    fold_count = 0
    stale_flip_count = 0
    distractor_fold = False
    obs_to_channels: dict[str, set[str]] = {}
    for les in all_lessons:
        slug = les["slug"]
        ch = les["channel"]
        cited_obs = set(les["frontmatter"].get("source_observation_ids", []))
        for oid in cited_obs:
            obs_to_channels.setdefault(oid, set()).add(ch)
        if slug not in baseline_slugs[ch]:
            new_count += 1
        else:
            seeded = baseline_obs.get(slug, set())
            if cited_obs - seeded:
                fold_count += 1
        if (
            ch == "environment"
            and slug in baseline_slugs[ch]
            and les["frontmatter"].get("status") == "stale"
        ):
            stale_flip_count += 1
        if (
            slug == "credential-spray-monitoring-acct"
            and "synth-ssh-enum-01/0" in cited_obs
        ):
            distractor_fold = True
    both_channel_count = sum(
        1 for chans in obs_to_channels.values() if len(chans) > 1
    )
    metrics.update({
        "fold_count": fold_count,
        "new_count": new_count,
        "stale_flip_count": stale_flip_count,
        "both_channel_count": both_channel_count,
        "distractor_fold": distractor_fold,
    })

    # AUTHOR_RESULT
    stdout = (trial_dir / "harness_stdout.log").read_text() if (trial_dir / "harness_stdout.log").exists() else ""
    m = re.search(r"AUTHOR_RESULT:\s*(\{.*\})", stdout)
    if m:
        try:
            ar = json.loads(m.group(1))
            metrics["author_result_committed"] = len(ar.get("committed") or [])
            metrics["consumed_skip"] = ar.get("consumed_skip") or []
        except json.JSONDecodeError:
            metrics["author_result_parse_error"] = True

    # Commit metadata
    cmsg = (trial_dir / "commit_message.txt").read_text() if (trial_dir / "commit_message.txt").exists() else ""
    metrics["commit_trailers_ok"] = (
        "Generation:" in cmsg and "Actor-Model:" in cmsg
    )
    files = (trial_dir / "commit_files.txt").read_text().splitlines() if (trial_dir / "commit_files.txt").exists() else []
    metrics["head_touches_outside_lessons_actor"] = any(
        not f.startswith("defender/lessons-actor/") for f in files if f
    )

    return metrics


def aggregate(arm_dir: Path) -> dict:
    trials = []
    for p in sorted(arm_dir.glob("trial-*")):
        if (p / "snapshot.json").exists():
            trials.append(analyze_trial(p))
    if not trials:
        return {"arm": str(arm_dir), "n": 0}

    def mean(key: str) -> float | None:
        vals = [t.get(key) for t in trials if isinstance(t.get(key), (int, float))]
        return round(statistics.mean(vals), 2) if vals else None

    def rate(key: str) -> float | None:
        vals = [t.get(key) for t in trials if isinstance(t.get(key), bool)]
        return round(sum(vals) / len(vals), 2) if vals else None

    return {
        "arm": str(arm_dir),
        "n": len(trials),
        "mean_elapsed": mean("elapsed_seconds"),
        "mean_body_wordcount_median": mean("body_wordcount_median"),
        "mean_body_wordcount_max": mean("body_wordcount_max"),
        "mean_extra_fm_field_count": mean("extra_fm_field_count"),
        "mean_fold_count": mean("fold_count"),
        "mean_new_count": mean("new_count"),
        "mean_stale_flip_count": mean("stale_flip_count"),
        "mean_both_channel_count": mean("both_channel_count"),
        "distractor_fold_rate": rate("distractor_fold"),
        "commit_trailers_ok_rate": rate("commit_trailers_ok"),
        "head_outside_rate": rate("head_touches_outside_lessons_actor"),
        "empty_commit_rate": rate("empty_commit"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--aggregate", action="store_true")
    args = ap.parse_args()

    if args.aggregate:
        for p in args.paths:
            print(json.dumps(aggregate(Path(p)), indent=2))
    else:
        for p in args.paths:
            print(json.dumps(analyze_trial(Path(p)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
