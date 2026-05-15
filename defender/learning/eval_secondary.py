#!/usr/bin/env python3
"""Secondary-metric harness — frozen-actor replay catch rate.

Where the primary metric (``eval_held_out.py``) asks "does the
current defender disposition match ground truth on held-out alerts?"
the secondary asks "would the current defender's lead sequence refute
stories an *older* actor writes?"

Divergence between the two (primary plateaus, secondary climbs) is
the diagnostic signal: defender is gaining curriculum-distribution
capability without target-distribution capability. See
``defender/docs/learning-loop-actor-learning.md`` §Secondary.

Pipeline per eligible alert:

  1. Current defender (HEAD) investigates the alert via
     ``defender/run.py --no-learn`` — produces ``report.md`` +
     ``lead_sequence.yaml``.
  2. Filter eligibility: ground-truth must be benign or
     inconclusive. Malicious held-out is primary-only.
  3. Filter executed: HEAD defender must not have escalated
     (``disposition != malicious``). False escalations drop out of
     the catch-rate denominator and are reported as
     ``not_executed``.
  4. Frozen actor (gen-{N-K} worktree) writes a story via
     ``defender/learning/replay_actor.py``, reading the HEAD
     defender's ``lead_sequence.yaml``. Model is pinned from the
     gen-{N-K} commit's ``Actor-Model:`` trailer.
  5. Current oracle + judge (HEAD) grade the story against the
     defender's lead sequence.

Catch rate = caught / (caught + survived + incoherent + undecidable)
over the executed set. ``skip-passthrough`` (frozen actor declined
to write a story) is excluded from the denominator and reported
separately as SKIP rate.

Usage:
  python3 defender/learning/eval_secondary.py [--k 3] [--out <dir>]

The harness writes no commits and creates no queue entries.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
EVAL_OUT_DIR = LEARNING_DIR / "eval" / "secondary"
FIXTURES_DIR = REPO_ROOT / "defender" / "fixtures" / "held-out"
WORKTREES_DIR = REPO_ROOT / ".claude" / "worktrees"

DEFAULT_RUNS_BASE = Path(os.environ.get("DEFENDER_RUNS_BASE", "/tmp/defender-runs"))

ELIGIBLE_DISPOSITIONS = {"benign", "inconclusive"}
ESCALATED_DISPOSITION = "malicious"
SKIP_OUTCOME = "skip-passthrough"
CATCH_OUTCOMES = {"caught", "survived", "incoherent", "undecidable"}


class SecondaryError(Exception):
    pass


# ---------------------------------------------------------------------------
# loop.py shims — load on demand so tests can import this module without
# pulling pyyaml-only loop dependencies into the import path.
# ---------------------------------------------------------------------------

def _load_loop():
    spec = importlib.util.spec_from_file_location(
        "_defender_learning_loop_secondary", LEARNING_DIR / "loop.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_defender_learning_loop_secondary", mod)
    spec.loader.exec_module(mod)
    return mod


def _load_shared():
    spec = importlib.util.spec_from_file_location(
        "_defender_learning_shared_secondary", LEARNING_DIR / "_author_shared.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_defender_learning_shared_secondary", mod)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Generation resolution
# ---------------------------------------------------------------------------

_TRAILER_GEN_RE = re.compile(r"^Generation:\s*(\d+)\s*$", re.MULTILINE)
_TRAILER_MODEL_RE = re.compile(r"^Actor-Model:\s*(\S.*?)\s*$", re.MULTILINE)


@dataclass
class GenerationPin:
    generation: int
    sha: str
    actor_model: str


def parse_trailers(commit_msg: str) -> tuple[int | None, str | None]:
    """Extract (Generation, Actor-Model) from a commit message body."""
    gm = _TRAILER_GEN_RE.search(commit_msg)
    mm = _TRAILER_MODEL_RE.search(commit_msg)
    gen = int(gm.group(1)) if gm else None
    model = mm.group(1) if mm else None
    return gen, model


def list_actor_commits(repo_root: Path) -> list[GenerationPin]:
    """Return all actor-author commits reachable from HEAD, latest first.

    Each entry carries the asserted generation + pinned actor model
    from the commit trailers. Commits missing either trailer are
    skipped with a stderr warning (defensive — the actor author
    asserts both, but malformed history shouldn't crash the harness).
    """
    proc = subprocess.run(
        [
            "git", "log",
            "--grep=^Actor-Model: ",
            "--format=__SHA__%H%n%B%n__END__",
            "HEAD",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    out: list[GenerationPin] = []
    for chunk in proc.stdout.split("__SHA__"):
        chunk = chunk.strip()
        if not chunk:
            continue
        sha, _, rest = chunk.partition("\n")
        body = rest.split("__END__", 1)[0]
        gen, model = parse_trailers(body)
        if gen is None or model is None:
            print(
                f"warning: actor-author commit {sha[:8]} missing trailer "
                f"(gen={gen!r}, model={model!r}) — skipping",
                file=sys.stderr,
            )
            continue
        out.append(GenerationPin(generation=gen, sha=sha, actor_model=model))
    return out


def resolve_target_pin(repo_root: Path, k: int) -> GenerationPin | None:
    """Find the actor-author commit asserting Generation: (latest - k).

    Returns None when no eligible target exists yet (history shorter
    than k commits, or the asserted generations don't cover the
    target). The harness reports this as ``replay-incompatible`` and
    exits 0 — the secondary metric is simply not yet meaningful.
    """
    commits = list_actor_commits(repo_root)
    if not commits:
        return None
    latest_gen = max(c.generation for c in commits)
    target_gen = latest_gen - k
    if target_gen < 1:
        return None
    for c in commits:
        if c.generation == target_gen:
            return c
    return None


# ---------------------------------------------------------------------------
# Worktree management
# ---------------------------------------------------------------------------

def worktree_path_for(pin: GenerationPin) -> Path:
    return WORKTREES_DIR / f"replay-gen-{pin.generation}"


def ensure_worktree(pin: GenerationPin, repo_root: Path) -> Path:
    """Idempotent: create the gen-{N-K} worktree if missing.

    Detached HEAD at the pinned SHA. Re-uses an existing worktree
    silently; the harness never mutates the worktree, so reuse is
    safe across runs.
    """
    path = worktree_path_for(pin)
    if path.is_dir() and (path / ".git").exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(path), pin.sha],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return path


def worktree_has_replay_script(worktree: Path) -> bool:
    return (worktree / "defender" / "learning" / "replay_actor.py").is_file()


# ---------------------------------------------------------------------------
# Eligibility / fixtures
# ---------------------------------------------------------------------------

@dataclass
class HeldOutAlert:
    slug: str
    alert_path: Path
    ground_truth: dict


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    out: list[HeldOutAlert] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        alert = child / "alert.json"
        gt = child / "ground_truth.yaml"
        if not (alert.is_file() and gt.is_file()):
            continue
        gt_doc = yaml.safe_load(gt.read_text()) or {}
        if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
            continue
        out.append(HeldOutAlert(child.name, alert, gt_doc))
    return out


def eligible_for_secondary(alerts: list[HeldOutAlert]) -> list[HeldOutAlert]:
    return [a for a in alerts if a.ground_truth.get("disposition") in ELIGIBLE_DISPOSITIONS]


# ---------------------------------------------------------------------------
# Per-alert pipeline
# ---------------------------------------------------------------------------

@dataclass
class AlertResult:
    slug: str
    ground_truth: str
    status: str               # executed | not_executed | failed
    head_disposition: str | None = None
    judge_outcome: str | None = None  # caught/survived/incoherent/undecidable/skip-passthrough
    error: str | None = None
    head_run_dir: str | None = None
    replay_run_dir: str | None = None

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "ground_truth": self.ground_truth,
            "status": self.status,
            "head_disposition": self.head_disposition,
            "judge_outcome": self.judge_outcome,
            "error": self.error,
            "head_run_dir": self.head_run_dir,
            "replay_run_dir": self.replay_run_dir,
        }


def run_head_defender(
    alert: HeldOutAlert,
    run_id: str,
    runs_base: Path,
    *,
    runner: "subprocess._RunFn" = subprocess.run,
) -> Path:
    """Invoke ``defender/run.py --no-learn`` and return the run dir.

    The run dir is created by ``run.py`` under ``$DEFENDER_RUNS_BASE``;
    we return the expected path so the caller can read its artifacts.
    """
    run_dir = runs_base / run_id
    env = os.environ.copy()
    env["DEFENDER_RUNS_BASE"] = str(runs_base)
    proc = runner(
        [
            sys.executable,
            str(REPO_ROOT / "defender" / "run.py"),
            str(alert.alert_path),
            "--run-id", run_id,
            "--no-learn",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SecondaryError(
            f"defender/run.py failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}"
        )
    if not run_dir.is_dir():
        raise SecondaryError(f"defender/run.py did not create {run_dir}")
    return run_dir


def read_head_disposition(run_dir: Path) -> str | None:
    """Parse ``report.md`` frontmatter, return disposition or None."""
    report = run_dir / "report.md"
    if not report.is_file():
        return None
    text = report.read_text()
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    try:
        fm = yaml.safe_load(text[3:end])
    except yaml.YAMLError:
        return None
    if not isinstance(fm, dict):
        return None
    disp = fm.get("disposition")
    return disp if isinstance(disp, str) else None


def run_frozen_actor(
    head_run_dir: Path,
    staging_dir: Path,
    worktree: Path,
    pin: GenerationPin,
    *,
    runner: "subprocess._RunFn" = subprocess.run,
) -> Path:
    """Invoke replay_actor.py in the gen-{N-K} worktree. Returns staging."""
    staging_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(head_run_dir / "alert.json", staging_dir / "alert.json")
    shutil.copy2(
        head_run_dir / "lead_sequence.yaml", staging_dir / "lead_sequence.yaml"
    )
    venv_python = worktree / "defender" / ".venv" / "bin" / "python3"
    # Walk-up the parent worktrees in case the pinned tree shares the
    # repo's venv with the main checkout (saves a `uv venv` per worktree).
    python = venv_python if venv_python.is_file() else Path(sys.executable)

    env = os.environ.copy()
    env["ACTOR_MODEL"] = pin.actor_model

    proc = runner(
        [
            str(python),
            str(worktree / "defender" / "learning" / "replay_actor.py"),
            str(staging_dir),
        ],
        cwd=str(worktree),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SecondaryError(
            f"replay_actor.py failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    if not (staging_dir / "actor_story.md").is_file():
        raise SecondaryError(f"replay_actor.py did not write actor_story.md in {staging_dir}")
    return staging_dir


def run_head_oracle_and_judge(
    head_run_dir: Path,
    staging_dir: Path,
    loop_mod,
) -> str:
    """Run HEAD oracle + judge against the frozen actor's story.

    Returns the judge outcome keyword. Raises ``SecondaryError`` on
    invalid oracle/judge output.
    """
    actor_story_path = staging_dir / "actor_story.md"
    actor_story = actor_story_path.read_text()
    if loop_mod.is_skip_story(actor_story):
        return SKIP_OUTCOME

    lead_seq_path = head_run_dir / "lead_sequence.yaml"
    lead_seq_text = lead_seq_path.read_text()
    exemplar_bundle = loop_mod.assemble_exemplar_bundle(head_run_dir, lead_seq_text)

    oracle_yaml = loop_mod.invoke_oracle(
        head_run_dir / "alert.json",
        actor_story_path,
        lead_seq_path,
        exemplar_bundle,
    )
    oracle_stripped = loop_mod.strip_yaml_fence(oracle_yaml)
    expected_positions = [
        e.get("position")
        for e in (yaml.safe_load(lead_seq_text) or {}).get("entries", [])
    ]
    try:
        oracle_doc = yaml.safe_load(oracle_stripped)
        loop_mod.validate_oracle_doc(oracle_doc, expected_positions)
    except (yaml.YAMLError, loop_mod.LoopError) as e:
        raise SecondaryError(f"oracle YAML invalid: {e}") from e
    projected_path = staging_dir / "projected_telemetry.yaml"
    projected_path.write_text(oracle_stripped)

    judge_yaml = loop_mod.invoke_judge(
        head_run_dir / "alert.json",
        head_run_dir / "investigation.md",
        actor_story_path,
        projected_path,
    )
    judge_stripped = loop_mod.strip_yaml_fence(judge_yaml)
    (staging_dir / "judge_findings.yaml").write_text(judge_stripped)
    try:
        judge_doc = yaml.safe_load(judge_stripped)
        loop_mod.validate_judge_doc(judge_doc)
    except (yaml.YAMLError, loop_mod.LoopError) as e:
        raise SecondaryError(f"judge YAML invalid: {e}") from e
    outcome = loop_mod._outcome_keyword(judge_doc["outcome"])
    return outcome


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@dataclass
class SecondarySummary:
    current_generation: int | None
    pinned_generation: int | None
    pinned_sha: str | None
    pinned_model: str | None
    k: int
    replay_incompatible_reason: str | None = None
    eligible: int = 0
    results: list[AlertResult] = field(default_factory=list)

    @property
    def executed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "executed"]

    @property
    def not_executed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "not_executed"]

    @property
    def failed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "failed"]

    @property
    def outcome_counts(self) -> dict[str, int]:
        counts = {o: 0 for o in CATCH_OUTCOMES | {SKIP_OUTCOME}}
        for r in self.executed:
            if r.judge_outcome in counts:
                counts[r.judge_outcome] += 1
        return counts

    def catch_rate(self) -> tuple[int, int]:
        counts = self.outcome_counts
        denom = sum(counts[o] for o in CATCH_OUTCOMES)
        caught = counts["caught"]
        return caught, denom

    def to_index_row(self) -> dict:
        caught, denom = self.catch_rate()
        return {
            "current_generation": self.current_generation,
            "pinned_generation": self.pinned_generation,
            "pinned_sha": self.pinned_sha,
            "pinned_model": self.pinned_model,
            "k": self.k,
            "eligible": self.eligible,
            "executed": len(self.executed),
            "skip_passthrough": self.outcome_counts.get(SKIP_OUTCOME, 0),
            "failed": len(self.failed),
            "caught": caught,
            "catch_denominator": denom,
            "catch_rate": (caught / denom) if denom else None,
            "replay_incompatible_reason": self.replay_incompatible_reason,
        }


def format_summary_md(s: SecondarySummary) -> str:
    out: list[str] = []
    out.append(f"# Secondary metric — generation {s.current_generation}")
    out.append("")
    if s.replay_incompatible_reason is not None:
        out.append(f"**replay-incompatible:** {s.replay_incompatible_reason}")
        out.append("")
        out.append(f"current generation: {s.current_generation}")
        out.append(f"k: {s.k}")
        return "\n".join(out) + "\n"

    counts = s.outcome_counts
    caught, denom = s.catch_rate()
    rate = f"{caught}/{denom} = {caught/denom:.1%}" if denom else "n/a (0 executed)"
    out.append(f"pinned generation: {s.pinned_generation} "
               f"(sha {s.pinned_sha[:8] if s.pinned_sha else '?'}, "
               f"model {s.pinned_model})")
    out.append(f"k: {s.k}")
    out.append("")
    out.append(f"eligible: {s.eligible}")
    out.append(f"executed: {len(s.executed)}")
    out.append(f"not_executed (false escalations): {len(s.not_executed)}")
    out.append(f"failed: {len(s.failed)}")
    out.append(f"skip_passthrough: {counts[SKIP_OUTCOME]}")
    out.append("")
    out.append(f"**catch rate (executed, ex-skip): {rate}**")
    for o in ("caught", "survived", "incoherent", "undecidable"):
        out.append(f"  {o}: {counts[o]}")
    out.append("")
    out.append("## Per-alert detail")
    for r in s.results:
        line = f"- {r.slug} (gt={r.ground_truth}): status={r.status}"
        if r.head_disposition:
            line += f" head_disp={r.head_disposition}"
        if r.judge_outcome:
            line += f" outcome={r.judge_outcome}"
        if r.error:
            line += f" error={r.error}"
        out.append(line)
    out.append("")
    out.append("## Interpretation")
    out.append("")
    out.append(
        "Primary plateau + this secondary climbing across consecutive "
        "checkpoints is the divergence signal — defender gaining "
        "curriculum-fit without target-fit. A single point is not a "
        "verdict; see design doc §Plateau detection for the "
        "3-checkpoint slope rule and bootstrap-CI gating."
    )
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def write_summary(summary: SecondarySummary, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / f"gen-{summary.current_generation}.summary.md"
    md.write_text(format_summary_md(summary))

    detail_dir = out_dir / f"gen-{summary.current_generation}"
    detail_dir.mkdir(exist_ok=True)
    for r in summary.results:
        (detail_dir / f"{r.slug}.json").write_text(json.dumps(r.to_dict(), indent=2))

    index = out_dir / "index.jsonl"
    with index.open("a") as fh:
        fh.write(json.dumps(summary.to_index_row()) + "\n")
    return md


def run_secondary(
    *,
    k: int,
    out_dir: Path,
    runs_base: Path,
    fixtures_dir: Path,
    repo_root: Path,
) -> SecondarySummary:
    shared = _load_shared()
    n_next = shared.actor_generation_count()  # = 1 + prior committed
    n_committed = n_next - 1                  # latest committed gen
    summary = SecondarySummary(
        current_generation=n_committed,
        pinned_generation=None,
        pinned_sha=None,
        pinned_model=None,
        k=k,
    )

    if n_committed < 1:
        summary.replay_incompatible_reason = (
            f"no actor-author commits in history yet (current gen={n_committed})"
        )
        write_summary(summary, out_dir)
        return summary

    pin = resolve_target_pin(repo_root, k)
    if pin is None:
        summary.replay_incompatible_reason = (
            f"no commit asserts Generation {n_committed - k} "
            f"(need {k} prior actor-author commits, have {n_committed})"
        )
        write_summary(summary, out_dir)
        return summary

    summary.pinned_generation = pin.generation
    summary.pinned_sha = pin.sha
    summary.pinned_model = pin.actor_model

    worktree = ensure_worktree(pin, repo_root)
    if not worktree_has_replay_script(worktree):
        summary.replay_incompatible_reason = (
            f"gen-{pin.generation} worktree at {worktree} does not ship "
            f"defender/learning/replay_actor.py"
        )
        write_summary(summary, out_dir)
        return summary

    fixtures = load_held_out_fixtures(fixtures_dir)
    eligible = eligible_for_secondary(fixtures)
    summary.eligible = len(eligible)

    loop_mod = _load_loop()
    for alert in eligible:
        run_id = f"sec-eval-gen{n_committed}-{alert.slug}"
        result = AlertResult(
            slug=alert.slug,
            ground_truth=alert.ground_truth["disposition"],
            status="failed",
        )
        try:
            head_run_dir = run_head_defender(alert, run_id, runs_base)
            result.head_run_dir = str(head_run_dir)
            head_disp = read_head_disposition(head_run_dir)
            result.head_disposition = head_disp
            if head_disp == ESCALATED_DISPOSITION:
                result.status = "not_executed"
                summary.results.append(result)
                continue

            staging = runs_base / f"{run_id}-replay"
            run_frozen_actor(head_run_dir, staging, worktree, pin)
            result.replay_run_dir = str(staging)
            outcome = run_head_oracle_and_judge(head_run_dir, staging, loop_mod)
            result.judge_outcome = outcome
            result.status = "executed"
        except SecondaryError as e:
            result.error = str(e)[:500]
        summary.results.append(result)

    write_summary(summary, out_dir)
    return summary


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--k", type=int, default=3,
                   help="generations back to pin the frozen actor (default 3)")
    p.add_argument("--out", default=str(EVAL_OUT_DIR),
                   help=f"output dir (default: {EVAL_OUT_DIR})")
    p.add_argument("--runs-base", default=str(DEFAULT_RUNS_BASE),
                   help=f"defender runs base (default: {DEFAULT_RUNS_BASE})")
    p.add_argument("--fixtures", default=str(FIXTURES_DIR),
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)

    summary = run_secondary(
        k=ns.k,
        out_dir=Path(ns.out),
        runs_base=Path(ns.runs_base),
        fixtures_dir=Path(ns.fixtures),
        repo_root=REPO_ROOT,
    )
    print(format_summary_md(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
