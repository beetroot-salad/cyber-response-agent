#!/usr/bin/env python3
"""Stress test for the post-mortem leads agent prompt.

Picks N real runs with ad-hoc findings, renders the agent prompt for
each in a fresh git worktree off the current branch, and invokes
`claude -p --dangerously-skip-permissions` with the prompt on stdin.
Captures the agent's output, the resulting commit (if any), and the
diff. Writes a per-run summary to outputs/<run_id>.md and an aggregate
findings.md.

The point is to validate that the prompt:
  - Produces a sensible classification on the diverse extracted shapes.
  - Halts cleanly when classification is ambiguous (no commit, returns
    a halt message in stdout).
  - Stages only catalog files, not stray repo state, when it does
    commit (so we know the `git add` scope is tight enough).
  - Doesn't hallucinate catalog dirs or template paths.

Usage:
  python docs/experiments/postmortem-leads-prompt-stress/run.py --max-runs 3
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
# This stress-runner targets a slice that lives on a feature branch — read
# the slice's source from the active worktree if main hasn't merged yet.
_WORKTREE_SOC_ROOT = (
    Path("/workspace/.claude/worktrees/postmortem-leads-pipeline/soc-agent")
)
SOC_AGENT_ROOT = (
    _WORKTREE_SOC_ROOT
    if (_WORKTREE_SOC_ROOT / "scripts" / "postmortem").exists()
    else REPO_ROOT / "soc-agent"
)
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.postmortem.leads.extract import extract_ad_hoc_leads, AdHocLead  # noqa: E402

OUTPUTS_DIR = Path(__file__).parent / "outputs"
PROMPT_TEMPLATE_PATH = (
    SOC_AGENT_ROOT / "scripts" / "postmortem" / "leads" / "agent_prompt.md"
)
RUNS_ROOT = Path("/workspace/runs")
WORKTREE_ROOT = Path("/tmp/postmortem-stress")


def _signature_id(run_dir: Path) -> str | None:
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
    except Exception:
        return None
    sig = meta.get("signature_id")
    if isinstance(sig, str) and "-" in sig:
        return sig
    return None


def _vendor(signature_id: str) -> str:
    return signature_id.split("-", 1)[0]


def _find_candidate_runs(limit: int) -> list[tuple[Path, str, list[AdHocLead]]]:
    """Walk RUNS_ROOT and return up to `limit` (run_dir, vendor, leads)
    triples for runs that contain at least one ad-hoc finding."""
    out: list[tuple[Path, str, list[AdHocLead]]] = []
    for parent in sorted(RUNS_ROOT.iterdir(), reverse=True):
        runs_subdir = parent / "runs"
        if not runs_subdir.is_dir():
            continue
        for run_dir in runs_subdir.iterdir():
            if not run_dir.is_dir():
                continue
            sig = _signature_id(run_dir)
            if sig is None:
                continue
            vendor = _vendor(sig)
            try:
                leads = extract_ad_hoc_leads(run_dir, vendor=vendor)
            except Exception:
                continue
            if leads:
                out.append((run_dir, vendor, leads))
                if len(out) >= limit:
                    return out
    return out


def _render_prompt(
    template: str,
    *,
    worktree_path: Path,
    base_ref: str,
    run_id: str,
    vendor: str,
    leads: list[AdHocLead],
) -> str:
    leads_yaml = yaml.safe_dump(
        [asdict(l) for l in leads], sort_keys=False, allow_unicode=True
    )
    return template.format(
        worktree_path=str(worktree_path),
        base_ref=base_ref,
        run_id=run_id,
        vendor=vendor,
        leads_yaml=leads_yaml.rstrip(),
    )


def _create_worktree(repo_root: Path, branch: str, path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Ensure branch doesn't exist
    subprocess.run(
        ["git", "-C", str(repo_root), "branch", "-D", branch],
        capture_output=True, text=True,
    )
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "add", "-b", branch, str(path), "HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"worktree add failed: {proc.stderr}"
        )


def _remove_worktree(repo_root: Path, branch: str, path: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(path)],
        capture_output=True, text=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_root), "branch", "-D", branch],
        capture_output=True, text=True,
    )


def _spawn_claude(prompt: str, cwd: Path, timeout: int = 600) -> dict[str, Any]:
    start = time.monotonic()
    # Pre-seed a project-local settings file allowing the catalog edits
    # and git commits the prompt asks for. Avoids
    # --dangerously-skip-permissions which is blocked under root.
    claude_dir = cwd / ".claude"
    claude_dir.mkdir(exist_ok=True)
    (claude_dir / "settings.local.json").write_text(json.dumps({
        "permissions": {
            "allow": [
                "Edit",
                "Write",
                "Read",
                "Glob",
                "Grep",
                "Bash(git add:*)",
                "Bash(git commit:*)",
                "Bash(git status:*)",
                "Bash(git diff:*)",
                "Bash(ls:*)",
                "Bash(cat:*)",
            ],
        },
    }))
    try:
        proc = subprocess.run(
            [
                "claude", "-p",
                "--permission-mode", "acceptEdits",
                "--output-format", "text",
            ],
            input=prompt,
            capture_output=True,
            text=True,
            cwd=str(cwd),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"timed_out": True, "elapsed_s": timeout, "stdout": "", "stderr": "TIMEOUT", "rc": -1}
    return {
        "timed_out": False,
        "elapsed_s": round(time.monotonic() - start, 1),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "rc": proc.returncode,
    }


def _git_log_commits(worktree: Path, base_ref: str) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(worktree), "log", "--oneline", f"{base_ref}..HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    return [l for l in proc.stdout.splitlines() if l.strip()]


def _git_diff(worktree: Path, base_ref: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(worktree), "diff", base_ref, "--stat"],
        capture_output=True, text=True,
    )
    return proc.stdout


def _git_diff_full(worktree: Path, base_ref: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(worktree), "diff", base_ref],
        capture_output=True, text=True,
    )
    return proc.stdout


def _staged_paths(worktree: Path, base_ref: str) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(worktree), "diff", "--name-only", base_ref],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return []
    return [l for l in proc.stdout.splitlines() if l.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-runs", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    template = PROMPT_TEMPLATE_PATH.read_text()

    base_ref = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()

    candidates = _find_candidate_runs(args.max_runs)
    print(f"# stress: {len(candidates)} runs with ad-hoc findings (max={args.max_runs})", flush=True)

    summary: list[dict[str, Any]] = []
    for i, (run_dir, vendor, leads) in enumerate(candidates):
        run_id = run_dir.name
        branch = f"postmortem-stress/{run_id[:12]}-{int(time.time())}"
        worktree = WORKTREE_ROOT / run_id[:12]
        print(f"\n## [{i+1}/{len(candidates)}] {run_id}  vendor={vendor}  leads={len(leads)}", flush=True)
        print(f"     worktree: {worktree}", flush=True)
        per_run_log = OUTPUTS_DIR / f"{run_id[:12]}.md"

        try:
            _create_worktree(REPO_ROOT, branch, worktree)
            prompt = _render_prompt(
                template,
                worktree_path=worktree,
                base_ref=base_ref,
                run_id=run_id,
                vendor=vendor,
                leads=leads,
            )
            # Persist the rendered prompt as a sibling, NOT inside the
            # worktree — `git add -A` mishaps in the agent must not pull
            # it into the commit. Stress run 3 caught exactly that.
            (per_run_log.parent / f"{run_id[:12]}.prompt.txt").write_text(prompt)
            result = _spawn_claude(prompt, cwd=worktree, timeout=args.timeout)
            commits = _git_log_commits(worktree, base_ref)
            diff_stat = _git_diff(worktree, base_ref)
            staged = _staged_paths(worktree, base_ref)
            committed = bool(commits)

            outcome = "COMMITTED" if committed else "NO_COMMIT"
            if result["timed_out"]:
                outcome = "TIMEOUT"
            print(f"     outcome={outcome} commits={len(commits)} files_changed={len(staged)} elapsed={result['elapsed_s']}s rc={result['rc']}", flush=True)

            per_run_log.write_text(
                "\n".join([
                    f"# Stress run — {run_id}",
                    "",
                    f"- vendor: {vendor}",
                    f"- leads: {len(leads)}",
                    f"- outcome: {outcome}",
                    f"- elapsed: {result['elapsed_s']}s",
                    f"- rc: {result['rc']}",
                    f"- timed_out: {result['timed_out']}",
                    f"- commits: {commits}",
                    f"- files_changed: {staged}",
                    "",
                    "## Diff stat",
                    "```",
                    diff_stat.rstrip() or "(empty)",
                    "```",
                    "",
                    "## Agent stdout (first 4000 chars)",
                    "```",
                    (result["stdout"] or "")[:4000],
                    "```",
                    "",
                    "## Agent stderr (first 2000 chars)",
                    "```",
                    (result["stderr"] or "")[:2000],
                    "```",
                    "",
                    "## Full diff (first 6000 chars)",
                    "```diff",
                    _git_diff_full(worktree, base_ref)[:6000],
                    "```",
                ])
            )

            summary.append({
                "run_id": run_id,
                "vendor": vendor,
                "leads": len(leads),
                "outcome": outcome,
                "commits": len(commits),
                "files_changed": staged,
                "elapsed_s": result["elapsed_s"],
                "rc": result["rc"],
            })
        except Exception as e:
            print(f"     ERROR: {e}", flush=True)
            summary.append({
                "run_id": run_id,
                "vendor": vendor,
                "leads": len(leads),
                "outcome": "ERROR",
                "error": str(e),
            })
        finally:
            # Keep the worktree on disk for inspection, but drop the
            # branch so subsequent stress runs don't collide.
            try:
                _remove_worktree(REPO_ROOT, branch, worktree)
            except Exception:
                pass

    findings = Path(__file__).parent / "findings.md"
    findings.write_text(
        "\n".join([
            "# Post-mortem leads agent-prompt stress test",
            "",
            f"Ran against {len(candidates)} real runs with ad-hoc findings.",
            "",
            "## Summary",
            "",
            "| run_id | vendor | leads | outcome | commits | files_changed | elapsed |",
            "|---|---|---:|---|---:|---:|---:|",
            *[
                f"| {s['run_id']} | {s['vendor']} | {s.get('leads',0)} | {s['outcome']} | "
                f"{s.get('commits','-')} | {len(s.get('files_changed',[]))} | "
                f"{s.get('elapsed_s','-')}s |"
                for s in summary
            ],
            "",
            "Per-run logs in outputs/.",
        ])
    )
    print(f"\nWrote {findings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
