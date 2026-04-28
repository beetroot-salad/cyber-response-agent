"""Post-mortem lead-pool normalization orchestrator.

CLI entry point spawned (detached) from `stop_handler.py` after each
investigation completes. Pipeline:

  1. Extract ad-hoc findings from `<run_dir>/investigation.md`.
  2. Skip if none. (Belt-and-suspenders — `stop_handler.py` already
     pre-checks via `has_ad_hoc_leads`.)
  3. Create a per-run git worktree off the current branch.
  4. Render the agent prompt and spawn a coding agent in the worktree
     to classify findings, edit the catalog, and commit.
  5. Verify the agent produced a commit; abort with a `failed` marker
     if not.
  6. Push the branch and open a PR via `gh`.
  7. Write `<out_dir>/status.json` (success) or `<out_dir>/failed`
     (any unhandled exception) with the relevant context.

The orchestrator is mechanical Python. The agent is the only LLM
component, scoped to classify→edit→commit.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

# Allow running as a script: `python -m scripts.postmortem.leads.run`.
SOC_AGENT_ROOT = Path(__file__).resolve().parents[3]
if str(SOC_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers.gather import _derive_vendor  # noqa: E402
from scripts.postmortem.leads.extract import (  # noqa: E402
    AdHocLead,
    extract_ad_hoc_leads,
)
from scripts.postmortem.worktree import (  # noqa: E402
    WorktreeError,
    create_worktree,
    current_branch,
)

REPO_ROOT = SOC_AGENT_ROOT.parent
PROMPT_TEMPLATE_PATH = (
    SOC_AGENT_ROOT / "scripts" / "postmortem" / "leads" / "agent_prompt.md"
)

# Env override for where the per-run worktree gets created. By default it
# lands at `<out_dir>/worktree`, sibling to status.json / run.log /
# failed. Operators who keep their post-mortem worktrees centrally
# (e.g. under .claude/worktrees/) can point this at a shared root and
# the orchestrator will materialize each run's worktree as a child:
# `$SOC_AGENT_POSTMORTEM_WORKTREE_DIR/<branch_name>`.
WORKTREE_DIR_ENV = "SOC_AGENT_POSTMORTEM_WORKTREE_DIR"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="postmortem.leads.run")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (default: parent of soc-agent/).",
    )
    return parser.parse_args(argv)


def _load_signature_id(run_dir: Path) -> str:
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        raise PostmortemError(
            f"meta.json missing under {run_dir}; cannot derive vendor"
        )
    meta = json.loads(meta_path.read_text())
    sig = meta.get("signature_id")
    if not isinstance(sig, str) or not sig.strip():
        raise PostmortemError(
            f"meta.json under {run_dir} has no usable signature_id"
        )
    return sig


def _render_prompt(
    template_path: Path,
    *,
    worktree_path: Path,
    base_ref: str,
    run_id: str,
    vendor: str,
    leads: list[AdHocLead],
) -> str:
    template = template_path.read_text()
    leads_yaml = yaml.safe_dump(
        [asdict(l) for l in leads],
        sort_keys=False,
        allow_unicode=True,
    )
    return template.format(
        worktree_path=str(worktree_path),
        base_ref=base_ref,
        run_id=run_id,
        vendor=vendor,
        leads_yaml=leads_yaml.rstrip(),
    )


# ---------------------------------------------------------------------------
# Agent spawn — stubbed in slice 1
# ---------------------------------------------------------------------------

class PostmortemError(RuntimeError):
    """Pipeline-internal failures (missing meta, push/PR errors, scope
    violations). Renamed from `OrchestrationError` to avoid collision
    with `scripts.orchestrate.OrchestrationError`, which is what
    `_derive_vendor` raises when the signature_id is malformed. Both
    funnel into `main`'s `except Exception` and mark `failed`."""


def _spawn_agent(
    worktree_path: Path,
    prompt: str,
) -> int:
    """Spawn a coding agent in the worktree to classify + edit + commit.

    SLICE 1: stubbed. Returns 1 unconditionally so the orchestrator
    falls into its no-commit failure path. The real agent invocation
    (likely `claude -p` with a tightly-scoped permission profile) is
    settled in a follow-up commit — see the plan's Open Q §1.

    Tests monkeypatch this function to simulate both success
    (synthesizes a commit in the worktree) and failure (returns
    non-zero).
    """
    _ = worktree_path, prompt
    sys.stderr.write(
        "postmortem.leads.run: _spawn_agent is stubbed; agent invocation "
        "not yet implemented (see plan Open Q §1).\n"
    )
    return 1


def _has_new_commit(worktree_path: Path, base_ref: str) -> bool:
    """True iff the worktree's HEAD has advanced past `base_ref`.

    Raises `PostmortemError` on git failure — silently returning False
    would let "git is broken" masquerade as "agent did not commit".
    """
    proc = subprocess.run(
        ["git", "-C", str(worktree_path), "rev-list", "--count", f"{base_ref}..HEAD"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise PostmortemError(
            f"git rev-list failed in {worktree_path} (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    try:
        return int(proc.stdout.strip()) > 0
    except ValueError as e:
        raise PostmortemError(
            f"git rev-list returned non-integer count: {proc.stdout!r}"
        ) from e


# The agent must commit only catalog edits. A `git add -A` mistake (or any
# stray file in the worktree) would otherwise hitchhike into the PR. The
# orchestrator does a post-commit scope check and refuses to push if any
# committed file falls outside this prefix.
ALLOWED_COMMIT_PREFIX = "soc-agent/knowledge/common-investigation/leads/"


def _committed_paths(worktree_path: Path, base_ref: str) -> list[str]:
    """Return the list of paths committed since `base_ref`.

    Raises `PostmortemError` on git failure — a swallowed failure here
    would return an empty list, which `_out_of_scope` would treat as
    "all clean" and let an unverified push proceed.
    """
    proc = subprocess.run(
        ["git", "-C", str(worktree_path), "diff", "--name-only", f"{base_ref}..HEAD"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise PostmortemError(
            f"git diff --name-only failed in {worktree_path} "
            f"(rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return [l for l in proc.stdout.splitlines() if l.strip()]


def _out_of_scope(paths: list[str]) -> list[str]:
    return [p for p in paths if not p.startswith(ALLOWED_COMMIT_PREFIX)]


def _push_and_pr(
    worktree_path: Path,
    branch_name: str,
    base_branch: str,
) -> str:
    """Push the worktree's branch and open a PR. Returns the PR URL.

    Failures are loud — they propagate up to `main()` which writes the
    `failed` marker.
    """
    push = subprocess.run(
        ["git", "-C", str(worktree_path), "push", "-u", "origin", branch_name],
        capture_output=True,
        text=True,
    )
    if push.returncode != 0:
        raise PostmortemError(
            f"git push failed (rc={push.returncode}): {push.stderr.strip()}"
        )
    pr = subprocess.run(
        [
            "gh", "pr", "create",
            "--base", base_branch,
            "--head", branch_name,
            "--title", f"post-mortem lead normalization ({branch_name})",
            "--body",
            (
                "Automated lead-catalog updates from a post-mortem run.\n\n"
                "Source branch is auto-generated. The orchestrator extracted "
                "ad-hoc lead invocations from a completed investigation and a "
                "coding agent classified + edited the catalog inside this "
                "branch's worktree.\n"
            ),
        ],
        cwd=str(worktree_path),
        capture_output=True,
        text=True,
    )
    if pr.returncode != 0:
        raise PostmortemError(
            f"gh pr create failed (rc={pr.returncode}): {pr.stderr.strip()}"
        )
    return pr.stdout.strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _write_status(out_dir: Path, payload: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "status.json").write_text(json.dumps(payload, indent=2) + "\n")


def _mark_failed(out_dir: Path, reason: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "failed").write_text(reason + "\n")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_dir: Path = args.run_dir
    out_dir: Path = args.out_dir
    repo_root: Path = args.repo_root
    run_id = run_dir.name

    try:
        signature_id = _load_signature_id(run_dir)
        vendor = _derive_vendor(signature_id)
        leads = extract_ad_hoc_leads(run_dir, vendor=vendor)
        if not leads:
            _write_status(
                out_dir,
                {"status": "skipped", "reason": "no ad-hoc findings"},
            )
            return 0

        base_ref = current_branch(repo_root)
        branch_name = f"postmortem-leads/{run_id}"
        worktree_root_env = os.environ.get(WORKTREE_DIR_ENV)
        if worktree_root_env:
            worktree_path = Path(worktree_root_env) / branch_name.replace("/", "-")
        else:
            worktree_path = out_dir / "worktree"

        try:
            create_worktree(repo_root, worktree_path, branch_name, base_ref)
        except WorktreeError as e:
            _mark_failed(out_dir, f"worktree create failed: {e}")
            return 1

        prompt = _render_prompt(
            PROMPT_TEMPLATE_PATH,
            worktree_path=worktree_path,
            base_ref=base_ref,
            run_id=run_id,
            vendor=vendor,
            leads=leads,
        )

        rc = _spawn_agent(worktree_path, prompt)
        if rc != 0 or not _has_new_commit(worktree_path, base_ref):
            _mark_failed(
                out_dir,
                f"agent did not produce a commit (rc={rc})",
            )
            return 1

        committed = _committed_paths(worktree_path, base_ref)
        out_of_scope = _out_of_scope(committed)
        if out_of_scope:
            _mark_failed(
                out_dir,
                "agent committed files outside the catalog scope; "
                f"refusing to push. Out-of-scope: {out_of_scope}. "
                f"All committed: {committed}.",
            )
            return 1

        pr_url = _push_and_pr(worktree_path, branch_name, base_ref)
        _write_status(
            out_dir,
            {
                "status": "ok",
                "branch": branch_name,
                "worktree": str(worktree_path),
                "pr_url": pr_url,
                "leads": [asdict(l) for l in leads],
            },
        )
        return 0

    except Exception as e:
        # Capture the full traceback so a human can recover by reading
        # run.log (where stdout/stderr is captured) and `failed`.
        traceback.print_exc(file=sys.stderr)
        _mark_failed(out_dir, f"unhandled exception: {e!r}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
