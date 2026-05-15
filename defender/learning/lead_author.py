#!/usr/bin/env python3
"""Defender learning-loop V0 lead-author (executed-side catalog curator).

Mirrors ``defender/learning/author.py`` (gap-side lessons curator)
but writes to ``defender/skills/gather/queries/`` instead of
``defender/lessons/``. The shape is the same — Python pre-flight +
LLM agent + Python post-flight:

  Pre-flight (Python):
    1. fcntl lock on ``_pending_leads/.lock`` — concurrent ticks refuse.
    2. Clean-scope check on ``defender/skills/gather/queries/`` (uses
       ``git status --porcelain`` so untracked files block too).
    3. Idempotency sentinel: ``<run_dir>/lead_author/done`` makes the
       same run a no-op on re-invocation.
    4. Capture ``base_sha = HEAD`` for the post-flight invariants.
    5. Extract executed leads + compute per-lead neighbor lists.

  Agent invocation (Claude Code, file-edit + Bash):
    Hand the pre-computed handoff blocks to the lead-author agent
    (``lead_author.md``). It reads neighbors, decides
    fold / merge / split / add for each lead, runs Tier 1 on every
    touched template, commits or no-ops, emits a final
    ``LEAD_AUTHOR_RESULT: {...}`` line.

  Post-flight (Python):
    6. Parse LEAD_AUTHOR_RESULT. Validate the actions / commit_sha /
       tier1_verdict matrix.
    7. Cross-check against git: HEAD invariants per the
       no-op-or-single-commit contract, scope enforcement, working
       tree must be clean.
    8. Overwrite ``executed_leads`` with the driver-computed ground
       truth and assert the agent's reported list matches.
    9. Write ``<run_dir>/lead_author/result.json`` + the done sentinel.

The agent itself owns fold-vs-add judgment and the per-edit Tier 1
gate; the driver enforces the transaction envelope and never trusts
agent-reported metadata that the driver can compute itself.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fcntl
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from defender.learning import lead_extract, lead_neighbors
    from defender.learning._agent_stream import (
        AgentStreamError,
        extract_marker_json,
        run_streaming,
    )
except ImportError:  # pragma: no cover — direct-script execution fallback
    import lead_extract  # type: ignore[no-redef]
    import lead_neighbors  # type: ignore[no-redef]
    from _agent_stream import (  # type: ignore[no-redef]
        AgentStreamError,
        extract_marker_json,
        run_streaming,
    )


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
CATALOG_DIR = REPO_ROOT / "defender" / "skills" / "gather" / "queries"
PENDING_DIR = LEARNING_DIR / "_pending_leads"
LOCK_FILE = PENDING_DIR / ".lock"
LEAD_AUTHOR_PROMPT = LEARNING_DIR / "lead_author.md"

LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
LEAD_AUTHOR_TIMEOUT = int(os.environ.get("LEAD_AUTHOR_TIMEOUT_SECONDS", "1800"))
LEAD_AUTHOR_EFFORT = os.environ.get("LEAD_AUTHOR_EFFORT")  # low|medium|high|xhigh|max

_RESULT_MARKER = re.compile(r"LEAD_AUTHOR_RESULT:\s*(?=\{)")


class LeadAuthorError(Exception):
    """Fatal pre/post-flight error — caller should abort."""


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def acquire_lock() -> Any:
    """Acquire the pending-leads lock. Returns ``None`` if another tick holds it."""
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    fh = LOCK_FILE.open("a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        return None
    return fh


def release_lock(fh: Any) -> None:
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def assert_catalog_clean() -> None:
    """``git status --porcelain`` over the catalog dir must be empty.

    Catches uncommitted edits *and* untracked files — bare ``git diff
    --quiet`` would miss a half-authored ``.md`` sitting in the
    catalog tree, and the agent would then commit it into the
    lead-author commit out of scope.
    """
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(CATALOG_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise LeadAuthorError(
            "defender/skills/gather/queries/ has uncommitted or untracked "
            f"changes — refusing to author. Output:\n{proc.stdout}"
        )


def done_sentinel(run_dir: Path) -> Path:
    return run_dir / "lead_author" / "done"


def assert_run_not_done(run_dir: Path) -> None:
    if done_sentinel(run_dir).is_file():
        raise LeadAuthorError(
            f"run already processed: {done_sentinel(run_dir)} exists"
        )


def git_head_sha() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Driver-side metadata: extracted leads + neighbor lists
# ---------------------------------------------------------------------------


def _executed_lead_key(lead: lead_extract.ExecutedLead) -> tuple[int, int]:
    return (lead.position, lead.query_index)


def build_handoff(
    run_dir: Path, executed: list[lead_extract.ExecutedLead]
) -> list[dict]:
    """For each ExecutedLead, compute the agent's per-lead handoff block.

    Includes the executed template path (Mode A) or ``None`` (Mode B),
    the top-3 neighbors (excluding the executed template), and the
    lead's goal / params / characterization. The agent reads this
    verbatim — it does not infer ``executed_template_path`` from
    ``query_id`` itself.
    """
    catalog = lead_neighbors.load_catalog()
    by_id = {t.id: t for t in catalog}
    idf_query = lead_neighbors.build_idf(
        lead_neighbors._all_query_variants(catalog)
    )
    idf_goal = lead_neighbors.build_idf(
        [lead_neighbors.tokenize_goal(t.goal_text) for t in catalog]
    )
    handoffs: list[dict] = []
    for lead in executed:
        mode, neighbors = lead_neighbors.top_k_neighbors(
            {"query_id": lead.query_id, "goal_text": lead.goal_text},
            catalog,
            idf_query=idf_query,
            idf_goal=idf_goal,
            k=3,
        )
        executed_tpl = by_id.get(lead.query_id)
        handoffs.append(
            {
                "position": lead.position,
                "query_index": lead.query_index,
                "query_id": lead.query_id,
                "mode": mode,
                "executed_template_path": (
                    str(executed_tpl.path.relative_to(REPO_ROOT))
                    if executed_tpl is not None
                    else None
                ),
                "neighbors": [
                    {
                        "template_path": str(
                            n.template_path.relative_to(REPO_ROOT)
                        ),
                        "score": n.score,
                    }
                    for n in neighbors
                ],
                "goal_text": lead.goal_text,
                "what_to_characterize": list(lead.what_to_characterize),
                "params": dict(lead.params),
                "cli": lead.cli,
                "result_refs": [
                    str(p.relative_to(run_dir)) for p in lead.result_refs
                ],
            }
        )
    return handoffs


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


def _resolve_verifier_python() -> Path:
    """Locate a python interpreter with pyyaml available.

    Same shape as ``author._resolve_verifier_python`` — env override
    first, then the venv next to the workspace root.
    """
    env = os.environ.get("LEAD_AUTHOR_PYTHON")
    if env:
        return Path(env).resolve()
    cand = REPO_ROOT / "defender" / ".venv" / "bin" / "python3"
    if cand.is_file():
        return cand
    return Path(sys.executable)


def invoke_agent(
    run_dir: Path, handoffs: list[dict], *, log_path: Path | None = None
) -> dict:
    """Spawn the lead-author agent; return parsed LEAD_AUTHOR_RESULT dict.

    The allowlist's leading ``Bash`` prefix for the Tier 1 invocation
    MUST match the form ``defender/.venv/bin/python3 -m
    defender.learning.lead_tier1`` exactly — the agent prompt
    instructs the agent to use that prefix, and any mismatch causes
    ``--print`` mode to silently deny the tool call.
    """
    verifier_py = _resolve_verifier_python()
    tier1_prefix = f"{verifier_py} -m defender.learning.lead_tier1"
    user_prompt = (
        f"run_dir: {run_dir}\n"
        f"catalog_dir: defender/skills/gather/queries/\n"
        f"tier1_command: {tier1_prefix} <template-path> [--trials N]\n"
        f"handoffs ({len(handoffs)}):\n"
        f"{json.dumps(handoffs, indent=2)}\n"
    )
    cmd = [
        "claude",
        "--print",
        "--model",
        LEAD_AUTHOR_MODEL,
        "--system-prompt-file",
        str(LEAD_AUTHOR_PROMPT),
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-hook-events",
        *(["--effort", LEAD_AUTHOR_EFFORT] if LEAD_AUTHOR_EFFORT else []),
        "--allowed-tools",
        (
            "Read,Glob,Grep,"
            "Edit(defender/skills/gather/queries/**),"
            "Write(defender/skills/gather/queries/**),"
            "Bash(git add defender/skills/gather/queries/:*),"
            "Bash(git commit:*),"
            "Bash(git rev-parse:*),"
            "Bash(git status:*),"
            "Bash(git diff:*),"
            f"Bash({tier1_prefix}:*)"
        ),
    ]
    if log_path is None:
        log_path = PENDING_DIR / "lead_author_run.jsonl"

    try:
        full_text = run_streaming(
            cmd,
            user_prompt=user_prompt,
            cwd=REPO_ROOT,
            timeout_seconds=LEAD_AUTHOR_TIMEOUT,
            log_path=log_path,
            log_header={"run_dir": str(run_dir), "started_at": _now_iso()},
            log_prefix="lead_author",
        )
    except AgentStreamError as e:
        msg = str(e)
        if "timed out" in msg:
            raise LeadAuthorError(
                f"lead-author agent timed out after {LEAD_AUTHOR_TIMEOUT}s "
                f"(see {log_path})"
            ) from e
        if msg.startswith("agent failed"):
            raise LeadAuthorError("lead-author " + msg) from e
        raise LeadAuthorError(msg) from e

    body = extract_marker_json(full_text, _RESULT_MARKER)
    if body is None:
        raise LeadAuthorError(
            "lead-author agent did not emit LEAD_AUTHOR_RESULT line:\n"
            + full_text[-2000:]
        )
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise LeadAuthorError(
            f"LEAD_AUTHOR_RESULT JSON invalid: {e}\n{body}"
        ) from e


# ---------------------------------------------------------------------------
# Post-flight
# ---------------------------------------------------------------------------


def _canonical_sha(sha: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", sha],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise LeadAuthorError(
            f"lead-author claimed commit_sha={sha!r} but git rev-parse "
            f"rejects it: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def _head_changed_only_catalog() -> bool:
    """HEAD's name-only list must be all under ``catalog/`` AND non-empty."""
    proc = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    files = [f for f in proc.stdout.splitlines() if f.strip()]
    if not files:
        return False
    rel = "defender/skills/gather/queries/"
    for f in files:
        if not f.startswith(rel):
            return False
    return True


def _parent_sha_of(sha: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", f"{sha}^"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def verify_agent_result(
    result: dict, *, base_sha: str, expected_executed: list[dict]
) -> dict:
    """Validate LEAD_AUTHOR_RESULT against git + the driver-computed leads.

    Returns the canonicalized result dict — driver overwrites
    ``commit_sha`` with the full sha and ``executed_leads`` with the
    pre-computed ground truth before persisting.
    """
    if not isinstance(result, dict):
        raise LeadAuthorError("LEAD_AUTHOR_RESULT must be a JSON object")

    actions = result.get("actions") or []
    if not isinstance(actions, list):
        raise LeadAuthorError("'actions' must be a list")
    commit_sha = result.get("commit_sha")
    tier1_verdict = result.get("tier1_verdict")

    if not actions:
        if commit_sha is not None:
            raise LeadAuthorError(
                "empty actions but commit_sha is set; one of the two is wrong"
            )
        if tier1_verdict not in (None, "not_run"):
            raise LeadAuthorError(
                f"empty actions but tier1_verdict={tier1_verdict!r}; "
                "no actions means no Tier 1 invocation"
            )
        if git_head_sha() != base_sha:
            raise LeadAuthorError(
                "no commit was claimed but HEAD advanced beyond base_sha"
            )
    else:
        if not isinstance(commit_sha, str) or not commit_sha:
            raise LeadAuthorError(
                "non-empty actions require a non-empty commit_sha"
            )
        if tier1_verdict != "pass":
            raise LeadAuthorError(
                f"non-empty actions require tier1_verdict='pass'; got "
                f"{tier1_verdict!r}"
            )
        canonical = _canonical_sha(commit_sha)
        if canonical != git_head_sha():
            raise LeadAuthorError(
                f"commit_sha={commit_sha} ({canonical}) does not match HEAD"
            )
        parent = _parent_sha_of(canonical)
        if parent != base_sha:
            raise LeadAuthorError(
                f"new commit's parent={parent} != base_sha={base_sha}; "
                "multi-commit / rebased / amended history rejected"
            )
        if not _head_changed_only_catalog():
            raise LeadAuthorError(
                "HEAD commit touches files outside "
                "defender/skills/gather/queries/"
            )
        result["commit_sha"] = canonical

    # Always: catalog must be clean post-flight (no staged-but-uncommitted
    # writes, no untracked files left behind).
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", str(CATALOG_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    if proc.stdout.strip():
        raise LeadAuthorError(
            "catalog has uncommitted edits after lead-author exit:\n"
            f"{proc.stdout}"
        )

    # Validate executed_leads matches the driver-computed ground truth.
    # The agent's reported value is *not* trusted — driver overwrites it
    # below — but a mismatch indicates the agent worked from a different
    # picture than the driver did, which should never happen and is a
    # signal that something went wrong upstream.
    agent_set = _executed_leads_signature(result.get("executed_leads") or [])
    expected_set = _executed_leads_signature(expected_executed)
    if agent_set != expected_set:
        raise LeadAuthorError(
            "agent-reported executed_leads disagree with driver ground truth: "
            f"agent={sorted(agent_set)}, driver={sorted(expected_set)}"
        )
    result["executed_leads"] = expected_executed
    return result


def _executed_leads_signature(items: list[dict]) -> set[tuple[Any, ...]]:
    """Order-insensitive set of (position, query_index, query_id) tuples."""
    sig: set[tuple[Any, ...]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        sig.add(
            (
                item.get("position"),
                item.get("query_index"),
                item.get("query_id"),
            )
        )
    return sig


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def persist_result(run_dir: Path, result: dict) -> Path:
    """Write ``<run_dir>/lead_author/result.json`` + the done sentinel."""
    out_dir = run_dir / "lead_author"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "result.json"
    out_path.write_text(json.dumps(result, indent=2))
    done_sentinel(run_dir).write_text(_now_iso())
    return out_path


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _log(msg: str) -> None:
    print(f"[lead-author] {msg}", file=sys.stderr)


def run(run_dir: Path) -> int:
    if not run_dir.is_dir():
        _log(f"FATAL: run_dir not found: {run_dir}")
        return 2

    lock_fh = acquire_lock()
    if lock_fh is None:
        _log("lock held by another process — skipping this tick")
        return 0
    try:
        try:
            assert_run_not_done(run_dir)
            assert_catalog_clean()
        except LeadAuthorError as e:
            _log(f"FATAL pre-flight: {e}")
            return 2

        try:
            executed = lead_extract.extract(run_dir)
        except (FileNotFoundError, ValueError) as e:
            _log(f"FATAL: cannot extract leads: {e}")
            return 2
        if not executed:
            _log("no executed leads to refine — nothing to do")
            return 0

        base_sha = git_head_sha()
        handoffs = build_handoff(run_dir, executed)
        expected_executed = [
            {
                "position": lead.position,
                "query_index": lead.query_index,
                "query_id": lead.query_id,
            }
            for lead in executed
        ]

        try:
            agent_result = invoke_agent(run_dir, handoffs)
        except LeadAuthorError as e:
            _log(f"FATAL agent: {e}")
            return 2

        try:
            verified = verify_agent_result(
                agent_result,
                base_sha=base_sha,
                expected_executed=expected_executed,
            )
        except LeadAuthorError as e:
            _log(f"FATAL post-flight: {e}")
            return 2

        out_path = persist_result(run_dir, verified)
        _log(
            f"done commit_sha={verified.get('commit_sha')} "
            f"actions={len(verified.get('actions') or [])} "
            f"tier1={verified.get('tier1_verdict')} result={out_path}"
        )
        return 0
    finally:
        release_lock(lock_fh)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="lead_author")
    p.add_argument("run_dir", type=Path)
    args = p.parse_args(argv)
    return run(args.run_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
