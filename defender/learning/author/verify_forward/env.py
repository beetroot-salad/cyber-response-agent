"""The environment curators\' forward check, as a library (#558).

A DETERMINISTIC retrieval check, not an LLM judgment: it re-runs the environment retrieval
with the exact inputs the runtime actor uses — the source case\'s canonical rule key and its
actual prologue entities, re-extracted from the source investigation — and confirms the
candidate lesson is returned. Because it keys off the real prologue (not the keys the curator
wrote), a selector carried over from the observation that the prologue cannot satisfy fails
here. Curators C (env-benign) and D (env-adversarial) share it via the in-process
``forward_check`` tool; it spends no metered request and writes no trace.

``corpus`` and ``runs_dir`` are arguments, never module constants. The corpus especially: the
curator writes the lesson into a throwaway worktree, so a corpus frozen at import would
retrieve against the main checkout and silently check the wrong lesson.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths, resolve_run_bundle
from defender.learning.core.config import LESSONS_ENV_RETRIEVE_SCRIPT, VERIFIER_TIMEOUT
from defender.learning.core.prologue import extract_case_entities

# The env-retrieval script offset lives once in core.config, shared with the in-process
# actor\'s pinned-script matcher; reuse it rather than re-deriving.
RETRIEVE = LESSONS_ENV_RETRIEVE_SCRIPT


def case_entities_arg(row: dict, runs_dir: Path) -> str:
    """Re-extract the source case's prologue entities — what the actor sees.

    Mirrors ``loop.invoke_actor_benign``: the runtime retrieval entities come
    from ``{source_run_dir}/investigation.md``'s ``:V prologue.vertices``, not
    from the observation's own selectors. The forward-check must use the same
    source so a curator's mis-keyed selector cannot self-confirm.

    Resolve the bundle via ``resolve_run_bundle`` off the shared-state ``runs_dir`` —
    NOT ``repo_root / source_run_dir``, which under a batch worktree resolves into the
    worktree's empty ``runs/`` and yields no entities (#425).
    """
    src = (row.get("source_run_dir") or "").strip()
    if not src:
        return ""
    return extract_case_entities(RunPaths(resolve_run_bundle(runs_dir, src)).investigation)


def rule_ids_arg(rule_ids: object) -> str:
    if isinstance(rule_ids, list):
        return ",".join(str(r).strip() for r in rule_ids if str(r).strip())
    return str(rule_ids or "").strip()


def run_retrieval(rule_ids: str, entities: str, corpus: Path) -> list[str]:
    """Return the list of repo-relative lesson paths the retrieval emits.

    Bounded by ``VERIFIER_TIMEOUT``, the same ceiling the two model-backed checks get from
    ``run_stage``'s ``wait_for``. This is the ONLY check that spends its wall clock outside
    that transport, and until #558 it was bounded by the bash tool's own subprocess timeout —
    in-process there is nothing else left to stop a wedged retrieval from hanging the batch's
    gather forever. A timeout is this pair's ERROR (``SystemExit`` is what ``_run_one``
    flattens), never a systemic abort.
    """
    cmd = [sys.executable, str(RETRIEVE), "--corpus", str(corpus)]
    if rule_ids:
        cmd += ["--alert-rule-ids", rule_ids]
    if entities:
        cmd += ["--entities", entities]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=VERIFIER_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise SystemExit(
            f"verify_forward_env: retrieval timed out after {VERIFIER_TIMEOUT}s"
        ) from e
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


def lesson_returned(lesson_path: Path, returned: list[str], *, repo_root: Path) -> bool:
    """Whether the retrieval returned the lesson under check. The retrieval prints
    repo-relative paths; match on basename too, since a validation corpus can sit outside
    the repo root entirely."""
    try:
        rel = str(lesson_path.relative_to(repo_root))
    except ValueError:
        rel = str(lesson_path)
    target_names = {rel, lesson_path.name}
    return any(p in target_names or Path(p).name == lesson_path.name for p in returned)
