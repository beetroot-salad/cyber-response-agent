from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths, resolve_run_bundle
from defender.learning.core.config import LESSONS_ENV_RETRIEVE_SCRIPT, verifier_timeout
from defender.learning.core.prologue import extract_case_entities

RETRIEVE = LESSONS_ENV_RETRIEVE_SCRIPT


def case_entities_arg(row: dict, runs_dir: Path) -> str:
    src = (row.get("source_run_dir") or "").strip()
    if not src:
        return ""
    return extract_case_entities(RunPaths(resolve_run_bundle(runs_dir, src)).investigation)


def rule_ids_arg(rule_ids: object) -> str:
    if isinstance(rule_ids, list):
        return ",".join(str(r).strip() for r in rule_ids if str(r).strip())
    return str(rule_ids or "").strip()


def run_retrieval(rule_ids: str, entities: str, corpus: Path) -> list[str]:
    cmd = [sys.executable, str(RETRIEVE), "--corpus", str(corpus)]
    if rule_ids:
        cmd += ["--alert-rule-ids", rule_ids]
    if entities:
        cmd += ["--entities", entities]
    timeout = verifier_timeout()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8"
        )
    except subprocess.TimeoutExpired as e:
        raise SystemExit(
            f"verify_forward_env: retrieval timed out after {timeout}s"
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


def lesson_returned(
    lesson_path: Path, returned: list[str], *, repo_root: Path, corpus_dir: Path
) -> bool:
    """Did the retrieval that grounds this lesson's forward-check actually return THIS file?

    Answered on RESOLVED IDENTITY, never on the basename. A basename match certified a
    lesson as retrievability-verified whenever some unrelated top-level file happened to
    share its name — and the case that made that unsound is a lesson written one directory
    down: the curator's write allow admitted nested paths while the corpus walk is flat
    (`glob('*.md')`), so `<corpus>/sub/x.md` was invisible to retrieval, to the corpus
    manifest and to the idempotency scan forever, and a pre-existing `<corpus>/x.md` still
    voted it GOOD. The write allow is now one level deep to match the walk; this rejects
    the same shape independently, because a check must never pass a file the walk cannot
    see.

    Returned lines are repo-relative when the retrieval script and this corpus share a
    repo root and absolute when they do not (the worktree case) — both are resolved
    against `repo_root` before comparison, so neither spelling depends on which."""
    target = lesson_path.resolve()
    if target.parent != corpus_dir.resolve():
        return False
    for p in returned:
        candidate = Path(p)
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        if candidate.resolve() == target:
            return True
    return False
