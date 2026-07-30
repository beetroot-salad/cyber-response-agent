from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths, resolve_run_bundle
from defender.learning.core.config import LESSONS_ENV_RETRIEVE_SCRIPT, verifier_timeout
from defender.learning.core.prologue import extract_case_entities

RETRIEVE = LESSONS_ENV_RETRIEVE_SCRIPT

# The root the retrieval script prints its hits relative to (`rel_to_repo`) is the root of the
# checkout THE SCRIPT lives in — never the caller's, and never the corpus's. The two differ on
# every real batch: the curator authors inside `<repo>/.worktrees/<batch>`, which sits UNDER the
# main checkout, so the script's `relative_to` SUCCEEDS and emits a `.worktrees/…`-prefixed
# spelling that resolves only against the main root. Anchored ONCE here, beside the script
# constant it belongs to, so `lesson_returned` never has to guess which root a line came from.
RETRIEVE_REPO_ROOT = RETRIEVE.resolve().parents[3]


def case_entities_arg(row: dict, runs_dir: Path) -> str:
    src = (row.get("source_run_dir") or "").strip()
    if not src:
        return ""
    return extract_case_entities(RunPaths(resolve_run_bundle(runs_dir, src)).investigation)


def rule_ids_arg(rule_ids: object) -> str:
    if isinstance(rule_ids, list):
        return ",".join(str(r).strip() for r in rule_ids if str(r).strip())
    return str(rule_ids or "").strip()


def absolute_hit(printed: str) -> str:
    """One printed retrieval hit, made absolute against the root the SCRIPT spelled it against.

    `rel_to_repo` inside the script prints repo-relative when the hit sits under the script's
    own checkout and absolute when it does not — and the batch worktree sits UNDER it
    (`<repo>/.worktrees/<batch>`), so the interesting case is the relative one, and the ONLY
    root it is relative to is `RETRIEVE_REPO_ROOT`. Anchoring it against anything else (the
    curator's worktree root, say) yields a path that does not exist and a BAD verdict for a
    lesson retrieval actually returned."""
    hit = Path(printed)
    return str(hit if hit.is_absolute() else RETRIEVE_REPO_ROOT / hit)


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
        paths.append(absolute_hit(line.split("\t", 1)[0]))
    return paths


def lesson_returned(
    lesson_path: Path, returned: list[str], *, corpus_dir: Path
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

    `returned` arrives ABSOLUTE — `run_retrieval` anchors the script's repo-relative spelling
    at that script's OWN checkout root, the only root it can have meant. So this compares
    identity and nothing else: it never re-derives a root, and therefore cannot disagree with
    the retrieval about which checkout a hit named (the worktree case, where the curator's root
    and the script's root are two different directories)."""
    target = lesson_path.resolve()
    if target.parent != corpus_dir.resolve():
        return False
    return any(Path(p).resolve() == target for p in returned)
