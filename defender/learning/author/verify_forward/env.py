from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths, resolve_run_bundle
from defender.learning.core.config import LESSONS_ENV_RETRIEVE_SCRIPT, VERIFIER_TIMEOUT
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
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=VERIFIER_TIMEOUT, encoding="utf-8"
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
    try:
        rel = str(lesson_path.relative_to(repo_root))
    except ValueError:
        rel = str(lesson_path)
    target_names = {rel, lesson_path.name}
    return any(p in target_names or Path(p).name == lesson_path.name for p in returned)
