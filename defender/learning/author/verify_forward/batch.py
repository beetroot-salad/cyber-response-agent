#!/usr/bin/env python3
"""Concurrent driver for the per-lesson forward-check gate.

Usage::

    verify_batch.py <verify_script.py> <lesson_path>=<id>[=<direction>] [...]

``<verify_script.py>`` is one of the existing single-check scripts
(``verify_forward.py`` for defender findings, ``verify_forward_actor.py``
for actor lessons) — each takes ``<lesson_path> <id>`` and prints ``GOOD``
or ``BAD`` on its last stdout line. This driver runs one such check per
pair **concurrently** (a thread pool over subprocesses) and prints one
result line per pair, so a curator agent runs its whole first verification
pass with a single tool call instead of a serial shell loop.

Each pair is ``<lesson_path>=<id>`` with an optional third ``=<direction>``
field: the lesson file to gate, the source row id (observation_id for actor
lessons, run_id for defender findings) the single-check script resolves from
its pending queue, and — when present — a direction passed through to the
child as ``--direction <direction>`` before the positionals (the
defender-findings check is direction-aware; the actor check is not, so it
omits the field).

Output (stdout), one line per pair, in input order::

    GOOD  <lesson_path>  <id>
    BAD   <lesson_path>  <id>
    ERROR <lesson_path>  <id>  <one-line reason>

then a trailing summary line ``BATCH: n_good=<> n_bad=<> n_error=<>``.
Exit 0 when every check ran (regardless of GOOD/BAD verdicts); non-zero
only on a usage error or when at least one check could not run (ERROR).
Verdict handling — keep GOOD, rewrite+recheck BAD — stays with the agent.
"""
from __future__ import annotations

import concurrent.futures
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
# Resolve `defender.*` imports whether run directly (the curator drives this as a
# `claude -p` Bash subprocess) or imported — mirrors actor.py/forward.py. core.config
# is stdlib-only, so importing it here adds no pyyaml dependency to the orchestrator.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from defender.learning.core.config import (  # noqa: E402
    VERIFY_BATCH_TIMEOUT,
    VERIFY_BATCH_WORKERS,
)

# Cap concurrency so a large batch does not fan out unbounded verify children — each
# child now runs an in-process GLM forward-check (Fireworks), not a `claude -p` call.
MAX_WORKERS = VERIFY_BATCH_WORKERS
# Per-check ceiling; above the single-check VERIFIER_TIMEOUT so a child that hits its
# own timeout reports BAD/ERROR rather than being killed here.
CHILD_TIMEOUT = VERIFY_BATCH_TIMEOUT


def _parse_pair(arg: str) -> tuple[str, str, str | None]:
    parts = arg.split("=")
    if len(parts) == 2:
        lesson, ident, direction = parts[0], parts[1], None
    elif len(parts) == 3:
        lesson, ident, direction = parts
        direction = direction.strip() or None
    else:
        raise SystemExit(
            f"verify_batch: malformed pair {arg!r} — expected "
            "<lesson_path>=<id>[=<direction>]"
        )
    if not lesson.strip() or not ident.strip():
        raise SystemExit(
            f"verify_batch: malformed pair {arg!r} — empty lesson or id"
        )
    return lesson.strip(), ident.strip(), direction


def _run_one(
    script: str, lesson_path: str, ident: str, direction: str | None
) -> tuple[str, str]:
    """Run one single-check subprocess. Returns (verdict, detail)."""
    cmd = [sys.executable, script]
    if direction:
        cmd += ["--direction", direction]
    cmd += [lesson_path, ident]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "ERROR", f"timeout after {CHILD_TIMEOUT}s"
    except OSError as e:
        return "ERROR", repr(e)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [""]
        return "ERROR", f"rc={proc.returncode}: {tail[0][:200]}"
    lines = [ln.strip() for ln in proc.stdout.strip().splitlines() if ln.strip()]
    verdict = lines[-1] if lines else ""
    if verdict not in ("GOOD", "BAD"):
        return "ERROR", f"no GOOD/BAD verdict (got {verdict!r})"
    return verdict, ""


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(
            "usage: verify_batch.py <verify_script.py> "
            "<lesson_path>=<id>[=<direction>] [...]",
            file=sys.stderr,
        )
        return 64
    script = argv[1]
    if not Path(script).is_file():
        print(f"verify_batch: verify script not found: {script}", file=sys.stderr)
        return 64
    pairs = [_parse_pair(a) for a in argv[2:]]

    results: list[tuple[str, str, str, str]] = [
        ("", lp, idv, "") for lp, idv, _ in pairs
    ]
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(MAX_WORKERS, len(pairs))
    ) as pool:
        futs = {
            pool.submit(_run_one, script, lp, idv, direction): i
            for i, (lp, idv, direction) in enumerate(pairs)
        }
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            lp, idv, _ = pairs[i]
            verdict, detail = fut.result()
            results[i] = (verdict, lp, idv, detail)

    n_good = n_bad = n_error = 0
    for verdict, lp, idv, detail in results:
        if verdict == "GOOD":
            n_good += 1
            print(f"GOOD  {lp}  {idv}")
        elif verdict == "BAD":
            n_bad += 1
            print(f"BAD   {lp}  {idv}")
        else:
            n_error += 1
            print(f"ERROR {lp}  {idv}  {detail}")
    print(f"BATCH: n_good={n_good} n_bad={n_bad} n_error={n_error}")
    return 0 if n_error == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
