#!/usr/bin/env python3
"""Forward-check Haiku gate for a single candidate actor lesson.

Usage: ``verify_forward_actor.py <lesson_path> <observation_id>``

Resolves the observation row from
``defender/learning/_pending/actor_observations.jsonl`` (the active
queue — the row is still present during the author run; the queue is
rotated only on AUTHOR_RESULT post-flight). Reads the actor story
section 0 + body from ``{source_run_dir}/actor_story.md``. Calls
``claude -p --model claude-haiku-4-5`` with
``defender/learning/verify_forward_actor.md`` as the system prompt.
Prints exactly ``GOOD`` or ``BAD`` on the last line of stdout.

One rep per invocation. The author prompt allows one retry per
lesson (rewrite + re-run) before reverting and routing to
``consumed_skip``.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (it has a __main__
# block — the author drives it as a `claude -p` Bash subprocess).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from defender.learning._loop_config import subscription_env  # noqa: E402

PENDING_FILE = HERE / "_pending" / "actor_observations.jsonl"
PROMPT_PATH = HERE / "verify_forward_actor.md"

VERIFIER_MODEL = os.environ.get("LEARNING_VERIFIER_MODEL", "claude-haiku-4-5")
VERIFIER_TIMEOUT = int(os.environ.get("LEARNING_VERIFIER_TIMEOUT_SECONDS", "180"))


def load_observation(observation_id: str) -> dict:
    if not PENDING_FILE.is_file():
        raise SystemExit(
            f"verify_forward_actor: pending queue not found at {PENDING_FILE}"
        )
    with PENDING_FILE.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("observation_id") == observation_id:
                return row
    raise SystemExit(
        f"verify_forward_actor: observation_id {observation_id!r} not found "
        f"in {PENDING_FILE}"
    )


def load_story(source_run_dir: str) -> str:
    path = (REPO_ROOT / source_run_dir / "actor_story.md").resolve()
    if not path.is_file():
        raise SystemExit(
            f"verify_forward_actor: actor_story.md missing at {path}"
        )
    return path.read_text()


def render_user_prompt(lesson_text: str, observation_text: str, story_text: str) -> str:
    template = PROMPT_PATH.read_text()
    return (
        template
        .replace("{story}", story_text)
        .replace("{observation}", observation_text)
        .replace("{lesson}", lesson_text)
    )


def call_haiku(user_prompt: str) -> str:
    cmd = [
        "claude",
        "-p",
        "--model",
        VERIFIER_MODEL,
        "--output-format",
        "text",
    ]
    proc = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=VERIFIER_TIMEOUT,
        env=subscription_env(),
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"verify_forward_actor: claude -p failed (rc={proc.returncode}): "
            f"{proc.stderr[-2000:]}"
        )
    return proc.stdout


def parse_verdict(text: str) -> str:
    for line in reversed(text.strip().splitlines()):
        s = line.strip()
        if s.startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip()
            if v in ("GOOD", "BAD"):
                return v
            raise SystemExit(f"verify_forward_actor: unrecognized verdict {v!r}")
    raise SystemExit(
        "verify_forward_actor: no VERDICT line found in Haiku output:\n"
        + text[-1000:]
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: verify_forward_actor.py <lesson_path> <observation_id>",
            file=sys.stderr,
        )
        return 64
    lesson_path = Path(argv[1]).resolve()
    observation_id = argv[2]
    if not lesson_path.is_file():
        print(
            f"verify_forward_actor: lesson not found: {lesson_path}",
            file=sys.stderr,
        )
        return 1
    row = load_observation(observation_id)
    observation_text = row.get("observation") or ""
    source_run_dir = row.get("source_run_dir") or ""
    if not observation_text or not source_run_dir:
        raise SystemExit(
            f"verify_forward_actor: observation row missing observation/source_run_dir: {row!r}"
        )
    story_text = load_story(source_run_dir)
    user_prompt = render_user_prompt(
        lesson_path.read_text(), observation_text, story_text
    )
    t0 = time.monotonic()
    output = call_haiku(user_prompt)
    elapsed = time.monotonic() - t0
    verdict = parse_verdict(output)
    log_path = os.environ.get("VERIFY_TIMING_LOG") or str(
        HERE / "_verify_timing_actor.log"
    )
    try:
        with open(log_path, "a") as fh:
            fh.write(f"{lesson_path.name} {observation_id} {elapsed:.2f}\n")
    except OSError:
        pass
    print(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
