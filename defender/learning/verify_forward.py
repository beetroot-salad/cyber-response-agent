#!/usr/bin/env python3
"""Forward-check Haiku gate for a single candidate lesson.

Usage: ``verify_forward.py <lesson_path> <run_id>``

Reads the lesson file, the source case's investigation transcript at
``defender/learning/runs/<run_id>/investigation.md``, and the
ground-truth disposition from
``defender/learning/runs/<run_id>/source_refs.yaml``. Calls
``claude -p --model claude-haiku-4-5`` with
``defender/learning/verify_forward.md`` as the system prompt.
Prints exactly ``GOOD`` or ``BAD`` on the last line of stdout.

Single rep — replication is for statistical TNR/TPR measurement, not
per-edit gating (see ``tasks-scratch/defender-author-verification/results/final.md``).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
RUNS_DIR = HERE / "runs"
PROMPT_PATH = HERE / "verify_forward.md"

VERIFIER_MODEL = os.environ.get("LEARNING_VERIFIER_MODEL", "claude-haiku-4-5")
VERIFIER_TIMEOUT = int(os.environ.get("LEARNING_VERIFIER_TIMEOUT_SECONDS", "180"))


def load_run_context(run_id: str) -> tuple[str, str]:
    run_dir = RUNS_DIR / run_id
    investigation = run_dir / "investigation.md"
    refs = run_dir / "source_refs.yaml"
    if not investigation.is_file():
        raise SystemExit(f"verify_forward: missing investigation.md at {investigation}")
    if not refs.is_file():
        raise SystemExit(f"verify_forward: missing source_refs.yaml at {refs}")
    refs_doc = yaml.safe_load(refs.read_text())
    disposition = refs_doc.get("normalized_disposition")
    if not isinstance(disposition, str):
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
        )
    return investigation.read_text(), disposition


def render_user_prompt(lesson_text: str, transcript: str, disposition: str) -> str:
    template = PROMPT_PATH.read_text()
    return (
        template
        .replace("{transcript}", transcript)
        .replace("{lesson}", lesson_text)
        .replace("{disposition}", disposition)
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
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"verify_forward: claude -p failed (rc={proc.returncode}): "
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
            raise SystemExit(f"verify_forward: unrecognized verdict {v!r}")
    raise SystemExit(
        "verify_forward: no VERDICT line found in Haiku output:\n"
        + text[-1000:]
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: verify_forward.py <lesson_path> <run_id>", file=sys.stderr)
        return 64
    lesson_path = Path(argv[1]).resolve()
    run_id = argv[2]
    if not lesson_path.is_file():
        print(f"verify_forward: lesson not found: {lesson_path}", file=sys.stderr)
        return 1
    transcript, disposition = load_run_context(run_id)
    user_prompt = render_user_prompt(lesson_path.read_text(), transcript, disposition)
    output = call_haiku(user_prompt)
    verdict = parse_verdict(output)
    print(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
