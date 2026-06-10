#!/usr/bin/env python3
"""Forward-check Haiku gate for a single candidate lesson.

Usage: ``verify_forward.py [--direction adversarial|benign] <lesson_path> <run_id>``

Reads the lesson file, the source case's investigation transcript at
``defender/learning/runs/<run_id>/investigation.md``, and the recorded
disposition from
``defender/learning/runs/<run_id>/source_refs.yaml``. Calls
``claude -p --model claude-haiku-4-5`` with
``defender/learning/verify_forward.md`` as the system prompt.
Prints exactly ``GOOD`` or ``BAD`` on the last line of stdout.

The disposition handed to the verifier is direction-aware (see
``expected_disposition``): a benign-direction (FP) lesson is generated from a
run the defender called ``malicious`` but which it exists to *correct toward*
``benign``, so the recorded ``malicious`` is exactly what it must NOT preserve.

Single rep — replication is for statistical TNR/TPR measurement, not
per-edit gating (see ``experiments/defender-author-verification/results/final.md``).
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
# The run bundle (investigation.md + source_refs.yaml) is written under
# DEFAULT_PATHS.runs_dir, which honors DEFENDER_LEARNING_STATE_DIR — out-of-repo
# under concurrent runs. Resolve from the same seam the producer wrote to rather
# than assuming the in-repo default. _loop_config is stdlib-only (no pyyaml), so
# importing it keeps this verifier runnable under any interpreter.
sys.path.insert(0, str(HERE))
try:
    from _loop_config import DEFAULT_PATHS  # type: ignore[import-not-found]
finally:
    sys.path.pop(0)
RUNS_DIR = DEFAULT_PATHS.runs_dir
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
    # source_refs.yaml is a flat key:value document with one nested
    # `paths:` block; we only need `normalized_disposition` from the
    # top level. Parse with a regex so the verifier runs under any
    # python interpreter (no pyyaml dependency).
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs.read_text(),
        re.MULTILINE,
    )
    if not m:
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
        )
    return investigation.read_text(), m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    """The disposition the lesson must drive the agent toward on its source case.

    Adversarial findings author only on a ``benign`` source disposition, and the
    lesson must *preserve* that benign call (generalize suspicion without
    over-escalating this known-good case) — so the recorded disposition is the
    target the verifier checks against. Benign (FP-direction) findings author on
    a ``malicious`` source disposition that the FP signal says was an
    over-escalation: the lesson exists to drive the agent *off* that malicious
    call toward ``benign``, so the recorded ``malicious`` is exactly what it must
    NOT preserve. Handing the verifier the recorded ``malicious`` would mark
    every de-escalation lesson BAD, holding the entire FP lesson path. The
    corrected target for the benign direction is therefore ``benign``.

    (Residual: this makes the benign forward-check an *efficacy* check — does the
    lesson reach the corrected disposition on its own source case — not a
    cross-case FN-safety guard against under-escalating real attacks. That guard
    needs known-malicious cases the source FP case is not; it is out of scope for
    a per-source-case forward check. See tasks/benign-actor-success-retrieval.md.)
    """
    if direction == "benign":
        return "benign"
    return recorded


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
    ap = argparse.ArgumentParser(prog="verify_forward.py")
    ap.add_argument(
        "--direction",
        default="adversarial",
        choices=["adversarial", "benign"],
        help=(
            "learning direction of the finding (default: adversarial). A benign "
            "finding targets the corrected `benign` disposition instead of the "
            "recorded one — pass the finding row's `direction`."
        ),
    )
    ap.add_argument("lesson_path")
    ap.add_argument("run_id")
    ns = ap.parse_args(argv[1:])
    lesson_path = Path(ns.lesson_path).resolve()
    run_id = ns.run_id
    if not lesson_path.is_file():
        print(f"verify_forward: lesson not found: {lesson_path}", file=sys.stderr)
        return 1
    transcript, recorded = load_run_context(run_id)
    disposition = expected_disposition(ns.direction, recorded)
    user_prompt = render_user_prompt(lesson_path.read_text(), transcript, disposition)
    import time as _time
    t0 = _time.monotonic()
    output = call_haiku(user_prompt)
    elapsed = _time.monotonic() - t0
    verdict = parse_verdict(output)
    # Append timing for the harness to reconstruct verifier time. The
    # path is opportunistic: if VERIFY_TIMING_LOG is set we use it,
    # else fall back to a sibling file next to the script. Last line
    # of stdout is still the verdict — author.md reads `last line` only.
    log_path = os.environ.get("VERIFY_TIMING_LOG") or str(HERE / "_verify_timing.log")
    try:
        with open(log_path, "a") as fh:
            fh.write(f"{lesson_path.name} {run_id} {elapsed:.2f}\n")
    except OSError:
        pass
    print(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
