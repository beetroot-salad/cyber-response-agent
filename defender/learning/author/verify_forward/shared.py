#!/usr/bin/env python3
"""Shared helpers for the verify-forward gate trio.

``verify_forward.py`` (adversarial lesson check), ``verify_forward_actor.py``
(actor lesson check) and ``verify_forward_env.py`` (deterministic environment
lesson check) used to carry byte-identical copies of these helpers, differing
only in the ``verify_forward*:`` error prefix and the prompt placeholders. They
live here once, parameterized on ``error_prefix`` (and, for the prompt, on the
template path + substitution kwargs), so the trio shares one implementation.

Pure + importable: no module-level state, no side effects on import. The
callers own ``VERIFIER_MODEL`` / ``VERIFIER_TIMEOUT`` and the
``subscription_env`` seam and pass them in, so behavior is identical to the
in-line copies this replaced.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from collections.abc import Callable

from defender._io import read_jsonl_rows


def render_prompt(template_path: Path, **subs: str) -> str:
    """Read ``template_path`` and substitute ``{key}`` -> value for each kwarg.

    Generic over placeholders: each caller passes the kwargs its template names
    (e.g. ``transcript=..., lesson=...`` or ``story=..., observation=...``).
    """
    text = template_path.read_text()
    for key, value in subs.items():
        text = text.replace("{" + key + "}", value)
    return text


def call_haiku(
    user_prompt: str,
    *,
    error_prefix: str,
    model: str,
    timeout: int,
    env_fn: Callable[[], dict],
) -> str:
    cmd = [
        "claude",
        "-p",
        "--model",
        model,
        "--output-format",
        "text",
    ]
    proc = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env_fn(),
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"{error_prefix}: claude -p failed (rc={proc.returncode}): "
            f"{proc.stderr[-2000:]}"
        )
    return proc.stdout


def parse_verdict(text: str, *, error_prefix: str) -> str:
    for line in reversed(text.strip().splitlines()):
        s = line.strip()
        if s.startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip()
            if v in ("GOOD", "BAD"):
                return v
            raise SystemExit(f"{error_prefix}: unrecognized verdict {v!r}")
    raise SystemExit(
        f"{error_prefix}: no VERDICT line found in Haiku output:\n" + text[-1000:]
    )


def load_observation(observation_id: str, pending: Path, *, error_prefix: str) -> dict:
    # Keep the explicit missing-file SystemExit: read_jsonl_rows would return []
    # and lose that contracted error. Reading via the shared tolerant reader
    # means a torn line elsewhere in the queue is skipped, not raised (#446).
    if not pending.is_file():
        raise SystemExit(f"{error_prefix}: pending queue not found at {pending}")
    for row in read_jsonl_rows(pending):
        if row.get("observation_id") == observation_id:
            return row
    raise SystemExit(
        f"{error_prefix}: observation_id {observation_id!r} not found in {pending}"
    )
