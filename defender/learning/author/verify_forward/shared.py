#!/usr/bin/env python3
"""Shared pure helpers for the verify-forward gate trio.

``forward.py`` (adversarial/benign lesson check), ``actor.py`` (actor lesson check) and
``env.py`` (deterministic environment lesson check) used to carry byte-identical copies of
these helpers, differing only in the ``verify_forward*:`` error prefix and the prompt
placeholders. They live here once, parameterized on ``error_prefix`` (and, for the prompt,
on the template path + substitution kwargs), so the trio shares one implementation.

Pure + importable: no module-level state, no side effects on import, no pydantic-ai —
these stay usable under any interpreter (the ``tests/test_verify_forward`` subprocess cases
import this without the runtime extra). The LLM TRANSPORT the two model-driven gates share —
the in-process GLM forward-check — lives in ``engine.py`` (imported lazily by their
``main``s); ``parse_verdict`` here parses its ``VERDICT: GOOD|BAD`` output.
"""
from __future__ import annotations

from pathlib import Path

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


def parse_verdict(text: str, *, error_prefix: str) -> str:
    for line in reversed(text.strip().splitlines()):
        s = line.strip()
        if s.startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip()
            if v in ("GOOD", "BAD"):
                return v
            raise SystemExit(f"{error_prefix}: unrecognized verdict {v!r}")
    raise SystemExit(
        f"{error_prefix}: no VERDICT line found in verifier output:\n" + text[-1000:]
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
