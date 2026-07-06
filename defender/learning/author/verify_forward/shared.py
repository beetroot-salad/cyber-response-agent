#!/usr/bin/env python3
"""Shared pure helpers for the verify-forward gate trio.

``forward.py`` (adversarial/benign lesson check), ``actor.py`` (actor lesson check) and
``env.py`` (deterministic environment lesson check) used to carry byte-identical copies of
these helpers, differing only in the ``verify_forward*:`` error prefix and the labeled data
blocks. They live here once, parameterized on ``error_prefix``, so the trio shares one
implementation.

Pure + importable: no module-level state, no side effects on import, no pydantic-ai —
these stay usable under any interpreter (the ``tests/test_verify_forward`` subprocess cases
import this without the runtime extra). The LLM TRANSPORT the two model-driven gates share —
the in-process GLM forward-check — lives in ``engine.py`` (imported lazily by their
``main``s); ``parse_verdict`` here parses its ``VERDICT: GOOD|BAD`` output.
"""
from __future__ import annotations

from pathlib import Path

from defender._io import read_jsonl_rows


def data_section(label: str, body: str) -> str:
    """One prose-labeled block — ``{label}:\\n\\n{body}`` — for a verifier's *data* (user) message.

    The two model-driven gates carry their INSTRUCTIONS in the ``.md`` that ``engine.run_stage``
    hands the agent as the system prompt, and build the *data-only* user message from these blocks —
    the system/user split the sibling stages honor (cf. the actor's ``_section``-built user in
    ``pipeline/malicious_actor/run.py``; that wraps bodies in ``<tag>``s, this keeps the verify
    prompts' own prose labels). A single f-string interpolation, so a ``body`` that itself contains a
    literal ``{placeholder}`` is inert (unlike a multi-pass ``str.replace`` template)."""
    return f"{label}:\n\n{body.strip()}"


def parse_verdict(text: str, *, error_prefix: str) -> str:
    # Tolerate a reasoning model (GLM, the migrated default) dressing the required line in markdown
    # emphasis / a heading marker / trailing punctuation — ``**VERDICT: GOOD**``, ``### VERDICT: BAD``,
    # ``VERDICT: GOOD.``, ``verdict: good`` — rather than losing an otherwise-valid verdict to a
    # formatting flourish (a lost verdict costs a metered call and surfaces as a batch ERROR). The
    # ``VERDICT:`` marker and the GOOD/BAD tokens themselves stay required.
    for line in reversed(text.strip().splitlines()):
        s = line.strip().strip("*`# ").strip()
        if s.upper().startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip().strip("*`. ").upper()
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
