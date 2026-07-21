#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from defender._io import read_jsonl_rows


def data_section(label: str, body: str) -> str:
    return f"{label}:\n\n{body.strip()}"


def parse_verdict(text: str, *, error_prefix: str) -> str:
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
    if not pending.is_file():
        raise SystemExit(f"{error_prefix}: pending queue not found at {pending}")
    for row in read_jsonl_rows(pending):
        if row.get("observation_id") == observation_id:
            return row
    raise SystemExit(
        f"{error_prefix}: observation_id {observation_id!r} not found in {pending}"
    )
