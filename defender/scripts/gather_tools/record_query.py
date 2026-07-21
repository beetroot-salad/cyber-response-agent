#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._env import env_int
from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths

LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
_NON_ADAPTER = frozenset({"invlang"})

def _passthrough_max_bytes() -> int:
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", 65536)


PASSTHROUGH_SAMPLE_COUNT = 3
_SAMPLE_MAX_CHARS = 600
_RECORD_KEYS = ("hits", "results", "events", "records", "data", "rows")


def derive_system(inner: list[str]) -> str | None:
    for tok in inner:
        if tok.startswith("defender-") and "/" not in tok and "=" not in tok:
            name = tok[len("defender-"):]
            if name and name not in _NON_ADAPTER:
                return name
        if "=" in tok:
            continue
        m = _ADAPTER_RE.search(tok)
        if m:
            name = m.group(1).replace("_", "-")
            if name not in _NON_ADAPTER:
                return name
    return None


def payload_digest(stdout: str, stderr: str, exit_code: int) -> str:
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _find_records(stdout: str):
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in _RECORD_KEYS:
            if isinstance(obj.get(key), list):
                return obj[key]
        lists = [v for v in obj.values() if isinstance(v, list)]
        if lists:
            return max(lists, key=len)
    return None


def _is_event_payload(stdout: str) -> bool:
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    if isinstance(obj, list):
        return True
    if isinstance(obj, dict):
        return any(isinstance(obj.get(k), list) for k in _RECORD_KEYS)
    return False


def _envelope_total(stdout: str) -> int | None:
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("total"), int) and not isinstance(
        obj.get("total"), bool
    ):
        return obj["total"]
    return None


def build_truncated_view(stdout: str, payload_rel: str | None, run_dir: Path) -> str:
    size = len(stdout)
    records = _find_records(stdout)
    total = _envelope_total(stdout)
    sampled = records is not None and total is not None and total > len(records)
    lines: list[str] = []
    if records is not None:
        shown = min(len(records), PASSTHROUGH_SAMPLE_COUNT)
        if sampled:
            lines.append(
                f"[record_query] {total} total matches (EXACT, from the envelope). "
                f"This payload is a {len(records)}-doc SAMPLE (returned-doc cap), "
                f"{size} bytes — showing the first {shown} for field shape. COUNTS "
                f"come from `total` (to count a subset, re-query with the narrowing "
                f"filter and read its `total`); NEVER count the sample — its length "
                f"is the cap, not a count."
            )
        else:
            lines.append(
                f"[record_query] {len(records)} records, {size} bytes — showing the "
                f"first {shown} as a FIELD-SHAPE sample (to write your filters). Do NOT "
                f"count these or read values off them; compute over the full payload on disk."
            )
        for idx, rec in enumerate(records[:PASSTHROUGH_SAMPLE_COUNT]):
            sample = json.dumps(rec, default=str)
            if len(sample) > _SAMPLE_MAX_CHARS:
                sample = sample[:_SAMPLE_MAX_CHARS] + "…"
            lines.append(f"sample[{idx}]: {sample}")
    else:
        lines.append(f"[record_query] {size} bytes — pass-through truncated")
        lines.append(stdout[:_SAMPLE_MAX_CHARS * PASSTHROUGH_SAMPLE_COUNT] + "…")
    if payload_rel:
        abs_payload = run_dir / payload_rel
        if sampled:
            lines.append(f"sample payload (≤ cap, field shape only): {abs_payload}")
            lines.append(
                "→ COUNTS come from a query envelope's `total`, not this file: to count "
                "a subset, re-query with the narrowing filter and read its `total`. Use "
                "the on-disk sample only to read field shape, e.g. (the viewers read "
                "STDIN — pipe the file in, don't pass it as an operand):\n"
                f"  cat {abs_payload} | head -40"
            )
        else:
            lines.append(f"full payload: {abs_payload}")
            lines.append(
                "→ compute every value over the full payload on disk (defender-sql, grep); "
                "never count or read answers off the samples above. The reducers read STDIN "
                "— pipe the file in, don't pass it as an operand, e.g.:\n"
                f"  cat {abs_payload} | defender-sql 'SELECT count(*) FROM data'"
            )
    return "\n".join(lines) + "\n"


def _next_seq(run_dir: Path, lead: str) -> int:
    log = RunPaths(run_dir).executed_queries
    try:
        rows = read_jsonl_rows(log)
    except OSError:
        return 0
    return sum(
        1
        for rec in rows
        if isinstance(rec, dict) and rec.get("lead_id") == lead
    )


