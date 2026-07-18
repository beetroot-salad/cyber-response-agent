#!/usr/bin/env python3
"""The queries table's PAYLOAD-SHAPING half — what a captured payload looks like on disk, in
the row, and in the model's context.

This module used to be a WRAPPER: a `defender-record-query` CLI the gather subagent piped its
adapter call through, which ran the inner command as a subprocess, captured its stdout, and
appended the queries row. #611 took the subprocess away — a data-source call is a typed `query`
tool now, and the row + by-ref payload are written by its capture capability
(`runtime/query_tool.py`), in-process. So `main()`, `parse_params` (which flattened every
positional into a meaningless `arg0`/`arg1`), `_derive_verb`, and `capture()` itself are gone
with the argv they parsed.

What survives is everything that was never about the process boundary:

  - `_next_seq` — the per-lead sequence, counted from ROWS (not files on disk), so a query whose
    payload write failed still advances it and the next query cannot collide on `(lead_id, seq)`.
  - `build_truncated_view` / `_is_event_payload` / `_envelope_total` / `payload_digest` — the
    in-context VIEW of a payload: a field-shape sample plus a pointer to the file, never the dump.
  - `_passthrough_max_bytes` — the char ceiling, shared with the `read_file` tool (`tools.py`
    imports it as `_read_char_cap`), so an on-disk read can never defeat the passthrough cap.
    Nothing to do with adapters; it is why this module could not simply be deleted.

The per-lead group id `L` comes from the dispatch (the `:L` invlang row id, e.g. `l-001`; see
`hooks/record_lead.py`); it is the address namespace for this lead's payloads and the
queries-table FK (`lead_id`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` imports resolve whether this file is
# imported in-process or read directly.
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._env import env_int
from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths

# A lead_id is the `:L` invlang row id used verbatim as the queries-table FK
# and a gather_raw/ path segment. Grammar mirrors hooks/record_lead.py and the
# invlang lead-id grammar (defender/skills/invlang/SKILL.md) — keep in sync.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

# An adapter `<system>_adapter.py` path token → its `<system>`. `\w+` (not
# `[A-Za-z0-9]+`) so a multi-word filename captures fully — `host_state_adapter.py`
# → `host_state` (normalized to `host-state` below), matching the `\w+_adapter` form
# in hooks/_cmd_segments.ADAPTER_RE.
_ADAPTER_RE = re.compile(r"(?:^|/)(\w+)_adapter\.py$")
# Non-adapter `defender-*` shims — never a lead system. Mirrors
# hooks/_cmd_segments.NON_ADAPTER_SHIMS. `record-query` left with its shim (#611).
_NON_ADAPTER = frozenset({"invlang"})

# Size safety: a query that over-returns (server-side filter didn't bind,
# broad window, high-cardinality index) would otherwise dump its whole
# stdout into the subagent's context — the 6000-hit / 500KB flood that
# drives hand-counting. Above this byte ceiling the pass-through is
# replaced by a count + samples + a pointer to the on-disk payload and a
# nudge to filter that file with jq/grep instead. The full payload is
# always persisted regardless; only the in-context view is capped.
def _passthrough_max_bytes() -> int:
    """The pass-through byte ceiling, read at call time so an env override set
    after import (e.g. a test's ``monkeypatch.setenv``) takes effect."""
    return env_int("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", 65536)


PASSTHROUGH_SAMPLE_COUNT = 3
_SAMPLE_MAX_CHARS = 600
_RECORD_KEYS = ("hits", "results", "events", "records", "data", "rows")


def derive_system(inner: list[str]) -> str | None:
    """Infer the lead ``system`` from the inner adapter invocation, generically.

    The inner command (everything after ``--``) is the adapter call: a
    ``defender-<system>`` shim or a ``<system>_adapter.py`` path. Returns the first
    system name found, or None when none is detectable (the caller then requires
    an explicit ``--system``). Pure — no IO, no per-system table; a newly
    onboarded adapter is covered with no edit here."""
    for tok in inner:
        # Adapter shim form `defender-<system>`. Require a bare shim token: skip
        # path/flag values that merely start with `defender-` (a
        # `…/defender-runs/…` arg, a `--defender-dir` value), which would
        # otherwise yield a garbage system. Mirrors the command-position anchor
        # block_main_loop_raw_access's adapter-shim regex uses for the same reason.
        if tok.startswith("defender-") and "/" not in tok and "=" not in tok:
            name = tok[len("defender-"):]
            if name and name not in _NON_ADAPTER:
                return name
        # Raw `<system>_adapter.py` path form. The filename uses `_` where the
        # canonical system name (and the `defender-<system>` shim) uses `-`
        # (host_state_adapter.py → host-state), so normalize to agree with the
        # shim-derived spelling and the queries-table join key. Skip `VAR=…`
        # assignment values (never an executable path) so a stray
        # `FOO=/x/elastic_adapter.py` doesn't pre-empt the real adapter token.
        if "=" in tok:
            continue
        m = _ADAPTER_RE.search(tok)
        if m:
            name = m.group(1).replace("_", "-")
            if name not in _NON_ADAPTER:
                return name
    return None


def payload_digest(stdout: str, stderr: str, exit_code: int) -> str:
    """Structural ≤200-char digest. Deterministic, not a smell-test —
    the lead-author reads the raw payload when it needs semantics."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _find_records(stdout: str):
    """Best-effort record array for sampling. Returns None if stdout isn't
    JSON or holds no obvious list (callers fall back to char truncation)."""
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
    """True iff stdout is an event/record *collection* — a top-level JSON array,
    or a dict carrying a recognized records key (`hits`/`results`/`events`/…).

    Stricter than ``_find_records`` on purpose: it does NOT use the "any list
    value" fallback, so a single object that merely *contains* a list field (an
    identity profile's ``authorized_hosts``, a host's ``ips``) is NOT flagged as
    an event stream — that object is the answer and passes through whole. This is
    the predicate that decides "always sample"; ``_find_records`` only decides
    what to sample once we're capping."""
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
    """Exact server-side match count from an adapter's JSON payload
    (`{total, returned, truncated, hits:[…]}`) — independent of how many docs were
    actually returned. None when the payload has no such field (a plain list, or an
    adapter that doesn't report a total): then the returned-record count is all
    there is. Keys on the field-name convention like `_RECORD_KEYS` — no per-system
    table, so an adapter adopting this shape is covered with no edit here."""
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
    """Reduce the in-context pass-through to a *field-shape sample*, not the full
    dump. A record-list payload becomes a count + the first few records (so the
    agent sees the field shape to write its filters) + a pointer to the persisted
    file; a non-list blob is char-truncated. The value is computed over the on-disk
    payload (gather SKILL §4), never read off this view.

    When the payload carries an exact envelope `total` greater than the returned
    set (an adapter with a non-overridable returned-doc cap), the
    on-disk file is a *bounded sample*, not the full data: counts come from `total`,
    never from counting the sample — so the message says so, and the agent doesn't
    jq-length a capped array and report the cap as the count."""
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
                "the on-disk sample only to read field shape, e.g. (jq reads STDIN — pipe "
                "the file in, don't pass it as an operand):\n"
                f"  cat {abs_payload} | jq '.hits[0]'"
            )
        else:
            lines.append(f"full payload: {abs_payload}")
            lines.append(
                "→ compute every value over the full payload on disk (jq, grep, the Grep "
                "tool); never count or read answers off the samples above. jq reads STDIN "
                "— pipe the file in, don't pass it as an operand, e.g.:\n"
                f"  cat {abs_payload} | jq '[.hits[] | select(.message | test(\"<substr>\"))] | length'"
            )
    return "\n".join(lines) + "\n"


def _next_seq(run_dir: Path, lead: str) -> int:
    """Next per-lead seq = number of rows already recorded for this lead in the
    queries table.

    Counting rows (not payload files on disk) keeps seq monotonic even when a
    payload write failed: that query still appends a row with ``payload_path:
    null``, so the next query won't reuse the seq and collide on
    ``(lead_id, seq)``.
    """
    log = RunPaths(run_dir).executed_queries
    try:
        rows = read_jsonl_rows(log)
    except OSError:
        # A read error after the is_file() check (TOCTOU delete, permission,
        # ENOSPC) degrades to seq 0 — the pre-_io behavior. read_jsonl_rows
        # tolerates torn lines but not a failed read, and neither capture()
        # call site (CLI main / in-process _capture_query) catches OSError, so
        # letting it propagate would abort the whole gather instead.
        return 0
    return sum(
        1
        for rec in rows
        if isinstance(rec, dict) and rec.get("lead_id") == lead
    )


