"""Per-lead telemetry oracle: input building, sample scrubbing, output assembly.

The oracle runs once per lead (``_loop_subagents.ClaudePrintSubagents.oracle`` fans
the calls out concurrently). Each call sees only its own lead — sanitized
``what_to_characterize`` + queries + one scrubbed sample event — and emits the lead's
predicted result as a signed diff over the baseline (``<standard environment noise>``):
distinguishable events, an additive-noise marker, a subtractive ``<suppressed: …>``
marker, or empty. This module owns the deterministic glue around those calls:

- ``sanitize_wtc`` — strip concrete clock times out of a ``what_to_summarize`` item so
  the oracle can't copy a wrong timestamp into an event (it falls back to ``<alert-time>``).
- ``redact_exemplar`` — reduce a ``gather_raw`` payload to a value-scrubbed shape skeleton
  (leaking the defender's real result would contaminate the projected-vs-actual compare).
- ``build_lead_user_prompt`` — assemble one lead's user message (no ``goal``).
- ``parse_lead_events`` / ``assemble_oracle_doc`` — turn the per-lead ``events:`` replies
  into the ``{projections: [{position, events}]}`` doc the validator + judge consume.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from _loop_config import LoopError
from _loop_validate import strip_yaml_fence


# ---------------------------------------------------------------------------
# what_to_characterize timestamp sanitizer
# ---------------------------------------------------------------------------

_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")   # HH:MM:SS(.ms)(Z)
_CLOCK_HM = re.compile(r"(?<![\d:])\d{1,2}:\d{2}Z\b")          # bare HH:MMZ


def sanitize_wtc(item: str) -> str:
    """Replace every absolute clock time in a characterization item with ``<alert-time>``.

    A concrete clock time embedded in ``what_to_summarize`` (e.g. "the login at
    17:08:19Z") is copyable: the oracle lifts it into an event timestamp even when the
    story never stated it, fabricating a wrong-time event. Relativizing it to the
    oracle's own ``<alert-time>`` anchor removes the copyable value while keeping the
    salience. Relative spans ("within +/-5 minutes", "a few minutes later") carry no
    absolute value and survive untouched. Query *windows* are NOT sanitized here — they
    are the legitimate envelope the oracle filters on.
    """
    item = _ISO.sub("<alert-time>", item)
    item = _CLOCK.sub("<alert-time>", item)
    item = _CLOCK_HM.sub("<alert-time>", item)
    return item


# ---------------------------------------------------------------------------
# Sample-event scrubbing (ported from main:defender/learning/_loop_exemplars.py)
# ---------------------------------------------------------------------------

_RAW_SAMPLE_HEADER_RE = re.compile(r"^### Raw Sample Events\b.*$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _scrub_skeleton(value, key=None):
    """Replace concrete leaf values with a type/field skeleton.

    Strings become ``<key>`` (or ``<string>`` without key context); numbers -> 0;
    booleans -> false; nulls stay null. Lists collapse to a single scrubbed element;
    dicts recurse, threading the parent key down so child strings carry their field name.
    """
    if isinstance(value, dict):
        return {k: _scrub_skeleton(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_skeleton(value[0], key)] if value else []
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, str):
        return f"<{key}>" if key else "<string>"
    return value  # null


def redact_exemplar(text: str) -> str:
    """Reduce a ``gather_raw`` payload to a schema-only skeleton.

    Drops everything outside the ``### Raw Sample Events`` block (so counts and
    per-event values from Summary/Aggregations are gone), then replaces every concrete
    leaf inside the embedded JSON with a ``<field-name>`` placeholder. With no Raw Sample
    Events block (or an empty one), returns a placeholder — the oracle still has the
    system/template/params from the lead and projects shape from those.
    """
    header_m = _RAW_SAMPLE_HEADER_RE.search(text)
    if not header_m:
        return "(no schema sample available for this lead)"
    block = text[header_m.start():]
    header_line = block.split("\n", 1)[0]

    json_m = _JSON_BLOCK_RE.search(block)
    if not json_m:
        return f"{header_line}\n(schema sample not in JSON form; skeleton unavailable)"
    try:
        sample = json.loads(json_m.group(1))
    except json.JSONDecodeError:
        return f"{header_line}\n(could not parse schema sample as JSON; skeleton unavailable)"

    skeleton = _scrub_skeleton(sample)
    return (
        f"{header_line} (values scrubbed — type/field skeleton only)\n\n"
        f"```json\n{json.dumps(skeleton, indent=2)}\n```"
    )


def lead_sample_text(run_dir: Path, entry: dict) -> str:
    """One scrubbed sample-event skeleton for a lead.

    Tries the entry's ``result_ref`` first, then falls back to globbing the lead's
    multi-query payloads (``gather_raw/{position}{a..z}.json``) — a single dispatch can
    fan into several files and ``result_ref`` may point at a position that was never
    written as a bare ``{position}.json``. Returns the first payload that yields a real
    JSON skeleton; a placeholder string if none do.
    """
    position = entry.get("position")
    gather_dir = run_dir / "gather_raw"
    candidates: list[Path] = []
    result_ref = entry.get("result_ref")
    if result_ref:
        candidates.append(run_dir / result_ref)
    if position is not None:
        candidates += sorted(
            p for p in gather_dir.glob(f"{position}*.json")
            if not p.name.endswith((".observations.json", ".lead.json"))
        )
    seen: set[Path] = set()
    for path in candidates:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        body = redact_exemplar(path.read_text())
        if not body.startswith("("):  # a real skeleton, not a "(no … available)" note
            return body
    return "(no schema sample available for this lead)"


# ---------------------------------------------------------------------------
# Per-lead user prompt
# ---------------------------------------------------------------------------


def _query_lines(entry: dict) -> str:
    lines = []
    for q in entry.get("queries") or []:
        lines.append(f"  - id: {q.get('id')}")
        lines.append(f"    params: {json.dumps(q.get('params', {}))}")
    return "\n".join(lines) if lines else "  (none)"


def build_lead_user_prompt(entry: dict, story: str, sample_text: str) -> str:
    """Assemble one lead's user message: story + sanitized characterization + queries +
    scrubbed sample. The defender's prose ``goal`` is deliberately omitted (it drove
    fabrication-to-fill); ``what_to_characterize`` is the sanitized ``what_to_summarize``.
    """
    position = entry.get("position")
    raw_wtc = (entry.get("lead_description") or {}).get("what_to_summarize") or []
    san_wtc = [sanitize_wtc(x) for x in raw_wtc]
    wtc_block = (
        yaml.safe_dump(san_wtc, default_flow_style=False, allow_unicode=True).rstrip()
        if san_wtc else "  (none)"
    )
    return (
        "## The actor's story\n\n"
        f"{story.rstrip()}\n\n"
        f"## This lead (position {position}) — no goal given\n\n"
        "what_to_characterize:\n"
        f"{wtc_block}\n\n"
        "queries:\n"
        f"{_query_lines(entry)}\n\n"
        "## Sample event one of these queries returned (shape reference; values scrubbed)\n\n"
        f"{sample_text}\n\n"
        "Emit the events the story's activity would produce that surface through this "
        "lead's queries, as a signed diff over the baseline.\n"
    )


# ---------------------------------------------------------------------------
# Per-lead reply parsing + doc assembly
# ---------------------------------------------------------------------------


def _normalize_marker(ev):
    """Rescue an unquoted ``<suppressed: reason>`` marker that YAML parsed as a mapping.

    The colon-space in ``- <suppressed: stopped auditd>`` makes ``yaml.safe_load`` read the
    item as a one-key mapping ``{"<suppressed": "stopped auditd>"}`` rather than a string.
    The oracle is told to quote markers, but quoting discipline is imperfect; when an item is
    a one-key mapping whose key opens with ``<`` and whose value closes with ``>``, rejoin it
    to the intended ``"<...>"`` marker string so the judge reads a clean marker.
    """
    if isinstance(ev, dict) and len(ev) == 1:
        (k, v), = ev.items()
        if isinstance(k, str) and k.startswith("<") and isinstance(v, str) and v.endswith(">"):
            return f"{k}: {v}"
    return ev


def parse_lead_events(raw: str, position) -> list:
    """Parse one per-lead oracle reply into its ``events`` list.

    The reply is a single YAML doc whose only key is ``events`` (a list of event mappings,
    or a single-item marker list, or ``[]``). Tolerates a stray fence/envelope via
    ``strip_yaml_fence`` and an unquoted suppression marker via ``_normalize_marker``. Raises
    ``LoopError`` on anything that is not an ``events`` list — item-level shape (mapping vs
    marker string) is the validator's job downstream.
    """
    try:
        doc = yaml.safe_load(strip_yaml_fence(raw))
    except yaml.YAMLError as e:
        raise LoopError(f"oracle lead {position}: reply is not valid YAML: {e}") from e
    events = doc.get("events") if isinstance(doc, dict) else None
    if not isinstance(events, list):
        raise LoopError(
            f"oracle lead {position}: reply has no `events` list (got {type(events).__name__})"
        )
    return [_normalize_marker(ev) for ev in events]


def assemble_oracle_doc(projections: list[tuple]) -> dict:
    """Build the ``{projections: [{position, events}]}`` doc from per-lead results.

    ``projections`` is a list of ``(position, events)`` tuples in lead order. Output shape
    matches what the router used to emit (minus ``uncovered``/``unrouted_leads``), so the
    validator + judge are unchanged.
    """
    return {
        "projections": [
            {"position": position, "events": events} for position, events in projections
        ]
    }
