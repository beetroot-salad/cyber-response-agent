"""Per-lead telemetry oracle: input building, sample scrubbing, output assembly.

The oracle runs once per lead (``_loop_subagents.ClaudePrintSubagents.oracle`` fans
the calls out concurrently). Each call sees only its own lead — sanitized
``what_to_summarize`` + queries + one scrubbed sample event — and emits the lead's
predicted result as a signed diff over the baseline (``<standard environment noise>``):
distinguishable events, an additive-noise marker, a subtractive ``<suppressed: …>``
marker, or empty. This module owns the deterministic glue around those calls:

- ``sanitize_wtc`` — strip concrete clock times out of a ``what_to_summarize`` item so
  the oracle can't copy a wrong timestamp into an event (it falls back to ``<alert-time>``).
- ``redact_exemplar`` — reduce a ``gather_raw`` payload to a value-scrubbed shape skeleton
  (leaking the defender's real result would contaminate the projected-vs-actual compare).
- ``build_lead_user_prompt`` — assemble one lead's user message (no ``goal``).
- ``parse_lead_events`` / ``assemble_oracle_doc`` — turn the per-lead ``events:`` replies
  into the ``{projections: [{lead_id, events}]}`` doc the validator + judge consume.
"""
from __future__ import annotations

import json
import re

import yaml

from _loop_config import LoopError
from _loop_validate import strip_yaml_fence


# ---------------------------------------------------------------------------
# what_to_summarize timestamp sanitizer
# ---------------------------------------------------------------------------

_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?Z\b")    # HH:MM:SS(.ms)Z (UTC only)
_CLOCK_HM = re.compile(r"(?<![\d:])\d{1,2}:\d{2}Z\b")          # bare HH:MMZ


def sanitize_wtc(item: str) -> str:
    """Replace every absolute UTC clock time in a ``what_to_summarize`` item with ``<alert-time>``.

    A concrete clock time embedded in ``what_to_summarize`` (e.g. "the login at
    17:08:19Z") is copyable: the oracle lifts it into an event timestamp even when the
    story never stated it, fabricating a wrong-time event. Relativizing it to the
    oracle's own ``<alert-time>`` anchor removes the copyable value while keeping the
    salience. Only ISO8601 timestamps and ``Z``-suffixed clock times are relativized —
    a bare ``HH:MM:SS`` without the ``Z`` UTC marker is ambiguous (a duration like
    ``1:30:00``, or the time half of a space-separated local datetime) and is left
    untouched, as are relative spans ("within +/-5 minutes", "a few minutes later").
    Query *windows* are NOT sanitized here — they are the legitimate envelope the
    oracle filters on.
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
    if not sample:  # empty list/object/null — no shape to show; let the caller try siblings
        # Leading "(" signals lead_sample_text to skip this payload and glob a sibling.
        return "(schema sample block is empty; skeleton unavailable for this lead)"

    skeleton = _scrub_skeleton(sample)
    return (
        f"{header_line} (values scrubbed — type/field skeleton only)\n\n"
        f"```json\n{json.dumps(skeleton, indent=2)}\n```"
    )


def lead_sample_text(lead) -> str:
    """One scrubbed sample-event skeleton for a lead.

    Reads the lead's by-ref payloads (``gather_raw/{lead_id}/{seq}.json``,
    exposed as ``raw_ref`` on each query row) in seq order and returns the
    first that yields a real JSON skeleton; a placeholder string if none do.
    The FK subdir scopes a lead's payloads, so there is no cross-lead
    over-match to defend against — each query's payload is addressed directly.
    """
    for q in lead.queries:
        if q.raw_ref is None or not q.raw_ref.is_file():
            continue
        body = redact_exemplar(q.raw_ref.read_text())
        if not body.startswith("("):  # a real skeleton, not a "(no … available)" note
            return body
    return "(no schema sample available for this lead)"


def unredacted_exemplar(text: str) -> str:
    """Like ``redact_exemplar`` but keeps the real leaf values.

    The judge is the *scorer*, not a gray-box actor, so it sees real values — the
    sample orients it (field names + example values to shape a jq query); it still
    queries the full payload for absence-checks. Reuses the same two block regexes as
    ``redact_exemplar`` so the extraction can't drift. Leading ``(`` on a return value
    signals ``real_sample_text`` to try a sibling payload, matching ``lead_sample_text``.
    """
    header_m = _RAW_SAMPLE_HEADER_RE.search(text)
    if not header_m:
        return "(no sample available for this lead)"
    block = text[header_m.start():]
    header_line = block.split("\n", 1)[0]
    json_m = _JSON_BLOCK_RE.search(block)
    if not json_m:
        return f"{header_line}\n(sample not in JSON form)"
    try:
        sample = json.loads(json_m.group(1))
    except json.JSONDecodeError:
        return f"{header_line}\n(could not parse sample as JSON)"
    if not sample:
        return "(sample block is empty; none for this lead)"
    return (
        f"{header_line} (real values — orientation only)\n\n"
        f"```json\n{json.dumps(sample, indent=2)}\n```"
    )


def real_sample_text(lead) -> str:
    """One unredacted sample event for a lead (for the grounded judge).

    Same per-lead ``raw_ref`` scan as ``lead_sample_text``, but returns real values.
    """
    for q in lead.queries:
        if q.raw_ref is None or not q.raw_ref.is_file():
            continue
        body = unredacted_exemplar(q.raw_ref.read_text())
        if not body.startswith("("):
            return body
    return "(no sample available for this lead)"


# ---------------------------------------------------------------------------
# Per-lead user prompt
# ---------------------------------------------------------------------------


def _query_lines(lead) -> str:
    lines = []
    for q in lead.queries:
        lines.append(f"  - id: {q.query_id}")
        lines.append(f"    params: {json.dumps(q.params or {})}")
    return "\n".join(lines) if lines else "  (none)"


def build_lead_user_prompt(lead, story: str, sample_text: str) -> str:
    """Assemble one lead's user message: story + sanitized ``what_to_summarize`` +
    queries + scrubbed sample. The defender's prose ``goal`` is deliberately omitted
    (it drove fabrication-to-fill); the oracle sees ``what_to_summarize`` with absolute
    UTC timestamps relativized (see ``sanitize_wtc``).

    ``lead`` is a ``lead_repository.JoinedLead``.
    """
    raw_wtc = lead.what_to_summarize
    if isinstance(raw_wtc, str):           # a scalar slipped through — one item, not N chars
        raw_wtc = [raw_wtc]
    elif not isinstance(raw_wtc, list):
        raw_wtc = []
    san_wtc = [sanitize_wtc(x) for x in raw_wtc if isinstance(x, str)]
    wtc_block = (
        yaml.safe_dump(san_wtc, default_flow_style=False, allow_unicode=True).rstrip()
        if san_wtc else "  (none)"
    )
    return (
        "## The actor's story\n\n"
        f"{story.rstrip()}\n\n"
        f"## This lead ({lead.lead_id}) — no goal given\n\n"
        "what_to_summarize:\n"
        f"{wtc_block}\n\n"
        "queries:\n"
        f"{_query_lines(lead)}\n\n"
        "## Sample event one of these queries returned (shape reference; values scrubbed)\n\n"
        f"{sample_text}\n\n"
        "Emit the events the story's activity would produce that surface through this "
        "lead's queries, as a signed diff over the baseline.\n"
    )


# ---------------------------------------------------------------------------
# Per-lead reply parsing + doc assembly
# ---------------------------------------------------------------------------


_UNQUOTED_SUPPRESSED_RE = re.compile(r'^(\s*-\s*)(<suppressed:.*>)\s*$', re.MULTILINE)


def _quote_unquoted_markers(text: str) -> str:
    """Double-quote an unquoted ``- <suppressed: …>`` list item before YAML parsing.

    The ``<suppressed: REASON>`` marker contains a colon, so an unquoted list item is read
    by YAML as a broken one-key mapping — and, when REASON carries a *second* ``: ``, raises
    a ScannerError outright (no mapping to rescue post-hoc). Wrapping the whole marker in
    double quotes makes it a clean string regardless of how many colons REASON holds. The
    ``<standard environment noise>`` marker has no colon and parses fine unquoted, so it is
    left alone. An already-quoted item (``- "<suppressed: …>"``) has a ``"`` right after the
    dash, not a ``<``, so the anchored pattern does not match and it is not double-quoted.
    """
    return _UNQUOTED_SUPPRESSED_RE.sub(r'\1"\2"', text)


def parse_lead_events(raw: str, lead_id) -> list:
    """Parse one per-lead oracle reply into its ``events`` list.

    The reply is a single YAML doc whose only key is ``events`` (a list of event mappings,
    or a single-item marker list, or ``[]``). Tolerates a stray fence/envelope via
    ``strip_yaml_fence`` and an unquoted suppression marker via ``_quote_unquoted_markers``.
    Raises ``LoopError`` (with the raw reply embedded for debuggability — a per-lead failure
    otherwise leaves nothing on disk) on anything that is not an ``events`` list; item-level
    shape (mapping vs marker string) is the validator's job downstream.
    """
    cleaned = _quote_unquoted_markers(strip_yaml_fence(raw))
    try:
        doc = yaml.safe_load(cleaned)
    except yaml.YAMLError as e:
        raise LoopError(
            f"oracle lead {lead_id}: reply is not valid YAML: {e}\n"
            f"--- raw reply ---\n{raw[:2000]}"
        ) from e
    events = doc.get("events") if isinstance(doc, dict) else None
    if not isinstance(events, list):
        raise LoopError(
            f"oracle lead {lead_id}: reply has no `events` list "
            f"(got {type(events).__name__})\n--- raw reply ---\n{raw[:2000]}"
        )
    return events


def assemble_oracle_doc(projections: list[tuple]) -> dict:
    """Build the ``{projections: [{lead_id, events}]}`` doc from per-lead results.

    ``projections`` is a list of ``(lead_id, events)`` tuples in lead order — the
    ``lead_id`` is the ``:L`` row id (FK), replacing the former dispatch position.
    """
    return {
        "projections": [
            {"lead_id": lead_id, "events": events} for lead_id, events in projections
        ]
    }
