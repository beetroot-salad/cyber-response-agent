from __future__ import annotations

import json
import re

from uuid import uuid4
import yaml

from defender._untrusted import wrap
from defender._yaml import safe_load
from defender.learning.core.config import RunUnprocessable
from defender.learning.core.validate import strip_yaml_fence
from defender.learning.pipeline._prompt import stage_user_message



_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?Z\b")
_CLOCK_HM = re.compile(r"(?<![\d:])\d{1,2}:\d{2}Z\b")


def sanitize_wtc(item: str) -> str:
    item = _ISO.sub("<alert-time>", item)
    item = _CLOCK.sub("<alert-time>", item)
    item = _CLOCK_HM.sub("<alert-time>", item)
    return item



_RAW_SAMPLE_HEADER_RE = re.compile(r"^### Raw Sample Events\b.*$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _scrub_skeleton(value, key=None):
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
    return value


def redact_exemplar(text: str) -> str:
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
    if not sample:
        return "(schema sample block is empty; skeleton unavailable for this lead)"

    skeleton = _scrub_skeleton(sample)
    return (
        f"{header_line} (values scrubbed — type/field skeleton only)\n\n"
        f"```json\n{json.dumps(skeleton, indent=2)}\n```"
    )


def lead_sample_text(lead) -> str:
    unreadable: Exception | None = None
    for q in lead.queries:
        if q.raw_ref is None or not q.raw_ref.is_file():
            continue
        try:
            raw = q.raw_ref.read_bytes().decode("utf-8")
        except (UnicodeDecodeError, OSError) as e:
            # A by-ref payload is bytes an adapter wrote, so neither its encoding nor its
            # readability is guaranteed. One unreadable payload does not blind the lead: the
            # loop goes on to its OTHER payloads, exactly as it does for one that decodes but
            # carries no sample — the same posture the judge's own reader takes
            # (`judge/compare.real_sample_text`). Raising here took the whole stage down over a
            # single bad file.
            unreadable = e
            continue
        body = redact_exemplar(raw)
        if not body.startswith("("):
            return body
    if unreadable is not None:
        return f"(schema sample unreadable — {unreadable}; skeleton unavailable for this lead)"
    return "(no schema sample available for this lead)"


# #791: `unredacted_exemplar` / `real_sample_text` MOVED to
# `defender/learning/pipeline/judge/compare.py` — the judge's surviving evidence column is
# the one caller left, and it must import nothing from this retired package.


def _query_lines(lead) -> str:
    lines = []
    for q in lead.queries:
        lines.append(f"  - id: {q.query_id}")
        lines.append(f"    params: {json.dumps(q.params or {})}")
    return "\n".join(lines) if lines else "  (none)"


def build_lead_user_prompt(lead, story: str, sample_text: str, *, salt: str | None = None) -> str:
    raw_wtc = lead.what_to_summarize
    if isinstance(raw_wtc, str):
        raw_wtc = [raw_wtc]
    elif not isinstance(raw_wtc, list):
        raw_wtc = []
    san_wtc = [sanitize_wtc(x) for x in raw_wtc if isinstance(x, str)]
    wtc_block = (
        yaml.safe_dump(san_wtc, default_flow_style=False, allow_unicode=True).rstrip()
        if san_wtc else "  (none)"
    )
    stage_salt = salt if salt is not None else uuid4().hex
    lead_body = (
        f"lead_id: {lead.lead_id}\n"
        "what_to_summarize:\n"
        f"{wtc_block}\n\n"
        "queries:\n"
        f"{_query_lines(lead)}\n\n"
        "Emit the events the story's activity would produce that surface through this "
        "lead's queries, as a signed diff over the baseline."
    )
    return stage_user_message(
        stage_salt,
        wrap(story, "actor_story", stage_salt),
        wrap(lead_body, "lead", stage_salt),
        wrap(sample_text, "sample_event", stage_salt),
    )




_UNQUOTED_SUPPRESSED_RE = re.compile(r'^(\s*-\s*)(<suppressed:.*>)\s*$', re.MULTILINE)


def _quote_unquoted_markers(text: str) -> str:
    return _UNQUOTED_SUPPRESSED_RE.sub(r'\1"\2"', text)


def parse_lead_events(raw: str, lead_id) -> list:
    cleaned = _quote_unquoted_markers(strip_yaml_fence(raw))
    try:
        doc = safe_load(cleaned)
    except yaml.YAMLError as e:
        raise RunUnprocessable(
            f"oracle lead {lead_id}: reply is not valid YAML: {e}\n"
            f"--- raw reply ---\n{raw[:2000]}"
        ) from e
    events = doc.get("events") if isinstance(doc, dict) else None
    if not isinstance(events, list):
        raise RunUnprocessable(
            f"oracle lead {lead_id}: reply has no `events` list "
            f"(got {type(events).__name__})\n--- raw reply ---\n{raw[:2000]}"
        )
    return events


def assemble_oracle_doc(projections: list[tuple]) -> dict:
    return {
        "projections": [
            {"lead_id": lead_id, "events": events} for lead_id, events in projections
        ]
    }
