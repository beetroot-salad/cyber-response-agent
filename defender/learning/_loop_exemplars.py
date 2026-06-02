"""Schema-only exemplar bundling for the telemetry oracle.

The oracle projects events from the actor story alone; handing it the full
`gather_raw/{position}.json` would leak the defender's *actual* lead result and
contaminate the projected-vs-actual comparison the judge later does. These helpers
reduce each payload to a value-scrubbed type/field skeleton.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from _loop_config import LoopError


_RAW_SAMPLE_HEADER_RE = re.compile(r"^### Raw Sample Events\b.*$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _scrub_skeleton(value, key=None):
    """Replace concrete leaf values with a type/field skeleton.

    Strings become `<key>` (or `<string>` without key context); numbers → 0;
    booleans → false; nulls stay null. Lists collapse to a single scrubbed element;
    dicts recurse, threading the parent key down so child strings carry their field
    name.
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
    """Reduce a `gather_raw/{position}.json` to a schema-only skeleton.

    Drops everything outside the `### Raw Sample Events` block (so counts and
    per-event values from Summary/Aggregations are gone), then replaces every
    concrete leaf inside the embedded JSON with a `<field-name>` placeholder. With
    no Raw Sample Events block, returns a placeholder — the oracle has the
    system/template/params from `lead_sequence.yaml` and projects shape from those.
    """
    header_m = _RAW_SAMPLE_HEADER_RE.search(text)
    if not header_m:
        return "(no schema sample available for this position)"
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


def assemble_exemplar_bundle(source_run_dir: Path, lead_sequence_text: str) -> str:
    """Concatenate per-lead schema samples — one redacted block per lead position."""
    doc = yaml.safe_load(lead_sequence_text)
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        raise LoopError("lead_sequence.yaml has no `entries` list")
    blocks: list[str] = []
    for entry in doc["entries"]:
        position = entry.get("position")
        queries = entry.get("queries") or []
        qid = (queries[0] or {}).get("id", "?") if queries else "?"
        result_ref = entry.get("result_ref") or f"gather_raw/{position}.json"
        path = source_run_dir / result_ref
        if path.is_file():
            body = redact_exemplar(path.read_text())
        else:
            body = "(no exemplars on disk for this position)"
        blocks.append(
            f'<exemplar position="{position}" query="{qid}" result_ref="{result_ref}">\n'
            f"{body}\n"
            f"</exemplar>"
        )
    return "\n".join(blocks)
