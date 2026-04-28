"""Deterministic context loading for phase handlers.

Phase subagents traditionally Read a predictable set of files — investigation.md,
alert.json, per-archetype story.md / trust-anchors.md, precedent snapshots.
Those are all path-deterministic lookups; there is no reasoning in the Read
itself. Pulling them into handler-side Python preloads lets us:

1. Ship all context to the subagent in one prompt — no Read/Glob round-trips
   consuming the subagent's wall-clock budget.
2. Shrink the subagent's tool surface (often to the point of `tools: []`).
3. Collapse the subagent's job to narrative synthesis + structured output
   emission — which is the only part that requires a language model.

This module is the single source of truth for "what's deterministically
loadable for a handler." Individual handlers import the relevant loaders
and format functions. Keep it narrow — anything that requires a decision
about what to load (e.g. which precedent to cite) stays in the handler, not
here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Run-dir artifacts
# ---------------------------------------------------------------------------


def load_alert(run_dir: Path) -> dict:
    """Read `{run_dir}/alert.json` and return the parsed dict.

    Missing file raises FileNotFoundError — alerts are required; a missing
    alert is an orchestration-level bug, not a recoverable runtime state.
    """
    return json.loads((run_dir / "alert.json").read_text())


def load_investigation_md(run_dir: Path) -> str:
    """Read `{run_dir}/investigation.md`; empty string if the file doesn't
    exist yet (valid early-phase state)."""
    path = run_dir / "investigation.md"
    return path.read_text() if path.exists() else ""


def load_run_salt(run_dir: Path) -> str:
    """Return the per-run salt from `{run_dir}/meta.json`.

    Fails fast if meta.json or its `salt` field is missing — the salt is
    required to wrap untrusted alert content in unguessable delimiters. A
    missing salt is an orchestration-level bug (setup_run.py always writes
    one), not a recoverable runtime state.
    """
    meta = json.loads((run_dir / "meta.json").read_text())
    salt = meta.get("salt")
    if not salt or not isinstance(salt, str):
        raise RuntimeError(
            f"meta.json at {run_dir} is missing a non-empty 'salt' field"
        )
    return salt


# ---------------------------------------------------------------------------
# Archetype shapes
# ---------------------------------------------------------------------------


def load_archetype_shapes(
    signature_id: str,
    soc_agent_root: Path,
    *,
    archetype_names: list[str] | None = None,
    include_precedents: bool = False,
) -> list[dict]:
    """Read story.md + trust-anchors.md (+ precedent JSONs) for each named
    archetype under `knowledge/signatures/{signature_id}/archetypes/`.

    If `archetype_names` is None, load every archetype directory. Otherwise
    load only the named ones, preserving the order given (so the handler can
    surface ranking order inline).

    Each entry is `{name, story_md, trust_anchors_md?, precedents?}`. Missing
    story.md/trust-anchors.md files are skipped silently — an archetype may
    legitimately lack a trust-anchors file (no required_anchors). Missing
    directories are dropped entirely (caller's job to validate archetype
    names upstream).
    """
    base = soc_agent_root / "knowledge" / "signatures" / signature_id / "archetypes"
    if not base.is_dir():
        return []

    if archetype_names is None:
        names = sorted(d.name for d in base.iterdir() if d.is_dir())
    else:
        names = [n for n in archetype_names if (base / n).is_dir()]

    out: list[dict] = []
    for name in names:
        d = base / name
        entry: dict[str, Any] = {"name": name}
        story = d / "story.md"
        if story.exists():
            entry["story_md"] = story.read_text()
        ta = d / "trust-anchors.md"
        if ta.exists():
            entry["trust_anchors_md"] = ta.read_text()
        if include_precedents:
            precedents: dict[str, dict] = {}
            for p in sorted(d.glob("*.json")):
                try:
                    precedents[p.stem] = json.loads(p.read_text())
                except json.JSONDecodeError:
                    continue
            if precedents:
                entry["precedents"] = precedents
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Signature-level knowledge (playbook + context)
# ---------------------------------------------------------------------------


def load_signature_text(signature_id: str, soc_agent_root: Path) -> dict[str, str]:
    """Read the signature's top-level markdown — playbook.md + context.md.

    Returns `{"playbook_md": ..., "context_md": ...}`. Missing files map to
    empty strings — a signature may legitimately lack context.md while
    playbook.md is required in practice (but not enforced here — caller
    decides how to treat an empty playbook).
    """
    base = soc_agent_root / "knowledge" / "signatures" / signature_id
    out = {"playbook_md": "", "context_md": ""}
    if (base / "playbook.md").exists():
        out["playbook_md"] = (base / "playbook.md").read_text()
    if (base / "context.md").exists():
        out["context_md"] = (base / "context.md").read_text()
    return out


# ---------------------------------------------------------------------------
# Lead catalog (common-investigation leads used by PREDICT)
# ---------------------------------------------------------------------------


def _lead_definition_path(soc_agent_root: Path, lead_name: str) -> Path:
    return (
        soc_agent_root
        / "knowledge"
        / "common-investigation"
        / "leads"
        / lead_name
        / "definition.md"
    )


def load_lead_definition(soc_agent_root: Path, lead_name: str) -> str | None:
    """Return the contents of one lead's `definition.md`, or `None` if the
    file does not exist (lead is ad-hoc / signature-local).

    Same path semantics as `load_lead_definitions` so the two cannot drift.
    """
    try:
        return _lead_definition_path(soc_agent_root, lead_name).read_text()
    except FileNotFoundError:
        return None


def load_lead_definitions(soc_agent_root: Path) -> dict[str, str]:
    """Return `{lead_name: definition_md}` for every lead under
    `knowledge/common-investigation/leads/{lead_name}/definition.md`.

    Directories without a `definition.md` (e.g. `_template`) are skipped.
    Non-directory entries (e.g. `TAGS.md`) are skipped.
    """
    base = soc_agent_root / "knowledge" / "common-investigation" / "leads"
    if not base.is_dir():
        return {}
    out: dict[str, str] = {}
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        if d.name.startswith("_"):
            continue
        defn = d / "definition.md"
        if defn.exists():
            out[d.name] = defn.read_text()
    return out


# ---------------------------------------------------------------------------
# Prompt block formatters (XML-style tags — LLM-friendly, unambiguous)
# ---------------------------------------------------------------------------


def format_alert_block(alert: dict, salt: str) -> str:
    """Render the alert JSON as a salted-tag block for inline prompt inclusion.

    The outer tag carries a per-run salt (`<alert-{salt}>…</alert-{salt}>`)
    so an attacker-controlled alert field cannot forge a tag close. Matches
    the `<run-{salt}-{tag}>` pattern in hooks/scripts/tag_tool_results.py,
    which wraps untrusted SIEM/MCP output at PostToolUse time. Handlers
    resolve the salt via `load_run_salt(run_dir)`.
    """
    if not salt:
        raise ValueError("format_alert_block requires a non-empty salt")
    return f"<alert-{salt}>\n{json.dumps(alert, indent=2)}\n</alert-{salt}>"


def format_current_gather_block(leads: list[dict]) -> str:
    """Render the current loop's gather envelope as a `<current_gather>`
    YAML block for the analyze prompt.

    Input: the `leads[]` list from `ctx.outputs[Phase.GATHER]["leads"]`
    (the same shape the gather subagent emitted). Raw SIEM payloads
    (`lead.raw`) are stripped — those are preloaded verbatim under
    `<raw_details>` and do not belong in this block.

    Returns an empty string when `leads` is empty.
    """
    if not leads:
        return ""
    try:
        import yaml  # Local import: handler-only dependency
    except ImportError:
        return ""
    pruned: list[dict] = []
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        pruned.append({k: v for k, v in lead.items() if k != "raw"})
    if not pruned:
        return ""
    body = yaml.safe_dump({"leads": pruned}, sort_keys=False).rstrip()
    return f"<current_gather>\n{body}\n</current_gather>"


_ARCHETYPES_SECTION_RE = re.compile(
    r"^##\s+Archetypes\s*\n.*?(?=^##\s|\Z)",
    re.DOTALL | re.MULTILINE,
)


def _strip_archetype_catalog(playbook_md: str) -> str:
    """Remove the `## Archetypes` section from a playbook.

    Archetype labels are a disposition-routing concern consumed by REPORT;
    they confuse PREDICT's mechanism-layer reasoning by presenting named
    buckets (`ci-pipeline-exec`, `operator-runtime-debug`, ...) as
    first-class shape candidates. Composition rules and hypothesis seeds
    stay because they encode escalation policy + mechanism-class structure
    that PREDICT legitimately consumes.
    """
    return _ARCHETYPES_SECTION_RE.sub("", playbook_md).rstrip() + "\n"


def format_signature_text_block(
    texts: dict[str, str],
    *,
    exclude_archetype_catalog: bool = False,
) -> str:
    """Render the signature's playbook.md + context.md as a tagged block.

    Missing files render as empty `<playbook/>` / `<context/>` tags so the
    subagent can still recognize them as absent rather than failing silently.

    `exclude_archetype_catalog=True` strips the `## Archetypes` section — use
    from PREDICT (archetypes are a REPORT concern and confuse shape choice).
    """
    lines = ["<signature-knowledge>"]
    playbook = (texts.get("playbook_md") or "").rstrip()
    if playbook and exclude_archetype_catalog:
        playbook = _strip_archetype_catalog(playbook).rstrip()
    context = (texts.get("context_md") or "").rstrip()
    if playbook:
        lines.append("  <playbook>")
        lines.append(playbook)
        lines.append("  </playbook>")
    else:
        lines.append("  <playbook/>")
    if context:
        lines.append("  <context>")
        lines.append(context)
        lines.append("  </context>")
    else:
        lines.append("  <context/>")
    lines.append("</signature-knowledge>")
    return "\n".join(lines)


def format_lead_definitions_block(defs: dict[str, str]) -> str:
    """Render the lead catalog (name → definition.md) as a tagged block.

    Empty catalog → `<lead-catalog/>` (self-closing).
    """
    if not defs:
        return "<lead-catalog/>"
    lines = ["<lead-catalog>"]
    for name in sorted(defs):
        lines.append(f'  <lead name="{name}">')
        lines.append(defs[name].rstrip())
        lines.append("  </lead>")
    lines.append("</lead-catalog>")
    return "\n".join(lines)


_GOAL_RE = re.compile(r"^##\s+Goal\s*\n(?P<body>.*?)(?=^##\s|\Z)", re.DOTALL | re.MULTILINE)
_FRONTMATTER_RE = re.compile(r"\A---\n(?P<fm>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)


def _lead_summary(defn: str) -> tuple[str, str]:
    """Extract (data_tags_csv, goal_body) from a lead definition.md.

    Returns empty strings when the respective section is missing — callers
    tolerate absent data.
    """
    fm_m = _FRONTMATTER_RE.match(defn)
    data_tags = ""
    body = defn
    if fm_m:
        body = fm_m.group("body")
        # crude data_tags extraction — avoid yaml import here
        for line in fm_m.group("fm").splitlines():
            if line.startswith("data_tags:"):
                data_tags = line.split(":", 1)[1].strip()
                break
    goal_m = _GOAL_RE.search(body)
    goal = goal_m.group("body").strip() if goal_m else ""
    return data_tags, goal


def format_lead_definitions_summary_block(defs: dict[str, str]) -> str:
    """Render the lead catalog as {name, data_tags, Goal body} only — omits
    pitfalls, variants, and per-vendor templates.

    Use from PREDICT where the subagent picks a lead name and the
    downstream GATHER handler has the full definition. Empty catalog →
    `<lead-catalog/>` (self-closing).
    """
    if not defs:
        return "<lead-catalog/>"
    lines = ["<lead-catalog>"]
    for name in sorted(defs):
        data_tags, goal = _lead_summary(defs[name])
        attrs = f' name="{name}"'
        if data_tags:
            attrs += f' data_tags="{data_tags}"'
        lines.append(f"  <lead{attrs}>")
        if goal:
            lines.append(goal)
        lines.append("  </lead>")
    lines.append("</lead-catalog>")
    return "\n".join(lines)


def format_archetype_shapes_block(
    shapes: list[dict], *, with_precedents: bool = False,
) -> str:
    """Render a list of archetype shapes as tagged blocks.

    Output shape:
        <archetypes>
          <archetype name="X">
            <story>...</story>
            <trust-anchors>...</trust-anchors>
            <precedents>                (only when with_precedents=True)
              <precedent id="TICKET-1">{"...": "..."}</precedent>
            </precedents>
          </archetype>
          ...
        </archetypes>

    Empty list → `<archetypes/>` (self-closing).
    """
    if not shapes:
        return "<archetypes/>"

    lines = ["<archetypes>"]
    for a in shapes:
        lines.append(f'  <archetype name="{a["name"]}">')
        if "story_md" in a:
            lines.append("    <story>")
            lines.append(a["story_md"].rstrip())
            lines.append("    </story>")
        if "trust_anchors_md" in a:
            lines.append("    <trust-anchors>")
            lines.append(a["trust_anchors_md"].rstrip())
            lines.append("    </trust-anchors>")
        if with_precedents and "precedents" in a:
            lines.append("    <precedents>")
            for ticket_id, payload in a["precedents"].items():
                lines.append(
                    f'      <precedent id="{ticket_id}">'
                    f"{json.dumps(payload, separators=(',', ':'))}</precedent>"
                )
            lines.append("    </precedents>")
        lines.append("  </archetype>")
    lines.append("</archetypes>")
    return "\n".join(lines)
