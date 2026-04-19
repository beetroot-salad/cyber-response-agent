#!/usr/bin/env python3
"""Render a case + depth + arm into the prior context for that trial.

Usage:
    render_prior.py <case_dir> <depth> <arm>

    case_dir = path to cases/case-{name}/  (must contain case.yaml +
               source/alert.json + source/investigation.md)
    depth    = shallow | deep
    arm      = A  (invlang YAML blocks only, plus alert)
             | B  (prose sections only, no YAML blocks, plus alert)
             | C  (alert only; minimal CONTEXTUALIZE header)

The cut point is read from case.yaml: depths.{shallow|deep}.cut_after_phase.
Recognized phase markers match `## {PHASE}` headers in investigation.md:
  CONTEXTUALIZE, SCREEN, HYPOTHESIZE (loop N), GATHER (loop N),
  ANALYZE (loop N), CONCLUDE. `cut_after_phase` values use the compact
  forms: CONTEXTUALIZE, SCREEN, HYPOTHESIZE_L{n}, GATHER_L{n},
  ANALYZE_L{n}.

Invariants:
  - Arms A and B carry identical underlying evidence (same cut).
  - Arm C carries only the alert.
  - Turn prompt is not included — run_arm.py appends it.

Writes to stdout.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


PHASE_HEADER_RE = re.compile(r"^##\s+(?P<phase>CONTEXTUALIZE|SCREEN|HYPOTHESIZE|GATHER|ANALYZE|CONCLUDE)(?:\s*\(loop\s+(?P<loop>\d+)\))?\s*$")
YAML_FENCE_OPEN = re.compile(r"^```yaml\s*$")
YAML_FENCE_CLOSE = re.compile(r"^```\s*$")


def parse_phase_tag(line: str) -> str | None:
    """Return the compact phase tag (CONTEXTUALIZE, HYPOTHESIZE_L1, ...)
    for a header line, or None if not a phase header."""
    m = PHASE_HEADER_RE.match(line.rstrip())
    if not m:
        return None
    phase = m.group("phase")
    loop = m.group("loop")
    if loop is None:
        return phase
    return f"{phase}_L{loop}"


def split_phases(investigation_md: str) -> list[tuple[str, list[str]]]:
    """Split investigation.md into a list of (phase_tag, [lines]) segments.
    Content before the first phase header is attached to a synthetic
    PREAMBLE tag."""
    segments: list[tuple[str, list[str]]] = []
    current_tag = "PREAMBLE"
    current_lines: list[str] = []
    for line in investigation_md.splitlines():
        tag = parse_phase_tag(line)
        if tag is not None:
            segments.append((current_tag, current_lines))
            current_tag = tag
            current_lines = [line]
        else:
            current_lines.append(line)
    segments.append((current_tag, current_lines))
    return segments


def truncate_at(segments: list[tuple[str, list[str]]], cut_after: str) -> list[tuple[str, list[str]]]:
    """Keep all segments up to and including the one tagged cut_after."""
    kept: list[tuple[str, list[str]]] = []
    found = False
    for tag, lines in segments:
        kept.append((tag, lines))
        if tag == cut_after:
            found = True
            break
    if not found:
        raise ValueError(f"cut_after_phase '{cut_after}' not found in investigation.md")
    return kept


def strip_yaml_blocks(lines: list[str]) -> list[str]:
    """Remove ```yaml ... ``` fenced blocks. Returns prose-only lines."""
    out: list[str] = []
    inside = False
    for line in lines:
        if not inside and YAML_FENCE_OPEN.match(line):
            inside = True
            continue
        if inside and YAML_FENCE_CLOSE.match(line):
            inside = False
            continue
        if not inside:
            out.append(line)
    return out


def keep_only_yaml_blocks(lines: list[str]) -> list[str]:
    """Keep ONLY the content inside ```yaml ... ``` fences, plus the
    phase header. Everything else in the phase (prose) is dropped."""
    out: list[str] = []
    # Preserve the phase header (first line) for structure.
    if lines and lines[0].startswith("## "):
        out.append(lines[0])
        out.append("")
    inside = False
    for line in lines:
        if not inside and YAML_FENCE_OPEN.match(line):
            inside = True
            out.append(line)
            continue
        if inside and YAML_FENCE_CLOSE.match(line):
            inside = False
            out.append(line)
            out.append("")
            continue
        if inside:
            out.append(line)
    return out


def render_arm_A(segments: list[tuple[str, list[str]]], alert_json: str) -> str:
    """Arm A: alert + YAML blocks only from each phase."""
    pieces = ["# Alert", "", "```json", alert_json.strip(), "```", ""]
    for tag, lines in segments:
        if tag == "PREAMBLE":
            continue
        yaml_only = keep_only_yaml_blocks(lines)
        if any(l.strip() for l in yaml_only):
            pieces.extend(yaml_only)
    return "\n".join(pieces) + "\n"


def render_arm_B(segments: list[tuple[str, list[str]]], alert_json: str) -> str:
    """Arm B: alert + prose sections only (no YAML blocks)."""
    pieces = ["# Alert", "", "```json", alert_json.strip(), "```", ""]
    for tag, lines in segments:
        if tag == "PREAMBLE":
            continue
        prose_only = strip_yaml_blocks(lines)
        if any(l.strip() for l in prose_only):
            pieces.extend(prose_only)
            pieces.append("")
    return "\n".join(pieces) + "\n"


def render_arm_C(alert_json: str) -> str:
    """Arm C: alert only, no prior investigation state."""
    pieces = [
        "# Alert",
        "",
        "```json",
        alert_json.strip(),
        "```",
        "",
        "## CONTEXTUALIZE",
        "",
        "(No prior investigation state. Alert is the only input.)",
        "",
    ]
    return "\n".join(pieces) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    case_dir = Path(argv[1])
    depth = argv[2]
    arm = argv[3]

    if depth not in ("shallow", "deep"):
        print(f"error: depth must be 'shallow' or 'deep', got '{depth}'", file=sys.stderr)
        return 2
    if arm not in ("A", "B", "C"):
        print(f"error: arm must be A, B, or C, got '{arm}'", file=sys.stderr)
        return 2

    case_yaml_path = case_dir / "case.yaml"
    alert_path = case_dir / "source" / "alert.json"
    investigation_path = case_dir / "source" / "investigation.md"
    for p in (case_yaml_path, alert_path, investigation_path):
        if not p.exists():
            print(f"error: missing required file {p}", file=sys.stderr)
            return 2

    case = yaml.safe_load(case_yaml_path.read_text())
    cut_after = case["depths"][depth]["cut_after_phase"]
    alert_json = alert_path.read_text()

    if arm == "C":
        sys.stdout.write(render_arm_C(alert_json))
        return 0

    investigation = investigation_path.read_text()
    segments = split_phases(investigation)
    truncated = truncate_at(segments, cut_after)

    if arm == "A":
        sys.stdout.write(render_arm_A(truncated, alert_json))
    else:
        sys.stdout.write(render_arm_B(truncated, alert_json))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
