#!/usr/bin/env python3
"""Search precedent files for a signature and output a summary.

Usage: python3 scripts/search_precedents.py <signature_id>

Outputs a structured summary of past investigations:
- Hypotheses tested and their outcomes
- Leads pursued and key observations
- Traces

Exit codes:
    0 - Success (even if no precedents found)
    1 - Invalid arguments or path traversal
"""

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
SIGNATURES_DIR = SOC_AGENT_ROOT / "knowledge" / "signatures"


def format_precedent(data: dict) -> str:
    """Format a single precedent as a readable summary."""
    lines = []

    ticket_id = data.get("ticket_id", "unknown")
    disposition = data.get("disposition", "unknown")
    status = data.get("status", "unknown")
    lines.append(f"### {ticket_id} — {disposition} ({status})")

    # Hypotheses
    hypotheses = data.get("hypotheses", [])
    if hypotheses:
        parts = []
        for h in hypotheses:
            h_id = h.get("id", "?")
            h_status = h.get("status", "?")
            parts.append(f"?{h_id} ({h_status})")
        lines.append(f"Hypotheses: {', '.join(parts)}")

    # Leads
    flow = data.get("flow", [])
    if flow:
        lead_names = [step.get("lead", "?") for step in flow]
        lines.append(f"Leads: {', '.join(lead_names)}")

    # Trace
    trace = data.get("trace", "")
    if trace:
        lines.append(f"Trace: {trace}")

    # Key indicators
    indicators = data.get("key_indicators", [])
    if indicators:
        lines.append(f"Key indicators: {', '.join(indicators)}")

    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <signature_id>", file=sys.stderr)
        return 1

    signature_id = sys.argv[1]
    sig_dir = (SIGNATURES_DIR / signature_id).resolve()

    # Prevent path traversal
    if not sig_dir.is_relative_to(SIGNATURES_DIR.resolve()):
        print("Error: invalid signature_id (path traversal)", file=sys.stderr)
        return 1

    precedents_dir = sig_dir / "precedents"
    if not precedents_dir.is_dir():
        print(f"No precedents found for {signature_id}")
        return 0

    files = sorted(precedents_dir.glob("*.json"))
    if not files:
        print(f"No precedents found for {signature_id}")
        return 0

    print(f"## Precedents for {signature_id}\n")

    for f in files:
        try:
            data = json.loads(f.read_text())
            print(format_precedent(data))
            print()
        except (json.JSONDecodeError, KeyError) as e:
            print(f"### {f.name} — parse error: {e}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
