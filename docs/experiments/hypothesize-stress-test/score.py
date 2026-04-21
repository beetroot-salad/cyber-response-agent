#!/usr/bin/env python3
"""Score each A/B subagent output against the failure modes + new schema.

For each (variant, fixture) pair, emits a short scorecard:
    - mode: fork | no-fork (which block type emitted)
    - FM1: legitimacy-prefixed classification names
    - FM2: parallel sanctioned/unsanctioned pairs (loose heuristic)
    - FM3: compound claims (;/AND/OR)
    - FM4: ?compromise-followup-style peer hypotheses
    - baseline ref: does any story/prose mention prior/baseline/cadence?
    - schema: does the block use `subject:` and `refutes_predictions:`?
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
AB_ROOT = REPO_ROOT / "docs/experiments/hypothesize-stress-test/ab-outputs"

FIXTURES = ["fixture-1-legitimacy-axis", "fixture-2-compound-pressure", "fixture-3-subsequent-event"]
VARIANTS = ["baseline", "current"]

EVALUATION_PREFIXES = (
    "authorized-", "unauthorized-", "legitimate-", "illegitimate-",
    "malicious-", "benign-", "sanctioned-", "unsanctioned-",
    "compromised-", "adversarial-",
)

SUBSEQUENT_EVENT_NAMES = (
    "compromise-followup", "post-failure-success", "post-exploit-success",
    "followup-success", "compromise-chain",
)

BASELINE_REFS_RE = re.compile(
    r"\b(prior|baseline|cadence|past \d+|history|repeat|recency|previous closure)\b",
    re.IGNORECASE,
)


def score(output: str) -> dict:
    scorecard: dict = {}

    # Mode detection
    has_hypothesize = re.search(r"^```yaml\s*\n\s*hypothesize:", output, re.M) is not None
    has_gather = re.search(r"^```yaml\s*\n\s*gather:", output, re.M) is not None
    if has_hypothesize:
        scorecard["mode"] = "fork"
    elif has_gather:
        scorecard["mode"] = "no-fork"
    else:
        scorecard["mode"] = "unknown/error"

    # FM1: evaluation-prefixed classifications/names
    fm1_hits = []
    for prefix in EVALUATION_PREFIXES:
        for m in re.finditer(r'(?:classification:\s*"?|name:\s*"?\??)' + re.escape(prefix) + r'[\w-]+', output):
            fm1_hits.append(m.group(0))
    scorecard["FM1_evaluation_prefixes"] = fm1_hits[:5]  # cap listing

    # FM2: parallel sanctioned/unsanctioned — heuristic: co-occurrence of
    # evaluation-prefix-paired classifications within the same hypothesize block
    scorecard["FM2_parallel_pair"] = (
        any(p in output for p in ["authorized-", "sanctioned-"])
        and any(p in output for p in ["unauthorized-", "unsanctioned-", "compromised-", "malicious-"])
    )

    # FM3: compound claims in prediction/refutation claim strings
    claim_strs = re.findall(r'claim:\s*"([^"]+)"', output)
    compound = []
    for c in claim_strs:
        for tok in ["; ", " AND ", " OR "]:
            if tok in c:
                compound.append((tok.strip(), c[:80]))
                break
    scorecard["FM3_compound_claims"] = compound

    # FM4: subsequent-event as hypothesis
    fm4_hits = []
    for name in SUBSEQUENT_EVENT_NAMES:
        for m in re.finditer(r'name:\s*"?\??' + re.escape(name) + r'[\w-]*"?', output, re.IGNORECASE):
            fm4_hits.append(m.group(0))
    scorecard["FM4_subsequent_as_peer"] = fm4_hits

    # Baseline reference in story or reasoning
    scorecard["baseline_ref"] = bool(BASELINE_REFS_RE.search(output))

    # Schema-extension field presence (only meaningful in fork mode)
    scorecard["schema_subject_present"] = "subject:" in output and "subject: " in output
    scorecard["schema_refutes_predictions"] = "refutes_predictions:" in output

    # Byte length as a coarse budget signal
    scorecard["chars"] = len(output)

    return scorecard


def format_card(variant: str, fixture: str, card: dict) -> str:
    lines = [f"[{variant:8s} × {fixture}]"]
    lines.append(f"  mode                : {card['mode']} ({card['chars']} chars)")
    lines.append(f"  FM1 eval prefixes   : {card['FM1_evaluation_prefixes'] or 'none'}")
    lines.append(f"  FM2 parallel pair   : {card['FM2_parallel_pair']}")
    lines.append(f"  FM3 compound claims : {card['FM3_compound_claims'] or 'none'}")
    lines.append(f"  FM4 subsequent peer : {card['FM4_subsequent_as_peer'] or 'none'}")
    lines.append(f"  baseline reference  : {card['baseline_ref']}")
    lines.append(f"  schema subject      : {card['schema_subject_present']}")
    lines.append(f"  schema refutes_preds: {card['schema_refutes_predictions']}")
    return "\n".join(lines)


def main() -> int:
    for fixture in FIXTURES:
        print(f"\n═══ {fixture} ═══")
        for variant in VARIANTS:
            path = AB_ROOT / f"{variant}-{fixture}" / "subagent_output.md"
            if not path.exists():
                print(f"[{variant:8s} × {fixture}] missing output")
                continue
            output = path.read_text()
            if output.strip() == "<TIMEOUT>" or not output.strip():
                print(f"[{variant:8s} × {fixture}] TIMEOUT or empty")
                continue
            print(format_card(variant, fixture, score(output)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
