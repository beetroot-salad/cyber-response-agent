#!/usr/bin/env python3
"""Score a trial's captured output against the case's gold labels.

Usage:
    score.py <round-dir>/<trial-id>/ <case.yaml> <depth>

Emits JSON:
  {
    "lead_chosen": "...",
    "lead_class": "gold" | "acceptable" | "trap" | "other",
    "assessment_agreement": true | false | "partial",
    "prior_tokens": N,
    "output_tokens": N,
  }

Lead classification is deterministic against the gold / trap sets in
case.yaml. Assessment agreement compares the subagent's emitted
weights to the gold `weighted_hypothesis` + `disposition_belief`.

Not yet implemented — stub.
"""

import sys


def main() -> int:
    raise NotImplementedError("score: not implemented yet")


if __name__ == "__main__":
    sys.exit(main())
