#!/usr/bin/env python3
"""Fake advisory CLI for the BvCvD-tight experiment.

Emits a canned non-empty `## ADVISORY RETRIEVAL` markdown block
regardless of input args. Same content per call so the agent has a
realistic-looking precedent table to react to, with no variance from
real corpus state. Used to isolate "does NL translation add value
over a deterministic call?" from "what does the corpus actually
say?" — the latter is moot when the corpus parser is broken.

Usage: any CLI args are accepted but ignored. Output is fixed.
"""
from __future__ import annotations

import sys


FAKE_BANNER = """## ADVISORY RETRIEVAL (precedent, not evidence)
Corpus: /tmp/defender-runs (12 cases for wazuh-rule-5710)

### Lead discrimination | frontier: <as requested>

| lead | n | left frontier | right frontier |
|---|---:|---|---|
| `cmdb-source-lookup` | 8 | -- (6/8) | + (5/8) |
| `iam-account-lookup` | 7 | -- (5/7) | + (6/7) |
| `wazuh-auth-pattern` | 6 | + (4/6) | -- (5/6) |

Caveat: precedent only. Use to choose what to gather; only current
observations can support or refute hypotheses in this case.
"""


def main() -> int:
    sys.stdout.write(FAKE_BANNER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
