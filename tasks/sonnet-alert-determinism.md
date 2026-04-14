---
title: Alert-selection determinism in fetch_alert.py
status: backlog
group: sonnet
---

Same scenario, two runs, different alert selected (first-of-burst vs mid-burst). Eval reproducibility requires stable ordering.

Options:
- Add --select {latest,earliest,first} flag, default to latest
- Respect --offset N so eval harness can skip past the first-of-burst alert deliberately

latest is probably the right default (matches what a human analyst would pick up). Affects eval reproducibility only, not the agent itself.
