---
title: Judge INTERNAL_CONSISTENCY against structured hypothesis ledger, not prose
status: backlog
groups: reliability, state
---

The judge now checks for composite/rollup grades and analyst-handoff drift via prose inspection of investigation.md + report.md. This is fragile — a model that writes prose carefully can evade it.

Longer-term, the judge should be fed a structured hypothesis ledger (YAML) extracted from ANALYZE blocks and verify the rollup and drift rules against parsed structure, not narrative.

Depends on the investigation-language canonicalization work (hypothesis names, lead names, structured observation snippets) landing first — otherwise ledger extraction can't be reliable across runs.
