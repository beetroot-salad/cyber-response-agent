# PREDICT golden-set cases

Each case is one labeled (input, expected) pair for evaluating a single
PREDICT subagent invocation. See `tasks/predict-eval-rubric.md` for the
scoring rubric.

## Index

| Case | Slice | Signature | Loop | Expected shape |
|---|---|---|---|---|
| case-001 | shape-E-loop-1-enrichment | wazuh-rule-5710 | 1 | E |
| case-002 | shape-A-authorization-fork | wazuh-rule-5710 | 2 | A |
| case-003 | shape-M-mechanism-fork | wazuh-rule-100110 | 1 | M |
| case-004 | unknown-hypothesis-discipline | wazuh-rule-100001 | 1 | E |
| case-005 | backward-traversal-after-plus-plus | wazuh-rule-5710 | 3 | E (A on upstream acceptable) |

## Status

- **Batch 0 (5 cases)** — drafted, awaiting human review of expected outcomes.
- Once batch 0 is locked, run current PREDICT prompt against each to set the
  baseline scores.
- Then expand to 20 cases (4 more batches of 5) covering remaining slices in
  the rubric's coverage table.
