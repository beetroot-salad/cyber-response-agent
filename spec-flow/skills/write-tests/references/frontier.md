# Legacy frontier format

This reference supports old numbered runs and the existing `spec-graph frontiers` tool. New write-tests runs use the compact working record in **contract.md**; they do not require a frontier for every action or leaf.

A legacy frontier is Markdown with YAML frontmatter, then a digest of at most 15 nonempty lines and the payload:

```markdown
---
phase: contract-review
status: complete
inputs: [10-candidate.md]
---

## Digest

- Reviewed the recorded candidate; findings are in the payload.

## Findings

...
```

`status` is `complete | design-refuted | blocked`; `phase` names the producer role; `inputs` lists consumed frontier filenames. Numeric-prefixed sibling inputs must exist. Optional `inventory` maps categories to integer counts; counts are not conservation evidence.

`spec-graph frontiers <dir> [--only <file>]` checks shape; `--resume` reports some input-file staleness. Neither proves design, base, profile or environment freshness, expected missing outputs, or semantic readiness. A `complete` review is reusable only for its unchanged recorded inputs and scope. See contract.md before resuming or migrating a numbered run.
