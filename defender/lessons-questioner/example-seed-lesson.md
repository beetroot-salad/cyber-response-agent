---
name: example-seed-lesson
description: Placeholder seed lesson — the questioner corpus is folded from real world findings starting with #1007; nothing has landed yet.
pattern: __none__
holding_system: elastic
bucket: shape-invention
source_finding_ids: []
created_at: 2026-09-08T00:00:00Z
---

This corpus is authored by the questioner curator from `subject: world` findings the family
judge enqueues (#1007). This seed exists only so the corpus is non-empty before the first real
finding lands; it names no real pitfall and should be deleted once one does.

`pattern` is deliberately `__none__` rather than a real corpus glob. `branch/questioner._questioner_lessons_section` selects a lesson into the questioner's own call-1 prompt by `pattern in stageable_patterns`, and `stageable` is `configured_patterns()` plus the capture's — so a seed spelling the shipped events index would be rendered into EVERY real episode's paid prompt, under a heading promising a recorded pitfall, carrying a body that says it is not one. A value no corpus is ever staged under keeps the file visible to the frontend census and out of every prompt.
