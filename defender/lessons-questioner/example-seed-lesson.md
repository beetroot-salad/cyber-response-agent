---
name: example-seed-lesson
description: Placeholder seed lesson — the questioner corpus is folded from real world findings starting with #1007; nothing has landed yet.
systems: []
bucket: fact-placement
source_finding_ids: []
created_at: 2026-09-08T00:00:00Z
---

This corpus is authored by the questioner curator from `subject: world` findings the family
judge enqueues (#1007). This seed exists only so the corpus is non-empty before the first real
finding lands; it names no real pitfall and should be deleted once one does.

`systems` is deliberately empty. `branch/questioner._questioner_lessons_section` selects a lesson into the question-writer's own call-1 prompt when its systems share a member with the episode's served systems, so an empty list is selected for no tenant: the file stays visible to the frontend census and out of every prompt, rather than being rendered into a paid prompt under a heading promising a recorded pitfall while its body says it is not one.
