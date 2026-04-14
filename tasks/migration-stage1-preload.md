---
title: Hook-based CONTEXTUALIZE preload
status: done
groups: sonnet-migration, cost
---

Landed as `scripts/contextualize_preload.py` — archetype-scan runs in the background and writes its result to disk; SKILL.md CONTEXTUALIZE reads the preloaded file. Ticket-context was originally preloaded too but moved to inline Haiku `Agent()` dispatch after a preload race was observed under Sonnet's faster cadence. See `docs/decision-opus-sonnet-migration.md` session 2026-04-13 and done-preload-race-condition.md.
