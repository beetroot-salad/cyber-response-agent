---
title: Preload hook race condition fixed (contextualize_preload.py detached child vs Sonnet)
status: done
groups: sonnet
---

contextualize_preload.py was forking a detached child to spawn ticket-context and archetype-scan in the background; the main agent's first CONTEXTUALIZE read raced the detached writes. Opus was slow enough that files landed in time; Sonnet reads raced past.

Fix: ticket-context is now dispatched inline by the main agent as a Haiku Agent() call (synchronous by construction, no race). Archetype-scan stays in preload because SKILL.md's graceful fallback handles the race. Validated in run #14.
