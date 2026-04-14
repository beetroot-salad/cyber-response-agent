---
title: act mode: auto-close for mature signatures with high-confidence precedent matches
status: backlog
groups: phase-2
---

MVP is recommend-only. act mode enables auto-close actions for signatures where confidence is consistently high and precedent matches are strong.

Design is already written — see `docs/design-v3-architecture.md`:
- §6.5 Quality Monitoring (auto-closure sampling + systematic error detection with auto-downgrade on >2% override rate)
- §7 rollout path (recommend-first, graduate to act per signature)
- §8 Security Model (`recommend` vs `act` gated per signature via `permissions.yaml`)

Remaining work is implementation: the per-signature `permissions.yaml` already has the shape, but the ticketing-system write path, sampling/override tracking, and the auto-downgrade mechanic need to be built. Requires mature signatures, proven Tier 2 judge reliability, and explicit opt-in per signature before any signature graduates from recommend to act.
