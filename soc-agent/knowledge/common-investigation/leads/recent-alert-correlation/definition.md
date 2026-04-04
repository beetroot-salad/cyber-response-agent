---
name: recent-alert-correlation
data_tags: [auth-events, network-events, process-events]
---

## Goal

Find related alerts involving the same entities (source IP, destination
host, username) within a recent time window. Determine if this alert
is part of a larger pattern or an isolated event.

## What to Characterize

- **Same-source alerts**: Other alerts from the same srcip across all
  rules in the last 24-72 hours. Note rule types and frequency.
- **Same-target alerts**: Other alerts targeting the same host/service
  in the same window. Note if from the same or different sources.
- **Escalation signals**: Composite or follow-on rules that fired
  (e.g., brute force composites after repeated auth failures,
  successful login after failures).
- **Temporal clustering**: Are alerts clustered in time (burst of
  activity) or spread out (ongoing low-frequency)?
- **Cross-signature patterns**: Alerts from different rule types that
  together suggest a kill chain (recon → exploit → lateral movement).

## Usage by ticket-context subagent

When this lead is executed by the ticket-context subagent (during
CONTEXTUALIZE), the scope is broader than standalone lead execution:

- **All signatures** are queried, not just the current one — the goal
  is situational awareness and cross-signature correlation
- **Longer time window** (4h vs the typical 1-2h) for the "maybe" tier
- Output feeds into **two-tier classification** (definite/maybe) with
  agent reasoning about entity centrality and causal plausibility
- The subagent may also check `audit.jsonl` for prior investigations
  of the same pattern to support fast-resolve recommendations

When executed as a standalone lead during the investigation loop,
the original scope applies (focused on the current signature's
escalation signals within the playbook-defined time window).

## Common Pitfalls

- High-volume rules generate correlation noise. Focus on rules that
  are diagnostically relevant, not just temporally close.
- Absence of correlated alerts is evidence too — an isolated alert
  with no related activity is itself a signal.
- Time zone and clock skew between systems can cause apparent
  temporal mismatches. Use UTC consistently.
