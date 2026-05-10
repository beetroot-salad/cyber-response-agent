# Fixture 1 — Legitimacy axis (FM1 + FM2 + FM5)

## The trap being set

The alert pattern (internal RFC1918 source, sentinel-shaped username, low volume, 2 prior benign repeats) is a textbook monitoring-probe setup. CONTEXTUALIZE gives the subagent:
- Strong monitoring-probe archetype match
- Adversarial archetype of "compromised-monitoring-host"
- Ticket-context showing the source has 2 prior benign rule-5710 closures

The temptation: write `?authorized-monitoring-probe` vs `?unauthorized-monitoring-probe` (or `?compromised-monitoring-host`) as a pair, both about the *same* upstream mechanism (a scheduled probe from 10.1.2.3), differing only on authority.

## Expected failure modes

- **FM1 legitimacy-packed classification** (e.g., `?authorized-monitoring-probe`)
- **FM2 parallel sanctioned/unsanctioned pair** (authorized vs compromised as peers)
- **FM5 prior-precedent bias** — leaning on the 2 benign repeats to pre-decide disposition

## What the updated prompt should produce

One hypothesis: `?monitoring-probe` (or `?scheduled-automation-probe`) attached to `v-001`, with:
- A `legitimacy_contract` (the contract is where the authority/anchor split lives)
- A story that anchors against the 2 prior repeats' baseline cadence (~20-min interval)
- Predictions about the probe's own attributes (cadence match, attempt-shape) — not about whether it's "authorized"

Discrimination comes from running the anchor + cadence leads. The hypothesis stays singular at formation time.

## Signals to score against in the subagent output

- Number of hypotheses emitted (target: 1 primary, optionally a mechanism-level `?adversary-controlled-monitoring-host` if integrity concern articulated)
- Classification names (flag anything starting with `authorized-`, `unauthorized-`, `compromised-`, `legitimate-`, `malicious-`, `sanctioned-`)
- Presence of `legitimacy_contract`
- Story: does it reference the ~20-min cadence from ticket-context repeats?
- Prediction `subject` values (all must be one of proposed_parent/attached_vertex/proposed_edge)
- Compound predictions (none should appear)
