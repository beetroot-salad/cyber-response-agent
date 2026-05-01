---
archetype: monitoring-probe
signature_id: elastic-ssh-invalid-user
required_anchors:
  - approved-monitoring-sources
---

# Monitoring Probe

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `approved-monitoring-sources`

**Question:** is the `(source.ip, user.name, host.name)` triple on
the sanctioned monitoring list — and is the observed cadence
consistent with what that entry declares?

**Confirmation:** the anchor returns an approved entry matching all
three keys, the cadence matches (single attempt per monitoring tick),
and the alert timestamp falls inside any time-bounded approval window
the entry declares. An entry that approves the source for a different
target, or a different username than observed, is not a confirmation.

A match here is load-bearing evidence that the alert is benign.
Absence of a match is a **refutation** — internal monitoring probes
must be on the sanctioned list, and an unlisted monitoring-shaped
probe is adversarial until proven otherwise.

## Precedents

Ticket snapshots that matched this archetype are stored next to this
README as `{TICKET-ID}.json`.
