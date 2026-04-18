---
archetype: service-account-rotation
signature_id: wazuh-rule-5710
required_anchors:
  - scheduled-jobs
---

# Service Account Rotation

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `scheduled-jobs`

**Question:** does the org's scheduled-job registry declare an entry
whose `(source, target, identity, schedule)` tuple matches the
observed `(srcip, target-host, srcuser, cadence)`?

**Confirmation:** the registry returns at least one entry whose
source host matches the alert srcip, whose target includes this host,
whose declared identity matches the observed srcuser, whose schedule
window contains the alert timestamp, and whose job type is consistent
with SSH-based automation. A registry that returns a different job
on the same host, or a job with a different username, or a job whose
schedule doesn't match the observed cadence, is **not** a confirmation.

A match here is evidence that the failing login corresponds to a
real, documented, broken automation. No match is a **refutation** —
an internal service-account-shaped login attempt without a matching
registry entry is exactly the case this anchor exists to catch, and
escalation is the correct response.

## Precedents

Ticket snapshots live as sibling `{TICKET-ID}.json` files next to this
README.
