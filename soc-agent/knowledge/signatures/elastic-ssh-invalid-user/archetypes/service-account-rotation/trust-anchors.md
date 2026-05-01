---
archetype: service-account-rotation
signature_id: elastic-ssh-invalid-user
required_anchors:
  - scheduled-jobs
---

# Service Account Rotation

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `scheduled-jobs`

**Question:** does an internal scheduled-jobs registry list a job
that runs from `source.ip`, attempts SSH to `host.name` as
`user.name`, and has a cron schedule consistent with the observed
cadence?

**Confirmation:** the registry returns a job entry whose source host,
target host, and identity match the alert, AND whose schedule
matches the observed inter-attempt cadence (within the tool's
declared jitter). The job's owner contact is part of the entry —
disposition includes a "notify owner that creds need rotating"
output.

Absence is a **refutation** — an internal source running a
service-account-pattern username on a strict cadence with no
matching scheduled-jobs entry is shadow automation, which escalates
regardless of cadence shape.

## Precedents

Ticket snapshots that matched this archetype are stored next to this
README as `{TICKET-ID}.json`.
