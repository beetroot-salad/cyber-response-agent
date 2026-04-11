---
archetype: service-account-rotation
signature_id: wazuh-rule-5710
required_anchors:
  - scheduled-jobs
---

# Service Account Rotation

## Story

An automated job on an internal host is attempting to authenticate to
this host using a service-account username that has been rotated,
retired, or otherwise no longer exists — typically because credential
rotation retired the account but the job's configuration wasn't
updated. Wazuh 5710 fires because the username is `Invalid user`,
even though the requesting side believes the credential is still
valid.

The shape is distinctive: **internal source**, **service-account
pattern username** (`svc-*`, `backup-*`, `cron-*`, `ansible-*`, or
the org's specific convention), **cron-like cadence** (recurring at
strict intervals — nightly, hourly, every N minutes), and **no
successful login** from that source (because the credential no longer
authenticates). The identity maps to a documented automated job in
the scheduled-jobs registry, but the job's declared username doesn't
match anything that currently exists on the target.

This archetype captures the "orphaned automation after a password
rotation" failure mode: the automation is benign, the failing login
is benign, but the automation is *broken* — someone needs to update
the job's credentials or retire the job. The disposition is benign
(no adversary involvement) but the investigation output should flag
the broken-automation state for the job owner.

What takes an alert *out* of this archetype: external source (not an
internal job at all), wordlist-shaped username (`external-bruteforce`),
volume burst without the cron cadence (not an automated schedule),
or a successful login from the same source (the job is not actually
broken — either the rotation partially worked, or there's a parallel
auth path we don't understand, either of which needs a human).

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
