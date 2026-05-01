---
archetype: service-account-rotation
signature_id: elastic-ssh-invalid-user
required_anchors:
  - scheduled-jobs
---

# Service Account Rotation — Story

An automated job on an internal host is attempting to authenticate
to this host using a service-account username that has been rotated,
retired, or otherwise no longer exists — typically because credential
rotation retired the account but the job's configuration wasn't
updated. The system integration emits an `event.outcome: failure`
document because the username is `Invalid user` (or because the
stored password no longer authenticates), even though the requesting
side believes the credential is still valid.

The shape is distinctive: **internal source**, **service-account
pattern username** (`svc-*`, `svc.*`, `backup-*`, `cron-*`,
`ansible-*`, or the org's specific convention), **cron-like cadence**
(recurring at strict intervals — nightly, hourly, every N minutes),
and **no successful login** from that source. The identity maps to
a documented automated job in the scheduled-jobs registry, but the
job's declared username doesn't match anything that currently exists
on the target.

This archetype captures the "orphaned automation after a password
rotation" failure mode: the automation is benign, the failing login
is benign, but the automation is *broken* — someone needs to update
the job's credentials or retire the job. The disposition is benign
(no adversary involvement) but the investigation output should flag
the broken-automation state for the job owner.

What takes an alert *out* of this archetype: external source (not
an internal job at all), wordlist-shaped username
(`external-bruteforce`), volume burst without the cron cadence (not
an automated schedule), or a successful login from the same source
(the job is not actually broken — either the rotation partially
worked, or there's a parallel auth path we don't understand, either
of which needs a human).
