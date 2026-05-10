=== FILE: alert.json ===
{
  "timestamp": "2026-04-18T14:22:17.441Z",
  "rule": {
    "id": "5710",
    "level": 5,
    "description": "sshd: Attempt to login using a non-existent user",
    "groups": ["syslog", "sshd", "invalid_login", "authentication_failed"]
  },
  "agent": {
    "id": "003",
    "name": "app-web-07",
    "ip": "10.30.12.88"
  },
  "data": {
    "srcip": "10.30.18.42",
    "srcuser": "root",
    "dstuser": "root"
  },
  "full_log": "Apr 18 14:22:17 app-web-07 sshd[18421]: Invalid user root from 10.30.18.42 port 52214",
  "location": "/var/log/auth.log"
}

=== FILE: investigation.md (state at HYPOTHESIZE entry) ===
# Investigation: wazuh-rule-5710 / alert-fixture-v2-01

## CONTEXTUALIZE

**Alert summary.** Single SSH invalid-user attempt on `app-web-07` (10.30.12.88) from internal source `10.30.18.42`, attempted username `root`. Rule 5710, level 5, at 2026-04-18T14:22:17Z.

**Prologue vertices/edges (canonical):**

- `v-src-ip-10.30.18.42` — type: ip
- `v-dst-host-app-web-07` — type: host
- `v-attempted-user-root` — type: username (as-string)
- `e-attempted-auth-01` — type: `attempted_auth`; source: `v-src-ip-10.30.18.42`; target: `v-dst-host-app-web-07`; identity: `v-attempted-user-root`; timestamp: 2026-04-18T14:22:17Z; outcome: failed (non-existent user)

**Environment readiness.** Wazuh indexer: reachable. Auth log pipeline: reachable. All leads' data sources available.

**Ticket-context correlation (4h window on `10.30.18.42` and `app-web-07`).** No prior tickets on either entity in the last 4 hours. No sibling 5710 events from the same srcip in the 4h window. No 5501 / 5715 success events on `app-web-07` in the last 4 hours.

**Archetype scan (ranked against the alert's shape):**

```yaml
archetype_scan:
  - archetype: credential-stuffing
    required_anchors: []
    disqualifiers:
      - "source IP is a known internal range with no external egress"
      - "attempted username is a documented sentinel (probe, healthcheck) rather than a real-looking human username"
    story_match: "weak — attempted username 'root' is a generic privileged account commonly used in breach-dump lists, but the source IP 10.30.18.42 is internal, which cuts against the external-breach story"
    boundary_note: "source is internal, which the story explicitly excludes"

  - archetype: external-bruteforce
    required_anchors: []
    disqualifiers:
      - "source IP is internal"
      - "only a single attempt observed in the alert window"
    story_match: "weak — 'root' matches the wordlist shape, but volume is 1 and source is internal"
    boundary_note: "volume and source both fail the story"

  - archetype: monitoring-probe
    required_anchors: [approved-monitoring-sources]
    disqualifiers:
      - "attempted username is not in the sentinel list (nagios, zabbix, prometheus, healthcheck, monitorprobe, sensu, testuser, probe)"
      - "source IP is not in the approved-monitoring-sources registry"
    story_match: "weak — source is internal but the attempted username 'root' is not a sentinel; the single-shot cadence fits the story but the identity does not"
    boundary_note: "attempted username is explicitly out-of-story"

  - archetype: service-account-rotation
    required_anchors: [scheduled-jobs]
    disqualifiers:
      - "attempted username is not a service-account-pattern name"
      - "no corresponding scheduled-job entry for the (source, username, target) triple"
    story_match: "weak — 'root' is not a service-account-pattern name; no automation shape evident"
    boundary_note: "identity shape fails the story"

adversarial_archetype:
  archetype: credential-stuffing
  required_anchors: []
  story_match: "weak — the single-attempt shape is atypical for stuffing, but 'root' being attempted from an internal IP could also be a post-compromise lateral probe, which is the most severe framing available in this signature's catalog"
  reason: "for 5710, the worst outcome is an authenticated adversary already inside the network using a foothold to probe for privileged accounts on adjacent hosts; lateral credential-guessing from an internal source fits credential-stuffing's 'worst-case' semantics better than external-bruteforce when the source is already internal"
```

**ASSESS decision.** The hypothesis space forks:
- No archetype matches strongly — all four score weak.
- The source is internal (10.30.18.42), which rules out the two external archetypes as-literally-defined but opens a lateral-movement reading.
- The attempted username `root` is generic, not a sentinel, not a service-account pattern — which rules out the two benign archetypes as-literally-defined.
- Competing one-hop classifications of the upstream process initiating `e-attempted-auth-01` are plausible and predict different observables.

Proceed to HYPOTHESIZE.

=== FILE: signature context.md ===
---
signature_id: wazuh-rule-5710
name: SSH Invalid User
severity: medium
data_sources:
  - auth-events
created_at: 2024-11-15
updated_at: 2026-04-08
mitre:
  tactics: Initial Access
  techniques: T1110
references: null
related_signatures:
  - wazuh-rule-5712
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 5710: SSH Invalid User

## Signature Logic

Wazuh built-in rule. The fundamental detected activity: **OpenSSH's `sshd`
process logged an authentication attempt for a username that does not
exist on the host.** OpenSSH writes this to `auth.log` (Debian/Ubuntu) or
`/var/log/secure` (RHEL family) before any password or key check happens.

The Wazuh sshd decoder parses the syslog line and extracts `srcip` and
`srcuser`. The parent rule 5700 catches all sshd messages; rule 5710 is a
child that matches the "Invalid user ..." pattern.

**Log pattern:**
```
Invalid user <username> from <IP> port <port>
```

**Example:**
```
Nov 15 02:30:00 server sshd[12345]: Invalid user testuser from 10.0.1.50 port 54321
```

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 5700 | sshd messages grouping | Parent rule (always fires first) |
| 5501 | SSH successful login | Check for subsequent success (compromise indicator) |
| 5715 | SSH authentication success | Check for subsequent success |
| 5712 | SSH brute force attack | Composite rule that fires when 5710 repeats |

## Threat & Motivation

**What the activity is.** Someone connected to the SSH port and submitted
a username that doesn't exist on the host. sshd logs this *before* the
password/key check, so we know nothing about credentials yet — only that
the username was wrong.

**Why an attacker would do this.** Brute-force credential guessing
(MITRE T1110). Attackers typically don't know what usernames exist on a
target, so they iterate through common ones (`admin`, `root`, `oracle`,
`postgres`, ...). Each invalid attempt produces this rule.

**Concrete attacker scenarios:**
- Mass scanning bot iterating a wordlist against SSH-exposed hosts
- Targeted enumeration trying to discover real account names before
  switching to password attacks
- Credential stuffing using usernames leaked from a third-party breach

**Legitimate reasons this fires.** Common in real environments:
- Monitoring systems using a test credential to verify SSH availability
- Users mistyping their username (often followed by a successful login)
- Service accounts using stale credentials after a password/account rotation
- Internal security scanners during approved assessment windows

**Blast radius if real.** Each individual 5710 doesn't grant access — the
auth check fails by definition. The risk is what *follows*: if the
attacker eventually guesses a valid username and password, they get a
shell on the host with that user's privileges.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Source trust

Where did the connection originate?

- Internal RFC1918 source IP, especially from a known monitoring,
  scanner, or jumpbox subnet (lower risk)
- External source IP, no prior history (higher risk)
- External source IP that has fired other rules in the recent past
  (higher risk)

### Axis 2 — Pattern shape

Does this look like a single misfire or like an attack in progress?

- Single attempt, single username, especially a username that fits a
  recognized monitoring or service-account pattern (lower risk)
- Multiple attempts in a short window, multiple distinct usernames,
  usernames from common attack wordlists (higher risk; rule 5712 may
  also fire)
- Followed by a successful login from the same source (higher risk —
  potential compromise; check rules 5501 / 5715)

A trusted source + single-shot pattern is the low-risk quadrant. An
external source + high-volume / multi-username pattern is the high-risk
quadrant.

=== FILE: signature playbook.md ===
---
signature_id: wazuh-rule-5710
last_updated: 2026-04-11
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: SSH Invalid User (5710)

This playbook is **steering, not procedure**. The investigation
methodology — hypothesis discipline, lead severity, verification and
scoping, escalation defaults, stop conditions — lives in the
`investigate` skill. This file provides only what is
signature-specific:

- Field shortcuts so the agent doesn't query for what the alert
  already carries
- Named archetypes the agent should try to recognize, each defined in
  `archetypes/`
- A recommended starter lead order
- A fast-path screen table for the most common benign archetype
- Quirks of this signature that aren't general investigation lessons

## Field shortcuts

| Field | JSON path |
|---|---|
| Source IP | `data.srcip` |
| Attempted username | `data.srcuser` |
| Target host | `agent.name` |

See `context.md` §Alert Fields for why `srcuser` is *the username the
attacker tried*, not the connecting user.

## Archetypes

The archetypes recognized for this signature are defined as
directories under `archetypes/`, each with a `story.md` (observable
shape) and a `trust-anchors.md` (required anchors + precedent
pointer), plus optional `{TICKET-ID}.json` snapshots of past tickets
that matched.

| Archetype | One-line description | Directory |
|---|---|---|
| `monitoring-probe` | Internal monitoring host running a sanctioned single-attempt probe using a sentinel username | `archetypes/monitoring-probe/` |
| `service-account-rotation` | Internal automation whose credentials were rotated but whose config wasn't updated — broken benign automation | `archetypes/service-account-rotation/` |
| `credential-stuffing` | External actor submitting real-looking usernames from a breach dump — escalation outcome | `archetypes/credential-stuffing/` |
| `external-bruteforce` | External actor iterating a wordlist of common usernames at high volume — escalation outcome | `archetypes/external-bruteforce/` |

Both benign archetypes require trust-anchor confirmation to resolve:
`monitoring-probe` is anchored by `approved-monitoring-sources`,
`service-account-rotation` is anchored by `scheduled-jobs`. Both
escalation archetypes have no anchor — they are adversarial by
construction, and the report's job is to ground the escalation in the
volume/source/username shape that distinguishes them from the benign
paths.

## Hypothesis seeds

The archetype catalog above is a *pattern-recognition cache* — fast
paths for alerts whose shape matches a past ticket. But every 5710
investigation should start from candidate mechanism hypotheses and
gather evidence against them; an archetype match, when it happens, is
a short-circuit on top of that, not a replacement for it. Novel
variants, shape mutations, and adversaries mimicking benign patterns
all require the agent to reason from mechanisms, not from cached
patterns alone.

The starter hypotheses below are lean mechanism-shaped candidates to
consider at HYPOTHESIZE. They map roughly to the archetypes when the
evidence fits, but the agent may confirm one of these without
matching any archetype (in which case the outcome is escalation with
a well-reasoned narrative), and may refute all of these and form a
novel hypothesis if the evidence doesn't fit any seed.

### ?legitimate-automation
Some sanctioned automated system — monitoring probe, health check,
scheduled job, backup worker — produced this failed login. Typical
shape: internal source, sentinel or service-account username, low
volume, no successful follow-up. Maps to `monitoring-probe` or
`service-account-rotation` archetypes when the specific automation
is documented in the sanction registry.

### ?authentication-mistake
A human or automation submitted a wrong username by accident — typo,
stale credential after rotation, misconfigured client. Typical shape:
any source, real-looking username or service-account shape, low
volume, often followed by a successful login within seconds (the
retry after noticing the typo). This hypothesis is usually benign but
has no dedicated archetype — it resolves via evidence discipline
rather than archetype match.

### ?credential-guessing
An adversary is trying to find valid accounts on this host. Typical
shape: external source, multiple distinct usernames or repeated
attempts, usernames drawn from wordlists or breach dumps, no
successful login (yet). Maps to `external-bruteforce` at high volume
with wordlist usernames, or `credential-stuffing` at low volume with
real-looking usernames.

### ?compromise-followup (adversarial — always keep active)
This failed auth is one event in a chain that includes (or will
include) a successful authentication from the same source. The shape
alone looks like any of the above, but the *temporal context* —
specifically any 5501 / 5715 success from the same srcip within
seconds — takes the event out of the benign archetypes entirely and
into compromise territory. This hypothesis must be explicitly
refuted with a forward-looking `authentication-history` check before
any resolution, regardless of which archetype the shape matched.

## Starter lead order

1. **`source-classification`** — classify `data.srcip` against
   `environment/context/ip-ranges.md`. Internal monitoring host,
   internal-other, or external determines which half of the archetype
   space is even applicable. Most investigations discriminate
   `monitoring-probe` / `service-account-rotation` from
   `credential-stuffing` / `external-bruteforce` on this lead alone.
2. **`authentication-history`** — failed logins from same `srcip` in
   the last 5 minutes, plus successful logins from same `srcip`
   within 60 seconds after the alert. This lead answers both the
   volume axis (how many attempts?) and the compromise axis (did any
   auth succeed?). The compromise check is non-negotiable — a 5710
   followed by a 5501 from the same source is a different problem
   regardless of which archetype the 5710 itself matched.
3. **`username-classification`** — classify `data.srcuser` against
   `environment/context/identity-patterns.md`. Monitoring-pattern
   (sentinel, anchored by source classification to monitoring-host),
   service-account pattern, wordlist-common, or real-looking. This
   lead picks between archetypes once source and volume are known.

Most investigations resolve cleanly after these three leads. When the
picture is still ambiguous after lead 3, fall through to the full
investigation loop.

> **Recent-alert correlation** ("other alerts from this host in last
> 24h", "is this a repeat", "did 5712/5501/5715 also fire") is
> handled by the ticket-context subagent at CONTEXTUALIZE — its
> findings are already in the investigation context. Don't re-execute
> these queries; reference the ticket-context output for escalation
> signals.

## Screen

Fast-path pattern for automated resolution. The screen subagent
checks this before the full investigation loop. Indicators are
**semantic predicates** — classifications derived from the environment
knowledge base and anchor lookups, not raw alert-field comparisons.

| Pattern | Indicators | Leads | Action | Archetype |
|---|---|---|---|---|
| monitoring-probe fast-path | `source_classification: internal-monitoring-host` (via `environment/context/ip-ranges.md`) AND `username_classification: monitoring-pattern` (via `environment/context/identity-patterns.md`) AND `approved-monitoring-sources` anchor confirms the triple AND `attempt_count_5min: 1` AND `successful_login_after_60s: false` | source-classification, username-classification, authentication-history, approved-monitoring-sources anchor | resolve → benign, matched_archetype: monitoring-probe, matched_ticket_id: SEC-2024-001 | `archetypes/monitoring-probe/` |

**Why a real query, not pure field matching:** `attempt_count_5min`
and `successful_login_after_60s` cannot be read from the alert
itself. They describe context that requires a historical + forward
lookup via `authentication-history`. This is by design — an
adversarial variant that reuses an approved source IP and username
family but bursts multiple attempts (same identity, different shape)
would trivially bypass a pure field-match screen; requiring the
historical + forward query forces the fast path to care about
cadence and follow-up success, both of which the anchor's
confirmation shape depends on.

**Indicator resolution:**

- **source_classification** — map `data.srcip` to a classification
  using `environment/context/ip-ranges.md`. Only
  `internal-monitoring-host` counts. An unclassified internal IP is
  not a known monitoring source.
- **username_classification** — map `data.srcuser` to a pattern in
  `environment/context/identity-patterns.md`. Monitoring-pattern
  matches the sentinel list (`nagios`, `zabbix`, `prometheus`,
  `healthcheck`, `monitorprobe`, `sensu`, `testuser`, `probe`).
- **approved-monitoring-sources anchor** — query the sanction anchor
  for the exact `(srcip, srcuser, target)` triple. See
  `environment/operations/approved-monitoring-sources.md`.
- **attempt_count_5min** — from `authentication-history`: how many
  5710 events from this srcip in the 5 minutes preceding the alert.
  The fast path requires **exactly 1** (the alert itself). Any retry
  burst disqualifies.
- **successful_login_after_60s** — from the same lead: was there any
  successful SSH login (rule group `authentication_success`) from
  this srcip in the 60 seconds after the alert. Must be **false**.

All five indicators must pass for the screen to match. Any failure
drops the investigation into the full loop.

## Signature quirks

- **`srcuser` is the attacker-supplied string, not a host identity.**
  The rule fires *because the username doesn't exist*. Do not treat
  `srcuser` as "the user who tried to log in" — it's whatever the
  connecting party typed. Classification against identity-patterns is
  pattern-matching the string, not looking up a real account.
- **`srcip` may be a NAT egress, not the actual attacker.** External
  IPs are often shared (cloud egress, proxy exit, CGNAT). When the
  disposition depends on source reputation, cite the IP as the
  connection source, not as "the attacker."
- **5712 is the composite rule for brute-force.** Co-firing 5712 in
  the same window is strong evidence for `external-bruteforce` but
  not sufficient alone — 5712 can fire on internal brute-force too,
  which is a different archetype space (operator typo recovery,
  scanner misconfiguration). Cross-reference with source
  classification.
- **Success-after-failure is always severe, regardless of archetype.**
  A 5710 followed within seconds by a 5501 / 5715 from the same
  source is a potential compromise indicator. Even if the 5710 would
  otherwise match a benign archetype, the successful follow-up takes
  it out of that archetype and into escalation. Check
  `authentication-history` explicitly for this.

## Scope

Standard for this signature: the alerting event and its immediate
context (5-minute window before, 60-second window after). Anything
beyond this requires escalation per the skill's stay-in-scope rule.


=== FILE: soc-agent/knowledge/signatures/wazuh-rule-5710/archetypes/credential-stuffing/story.md ===
---
archetype: credential-stuffing
signature_id: wazuh-rule-5710
required_anchors: []
---

# Credential Stuffing — Story

An external actor attempted to log in as a small set of **real-looking
usernames** with credentials likely sourced from a third-party breach.
The attempt volume is low — one to three tries per source — and the
usernames are not drawn from an attack wordlist but from a leaked
credential dump: plausible first-name / last-name combinations,
service account names from specific products (`jenkins`, `gitlab`,
`jira`), or usernames that correspond to real accounts elsewhere in
the org but not on this host.

The shape differs from `external-bruteforce` in **volume** and
**username style**. Brute-force iterates wordlists at high volume to
find *any* account that accepts a guess; credential stuffing targets
*specific* identities with presumed-valid credentials. Brute-force
fires 5712 (the composite rule) routinely; credential stuffing
usually does not — the volume is below 5712's threshold.

The shape differs from `monitoring-probe` in **source classification
and username realism**. Monitoring probes come from internal
monitoring hosts with sentinel usernames; credential stuffing comes
from external sources using realistic usernames.

This archetype always escalates. The disposition is always escalate
to a human — the analyst needs to verify whether the attempted
usernames correspond to real accounts on *any* host in the
environment, and whether any of them appear in a known breach dump.

What takes an alert *out* of this archetype: internal source (a
different archetype entirely), high-volume wordlist pattern
(`external-bruteforce`), or a single-attempt sentinel username
(`monitoring-probe`).

=== FILE: soc-agent/knowledge/signatures/wazuh-rule-5710/archetypes/external-bruteforce/story.md ===
---
archetype: external-bruteforce
signature_id: wazuh-rule-5710
required_anchors: []
---

# External Brute-Force — Story

An external actor systematically attempted SSH authentication against
this host using a wordlist of common usernames. The source IP is
external (not in any RFC1918 range or org-internal subnet). Multiple
distinct usernames are tried in close succession — typically more
than five attempts in five minutes — drawn from common attack
wordlists like `admin`, `root`, `user`, `test`, `oracle`, `postgres`,
or service-account names the attacker doesn't actually have.

The attacker's goal is to find any account that accepts a guess. They
are not targeting a specific identity. The high volume and username
diversity is the signature.

This archetype always escalates. External sources running wordlist
attacks are adversarial by definition; coordinated pentests would
match a different archetype anchored by a change ticket.

What takes an alert *out* of this archetype is the volume profile or
the source classification. A single attempt is `credential-stuffing`
(if the username is real-looking) or noise. Attempts from an internal
source are an entirely different archetype (operator typo, automation
misconfiguration, monitoring probe). The combination of external
source + multiple distinct usernames + high volume is what defines
this archetype.

=== FILE: soc-agent/knowledge/signatures/wazuh-rule-5710/archetypes/monitoring-probe/story.md ===
---
archetype: monitoring-probe
signature_id: wazuh-rule-5710
required_anchors:
  - approved-monitoring-sources
---

# Monitoring Probe — Story

An internal monitoring system confirmed that `sshd` is listening on
port 22 by attempting a single authentication with a sentinel username
that is not a real account on the target. The connection attempt
fails at the username-existence check — which is the point, since the
probe is not trying to log in — and Wazuh 5710 fires on the resulting
`Invalid user` log line.

The probe is by construction **low-volume**: one attempt per tick from
the same source, separated by the monitoring system's configured
interval (typically minutes). It uses a **stable username** from a
narrow set of monitoring-pattern names (`nagios`, `zabbix`,
`prometheus`, `healthcheck`, `monitorprobe`, `sensu`, `testuser`,
`probe`) — never a real user, never a wordlist rotation, never a
burst of distinct usernames. The source IP is **internal** and
classified as a known monitoring host in
`environment/context/ip-ranges.md`.

Legitimately, there is never a successful login following a probe —
the sentinel username doesn't exist, so even if the probe submitted
credentials there is nothing to authenticate against. A 5710 probe
followed within a minute by a 5501 (auth success) from the same source
is **not** this archetype; the shape has shifted into "operator typo
recovery" or "credential compromise," either of which escalates.

What takes an alert *out* of this archetype: volume (more than one
attempt in the monitoring window), username diversity (multiple
distinct usernames from the same source), an external source (the
monitoring-pattern username is not an identity — an external source
using `nagios` is an attacker borrowing a common probe name, not a
probe), or a successful follow-up login.

=== FILE: soc-agent/knowledge/signatures/wazuh-rule-5710/archetypes/service-account-rotation/story.md ===
---
archetype: service-account-rotation
signature_id: wazuh-rule-5710
required_anchors:
  - scheduled-jobs
---

# Service Account Rotation — Story

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
