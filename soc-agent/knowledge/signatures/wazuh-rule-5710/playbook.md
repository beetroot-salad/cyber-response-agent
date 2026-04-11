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
directories under `archetypes/`, each with a `README.md` describing
the story + required trust anchors, and `{TICKET-ID}.json` snapshots
of past tickets that matched.

| Archetype | One-line description | File |
|---|---|---|
| `monitoring-probe` | Internal monitoring host running a sanctioned single-attempt probe using a sentinel username | `archetypes/monitoring-probe/README.md` |
| `service-account-rotation` | Internal automation whose credentials were rotated but whose config wasn't updated — broken benign automation | `archetypes/service-account-rotation/README.md` |
| `credential-stuffing` | External actor submitting real-looking usernames from a breach dump — escalation outcome | `archetypes/credential-stuffing/README.md` |
| `external-bruteforce` | External actor iterating a wordlist of common usernames at high volume — escalation outcome | `archetypes/external-bruteforce/README.md` |

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
