---
signature_id: wazuh-rule-5710
last_updated: 2026-04-11
total_investigations: 0
resolution_rate: null
# Opt-in to the PREDICT loop-1 fast-path. Each entry maps a vertex
# `classification` to regex patterns an `identifier` must match to count as
# the same key-attribute family. Two prologues with the same topology but
# identifiers in different families produce different cache keys, so an
# adversarial collision (e.g., monitoring-pattern with `admin` instead of
# `nagios`) cannot reuse a benign precedent's lead choice.
discriminating_classifications:
  monitoring-pattern:
    - "^(nagios|sensu|monitor.*|probe.*|check.*|sentinel.*|testuser)$"
  service-account:
    - "^(svc-.*|backup-.*|cron-.*|ansible-.*|deploy-.*)$"
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
| `monitoring-probe` | Single-attempt failure from a registered source at the source's documented periodic cadence; no forward success | `archetypes/monitoring-probe/` |
| `service-account-rotation` | Failure stream from an internal source after a credential change, tied to a scheduled job whose config lags rotation | `archetypes/service-account-rotation/` |
| `credential-stuffing` | Failure stream targeting real-looking usernames that match a breach-dump pattern | `archetypes/credential-stuffing/` |
| `external-bruteforce` | High-volume username-iteration from one source against many candidate accounts | `archetypes/external-bruteforce/` |

Archetype membership is observable-shape-determined at REPORT time. Reaching an archetype is downstream of resolving the open questions below — do not pre-commit to an archetype before the questions that would discriminate among them are answered. Registration in an authority anchor (`approved-monitoring-sources`, `scheduled-jobs`) is necessary but NOT sufficient for the corresponding archetype: registration confirms the triple *can* be used by the registered automation; it does NOT confirm the registered automation *did* use it on this specific alert. Identity-of-use is its own question.

## Open questions the agent must determine

This signature does not pre-name hypotheses for the agent. The alert
confirms an `attempted_auth` edge from `v-src-ip` to `v-dst-host`
with identity `v-attempted-user` and outcome `failed`; the process
that initiated it on the source endpoint is not named in the event.
What follows is the list of unknowns the investigation has to
resolve — the agent picks the next-cheapest unknown each loop and
authors hypotheses against it, rather than starting from a
pre-committed mechanism story.

### Unknowns

1. **Source classification** — what kind of host produced
   `data.srcip`? (internal-monitoring-host, internal-other, external,
   unclassified.) Resolved by `source-classification` lead against
   `environment/context/ip-ranges.md`.
2. **Username classification** — what kind of identity is
   `data.srcuser`? (monitoring-pattern, real-account, common-default,
   leaked-dump, random-string.) Resolved by `username-classification`
   lead against `environment/context/identity-patterns.md`.
3. **Volume / cadence shape** — does the alert window plus its
   neighborhood read as a single attempt, a brute-force volume, a
   burst cluster, or a steady periodic cadence? Resolved by
   `authentication-history` over a window that brackets the alert
   plus enough history to characterize baseline.
4. **Triple registration** — is the `(srcip, srcuser, target)`
   triple recorded in `approved-monitoring-sources` or
   `scheduled-jobs` as an authorized automation? An `org-authority`
   anchor consultation answers registration; it does **not** answer
   identity-of-use.
5. **Identity-of-use (only if registration is `present`)** — was
   the registered automation the actor on this specific alert, or
   did some other process on the same host produce the wire-side
   triple? The registry confirms the triple *can* be used by the
   automation; it does not confirm the automation *did* use it
   here. Anyone with shell access on the source host (a different
   script, a manual operator, a compromised process) can produce
   the same `(srcip, srcuser, target)` string on the wire.
6. **Forward outcome** — was there a `successful_login` from the
   same source/user within ~60s? An auth-success after the failure
   stream upgrades severity regardless of the other answers.

### How to use these unknowns at PREDICT time

Pick the cheapest unresolved unknown that discriminates the most
remaining outcomes given what you have so far. Author the hypothesis
or lead-level prediction against THAT question — name the question,
not a mechanism. For example, when unknown 5 (identity-of-use) is
the next cheapest:

> The registry confirms the triple is present, so unknown 4 is
> resolved. Identity-of-use (unknown 5) is the next discriminator
> — it splits between "registered automation produced this attempt"
> and "different process on the same host produced this attempt".
> The two branches diverge on whether the automation's own
> audit/output channel records an action at t-0 and on whether the
> observed (srcport, cadence, cluster-shape) matches the
> automation's historical baseline. Predictions live on those
> observable fields.

Whether you carry both branches as one hypothesis-with-contract or
as a peer-fork is a Shape A vs Shape M call per `predict.md` — the
choice depends on whether the contract anchor (registry) attests to
identity-of-use or only to registration. For monitoring-pattern
sources where the anchor is registration-only, the discriminating
evidence sits on the automation's own audit channel, not on the
contract — that's Shape M (mechanism fork on identity-of-use), not
Shape A (single hypothesis closed by contract).

### Loop 1 default

Loop 1 is typically attribute-enrichment on the already-confirmed
vertices (resolves unknowns 1, 2, 3, 6 in one composite). The
starter leads below are scoped to that. Stay in the mechanical /
interpretive lane per §ASSESS — author hypotheses only when an
unresolved unknown forces a topology-extending decision.

### Authorization-contract case (when the triple is NOT registered)

When the source/username pair is NOT in the registry — external
source or internal-other — the fork is a single authorization question
on the `attempted_auth` edge carried as an `authorization_contract`
(same mechanism, only the authority answer differs). The resolving
lead writes the verdict inline on the materializing edge:

- an `authorization_resolutions[]` entry on the `attempted_auth`
  edge (or via `attribute_updates[].updates.authorization_resolutions[]`
  if the edge already exists), with `verdict: authorized | unauthorized
  | indeterminate`, `grounding_kind: org-authority`,
  `fulfills_contract: h-*.ac*`, and a concrete `anchor_id` / `anchor_kind`;
- the consultation itself is recorded on the lead outcome via
  `anchor_consultations[]` — baseline/registry lookups are consultations,
  not resolutions.

The resolution's verdict routes to archetype:
- `authorized` → `monitoring-probe` or `service-account-rotation`
  depending on username class.
- `unauthorized` → `credential-stuffing` or `external-bruteforce`
  depending on username class × volume shape.
- `indeterminate` → escalate; the anchor gap is the rationale.

### Always-on checks

Forward-window success (a 5501/5715 from the same srcip within 60s)
is a mandatory attribute check inside `authentication-history`, not
a separate hypothesis slot. If observed, it overrides every root
fork — success-after-failure is always severe (escalation).

The escalation archetypes (`credential-stuffing`, `external-bruteforce`)
are adversarial-by-mechanism: classification carries the claim and
no contract is declared. Their `--` refutation comes from concrete
volume/shape evidence, not from an anchor lookup.

See `docs/investigation-language.md` §Authorization as edge attribute and
`docs/design-v3-authority-consultation.md` for the full primitive.

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
| monitoring-probe fast-path | `source_classification: internal-monitoring-host` (via `environment/context/ip-ranges.md`) AND `username_classification: monitoring-pattern` (via `environment/context/identity-patterns.md`) AND `approved-monitoring-sources` anchor confirms the triple AND `cadence_shape: periodic` (see resolution below) AND `successful_login_after_60s: false` | source-classification, username-classification, authentication-history, approved-monitoring-sources anchor | resolve → benign, matched_archetype: monitoring-probe, matched_ticket_id: SEC-2024-001 | `archetypes/monitoring-probe/` |

**Why a real query, not pure field matching:** `cadence_shape` and
`successful_login_after_60s` cannot be read from the alert itself.
They describe context that requires a historical + forward lookup via
`authentication-history`. This is by design — an adversarial variant
that reuses an approved source IP and username family but bursts
multiple attempts (same identity, different shape) would trivially
bypass a pure field-match screen; requiring the historical + forward
query forces the fast path to care about cadence and follow-up
success, both of which the anchor's confirmation shape depends on.

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
- **cadence_shape** — from `authentication-history` cluster stats over
  a window scoped to the `(srcip, srcuser)` pair that brackets the
  alert: **1h before T0 plus 60s after T0**. The forward look-ahead
  is load-bearing for first-of-burst bait detection — without it, when
  the alert itself is the first event of a same-second burst, the
  follow-up attempts land outside the lookup window and
  `max_cluster_size` reports 1 instead of N. Use `--start (T0 - 1h)
  --end (T0 + 60s)` or equivalent.
  Fast-path passes when ALL of:
  - `cluster_count ≥ 3` — at least three distinct probe attempts in
    the window (fewer = insufficient evidence of periodicity, fall
    through to the full loop)
  - `max_cluster_size ≤ 3` — no single probe attempt has more than
    three events; larger clusters are burst-shaped and disqualify
    regardless of repetition
  - (optional, strengthening) `stdev_cluster_gap_s / mean_cluster_gap_s ≤ 0.3` —
    inter-cluster gaps tightly clustered around a mean; tolerates
    any natural cadence (1m, 5m, 15m, 1h) without hard-coding an
    expected interval
  See `knowledge/common-investigation/leads/authentication-history/definition.md`
  §"Cluster stats" for the clustering rule (10s retry gap).
- **successful_login_after_60s** — from the same lead: was there any
  successful SSH login (rule group `authentication_success`) from
  this srcip in the 60 seconds after the alert. Must be **false**.

All five indicators must pass for the screen to match. Any failure
drops the investigation into the full loop.

**Why cluster-count, not per-minute attempt count:** Legitimate
probes use a wide range of natural cadences (1m production Nagios,
5m default Nagios, 15m lightweight health checks, hourly audits).
A fixed "≤N events per M minutes" indicator either excludes faster
tools or admits slow brute-force attempts. Clustering events into
probe attempts first, then checking repetition, captures the actual
shape a monitoring probe leaves in a SIEM: multiple distinct probe
attempts at regular intervals, each attempt 1-2 events (single
connection or one natural retry). The first tick of a newly-started
probe chain cannot pass (cluster_count=1), which is correct — a
single sentinel-named attempt with no prior cadence is
indistinguishable from an opportunistic stray and should route
through the full loop.

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
