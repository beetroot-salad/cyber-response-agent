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

At loop 1 there is typically no fork to articulate. The alert
confirms an `attempted_auth` edge from `v-src-ip` to `v-dst-host`
with identity `v-attempted-user` and outcome `failed`; the process
that initiated it on the source endpoint is not named in the event.
The starter leads below are attribute-enrichment on those
already-confirmed vertices (source classification, username
classification, auth-history around the event) — not
topology-extending proposals. Stay in the mechanical / interpretive
lane per §ASSESS.

Most investigations resolve through enrichment alone: the archetype
catalog above captures the cross-product of (source sanctioned?) ×
(username class) × (volume shape) × (forward success?) that these
leads discriminate.

### Fork structure when enrichment leaves disposition ambiguous

If the starter leads leave disposition ambiguous **and the source is
internal-monitoring-host with a monitoring-pattern username**, the
approved-monitoring-sources anchor will typically confirm the triple
is registered. That confirms the triple *could* be used by the
monitoring system — it does **not** confirm the monitoring system
was the actor on this specific alert. Anyone with shell access to
the monitoring host (a different script, a manual operator, a
compromised process) can produce the same `(srcip, srcuser, target)`
string on the wire. The anchor answers registration, not
identity-of-use.

**Root fork is identity-of-use, not mechanism.** Fork into:

- `?monitoring-system-is-the-actor` — the registered monitoring
  tool itself produced this attempt. Predictions: the monitoring
  system's own audit/output channel records a scheduled action at
  t-0 ±jitter; the observed (srcport, cadence, cluster-shape)
  matches the historical baseline for this tool's traffic to this
  target; the tool's process on monitoring-host is alive and
  scheduled around t-0.
- `?credentials-used-outside-registered-actor` — some other actor
  on monitoring-host (or spoofing its identity) produced the
  attempt using the registered credential string. Predictions:
  no matching monitoring-system audit entry at t-0; observed shape
  deviates from the tool's historical baseline (burst, off-cadence,
  unfamiliar srcport pattern); the monitoring tool's own process
  is idle or running a separate cycle at t-0.

These siblings share the registered triple. Their discriminators
are **correlation queries on adjacent systems**, not process-lineage
on the source host (which is typically unavailable — the monitoring
host often has no endpoint agent). See the new-lead suggestions
below the starter lead order.

**Refinement after identity-of-use resolves.** Only after the root
fork resolves `++` on one side do mechanism-layer children register:

- Children of `?monitoring-system-is-the-actor`: `?scheduled-retry-
  misfire`, `?scheduled-behavior-drift`, `?operator-manual-probe`
  (an operator ran a sibling monitoring-class script whose shape
  differs from the approved tool's — e.g., a test/bait variant).
- Children of `?credentials-used-outside-registered-actor`:
  `?local-process-credential-reuse`, `?tunnel-hijack`,
  `?source-spoofed-from-elsewhere`.

Do not register these at loop 1 — they depend on the root fork
having resolved. Identity-of-use first, mechanism second.

### Legitimacy-contract case (when the triple is NOT registered)

When the source/username pair is NOT in the registry — external
source or internal-other — the fork is a single legitimacy question
on the `attempted_auth` edge carried as a `legitimacy_contract`
(same mechanism, only the authority answer differs). The resolving
lead writes two coupled records in its own `outcome`:

- a `trust_anchor_result` with `asks: authorization`, `kind: org-authority`,
  and `verdict: authorized | unauthorized | indeterminate`;
- a `legitimacy_resolutions[]` entry with `target: e-*` pointing at
  the `attempted_auth` edge and `fulfills_contract: h-*.lc*`.

The contract's verdict routes to archetype:
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

See `docs/investigation-language.md` §Legitimacy as edge attribute and
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
  a **1h backward window** scoped to the `(srcip, srcuser)` pair.
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
