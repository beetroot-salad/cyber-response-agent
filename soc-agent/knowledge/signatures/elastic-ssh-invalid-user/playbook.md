---
signature_id: elastic-ssh-invalid-user
last_updated: 2026-04-30
total_investigations: 0
resolution_rate: null
# Opt-in to the PREDICT loop-1 fast-path. Each entry maps a vertex
# `classification` to regex patterns an `identifier` must match to count as
# the same key-attribute family.
discriminating_classifications:
  monitoring-pattern:
    - "^(nagios|sensu|monitor.*|probe.*|check.*|sentinel.*|testuser|healthcheck|zabbix|prometheus|monitorprobe)$"
  # Anchored on the actual playground identity pool — see
  # `playground-v2/keycloak/realm.yaml` and `hosts/inventory.yaml`. The
  # only service-account convention in this environment is `svc.<role>`
  # (svc.backups, svc.reports, svc.monitoring). Do not extend this regex
  # to vendor wordlist conventions (`backup-*`, `cron-*`) that the
  # environment doesn't actually use.
  service-account:
    - "^svc\\.[a-z][a-z0-9_]*$"
---

# Investigation Playbook: SSH Authentication Failure (elastic-ssh-invalid-user)

This playbook is **steering, not procedure**. The investigation
methodology — hypothesis discipline, lead severity, verification and
scoping, escalation defaults, stop conditions — lives in the
`investigate` skill. This file provides only what is signature-specific:

- Field shortcuts so the agent doesn't query for what the alert already carries
- Named archetypes the agent should try to recognize, each defined in `archetypes/`
- A recommended starter lead order
- A fast-path screen table for the most common benign archetype
- Quirks of this signature that aren't general investigation lessons

## Field shortcuts

| Field | JSON path |
|---|---|
| Attempted username | `user.name` |
| Source IP | `source.ip` |
| Source port | `source.port` |
| Target host | `host.name` |
| Raw syslog line | `message` |

See `field-quirks.md` for why `user.name` is the *attacker-supplied string*,
not a verified identity, and why `source.port` is the same-connection
discriminator.

## Archetypes

Defined as directories under `archetypes/`, each with `story.md` (observable
shape) and `trust-anchors.md` (required anchors + precedent pointer), plus
optional `{TICKET-ID}.json` snapshots of past tickets.

| Archetype | One-line description | Directory |
|---|---|---|
| `monitoring-probe` | Internal monitoring host running a sanctioned single-attempt probe using a sentinel username | `archetypes/monitoring-probe/` |
| `service-account-rotation` | Internal automation whose credentials were rotated but config wasn't updated — broken benign automation | `archetypes/service-account-rotation/` |
| `credential-stuffing` | External actor submitting real-looking usernames from a breach dump — escalation outcome | `archetypes/credential-stuffing/` |
| `external-bruteforce` | External actor iterating a wordlist of common usernames at high volume — escalation outcome | `archetypes/external-bruteforce/` |

Both benign archetypes require trust-anchor confirmation to resolve:
`monitoring-probe` is anchored by `approved-monitoring-sources`;
`service-account-rotation` is anchored by `scheduled-jobs`. Both
escalation archetypes have no anchor — they are adversarial by
construction, and the report grounds the escalation in the
volume/source/username shape that distinguishes them from the benign paths.

## Hypothesis seeds

At loop 1 there is typically no fork to articulate. The alert confirms an
`attempted_auth` edge from `v-src-ip` to `v-dst-host` with identity
`v-attempted-user` and outcome `failed`. The starter leads below are
attribute-enrichment on those already-confirmed vertices (source
classification, username classification, auth-history around the event)
— not topology-extending proposals. Stay in the mechanical / interpretive
lane per §ASSESS.

Most investigations resolve through enrichment alone: the archetype catalog
captures the cross-product of (source sanctioned?) × (username class) ×
(volume shape) × (forward success?) that these leads discriminate.

### Fork structure when enrichment leaves disposition ambiguous

If the starter leads leave disposition ambiguous **and the source is an
internal-monitoring-host with a monitoring-pattern username**, the
`approved-monitoring-sources` anchor will typically confirm the triple is
registered. That confirms the triple *could* be used by the monitoring
system — it does **not** confirm the monitoring system was the actor on
this specific alert.

**Root fork is identity-of-use, not mechanism.** Fork into:

- `?monitoring-system-is-the-actor` — the registered monitoring tool
  itself produced this attempt. Predictions: the monitoring system's
  own audit/output channel records a scheduled action at t-0 ±jitter;
  the observed (srcport, cadence, cluster-shape) matches the historical
  baseline for this tool's traffic to this target; the tool's process
  on monitoring-host is alive and scheduled around t-0.
- `?credentials-used-outside-registered-actor` — some other actor on
  monitoring-host (or spoofing its identity) produced the attempt using
  the registered credential string. Predictions: no matching
  monitoring-system audit entry at t-0; observed shape deviates from
  the tool's historical baseline (burst, off-cadence, unfamiliar
  srcport pattern).

Do not register mechanism-layer children until the root fork resolves.

### Authorization-contract case (when the triple is NOT registered)

When the source/username pair is NOT in the registry — external source or
internal-other — the fork is a single authorization question on the
`attempted_auth` edge carried as an `authorization_contract`. The
resolution's verdict routes to archetype:

- `authorized` → `monitoring-probe` or `service-account-rotation`
  depending on username class.
- `unauthorized` → `credential-stuffing` or `external-bruteforce`
  depending on username class × volume shape.
- `indeterminate` → escalate; the anchor gap is the rationale.

### Always-on checks

Forward-window success (a successful SSH login from the same `source.ip`
within 60s) is a mandatory attribute check inside `authentication-history`,
not a separate hypothesis slot. If observed, it overrides every root fork —
success-after-failure is always severe (escalation).

## Starter lead order

1. **`source-classification`** — classify `source.ip` against
   `environment/context/ip-ranges.md`. Internal monitoring host,
   internal-other, or external determines which half of the archetype
   space is applicable. Most investigations discriminate
   `monitoring-probe` / `service-account-rotation` from
   `credential-stuffing` / `external-bruteforce` on this lead alone.

2. **`authentication-history`** — failed logins from the same `source.ip`
   in the last 5 minutes, plus successful logins from the same `source.ip`
   within 60 seconds after the alert. Answers both the volume axis (how
   many attempts?) and the compromise axis (did any auth succeed?).
   Use the Elastic CLI with the ECS field mapping from `field-quirks.md`
   (see `common-investigation/leads/authentication-history/templates/` for
   the template structure; Elastic template is TODO — use wazuh.md as
   the structural reference, substituting ECS field names).
   The compromise check is non-negotiable — a failure followed by a
   success from the same source is a different problem regardless of
   which archetype the failure itself would match.

3. **`username-classification`** — classify `user.name` against
   `environment/context/identity-patterns.md`. Monitoring-pattern
   (sentinel, anchored by source classification to monitoring-host),
   service-account pattern, wordlist-common, or real-looking. Picks
   between archetypes once source and volume are known.

Most investigations resolve after these three leads. When the picture is
still ambiguous after lead 3, fall through to the full investigation loop.

> **Recent-alert correlation** ("other alerts from this host in last 24h",
> "did this source also fire elsewhere") is handled by the ticket-context
> subagent at CONTEXTUALIZE — its findings are already in the investigation
> context. Don't re-execute these queries; reference the ticket-context
> output for escalation signals.

## Screen

Fast-path pattern for automated resolution. The screen subagent checks this
before the full investigation loop. Indicators are **semantic predicates** —
classifications derived from the environment knowledge base and anchor
lookups, not raw alert-field comparisons.

| Pattern | Indicators | Leads | Action | Archetype |
|---|---|---|---|---|
| monitoring-probe fast-path | `source_classification: internal-monitoring-host` (via `environment/context/ip-ranges.md`) AND `username_classification: monitoring-pattern` (via `environment/context/identity-patterns.md`) AND `approved-monitoring-sources` anchor confirms the triple AND `cadence_shape: periodic` AND `successful_login_after_60s: false` | source-classification, username-classification, authentication-history, approved-monitoring-sources anchor | resolve → benign, matched_archetype: monitoring-probe | `archetypes/monitoring-probe/` |

**Indicator resolution:**

- **source_classification** — map `source.ip` to a classification using
  `environment/context/ip-ranges.md`. Only `internal-monitoring-host`
  counts. An unclassified internal IP is not a known monitoring source.
- **username_classification** — map `user.name` to a pattern in
  `environment/context/identity-patterns.md`. Monitoring-pattern matches
  the sentinel list (`nagios`, `zabbix`, `prometheus`, `healthcheck`,
  `monitorprobe`, `sensu`, `testuser`, `probe`).
- **approved-monitoring-sources anchor** — query the sanction anchor for
  the exact `(source.ip, user.name, host.name)` triple. See
  `environment/operations/approved-monitoring-sources.md`.
- **cadence_shape** — from `authentication-history` cluster stats over a
  **1h backward window** scoped to the `(source.ip, user.name)` pair.
  Fast-path passes when ALL of:
  - `cluster_count ≥ 3` — at least three distinct probe attempts
  - `max_cluster_size ≤ 3` — no burst-shaped cluster
  - `stdev_cluster_gap_s / mean_cluster_gap_s ≤ 0.3` (when available)
    — periodic inter-cluster spacing
- **successful_login_after_60s** — from the same lead: any `event.outcome:
  success` from this `source.ip` in the 60 seconds after the alert. Must
  be **false**.

All five indicators must pass for the screen to match. Any failure drops
the investigation into the full loop.

## Signature quirks

- **`user.name` is the attacker-supplied string, not a verified identity.**
  The rule fires because credentials didn't authenticate. Do not treat
  `user.name` as "the user who tried to log in" — it's whatever the
  connecting party submitted. Classification against identity-patterns
  is pattern-matching the string, not looking up a real account.
- **ECS collapses "Invalid user" and "Failed password" into the same
  outcome.** Both produce `event.outcome: failure`. To recover which
  shape fired, parse `message` for `Invalid user` (username doesn't exist
  on host) vs `Failed password` (username exists, creds wrong).
- **`source.ip` may be a NAT egress, not the actual attacker.** External
  IPs are often shared (cloud egress, proxy exit, CGNAT). Two failures
  sharing `source.ip` do not necessarily share an actor.
- **PAM noise.** Without the sshd `-e` flag, PAM writes an
  `authentication failure` line alongside sshd's own line for the same
  attempt. PAM lines don't populate `user.name` / `source.ip`. Filter
  `user.name: *` to drop PAM-only docs when counting real attempts.
- **Success-after-failure is always severe, regardless of archetype.**
  Any `event.outcome: success` from the same `source.ip` within 60s
  overrides every archetype; escalate and cite the success event.

## Scope

Standard for this signature: the alerting event and its immediate context
(5-minute window before, 60-second window after). Anything beyond this
requires escalation per the skill's stay-in-scope rule.
