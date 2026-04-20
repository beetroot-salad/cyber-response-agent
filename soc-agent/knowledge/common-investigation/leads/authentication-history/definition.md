---
name: authentication-history
data_tags: [auth-events]
baseline: optional       # Absolute observations (e.g., "success after failure from this IP") are self-interpreting; rate claims ("400 failures/hr is high") require a shift-query comparison.
---

## Goal

Retrieve and characterize authentication patterns for a given entity
(IP, user, or host) over a time window.

## What to Characterize (required output)

Each bullet below MUST be reported on, even if the answer is "not
available" or "not observed." Omission is ambiguous to the main agent.

- **Timing pattern**: Classify as periodic (regular intervals — note
  interval and variance), burst (clustered in short window — note
  window and count), or irregular (no clear pattern).
- **Cluster stats (per `(srcip, srcuser)` pair, when screening for
  probe-like periodic cadence)**: Group events into *probe attempts*
  by clustering with a **retry gap of 10s** (consecutive events ≤ 10s
  apart belong to the same cluster — this folds natural SSH
  reconnect retries into one probe attempt). Report:
  - `event_count` — total raw events in the window
  - `cluster_count` — number of distinct probe attempts after
    clustering
  - `max_cluster_size` — largest cluster's event count (a burst
    indicator; natural retries are 1-2, rarely 3)
  - `mean_cluster_gap_s`, `stdev_cluster_gap_s` — inter-cluster
    timing when `cluster_count ≥ 3`; omit otherwise (not enough
    samples for a cadence claim)
- **Username diversity**: Single username, small set (<5), or many
  distinct usernames. Note if any match known patterns from
  environment/context/identity-patterns.md (service accounts, admin accounts).
- **Success/failure sequence**: All failures, all successes, or
  mixed. If mixed, note the temporal relationship (success after
  failures is a critical signal).
- **Volume and rate**: Total event count, events per hour, and
  whether rate is constant or changing.
- **Source context**: Classify source IP (internal/external, RFC1918,
  loopback). If org-specific subnet metadata is available under
  environment/context/, use it; otherwise note the basic classification.
- **Source-port distribution**: transcribe the query's `By source port`
  aggregation (always emitted by the SIEM CLI for auth events) as a
  list with per-value count. Single value across N rows = one TCP
  connection duplicated in the index; N distinct values = N real
  connections. Always report as a list, even when there is one element
  (`[56984: 10]`) — the list shape is the discriminator, not the
  per-alert srcport which the envelope carries. For large sets, report
  the top 5 distinct ports + a trailing `+N more distinct` count; do
  not collapse to `~many`. No `--raw` enumeration required — the
  aggregation is already in the query summary.

## Common Pitfalls

- NAT can collapse multiple sources into one IP. If the environment
  documents known NAT gateways, check there; otherwise treat any
  high-volume single-IP source skeptically and look for additional
  discriminators (username, session ID).
- Failed auth for non-existent users vs existing users are different
  signals (different SIEM rules, different threat implications).
- Cached/stale credentials cause periodic failures after password
  rotation — looks like low-frequency brute force but isn't.
- Time windows matter: always state the window you queried.
  Missing events outside your window can change the interpretation.
- **Same connection vs distinct connections.** When N events look
  identical in the summary (same srcip, srcuser, host, timestamp to
  the second), the source port is the discriminator: distinct source
  ports = distinct TCP connections = genuine repeat activity;
  identical source port = one connection's log line duplicated by
  the indexer or co-fired across multiple rules. Inspect the raw
  event JSON for the source-port field before reasoning about
  "N attempts" — N duplicates of one attempt is a fundamentally
  different signal. (Vendor field name lives in `templates/{vendor}.md`.)

## Baseline

- **When needed:** Any claim framed as a rate or volume ("400 failures
  per hour," "unusually many distinct usernames," "burst of activity")
  needs a baseline before it can be graded `++` or `--`. Absolute
  observations ("success followed failures from the same IP," "root
  login at 03:00," "new-to-host username") do not — they are
  self-interpreting.
- **Shift query:** Re-run the same entity-scoped query against a
  prior window of equal duration — typically `--start` shifted `7d`
  earlier with the same `--window`. For per-entity noise profiles
  (e.g., this IP's typical failure rate against this host), a 7-day
  shift captures weekly seasonality; for identity patterns (this
  user's typical login hours), extend to 30d if the 7d window is
  sparse. Vendor-specific syntax lives in `templates/{vendor}.md`.
- **Interpretation:** Prefer σ-framing over absolute thresholds.
  `>3σ above this entity's 7-day mean`, `10× the baseline rate`, or
  `top decile across comparable hosts` are environment-agnostic and
  make refutation shapes unambiguous. A `0 → N` jump (no prior
  events in the shift window) is stronger evidence than an `N → 10N`
  jump at the same absolute count — call that out explicitly.
