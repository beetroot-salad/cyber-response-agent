---
tags: [trust-anchor, baseline, telemetry-derived]
provides: [image-baseline]
---

# Image Baseline

Established telemetry pattern for a container image — confirms whether an observed event matches the image's historical normal.

## Epistemic note

This is a **pragmatic anchor**, not a sanction anchor. It is derived from telemetry, not from an org authority. It tells you "this image has done this before, many times, without incident" — it does **not** tell you whether the prior occurrences were authorized.

The justification for treating it as an anchor anyway: at the volumes typical of healthy container workloads, demanding sanction confirmation for every routine event is impractical, and an established baseline is the strongest evidence available short of one. The risk is that an attacker who establishes a foothold early enough can train the baseline to accept their activity. Mitigations:

- The baseline's recency window must predate any plausible compromise.
- Sample size must be large enough that one or two anomalies cannot pollute it.
- Reports that cite this anchor must say so explicitly, so downstream auditors can notice patterns of baseline-only resolutions.

When a baseline is the only available anchor for a benign archetype, the report's anchor citation must include the `kind: telemetry-baseline` field (vs `kind: org-authority` for the others).

## Question answered

For a given `container.image`, does the historical event record show a particular `proc.pname` → `proc.cmdline` shape recurring with sufficient frequency, over a long enough window, to be considered routine? Two query modes:

- **Recurrence mode** (used by `app-spawned-shell`): does this parent/cmdline shape recur across normal operation?
- **Startup mode** (used by `container-init-script`): does this parent/cmdline shape fire within seconds of container start, on every (or nearly every) prior container start?

## Available systems

<!-- Example
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Wazuh indexer | All ingested Falco events | MCP: wazuh | Primary |
-->

## Query

<!-- Example
Recurrence mode:
`MCP: wazuh.search(rule_id=100001, container.image=X, range=last_30d)`
Group by proc.pname + proc.cmdline shape, count, span.
Returns: list of { pname, cmdline_shape, count, first_seen, last_seen }

Startup mode:
Same query, additionally filter by event_time relative to container_start_time ≤ N seconds.
-->

## Confirmation shape

A confirmation in **recurrence mode** requires:

- Sample size ≥ N events (configurable; floor around 50 for high-volume images)
- Time span ≥ M days (configurable; floor around 14 days)
- Recency window includes the current image version (no major image rebuild since the baseline started)
- The observed event's parent and cmdline shape match an established cluster, not a one-off

A confirmation in **startup mode** requires:

- ≥10 prior container starts observed for this image
- ≥90% of prior starts produced an event with this parent and cmdline shape within the start-time window
- Recency window includes the current image version

A baseline that shows only a few recent occurrences without a longer-term pattern is **not** sufficient confirmation — that could be the early stages of a compromise being treated as the new normal.

## Failure modes

- **Baseline data unavailable / telemetry retention too short:** escalate.
- **Baseline exists but sample size below floor:** escalate as "insufficient baseline" — the archetype cannot match.
- **Baseline exists but recency window predates the current image version:** escalate as "stale baseline."
- **Observed event matches a cluster that itself looks anomalous** (the cluster started recently, no longer-term history): escalate — the baseline may have been polluted.
