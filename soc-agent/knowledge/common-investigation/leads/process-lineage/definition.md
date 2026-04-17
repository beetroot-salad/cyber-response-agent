---
name: process-lineage
data_tags: [process-events]
baseline: optional   # "First-ever parent→child pair on this host" and "unknown binary hash" are binary observations. "This parent spawns shells 10× more than usual" is a rate claim and needs a shift-query comparison.
---

## Goal

Reconstruct the process tree for a suspicious process — its parent chain,
child processes, and the context of execution.

## What to Characterize

- **Parent chain**: Walk from the process up to init/systemd. Note each
  parent's binary, user, and whether it's expected. Unusual parents
  (web server → shell, container runtime → unexpected binary) are
  strong signals.
- **Child processes**: What did the process spawn? Shells, network
  tools (curl, wget, nc), or reconnaissance commands (whoami, id,
  uname) are post-exploitation indicators.
- **Command line arguments**: Full command line of the process and its
  parents. Note encoded/obfuscated arguments.
- **Binary path and integrity**: Is the binary in a standard location?
  Is it a known system tool or a dropped binary? If possible, verify
  hash against known-good.
- **Execution context**: User, working directory, environment variables
  (if available). Container ID if containerized.
- **Timing**: When did the process start relative to the alert and
  relative to other processes in the chain?

## Common Pitfalls

- Process trees may be incomplete if telemetry started after the
  parent already exited. Short-lived processes may be missed entirely.
- Legitimate admin tools (PowerShell, python, bash) are also attacker
  tools (LOLBins). The parent chain and context distinguish legitimate
  from malicious use.
- Containerized processes have different expectations than host
  processes. A shell in a container may be normal (entrypoint) or
  suspicious depending on the image's purpose.
- PID reuse can cause false parent-child relationships in some
  telemetry systems. Cross-reference timestamps.

## Baseline

- **When needed:** Rate or rarity claims — "this parent→child pair
  is anomalous for this host," "this user spawns shells 10× more
  than typical," "this binary has never been seen in the fleet."
  Structural claims ("web server spawned `/bin/sh`," "command line
  contains base64-encoded payload," "binary hash not in known-good
  set") are self-interpreting and do not need a baseline.
- **Shift query:** Re-run the parent→child (or binary-hash, or
  user→command) query against a prior window of equal duration,
  typically `--start` shifted `7d` earlier with the same `--window`.
  For fleet-wide rarity ("has this hash ever run here?"), widen
  the window to 30d+ and drop the host filter — a same-host 7d
  baseline won't refute a genuinely novel binary. For short-lived
  containers, substitute "peer host in the same role" for the
  entity filter; the container didn't exist 7 days ago.
- **Interpretation:** Prefer σ-framing and first-seen framing over
  absolute counts. `first-ever occurrence of nginx→/bin/sh on this
  host in 30d`, `>3σ above this user's 7-day shell-spawn rate`,
  `hash not present in any fleet process event in 30d` are
  environment-agnostic and make refutation shapes unambiguous. A
  `0 → N` jump (first-ever, never-before-seen) is stronger than a
  `N → 10N` increase at the same absolute count; call it out
  explicitly.
