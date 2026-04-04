---
name: process-lineage
data_tags: [process-events]
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
