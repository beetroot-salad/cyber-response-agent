---
id: host-query.process-list
status: established
---

## Goal

Current process names running on the host that match a given pattern. Answers what processes are active now, useful for identifying browsers, agents, or anomalous executables. Matches process executable basenames (e.g., `chrome`, `firefox`, `datadog-agent`).

## What to characterize

- process names matching the pattern
- count of matching processes
- absence or presence of expected processes (browser, monitoring agents)

## Query

```
process-list --pattern ${pattern}
```

`${pattern}` is a POSIX extended regular expression matched against the executable basename of each running process. Examples: `chrome|firefox|chromium` (browsers), `datadog.*|telegraf|collectd` (telemetry agents), `curl|wget` (web clients).

## Filter binding

- `pattern` → regex string, matched case-sensitively against process names. POSIX ERE syntax (not PCRE). Examples:
  - `chrome` matches processes named `chrome`, `chrome-extensions`, etc.
  - `firefox|chromium|chrome` matches any of the three browsers.
  - `.*agent.*` matches any process with "agent" in its name.

## Common pitfalls

- **Case sensitivity**: pattern is case-sensitive. `curl` matches `curl` but not `CURL`.
- **Basename only**: pattern matches against the executable basename (e.g., `curl` in `/usr/bin/curl`), not the full path or command-line arguments.
- **Live-host race**: the process snapshot is taken at dispatch time; short-lived processes active at the alert timestamp may have already exited. Empty result on a transient entity is not a refutation — pair with Wazuh syscall audit events for "what was running at time T."
- **No argv, no pid → user mapping**: the adapter returns names only. For process ancestry, invocation context, or which user spawned the process, route to Wazuh.
