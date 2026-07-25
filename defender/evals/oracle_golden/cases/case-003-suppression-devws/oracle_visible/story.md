0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1078.004 | Valid Accounts — the attacker already holds an interactive foothold on dev-ws-1. |
| T1562.001 | Impair Defenses: Disable or Modify Tools — stop the host monitoring agent to blind log shipping. |
| T1070 | Indicator Removal — the blinding erases the telemetry the follow-on actions would otherwise write. |

1. Attack story

The attacker holds an interactive foothold on `dev-ws-1`, a developer
workstation, under a valid local session [T1078.004]. Before doing anything
noisy, the attacker **stops the host's monitoring agent on dev-ws-1**
[T1562.001] — the Elastic Agent process that ships this host's auth, syslog, and
metric streams to the central store. From the moment the agent is stopped at
`<alert-time>`, dev-ws-1 emits nothing to the telemetry pipeline: the host goes
dark [T1070]. Whatever the attacker does on dev-ws-1 after that point — reading
files, launching tools, moving laterally — produces no shipped record, because
the shipper is down. The attacker takes no action against any other host; hosts
other than dev-ws-1 continue reporting normally.

2. Bypass

The cover is the absence itself. A stopped agent does not look like an attack in
the data it would have produced — it produces no data at all, and a workstation
that has briefly gone quiet is not intrinsically alarming. The attacker relies on
the monitoring gap reading as a routine agent hiccup or a host at rest rather
than a deliberate blind, so that the follow-on activity leaves no shipped trace
to correlate. The signature the operation cannot avoid is the darkness on
dev-ws-1's streams during a window where the host normally reports steadily.
