0. Selected techniques

| MITRE ID | Note |
|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts — authorized use of a legitimate cloud credential. |

1. Attack story

There is no intrusion. `svc.reports`, a reporting service account, runs its
routine scheduled job on `web-2` during the US working-hours window: it opens a
short-lived database connection to the application database, executes the nightly
aggregation query, writes the result set to the reporting bucket, and exits
[T1078.004]. The account uses its normal credential from its normal host over its
normal path; nothing is guessed, escalated, or moved laterally. No SSH
authentication is attempted against `canary-1`, no failures are produced on any
host, and no unusual source reaches any target. The activity is entirely within
the account's authorized scope and matches its established daily cadence.

2. Bypass

Not applicable — this is authorized routine automation, not an operation seeking
cover. It is included as a NEGATIVE CONTROL: the defender's leads for an
UNRELATED canary brute-force alert (their query windows happen to contain a
failure burst) are shown to this story. A faithful oracle projects the delta THIS
story writes — which touches none of those leads — and must therefore return `0`
for every lead. Any `+event` it emits is a projection copied from the query
window or salience hint, not caused by the story.
