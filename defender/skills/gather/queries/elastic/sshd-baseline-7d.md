---
id: elastic.sshd-baseline-7d
status: established
---

## Goal

Establish a 7-day pre-alert sshd authentication baseline for a source IP to a target host, anchored at the alert timestamp. Use as a baseline_shift companion to `sshd-auth-sequence-v2`: co-dispatch both to answer whether the source IP + host pair has prior SSH history and whether the alert-window activity is a departure from normal volume or auth method. Use the same `source.ip` structured-field filter and `logs-system.auth-*` index as `sshd-auth-sequence-v2`.

## What to summarize

- Count of successful (Accepted) and failed sshd auth events from the source IP over the 7-day period
- Auth methods observed historically (password / publickey / gssapi) and their relative counts
- Whether the source IP has any prior auth history to this host (zero-vs-nonzero baseline)

## Filter binding

- `${src_ip}` — source IP address; matched via `source.ip`
- `${host}` — destination hostname; matched via `host.name`
- `start` — 7 days before the alert timestamp (ISO-8601)
- `end` — alert timestamp (ISO-8601); excludes the alert window itself
- `index` — `logs-system.auth-*`

## Baseline

Anchored at the alert time minus 7 days. The window explicitly excludes the alert period so the baseline reflects pre-alert state only. When the baseline count is zero, the source IP has no prior sshd auth history to this host.

## Query

```
data_stream.dataset: "system.auth" AND host.name: "${host}" AND source.ip: "${src_ip}"
```

## Common pitfalls

- **Co-dispatch with `sshd-auth-sequence-v2`.** The baseline query and the alert-window query use the same filter expression; only `start`/`end` differ. Dispatch both in the same lead to avoid a round-trip.
- **Large baseline payloads when the source IP has frequent legitimate auth.** A source with regular automated SSH activity (e.g., monitoring agents) returns hundreds of full event docs (multiple MB). Take the **counts from the `--raw` envelope's `total`** — run the Accepted-filtered and Failed-filtered queries with a small `--limit` and read each `total`, rather than pulling event bodies and counting them. Pull hit bodies only for the auth-method distribution.
