---
id: wazuh.auth-events-by-host
params: [host, window]
data_tags: [auth-events]
baseline: optional
---

## Goal

Retrieve authentication events (success and failure) targeting a given
host over a time window. Used to characterize who has been logging into
the host, from where, and with what success rate.

## What to characterize

- Source IP diversity (count of distinct `data.srcip`, top sources)
- Username diversity (count of distinct `data.dstuser`, top usernames)
- Success/failure ratio (`rule.groups:authentication_success` vs
  `authentication_failed`)
- Timing pattern (burst, periodic, irregular) over the window
- Volume — total events and events/hour

## Query

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(authentication_success OR authentication_failed) AND agent.name:${host}' \
  --window ${window} \
  --run-dir ${run_dir}
```

## Common pitfalls

- NAT collapse: a single `data.srcip` may aggregate many real sources;
  inspect username diversity and session ids before claiming "single
  origin."
- Window edges: same-second bursts straddle window boundaries. Bracket
  with a forward lookahead (e.g. `--end T0+60s`) when the alert
  timestamp is the leading edge.

## Baseline

When deviation framing is in play (rate / volume claims), shift the
window 7 days earlier and re-run with the same scoping. Compare
keys per-key.
