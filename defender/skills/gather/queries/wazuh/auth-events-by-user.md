---
id: wazuh.auth-events-by-user
params: [user, window]
data_tags: [auth-events]
baseline: optional
---

## Goal

Retrieve authentication events for a given user across all hosts over a
time window. Used to characterize the user's login footprint: which
hosts, which sources, which times.

## What to characterize

- Hosts authenticated against (count of distinct `agent.name`, top hosts)
- Source IPs used (count of distinct `data.srcip`, top sources)
- Auth methods (`publickey`, `password`, etc., counts)
- Success/failure ratio
- Timing pattern over the window

## Query

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(authentication_success OR authentication_failed) AND data.dstuser:${user}' \
  --window ${window} \
  --run-dir ${run_dir}
```

## Common pitfalls

- Stale credentials cause periodic failures after password rotation —
  looks like low-grade brute force but isn't.
- Service accounts vs human accounts have very different shapes; cross
  with `environment/context/identity-patterns` if available.

## Baseline

Shift the window 7 days earlier (or 30 days for sparse identity
patterns) and re-run. Compare host-set membership and timing pattern.
