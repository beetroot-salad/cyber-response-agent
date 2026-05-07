---
id: wazuh.recent-rule-fires
---

## Goal

Retrieve recent fires of a specific Wazuh rule across the fleet over a
time window. Used to gauge whether the alert under investigation is a
one-off or part of a broader pattern (and where else it has fired).

## What to characterize

- Total fire count
- Hosts affected (count + top names)
- Source IPs (count + top sources)
- Timing — burst around the alert timestamp, or steady drumbeat?

## Query

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query 'rule.id:${rule_id}' \
  --window ${window} \
  --run-dir ${run_dir}
```

## Common pitfalls

- Some rules fire every few seconds for healthcheck-style traffic — a
  big number is not interesting on its own; look at distribution
  across hosts and srcips.
