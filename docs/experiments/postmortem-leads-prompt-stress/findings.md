# Post-mortem leads agent-prompt stress test

Ran against 3 real runs with ad-hoc findings.

## Summary

| run_id | vendor | leads | outcome | commits | files_changed | elapsed |
|---|---|---:|---|---:|---:|---:|
| ac307d29-cd25-444d-bb23-2e5f8d97c100 | wazuh | 3 | COMMITTED | 1 | 5 | 530.7s |
| 81ae27f2-fd67-464b-bbe2-68c926e20d11 | wazuh | 2 | COMMITTED | 1 | 2 | 460.1s |
| ed5d7c88-36fb-4980-bb0f-8fc09ce71788 | wazuh | 1 | COMMITTED | 1 | 3 | 374.8s |

Per-run logs in outputs/.