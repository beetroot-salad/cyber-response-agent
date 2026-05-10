# Fixture index

Each fixture is a directory with `alert.json`, `investigation.md`
(prologue + CONTEXTUALIZE only, no PREDICT yet), and `meta.json`
declaring the expected `prior_level` and the hand-labeled
`ground_truth_lead`. The runner consumes that metadata to route
fixtures to the right arms and to score `selected_lead` correctness.

| Fixture | signature_id | prior_level | ground_truth_lead | adversarial? |
|---|---|---|---|---|
| 5710-nagios-monitoring-probe | wazuh-rule-5710 | exact | approved-monitoring-sources | no |
| 5710-sensu-monitoring-probe | wazuh-rule-5710 | exact | approved-monitoring-sources | no |
| 5710-root-external | wazuh-rule-5710 | strong | external-bruteforce | no |
| 5710-admin-internal-collision | wazuh-rule-5710 | strong (adversarial) | source-classification | YES — topology matches monitoring-probe but srcuser=admin (not in monitoring family) |
| 5710-novel-srcuser-internal | wazuh-rule-5710 | moderate | username-classification | no |
| 550-filebeat-inode-flap | wazuh-rule-550 | exact | syscheck-db-state | no |
| 550-novel-opt-path | wazuh-rule-550 | none | file-classification | no |

The first three populate the "happy path" results; the adversarial
collision is the most important: D must reject it via IFF #5 even
though IFF #1–4 all pass.

Status: meta files scaffolded for one fixture below as a template.
Remaining fixtures are TBD — collect from `runs/` + author the
synthetic prologue+alert pairs as needed.
