<!-- Trimmed; rule100001 ad-hoc leads in dense format with ANALYZE prose. -->

## CONTEXTUALIZE

```invlang
:V prologue.vertices [id|type|class|ident|attrs]
v-001|alert|wazuh-alert|wazuh-rule-100001|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]
h-002|?ci-pipeline-exec||||||||||||

:L findings [id|name|loop|target|mode|system|template|query|window|status|fail_reason]
l-001|correlated-falco-events|1|v-002|analyze|wazuh-indexer|ad-hoc|rule.groups:falco AND agent.name:wazuh.manager AND data.output_fields.container.id:2427c46c4575 AND rule.id:(100002 OR 100006 OR 100001)|2026-04-18T20:22Z–2026-04-18T20:52Z|active|
l-002|container-baseline|1|v-002|analyze|wazuh-indexer|ad-hoc|rule.id:100001 AND data.output_fields.container.image.repository:cyber-response-agent_devcontainer-target-endpoint|2026-03-19T00:00Z–2026-04-18T20:22Z|active|

:L l-001.substitutions [key|value]
container_id|2427c46c4575

:L l-002.substitutions [key|value]
image_repository|cyber-response-agent_devcontainer-target-endpoint

:R attr_updates [resolved_by|target|key|value]
l-001|v-002|correlated_100002_count_in_15min_window|24
l-002|v-002|image_baseline_prior_100001_count|11

:L findings [id|name|loop|target|mode|system|template|query|window|status|tests|fail_reason]
l-003|ad-hoc|2|v-003|gather|deploy-runs|ad-hoc|find CI/CD job records correlated to container a3b274907152_target-endpoint within ±5 minutes of 2026-04-18T20:37Z|2026-04-18T20:32Z–2026-04-18T20:42Z|||adapter-error

:L l-003.substitutions [key|value]
container_name|a3b274907152_target-endpoint
timestamp|2026-04-18T20:37Z
```

## ANALYZE (loop 2)

**Lead:** correlated-falco-events

**Query:** `rule.groups:falco AND agent.name:wazuh.manager AND data.output_fields.container.id:2427c46c4575 AND rule.id:(100002 OR 100006 OR 100001)`

**Selection rationale:** Primary composition-rule check: tests whether 100002/100006 events overlap the shell event at 20:37Z within ±15 minutes — the key composition-rule check discriminator for h-003.

**Lead:** container-baseline

**Query:** `rule.id:100001 AND data.output_fields.container.image.repository:cyber-response-agent_devcontainer-target-endpoint`

**Selection rationale:** Tests h-003's p2 baseline for this image.

**Lead:** ad-hoc

**Query:** `find CI/CD job records correlated to container a3b274907152_target-endpoint within ±5 minutes of 2026-04-18T20:37Z`

**Selection rationale:** Resolves lc1 on h-002 by querying deploy-runs for a CI/CD job correlated to a3b274907152_target-endpoint.

