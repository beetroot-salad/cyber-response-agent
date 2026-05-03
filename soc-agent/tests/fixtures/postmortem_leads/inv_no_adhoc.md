<!-- All findings reference catalog leads with vendor templates. -->

## CONTEXTUALIZE

```invlang
:V prologue.vertices [id|type|class|ident|attrs]
v-001|alert|wazuh-alert|wazuh-rule-5710|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]

:L findings [id|name|loop|target|mode|system|template|query|window|status|tests|fail_reason]
l-001|authentication-history|1|v-001|gather|wazuh-indexer|wazuh|rule.id:5710 AND data.srcip:1.2.3.4|2026-04-18T19:00Z–2026-04-18T20:00Z|||

:L l-001.substitutions [key|value]
srcip|1.2.3.4

:V l-001.observations.vertices [id|type|class|ident|attrs]
v-002|ip|external-ip|1.2.3.4|
```
