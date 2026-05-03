<!-- process-lineage is in the catalog but ships no templates/wazuh.md;
     gather routes the missing template to ad-hoc. -->

## GATHER (loop 1)

```invlang
:L findings [id|name|loop|target|mode|system|template|query|window|status|tests|fail_reason]
l-001|process-lineage|1|v-001|gather|host-query|wazuh|process-list --pid 12345|2026-04-18T20:00Z–2026-04-18T21:00Z|||

:L l-001.substitutions [key|value]
pid|12345
```
