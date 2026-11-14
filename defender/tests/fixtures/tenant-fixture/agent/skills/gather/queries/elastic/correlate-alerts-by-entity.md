---
id: elastic.correlate-alerts-by-entity
status: established
verb: alerts
params: [end, start]
body_substitutions: [entity_filter]
---

## Goal

Fixture content for tests (#1108 P4). Count detection alerts naming one entity over a window
(correlate alerts, entity, prior alert). The whole body is `${entity_filter}`, so it is a wide
query you narrow or widen yourself.

## Query

```
${entity_filter}
```
