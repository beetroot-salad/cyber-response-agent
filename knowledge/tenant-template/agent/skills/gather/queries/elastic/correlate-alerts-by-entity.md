---
id: elastic.correlate-alerts-by-entity
status: established
verb: alerts
params: [end, start]
body_substitutions: [entity_filter]
---

## Goal

Detection alerts naming one entity over a window, counted across every rule: is this entity
already on the SOC's radar (correlate alerts, entity, prior alert, scoped count). The
envelope's `total` is the count; the returned hits are a capped sample of it.

The whole body is `${entity_filter}`: narrow it by ANDing more of the alert's own fields,
widen it by dropping clauses down to the one field that carries the entity, or drop the
filter for the unscoped count over the same window. Say which filter produced which number.

## Query

```
${entity_filter}
```
