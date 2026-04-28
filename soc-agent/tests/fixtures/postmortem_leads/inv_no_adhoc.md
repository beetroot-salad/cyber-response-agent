<!-- All findings reference catalog leads with vendor templates. -->

## CONTEXTUALIZE

```yaml
prologue:
  vertices:
    - id: v-001
      type: alert
      identifier: "wazuh-rule-5710"
  edges: []
```

## GATHER (loop 1)

```yaml
gather:
  - id: l-001
    loop: 1
    name: authentication-history
    target: v-001
    selection_rationale: "Cadence baseline for the source-IP."
    query_details:
      system: wazuh-indexer
      template: wazuh
      query: "rule.id:5710 AND data.srcip:1.2.3.4"
      time_window: "2026-04-18T19:00Z–2026-04-18T20:00Z"
      substitutions:
        srcip: "1.2.3.4"
    outcome:
      attribute_updates: []
      observations:
        vertices:
          - id: v-002
            type: ip
            identifier: "1.2.3.4"
        edges: []
    resolutions: []
```

## GATHER (screen mode)

```yaml
gather:
  - id: l-002
    loop: 0
    name: source-classification
    target: v-002
    mode: screen
    query_details:
      system: classification-lookup
      template: ad-hoc
      query: "lookup 1.2.3.4"
    outcome:
      observations:
        vertices: []
        edges: []
      screen_result: match
    resolutions: []
```
