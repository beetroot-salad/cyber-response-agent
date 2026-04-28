<!-- Lead `process-lineage` exists in the catalog but has no templates/wazuh.md.
     The agent declared template: wazuh; the per-vendor template is missing.
     Per gather's _lead_template_path rule, this routes to ad-hoc. -->

## GATHER (loop 1)

```yaml
gather:
  - id: l-001
    loop: 1
    name: process-lineage
    target: v-001
    selection_rationale: "Walk the parent chain of the suspect process."
    query_details:
      system: host-query
      template: wazuh
      query: "process-list --pid 12345"
      time_window: "2026-04-18T20:00Z–2026-04-18T21:00Z"
      substitutions:
        pid: "12345"
    outcome:
      attribute_updates: []
      observations:
        vertices: []
        edges: []
    resolutions: []
```
