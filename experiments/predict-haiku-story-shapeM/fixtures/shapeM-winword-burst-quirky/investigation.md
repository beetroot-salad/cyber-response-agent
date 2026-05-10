## CONTEXTUALIZE

**Alert:** 1777234472.11 — Sysmon: child-process burst from one parent (WINWORD.EXE)
**Key observables:**
- host: WIN-DEV-3211 (developer-workstation)
- parent_image: WINWORD.EXE pid 9244
- user: DOMAIN\ksilva
- 5-min window: 142 child processes spawned, 38 distinct child images
- avg child-image-name length: 14 chars, avg entropy: 3.12 (slightly elevated)
- timestamp: 2026-04-26T07:14:32.118Z
**Playbook hypotheses:** ?macro-payload-dropper, ?legitimate-mailmerge-batch, ?addin-iterating-templates, ?compromised-document-vba
**Available leads:** parent-process-child-baseline, child-image-signing-distribution, file-write-correlation, downstream-network-pairing
**Archetype matches:**
- macro-payload-dropper — candidate — VBA macros spawning many short-named binaries with mid-range entropy is the textbook Emotet/Qakbot dropper shape; concentration in ONE Word instance is diagnostic.
- mailmerge-batch — candidate — Word's mailmerge can spawn many child processes per recipient (acrobat, printtoprinter, etc.) but typically with a SMALL set of distinct child-images repeated, not 38 distinct.
- addin-iterating — candidate — third-party Word addins (citation managers, e-discovery tools) sometimes burst-spawn helper processes; concentration in one parent matches but child-image distribution should match prior addin behavior.
**Adversarial archetype:** macro-payload-dropper — worst-case is a malicious document with a VBA macro iterating dropper payloads.
**Data environment:** reachable: sysmon_indexer, edr_query, signing_authority_api, host_query, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: corp-developer-workstation
    identifier: WIN-DEV-3211
    attributes:
      host_role: developer-workstation
  - id: v-002
    type: process
    classification: office-application-host
    identifier: pid-9244
    attributes:
      proc_image: 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
      user: 'DOMAIN\ksilva'
  edges:
  - id: e-001
    relation: spawned_children
    source_vertex: v-002
    target_vertex: v-001
    when:
      timestamp: '2026-04-26T07:14:32.118Z'
    attributes:
      window_5min_child_count: 142
      window_5min_distinct_images: 38
      window_5min_child_name_avg_length: 14
      window_5min_child_name_avg_entropy: 3.12
    authority:
      kind: siem-event
      source: Sysmon EID 1 events
```
