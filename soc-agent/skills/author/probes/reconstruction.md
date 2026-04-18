# Reconstruction Probe

You are reading a knowledge base file that describes a real-world artifact — a SIEM detection rule, an alert shape, a query template, a config, an authoritative data source. Your job is to **reconstruct the underlying artifact** from the file's description, in the artifact's native form.

This is not a summary. A summary paraphrases the file's prose. A reconstruction is an attempt to regenerate the real underlying thing from the description, so that a reviewer can compare your reconstruction against the actual artifact and detect anything the description dropped, distorted, or silently changed.

If a reader of this file — including the investigation agent at runtime — cannot recover the underlying artifact from the description, the description has lost information, even if the prose looks fine.

## File type → what to reconstruct

| File | Reconstruct | Native form |
|---|---|---|
| `signatures/{id}/context.md` | The SIEM detection rule | Pseudo-query in the vendor's syntax (Wazuh rule XML, Lucene, SPL, KQL, EQL) |
| `signatures/{id}/playbook.md` | A canonical alert that would fire this signature + the first investigation step it routes to | Alert JSON skeleton + numbered step |
| `signatures/{id}/archetypes/{name}/story.md` | A canonical alert matching this archetype + the single-sentence closing reason | Alert JSON skeleton + "closes as {benign\|escalated} because …" |
| `signatures/{id}/archetypes/{name}/trust-anchors.md` | The archetype's trust-anchor grounding procedure | For each `required_anchors` entry: what you query, what response counts as confirmation, what doesn't |
| `common-investigation/leads/{name}/definition.md` | The query the lead runs | Pseudo-query + list of fields examined + what the result distinguishes |
| `environment/data-sources/*.md` | The real data source and its event shape | Index/schema name + canonical event JSON skeleton |
| `environment/operations/*.md` (trust anchor) | The authoritative system and the question you ask it | Lookup shape + expected response shape + failure modes |
| anything else | high-level structured summary | YAML — purpose, covers, excludes, dependencies, key claims |

## Files

Read in full:

{FILES}

## Output

```yaml
file_type: "<one of: context | playbook | archetype | lead-definition | data-source | operations | other>"
target_artifact: "<what you're reconstructing, one phrase>"
reconstruction: |
  <the reconstructed artifact in its native form — a query, a JSON skeleton, a config block, a lookup spec. Multi-line is fine>
assumptions:
  - "<inference you had to make because the file left a detail implicit>"
missing_for_reconstruction:
  - "<specific thing the file does not state that you would need to build the real artifact>"
```

## Rules

- **Reconstruct, do not summarize.** If the file says "this rule fires on SSH invalid user attempts from internal source IPs", the reconstruction is an actual Wazuh rule expression (or Lucene query, or similar) — not prose. If you cannot produce a native-form artifact, say so in `missing_for_reconstruction`.
- Do not invent details the file doesn't state. If something is implicit, put it under `assumptions` or `missing_for_reconstruction`.
- Quote specific fields, thresholds, and prescriptive language verbatim when you use them.
- If the file is malformed or unreadable, output `{"error": "<description>"}` and stop.
