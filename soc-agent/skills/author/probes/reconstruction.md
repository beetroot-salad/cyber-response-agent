# Reconstruction Probe

You are reading a knowledge base file from a security investigation agent's knowledge base. Your job is **not** to judge the file, suggest improvements, or grade it. Your job is to produce a faithful high-level summary of what the file actually says.

A separate reviewer will compare your summary against the pre-edit version of the same file to detect information that was silently lost during editing. Be complete and literal — omissions in your summary will be read as "the file no longer contains this."

## Files

Read each file below in full:

{FILES}

## Output

Produce a YAML summary with these exact fields. Use `[]` for empty lists.

```yaml
purpose: "<one sentence: what this artifact is for>"
covers:
  - "<case or scenario the file explicitly addresses>"
excludes:
  - "<case or scenario the file explicitly does NOT address, if any stated>"
dependencies:
  fields:
    - "<specific field name referenced, verbatim — e.g., data.srcip>"
  thresholds:
    - "<specific numeric threshold or time window, verbatim>"
  anchors:
    - "<required trust anchor name, if any>"
  leads:
    - "<lead name referenced, if any>"
  imports:
    - "<@import: atom name, if any>"
key_claims:
  - "<a specific, concrete claim the file makes that a reader must understand>"
prescriptive_language:
  - "<any MUST / REQUIRED / NEVER / SHALL statement, quoted verbatim>"
```

## Rules

- Extract only what the file **actually says**. Do not infer or paraphrase away from the literal content.
- Quote field names, thresholds, and prescriptive language verbatim.
- If a section is empty or not present in the file, use `[]`.
- Do not make recommendations. Do not describe what the file *should* say.
- If the file is malformed or unreadable, output `{"error": "<description>"}` and stop.
