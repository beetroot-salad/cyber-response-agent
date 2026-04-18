---
signature_id: SIGNATURE-ID
purpose: Field-level quirks for shape comparison. Read by archetype-scan and other subagents that extract observables from the alert. Not a substitute for context.md — just the gotchas.
---

# Field Quirks — {signature-id}

## Key observables

The fields that define this alert's identity — what makes THIS alert
THIS alert. Used by subagents to extract entities for SIEM queries
(ticket-context) and compare shape against archetype stories
(archetype-scan). Each entry names the observable, its JSON path, and
one-line reason it matters for shape comparison.

| Observable | JSON path | Why it matters for shape comparison |
|-----------|-----------|-------------------------------------|
|           |           |                                     |

## Field gotchas

Non-obvious semantics a reader would get wrong from the field name
alone. For each gotcha, name the field and say what it *actually*
means (not what it looks like).

- **`field_name`** — {what's counterintuitive about this field}
