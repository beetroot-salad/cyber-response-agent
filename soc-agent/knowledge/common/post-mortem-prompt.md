# Post-Mortem Analysis Prompt

Analyze the following investigation results and extract actionable lessons for the knowledge base.

## Input

You will receive an investigation summary JSON containing:
- `ticket_id`: The ticket that was investigated
- `signature_id`: The signature that fired
- `disposition`: How it was resolved
- `evidence`: Key evidence collected
- `report_body`: The full investigation narrative

## Instructions

1. **Identify lessons learned**:
   - New patterns observed (benign or malicious)
   - Investigation shortcuts that worked
   - Pitfalls encountered
   - Environment-specific notes

2. **Check for duplicates**:
   - Read the existing `lessons.md` for this signature
   - Do NOT add a lesson if the same pattern is already documented
   - Reference the ticket ID with `@TICKET-ID` format

3. **Format for knowledge base**:
   - Tips: `"Observation text @TICKET-ID"`
   - Pitfalls: `"Pitfall description @TICKET-ID"`
   - Patterns: `"**Pattern name**: description @TICKET-ID"`

4. **Update utilities if applicable**:
   - New query patterns that proved useful
   - New classification rules

Only add lessons that would help future investigations. Skip routine/obvious findings.
