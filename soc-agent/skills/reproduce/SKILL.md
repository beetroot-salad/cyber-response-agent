---
name: reproduce
description: Validate an investigation hypothesis by reproducing conditions in an isolated Docker sandbox. Returns confirmed/refuted/inconclusive result.
arguments:
  - name: hypothesis
    description: Clear, testable hypothesis to validate (e.g., "Running /opt/scripts/backup.sh creates /tmp/backup.tar.gz")
    required: true
  - name: ticket_id
    description: Ticket ID for tracking and container naming
    required: true
  - name: signature_id
    description: Signature ID for knowledge lookup
    required: false
  - name: timeout
    description: Timeout in seconds (default 120, max from permissions)
    required: false
---

# Reproduce Hypothesis

## Workflow

1. **Generate run ID** from ticket_id and timestamp for container naming.

2. **Load context** (if signature_id provided):
   - Read `config/signatures/{signature_id}/permissions.yaml` for max timeout
   - Read `knowledge/signatures/{signature_id}/` for environment context

3. **Invoke reproducer subagent** with:
   - The hypothesis to test
   - Run ID for container naming (`repro-{RUN_ID}-<purpose>`)
   - Timeout constraint
   - Isolation requirements (--network none, dropped capabilities)

4. **Cleanup** - After the subagent completes, remove all containers matching `repro-{RUN_ID}-*`:
   ```bash
   docker ps -a --filter "name=repro-{RUN_ID}" -q | xargs -r docker rm -f
   ```

5. **Return result** - The subagent output must contain:
   ```json
   {
     "result": "confirmed|refuted|inconclusive",
     "hypothesis_tested": "...",
     "observations": ["..."],
     "not_reproducible_reason": null
   }
   ```

## Error Handling

If reproduction fails, return:
```json
{
  "result": "inconclusive",
  "hypothesis_tested": "...",
  "observations": ["Reproduction failed: error description"],
  "not_reproducible_reason": "error description"
}
```
