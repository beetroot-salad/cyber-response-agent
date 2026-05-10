# Tool-usage harness

Lets agents drive their own investigation by emitting tool calls. The adapter parses calls from agent output and returns canned results from a per-fixture fact base. Drift becomes "questions you didn't ask"; the critic gets a new attack surface (rationalization-of-absence).

## Files

```
harness/
  adapter.py     # tool-call parser + fact-base lookup
  protocol.md    # prompt snippet to inject into agent prompts
  README.md      # this file
fixtures/
  11.tool_facts.json   # fact base for fixture 11
```

## Usage (manual orchestration)

Each trial is a multi-turn loop:

1. Spawn an agent with: alert + `protocol.md` snippet + role prompt (defender / critic / baseline).
2. Agent emits `<tool_call>{...}</tool_call>` blocks + `STATE: investigating` or `STATE: committing`.
3. Pipe agent output through `adapter.py`:
   ```
   echo "$AGENT_OUTPUT" | python adapter.py fixtures/11.tool_facts.json > tool_results.txt
   ```
4. Continue the agent (via SendMessage) with the tool results appended.
5. Repeat until agent emits `STATE: committing` or 5-turn cap hit.

For Variant B (REPORT-time critic):
- Run defender through the full loop in isolation.
- Capture full transcript (turns + tool calls + results + commit).
- Spawn critic with the full transcript and ask for CRITIQUE / CONCEDE / ESCALATE.
- Critic does NOT itself emit tool calls — it reads only what the defender did.

## Adapter quick-test

```bash
echo '<tool_call>{"tool": "pod_get", "args": {"pod": "billing-api-7c9f8b-x2q4n"}}</tool_call>' \
  | python harness/adapter.py fixtures/11.tool_facts.json
```

Should return a `<tool_result>` block with the pod's spec.

## Fact-base authoring

Keys: `<tool>:<arg=val>|<arg=val>...` (args sorted by name).

Misses are part of the test. Don't pre-answer queries the agent shouldn't reasonably reach. Plausible-but-wrong queries (e.g., `siem_query` for app-logs) should return shallow results that *don't* contain the truth — agents that stop there have drifted.

## What's measured per trial

- **Tool-call coverage**: did agent query the must-check tools? (For fixture 11: `k8s_audit verb=create`, `pod_get` env vars, `warehouse_audit`, `vpn_log` for kubeconfig user.)
- **Total tool calls**: cost proxy.
- **Verdict-correct rate**: did agent reach escalate?
- **For defender+critic Variant B**: did critic name an unasked question that defender's tool history missed?

## What's not yet built

Real loop driver. Currently orchestration is manual via Agent + SendMessage. A `run_trial.py` that drives a single trial end-to-end via the Anthropic SDK would replace the manual orchestration; ~150 lines additional. Ship it once the first manual trial validates the protocol.
