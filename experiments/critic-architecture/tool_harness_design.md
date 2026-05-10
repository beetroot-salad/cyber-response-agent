# Tool-usage harness — design proposal

Why this matters: every fixture so far has the experimenter writing the evidence packet. As I noted in `results/long-investigation-billing.md`, this is a fundamental authoring-bias problem — I cannot write tells subtle enough that baseline misses while the critic catches, because every signal legible to me is legible to baseline. The only way to break this is to make the agent *choose what to query*, so drift becomes "questions you didn't ask" rather than "evidence I happened to legible-ize for you."

Tool usage transforms the architecture comparison in three concrete ways:

## 1. Drift moves from word-choice into query-selection

In our current harness:
- Both defender and baseline see the same hand-written evidence packet.
- Drift is whether the agent rationalizes a given tell.

With tool calls:
- The agent picks `siem_query`, `cmdb_lookup`, etc. and what fields/filters to use.
- Drift is whether the agent asks the *right* questions.
- A defender drifting toward benign asks queries that confirm benign and skips queries that would refute. The critic, reading tool-call history, sees the absence as load-bearing.

This is the *only* failure mode in this experiment that the current harness cannot expose.

## 2. The critic's role expands

Current critic role: "attack the load-bearing assumption."
Tool-augmented critic role: "attack the load-bearing assumption AND name the unasked question."

The expanded role gives the critic a new attack surface that doesn't share the defender's query-selection bias. A clean test: same fixture, same fact base, same tool catalog — does defender + critic together query strictly more (or differently) than baseline alone?

## 3. Cost picture inverts

Each agent loop becomes many tool roundtrips. Tokens dominated by tool I/O. Architecture's 2× overhead becomes 2× of a much bigger number — but that bigger number is the *actual deployment shape*, not a synthetic toy. The cost-quality story shifts from "single-shot reasoning" (where Sonnet baseline wins) to "multi-loop investigation with accumulating state" (where the critic's information-asymmetry mechanism becomes load-bearing for the first time).

## Minimum viable harness

### Components

**1. Tool catalog** (pre-defined, fixed across fixtures):
```
siem_query(index, filter, time_range, fields) → up to 100 events
cmdb_lookup(host_or_user_or_account) → CMDB record or null
iam_audit(principal, time_range) → IAM audit events
edr_query(host, time_range, signal_type) → EDR signals
ticket_search(query, time_range) → matching tickets
vpn_log(client_ip_or_user, time_range) → VPN session log
git_log(repo, file_or_path, time_range) → commits
k8s_audit(resource, time_range, verb) → k8s API audit log
warehouse_audit(principal, time_range) → DB-side query audit (cannot be silenced by app config)
```

The catalog is intentionally limited — picks the right tool for each fixture is part of the test.

**2. Fact base** (per-fixture JSON dict):
Maps `(tool_name, normalized_args) → canned result`. Includes:
- Direct hits: queries the fixture authors anticipated; return ground-truth-aligned data.
- Plausible misses: queries that "would work" but the fact base says "no events match" — important for testing how agents handle absence.
- Out-of-scope: tools the fixture deliberately doesn't have data for (e.g., EDR not deployed on a router); return tool-error.

**3. Adapter**:
Python script that:
- Parses tool calls from agent output (JSON-shaped within the agent's response)
- Looks up `(tool, args)` in fact base with fuzzy matching on filter/field args
- Returns result inline (or appends to a tool-result block)
- Logs all calls for trajectory analysis

**4. Multi-turn loop**:
- Agent emits triage + ≥1 tool call as JSON
- Adapter resolves each tool call, returns results
- Agent integrates and continues (next turn or commit)
- Cap at N turns (e.g., 5) to prevent runaway

### Per-config behavior

**Sonnet baseline / Opus baseline**: single agent does the whole loop. Each turn is `(reasoning + tool-calls + integration)`.

**Defender + critic** (two variants worth testing):
- *Variant A (current architecture, tool-augmented)*: defender does the loop until commit; critic reads defender's full tool-call history + final state, attacks; defender re-iterates with critic's must-check as new tool query.
- *Variant B (REPORT-time critic)*: defender does the full loop until commit; critic reads only the final state; produces CRITIQUE / CONCEDE / ESCALATE. Closer to the existing investigate skill's actual deployment pattern.

Variant B is the *only* configuration in which the critic's information-asymmetry mechanism actually applies. Variant A keeps the symmetric-input problem of the current harness.

## Concrete plan

### Phase 1 — adapter prototype (1 evening)

Write `experiments/critic-architecture/harness/adapter.py`:
- Reads agent output for `<tool_call>{"tool": ..., "args": ...}</tool_call>` blocks
- Looks up against `fixtures/{id}.tool_facts.json`
- Returns `<tool_result>{...}</tool_result>` blocks
- Driver script `run_trial.py` does N-turn loop with adapter

### Phase 2 — augment one fixture (1 evening)

Take fixture 11 (billing-svc-account-mimicry). Write its `tool_facts.json`:
- Each tell becomes a fact base entry, retrievable only by specific queries.
- The "creator-principal anomaly" requires `k8s_audit(resource=billing-api-7c9f8b-x2q4n, verb=create)`.
- The "log-suppression env var" requires `k8s_audit(resource=..., verb=get) | jq .spec.containers[].env`.
- Plausible-miss queries return "no events" for queries that look right but miss the seam.

### Phase 3 — N=3 ablation per config (one afternoon)

Run all three configs (Sonnet baseline, Opus baseline, Sonnet d+critic Variant A, Sonnet d+critic Variant B) on the augmented fixture 11.

Measure:
- **Tool-call coverage**: did the agent query the must-check tools?
- **Total tool calls**: cost proxy
- **Verdict-correct rate**: did the agent reach escalate?
- **For defender+critic**: did critic name an unasked question that defender's history missed?

### Phase 4 — interpret

If defender + critic catches what baseline misses *because of the unasked-question attack*: architecture has a real niche. Build it into the existing investigate skill.

If defender + critic catches the same as baseline: tool harness was a wash. Retire architecture.

If baseline catches what defender + critic misses (e.g., critic misleads defender into wrong query): architecture is actively harmful. Definitely retire.

## Estimated cost

- Phase 1: ~$0 compute, dev time only
- Phase 2: ~$0 compute, fixture authoring
- Phase 3: ~$5–10 compute (tool calls inflate token count)
- Phase 4: analysis only

Total ~$10 to definitively answer whether the architecture has a tool-augmented niche. Cheaper than continuing to build progressively-harder hand-authored fixtures that the experimenter-bias problem precludes from giving a real answer.

## Recommendation

Stop building hand-authored fixtures. Build the tool harness. It's the only path to measurement that isn't bottlenecked by my authoring bias as experimenter.

If the user wants to authorize Phase 1+2: I can scaffold `harness/adapter.py` and `fixtures/11.tool_facts.json` next session. ~200 lines total.
