# HYPOTHESIZE variance — root cause analysis (run #50 + cross-run)

Question: what drives the wall-clock variance in the HYPOTHESIZE subagent on rule-100001 across orchestrator runs?

## The data

Per-run durations of the HYPOTHESIZE subagent on rule-100001, from `subagent_audit.jsonl` across `/tmp/soc-agent-orchestrate-eval/`:

| Run (dir timestamp) | Attempt 1 | Attempt 2 | Attempt 1 stdout | Notes |
|---|---|---|---|---|
| 20260421-171849 | 277s | 170s | 2982 chars | both attempts emitted output — ran twice for another reason |
| 20260421-174559 | 301s | — | 905 chars | single attempt, short output |
| 20260421-175726 | **144s** | — | 2017 chars | **fast clean success** |
| 20260421-181641 | 165s | 31s | **1 char** | attempt 1 emitted empty stdout, retry recovered in 31s |
| 20260421-183244 | 324s | 144s | 1362 chars | both attempts emitted — retry reason unrelated |
| 20260421-213431 | 308s | 25s | **1 char** | run #50; attempt 1 empty stdout, retry recovered in 25s |

Range on attempt 1: **144s → 324s (2.25× spread)**. Two of six runs emit effectively empty stdout (1 char) on attempt 1 and need a retry. The retry — when it fires on the `stdout_summary_not_yaml` remediation path — is consistently fast (25-31s).

## Root cause #1 — checkpoint-after-YAML ordering leaves no final text turn

`claude --print` emits only the **final assistant text turn** to stdout. Tool-use turns after that text are ignored by the print mode.

The hypothesize.md prompt (`soc-agent/agents/hypothesize.md`, lines 652-663, §Progress checkpoint) specifies four milestones and defines M(last) as:

> **M(last) — terminal.** After `Selected lead:` and `Pitfalls:` are written. Set `status: complete`.

So the contract puts the M(last) `Write` **after** the text response. When the model follows the contract literally, its last turn is a tool_use (Write), not text, and `claude --print` returns empty.

Direct evidence from the two `stdout=1` sessions:

Run #50 attempt 1 (session `1c7e39eb`), turn-by-turn:
```
[8]  THINKING (28485 ch)  ← huge upfront analysis
[10] TOOL_USE Bash (mkdir)
[16] TOOL_USE Write (M1 checkpoint)
[20] TOOL_USE Write (M2)
[24] TOOL_USE Write (M3)
[28] TEXT (4780 ch)       ← the full YAML response is emitted HERE
[29] TOOL_USE Write (M_last)  ← but a Write turn follows it
[30] TOOL_RESULT
← session ends. `claude --print` emitted nothing after [28].
```

Run #45 attempt 1 (session `dda3bc46`, from 181641), identical tail:
```
[29] TEXT (4675 ch)
[30] TOOL_USE Write (M_last)
[31] TOOL_RESULT
← same pattern.
```

Contrast with run 175726 (144s, fast clean success, session `f692457c`):
```
[26] TOOL_USE Write
[28] TOOL_USE Write
[30] TEXT (2016 ch)       ← last turn is text
← session ends. `claude --print` captures the full 2017 chars.
```

The fast-success run emits all its Writes **before** the terminal text turn. That violates the prompt contract (M_last should come *after* the response) but produces the behavior `claude --print` requires. Whether the model ends on text or on Write is stochastic — the prompt doesn't make stdout-is-the-deliverable strong enough to override the literal "write M_last after Pitfalls" instruction.

**The retry path is fast because `stdout_summary_not_yaml` explicitly tells the model to cat the checkpoint and transcribe it.** Attempt 2's thinking is 972 chars; it reads the existing checkpoint, recognizes the work is done, and does a single text turn. No checkpoint writes during the retry turn, so the text is the final turn.

Cite: `soc-agent/agents/hypothesize.md:652-663` (checkpoint milestone contract), `soc-agent/scripts/handlers/hypothesize.py:_FAILURE_REMEDIATIONS["stdout_summary_not_yaml"]` (retry remediation that forces text-last).

## Root cause #2 — 28K-char upfront thinking block duplicates the preloaded prompt

Attempt 1's thinking block on run #50 was **28,485 chars** before any action. Attempt 2 on the same run: 972 chars.

Reading the [event 8] thinking block (see `hypothesize-transcript-run50.md`), the model spends most of those 28K chars **restating content already present in the prompt**:

- "Falco 'Terminal shell in container' alert … proc.name: bash, proc.cmdline: bash -c whoami, proc.pname: null …" ← the `<alert>` block literally provides this verbatim.
- "operator-runtime-debug came back strong … ci-pipeline-exec and post-exploit-interactive are moderate" ← the archetype-scan block provides this verbatim.
- "The playbook indicates that pname=null typically signals a parent process that exited after namespace injection" ← the `<signature-knowledge>` → `<playbook>` body provides this.

About 80% of attempt 1's thinking is **summarization of the prompt back to itself**. The actual reasoning — picking the h-001/h-002 fork, drafting stories and predictions — takes maybe 4K chars. The rest is prompt-restatement overhead.

On a 28K-char thinking block with Sonnet, the thinking generation itself costs ~180-220s. That's most of the 300s wall clock. The other 100s is distributed across the three M1/M2/M3 tool calls and the final response assembly.

Compare fast-success run 175726: thinking blocks are 81 + 10,511 + 1,683 chars = ~12K total, about 40% of the 28K attempt. Wall clock 144s ≈ 50% of the slow attempt. The correlation is approximately linear.

Whether the model decides to restate the prompt in thinking looks stochastic too — sometimes it does, sometimes it doesn't. Nothing in the prompt says "do not repeat prompt content back in thinking."

## Question 3 — invlang vs. prompt: shape vs. content post-mortem

Checked: does the prompt duplicate invlang schema content, confusing the agent?

**Where the prompt overlaps invlang:** the prompt prose (hypothesize.md §Hypothesis shape, §Causal story, §Discipline, §Output schema, §Terminal routing YAML) describes:
- hypothesis id / attached_to_vertex / proposed_edge / story / predictions / refutation_shape
- weight null, shelved list, hierarchical refinement IDs
- legitimacy_contract attached to hypothesis, legitimacy_resolutions[] on lead outcome
- subject field (proposed_parent / attached_vertex / proposed_edge)
- one-observable-per-claim, lean cap (≤2 predictions), story-first discipline
- trust_anchor_result shape for authority consultations

The canonical spec is `docs/investigation-language.md` (v2.8, 23 rules). The validator `hooks/scripts/invlang_validate.py` enforces it. The prompt **re-expresses a subset** of that spec in prose.

### Shape (YAML structure) — the model fails here

Direct evidence from run #50: the agent emitted
```yaml
legitimacy_contract:
  id: lc1
  authority: oncall-schedule
  asks: authorization
```
(a dict) where the validator expects a list of dicts. Handler rejected with `legitimacy_contract must be a list` (driver.log line 6).

Why the model got it wrong: the prompt's §Discipline paragraph on legitimacy (lines 270-291) describes the concept in prose without showing YAML syntax. §Output schema (lines 400-420) doesn't include legitimacy_contract. **None of the three examples in the prompt (lines 466-637) includes a legitimacy_contract block**, even though the signature playbook's `?underlying-host` seed declares one. The model fabricates the YAML shape from the prose hint — and gets it wrong because "legitimacy_contract on the hypothesis naming the edge and the authority" reads as singular.

The invlang schema (`soc-agent/knowledge/invlang/schema.md`) shows the correct list shape, but **schema.md is not injected into the subagent prompt** — only the prose §Discipline text is. Confirmed by greping the full 1300-line subagent prompt for `legitimacy`: zero matches.

### Content (what to reason about) — the prompt works

Content-wise the model reasoned correctly about the legitimacy contract on run #50:
- authority: `oncall-schedule` — correct (from signature context: host-side docker exec requires an oncall operator)
- asks: `authorization` — correct (v2.8 vocabulary for the verdict the authority returns)
- applied to the right hypothesis (`?underlying-host`, the hypothesis whose disposition depends on whether the host-side actor was authorized)

Same pattern across the earlier `stdout=1` run (181641): the agent reasoned the right things, just mis-shaped the YAML.

### The duplication diagnosis

The prompt and invlang spec **don't duplicate content** — they duplicate *concepts*. The prompt describes concepts in prose that maps to invlang fields, but:
- Shape examples for all load-bearing fields are **not in the prompt**; only some (hypothesis block, prediction list, refutation_shape list) are.
- Fields introduced after the core skeleton (legitimacy_contract, trust_anchor_result, legitimacy_resolutions) are prose-described but not YAML-exampled.
- The canonical schema with correct shapes lives in `knowledge/invlang/schema.md` but is only loaded into the main-agent context, not the subagent prompt.

The confusion isn't the prompt conflicting with the validator — it's the prompt describing a concept in prose and the model inventing the YAML, while the validator demands the exact shape defined in a file the model can't see.

### Two orthogonal fix directions (ordered by leverage)

1. **Inline YAML shape examples for every invlang field the prompt discusses**, including legitimacy_contract, trust_anchor_result, legitimacy_resolutions. These are small (~5-10 lines each) and close the shape-drift gap directly. Lowest-effort, highest-leverage.

2. **Inline the relevant invlang schema excerpt into the subagent prompt.** Currently `knowledge/invlang/schema.md` is loaded only into the main-agent context, but the subagent emits invlang — it's the one that needs the schema, not the main agent. The context preload refactor (`_context_loader.py`) has the right shape to add this. Medium-effort, addresses the root ("the model can't see the schema it's expected to satisfy") but increases prompt size ~3-5 KB.

A mechanism-level fix — passing the raw validator error through as `remediation_notes` on retry — didn't work on run #50 (we tried; Sonnet got the dict-not-list message and still re-emitted a dict, then we registered a `legitimacy_contract_must_be_list` remediation, which did work but is a one-off patch per validator rule). Fixing the source (the prompt lacks the shape) is more durable.

## Summary

Two orthogonal drivers of HYPOTHESIZE variance:

1. **Stdout-capture pathology** — prompt contract asks for M(last) after the YAML response, which can end the session on a tool_use, which `claude --print` silently drops. Stochastic: ~1-in-3 first attempts on rule-100001 hit this. When it hits, retry adds 300s total. Fix: re-order the prompt to make M(last) the second-to-last step (before Selected lead:), or drop the M(last) checkpoint entirely and treat completion as "final text emitted".

2. **Upfront thinking overhead** — when the model elects to restate the prompt in its first thinking block, attempt 1 stretches from 144s to 300+s. Stochastic. Fix: add explicit prompt guidance that thinking should be reasoning-forward, not prompt-restatement.

Invlang-vs-prompt: not a duplication problem in content terms — a shape-example gap in the prompt. The validator enforces field shapes the prompt only describes in prose, so Sonnet invents shapes for fields it hasn't seen exampled. Fix by inlining YAML examples for every field the prompt references (cheaper) or injecting `knowledge/invlang/schema.md` into the subagent preload (more durable).
