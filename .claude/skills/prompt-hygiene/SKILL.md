---
name: prompt-hygiene
description: "Audit a SKILL.md, agent prompt, or knowledge doc against the recurring prompt-hygiene corrections from past sessions. Flag violations and propose fixes. Use when editing files under defender/ — defender/SKILL.md, defender/skills/, or defender/knowledge/."
---

# Prompt Hygiene Audit

Read the target file(s) and check each rule below. For each violation, report file:line, the rule violated, and a concrete fix. If clean, say so.

Take target paths from the user; otherwise audit the files changed on the current branch (`git diff --name-only main...HEAD` filtered to `*.md`).

The runtime is `defender/`: a single root `defender/SKILL.md` drives the ORIENT→PLAN→GATHER→ANALYZE→REPORT loop. Two layers matter for hygiene:

- **Orchestration core** (vendor-agnostic): `defender/SKILL.md` and `skills/{gather,invlang,handbook,data-source-debug,advisory}/`. Dispatches to per-system skills generically.
- **Per-system layer** (deployment/vendor): `skills/{elastic,identity,ticket,threat-intel,host-state,cmdb,change-mgmt}/` plus `knowledge/environment/systems/{vendor}/config.env`. This is where v2-playground specifics legitimately live.

## Rules

### Scope & layering

1. **Orchestration core stays vendor-agnostic.** `defender/SKILL.md` and `skills/{gather,invlang,handbook,data-source-debug,advisory}/` must not hardcode the deployment — container names, `docker exec`, a specific vendor CLI as the dispatch mechanism, or one system's indices/field names baked into the flow. They dispatch generically (gather reads `skills/{system}/SKILL.md` on demand). Deployment specifics belong to the per-system layer. (Illustrative example rows that name a real source tag are governed by rule 9, not this rule.)
2. **Per-system skills split descriptor from execution.** A `skills/{system}/SKILL.md` is the lean entrypoint — what the system holds, its field vocabulary, its load-bearing rules. The CLI surface, query syntax, and connectivity notes go in an adjacent `skills/{system}/execution.md` (e.g. elastic), under "use `--help`, don't read source." Verbatim deployment config (hosts, indices, transport) lives in `knowledge/environment/systems/{vendor}/config.env`, not inline in the prompt.
3. **Runtime reference vs deployment config.** How-the-runtime-works docs (the loop, the learning loop, run artifacts, invlang grammar) live in `skills/handbook/content/`. Deployment/system config lives under `knowledge/environment/`. Don't put runtime mechanics in `knowledge/` or deployment config in the handbook.

### Prompt shape

4. **Long subagent instructions live in their own file.** If a subagent prompt is >~10 lines of instructions, extract it: the dispatching SKILL keeps a 1-line description + the minimal call, and the subagent reads its own file. The live pattern is gather's `finder.md` / `executor.md`, dispatched from `skills/gather/SKILL.md`.
5. **Subagent prompts stay terse.** Drop parenthetical scope notes and rule-rationale prose. Two operational sentences per discipline bullet.
6. **No hook-check duplication in agent prompts.** Hooks under `defender/hooks/` fire regardless (e.g. `invlang_validate`, `block_unwrapped_adapter_calls`). If a hook enforces a constraint and the agent can't remediate at the point of failure, don't add a precondition bullet — keep the check silent.
7. **Skip label/dotted-path translation maps when only the LLM consumes them.** Emit raw paths and the raw closed vocabulary (invlang reads `vocab.py` directly); don't add a human-readable alias table the model doesn't need.

### Redundancy & polish

8. **Don't explain what's clear from context.** Cut sentences that restate the surrounding header, the obvious purpose of a section, or what well-named identifiers already convey. If removing the line wouldn't confuse a future reader, remove it.
9. **Refactor patched prompts to feel native.** After multiple edits, prompts often read as original-plus-stitches: late additions parenthesized into earlier sentences, redundant bullets covering the same rule from two angles, vestigial framing from a superseded design, terminology that drifted between sections. Rewrite so the current intent reads as if drafted in one pass — collapse duplicates, fold parentheticals into prose, drop sentences that only made sense in a prior version, unify vocabulary. Flag specific stitches; don't just say "feels patched." Vestigial `soc-agent` framing left over from the rename is a frequent instance.

### Examples & claims

10. **Examples must be real and self-flagged.** An example may carry a deployment-specific value — a real system tag, field name, or query language — and often should, to stay concrete. Two conditions: (a) it names something that exists in *this* deployment — a stale or phantom vendor (e.g. `wazuh` where the stack runs `elastic`) is a misleading example; rename it and unify with the real tags used elsewhere (rule 9); (b) it is flagged as illustrative (`e.g.`, `// example values throughout`, a `{placeholder}`) so a reader can't mistake it for the general rule. A vendor mechanism written as the bare rule in a system-generic prompt (e.g. "Under ES|QL the query is one positional" in the cross-system lead-author) reads as universal — state the general shape, then demote the vendor to a flagged `e.g.`. And if a warning block exists only to compensate for a pitfall in an example, fix the example structurally (rename, drop the asymmetry) instead of layering warning text.
11. **Don't oversell design mechanisms.** Separate load-bearing mechanisms from speculative ones. Don't stack unverified claims to pad a pitch.
12. **No legacy-compat shims for unshipped code.** If the only consumer is in this repo, rewrite the old shape — don't design dual interfaces. (A deliberately A/B-tested path behind a flag, like lean vs split gather under `DEFENDER_GATHER_LEAN`, is an experiment, not a shim — don't flag it.)

### Investigation-language specifics (when target touches invlang)

13. **Hypothesis resolution uses the closed weight vocab.** Lead→hypothesis resolution is `++` / `+` / `-` / `--` (from invlang `vocab.py` / `queries.py`), not ad-hoc strong/moderate/weak or candidate/ruled-out ratings. `hypothesis_shape_match` is a topology query, not a confidence scale — don't conflate the two.
14. **Closed vocabularies have one source.** Slot vocabularies (anchor kinds, etc.) live in `skills/invlang/vocab.py` and are reached via `defender-invlang enum {slot}`. Don't restate or fork a vocab list inline in a prompt; reference the enum.
15. **Empty / suspect results resolve in `gather/validate.md`, then escalate to data-source-debug.** Gather resolves a suspect empty inline (positive control, clause narrowing); only an unresolved, source-healthy quirk hands off to the `defender-data-source-debug` subagent (fresh `claude -p` context). There is no separate "composite" gather path — don't reference one.
16. **Load structured artifacts on demand, don't preload.** Conditionally-load-bearing material gets pulled when needed — the per-system `SKILL.md`/`execution.md` for the system being queried, handbook content by topic — not dumped into the base prompt.

## Output format

```
<file>:<line> — <rule#> <short name>
  Violation: <quote or paraphrase>
  Fix: <concrete edit>
```

End with a one-line summary: `N violations across M files` or `clean`.

Do not edit files unless the user asks. Audit first, then propose.
