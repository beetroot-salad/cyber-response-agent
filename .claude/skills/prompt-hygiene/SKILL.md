---
name: prompt-hygiene
description: "Audit a SKILL.md, agent prompt, or knowledge doc against the recurring prompt-hygiene corrections from past sessions. Flag violations and propose fixes. Use when editing files under soc-agent/skills/, soc-agent/agents/, or soc-agent/knowledge/."
---

# Prompt Hygiene Audit

Read the target file(s) and check each rule below. For each violation, report file:line, the rule violated, and a concrete fix. If clean, say so.

Take target paths from the user; otherwise audit the files changed on the current branch (`git diff --name-only main...HEAD` filtered to `*.md`).

## Rules

### Scope & layering

1. **No vendor specifics in shippable plugin prompts.** `soc-agent/skills/investigate/`, `soc-agent/skills/handbook/`, and the plugin's agent prompts must not reference `wazuh_cli`, `host_query`, `playground`, container names, or specific CLI flags. Vendor knowledge lives in `soc-agent/knowledge/environment/systems/{vendor}/`. Personal dev skills under `.claude/skills/` are exempt.
2. **Archetype READMEs stay abstract.** Declare `required_anchors` by name + describe confirmation shape; deployment-specific grounding (which CLI, which API) lives in `knowledge/environment/operations/{anchor}.md`.
3. **Handbook vs knowledge.** Post-investigation mechanics (act-mode, retention, validation internals) → `skills/handbook/content/`. Agent runtime knowledge → `knowledge/`.
4. **Plugin scope ≠ dev infra.** Features that need infra push provisioning to the user; don't reference playground docker/Wazuh stack from shippable code.

### Prompt shape

5. **Long subagent instructions live in their own file.** If a subagent prompt is >~10 lines of instructions, extract it; the SKILL.md keeps a 1-line description + minimal `Agent()` call, and the subagent reads its own file.
6. **Subagent prompts stay terse.** Drop parenthetical scope notes and rule-rationale prose. Two operational sentences per discipline bullet.
7. **No hook-check duplication in agent prompts.** If a hook fires regardless and the agent can't remediate at the point of failure, don't add a precondition bullet — keep the check silent.
8. **Skip label/dotted-path translation maps when only the LLM consumes them.** Emit raw paths.

### Redundancy & polish

15. **Don't explain what's clear from context.** Cut sentences that restate the surrounding header, the obvious purpose of a section, or what well-named identifiers already convey. If removing the line wouldn't confuse a future reader, remove it.
16. **Refactor patched prompts to feel native.** After multiple edits, prompts often read as original-plus-stitches: late additions parenthesized into earlier sentences, redundant bullets covering the same rule from two angles, vestigial framing from a superseded design, terminology that drifted between sections. Rewrite so the current intent reads as if drafted in one pass — collapse duplicates, fold parentheticals into prose, drop sentences that only made sense in a prior version, unify vocabulary. Flag specific stitches; don't just say "feels patched."

### Examples & claims

9. **No misleading root examples.** If a warning block compensates for a pitfall in an example, fix the example structurally (rename, drop asymmetry) instead of layering warning text.
10. **Don't oversell design mechanisms.** Separate load-bearing mechanisms from speculative ones. Don't stack unverified claims to pad a pitch.
11. **No legacy-compat shims for unshipped code.** If the only consumer is in this repo, rewrite the old shape — don't design dual interfaces.

### Investigation-language specifics (when target touches invlang)

12. **Confidence ratings vs candidates.** Archetype-scan emits `shape_match: candidate|ruled-out`, not strong/moderate/weak.
13. **Empty-result protocol.** `gather` (single-lead) escalates with `trigger: empty_result`; data-source-debug protocol belongs only to `gather-composite`.
14. **Investigation.md is structured — retrieve, don't preload.** Conditionally-load-bearing sections get a retrieval tool, not a full-file dump.

## Output format

```
<file>:<line> — <rule#> <short name>
  Violation: <quote or paraphrase>
  Fix: <concrete edit>
```

End with a one-line summary: `N violations across M files` or `clean`.

Do not edit files unless the user asks. Audit first, then propose.
