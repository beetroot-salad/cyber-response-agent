---
title: Add good/bad hypothesis examples to the HYPOTHESIZE prompt (few-shot)
status: done
groups: hypothesize, prompt, knowledge
---

During the playbook rewrites (rule-100001, rule-100110, rule-5710, 2026-04-18) it became clear that the HYPOTHESIZE phase prompt in `soc-agent/skills/investigate/SKILL.md` §HYPOTHESIZE teaches the rules in prose but never *shows* a concrete good/bad pair. The playbook-seed rewrites did the work of deriving the lean one-hop shape from the rules, but the agent (or a standalone hypothesize-subagent) would benefit from worked examples alongside the rules.

**Proposal.** Add a short "Examples" subsection under §HYPOTHESIZE with 2–3 worked pairs:

1. **Container shell (rule-100001 shape — alert carries mechanism data).** Bad: narrative umbrella (`?post-exploit-shell — attacker with RCE opened a shell to enumerate secrets and move laterally`). Good: mechanism seed (`?runtime-process — parent process ancestry walks back to the container's PID 1 entirely inside the pid namespace, never touching a runtime exec primitive`). Call out *why* the bad one fails (packs mechanism + intent + forward-actions into one label; not falsifiable by the ancestry lead alone).

2. **DNS / SSH / FIM (enrichment-first shape — alert does not carry mechanism data).** Bad: pre-committing to a mechanism fork at loop 1 when the discriminating data isn't yet available (`?dga-malware — malware is probing candidate domains via DGA`). Good: staying in the mechanical/interpretive lane and pre-registering lead-level readings instead (no hypothesis block; `predictions` on the interpretive fields of the enrichment lead). Call out that §ASSESS routes to GATHER-without-HYPOTHESIZE in this case.

3. **Legitimacy-as-attribute.** Bad: parallel adversarial hypothesis that doubles the frontier (`?compromise-followup` shape). Good: the mechanism hypothesis plus a `legitimacy_attributes` note on the confirmed parent, resolved by trust-anchor at disposition time. (This one depends on the adversarial-as-attribute task landing first — see `tasks/adversarial-as-attribute-not-hypothesis.md`.)

**Where to put them.** Inline under §HYPOTHESIZE → Generating Hypotheses, after the 5-step procedure. Keep each example to ~8–12 lines — short enough to live in the prompt.

**Dependencies.**
- `tasks/adversarial-as-attribute-not-hypothesis.md` — example 3 is blocked on the reframe.
- The hypothesize-subagent v2 pilot will use these examples as the ground-truth corpus once written.