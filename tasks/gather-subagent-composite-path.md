---
title: Broaden the gather subagent to cover composite-dispatch leads, not just single-lead template-driven
status: done
groups: gather, subagent, cost
---

**Shipped.** Took option (1) variant: added a separate `gather-composite` subagent (`soc-agent/agents/gather-composite.md`, Sonnet) alongside the Haiku `gather` subagent, rather than extending the Haiku one. SKILL.md GATHER dispatch now: Haiku `gather` for single-template-available; `gather-composite` fallback for composite / ad-hoc / escalated-from-Haiku cases. Validated end-to-end in run #40: the subagent fired, GATHER phase dropped from 1141s (run #39, inline) to 782s = **−31%**. The separate-subagent approach was preferred over extending `gather.md` because the Haiku contract is template-strict by design (documented in its prompt as *"Execute **one** template-driven lead"*); composite work requires Sonnet-grade query construction and cross-lead reasoning, and keeping the two contracts separate avoids mode-conditional prompting inside one subagent.

Future refinement (non-blocking): the cost lever could widen further if `gather-composite` sub-dispatches per-lead Haiku work internally when the lead is template-driven, escalating only cross-lead refinement to its own Sonnet reasoning. Not in scope now — current shape is clean and validated.

---

**Gap observed in run #38 post-mortem.** The `gather` subagent (`soc-agent/agents/gather.md`, Haiku-pinned) is the documented cost lever for GATHER work. The SKILL.md dispatches it for *"Single lead, template available"* cases. Composite dispatch (cross-lead refinement, session-window narrowing, consistency checks) and ad-hoc leads are explicitly routed back to the main agent inline (SKILL.md line ~530).

This narrows the Haiku cost lever further than the design language suggests. For many adversarial signatures — including rule 100001 observed in run #38 — the natural investigation shape is **composite**: container-baseline + correlated-falco-events together, with cross-lead notes driving refinement. In this case neither lead is single-template, so the gather subagent is skipped, and the entire GATHER phase runs on main-rate Sonnet.

Run #38 GATHER data:
- 133s phase wall clock (inline on main agent)
- 7 tool calls (the two wazuh queries + invlang checks + edits)
- 9.4 KB thinking chars (main agent forming the composite cross-lead observation)
- 0 subagent spawns

**Options for widening the cost lever:**

1. **Composite-capable gather subagent.** Extend `agents/gather.md` to accept a list of leads with a declared composition mode (refinement / narrowing / consistency) and run them in sequence, carrying cross-lead state. The subagent would still be Haiku by default, escalating when reasoning is needed. The main agent dispatches once per GATHER loop instead of running the leads inline.

2. **Per-lead gather-subagent fan-out.** Main agent dispatches one gather-subagent per lead in parallel (where independent) or in series (when dependent), then stitches the cross-lead observation itself. Simpler contract per subagent, more coordination work in main.

3. **Accept the narrow cost lever.** Keep the current design (single-template only) and optimize the main-agent composite path separately — e.g. by tightening the GATHER prompt in SKILL.md to produce less thinking per composite lead. Zero architectural change, bounded savings.

Option (1) is the highest-leverage path but requires a larger contract change in the subagent. Option (3) is the lowest-risk. Option (2) is a middle ground.

**Decision dependency.** Related to `hypothesize-subagent-wiring.md` — if HYPOTHESIZE output is restructured to explicitly declare composition mode + lead list, the gather subagent can consume that contract directly. Sequencing: decide HYPOTHESIZE-subagent wiring first, then choose gather-subagent composite path based on the HYPOTHESIZE output shape.

**Validation.** Same approach as `hypothesize-subagent-wiring.md`: re-run rule 100001 and measure GATHER wall-clock. Expect composite-capable gather to drop GATHER from ~133s (inline) to ~50-80s (Haiku-primary).

**Related:** see run #38 in `.claude/skills/testrun/SKILL.md`.
