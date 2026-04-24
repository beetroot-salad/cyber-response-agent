---
title: Audit downstream integrity safeguards after rule #32 narrowing
status: todo
groups: invlang, validation, evaluation
---

**Context.** Invlang v2.12 narrowed rule #32 — no longer mandates a waiver on acting-entity contracts. Only fires on the invoker-identity anti-pattern (siblings sharing proposed_edge + subset-or-equal predictions where at least one carries a contract). The front-end integrity question is no longer structurally forced.

**Concern.** Without rule #32's up-front mandate, the agent may declare a contract on a `process` / `session` / `identity` edge, get an `authorized` verdict from the anchor, and conclude `disposition: benign` without considering credential-compromise variants. The theory is that downstream safeguards catch this:

1. **Composition rules in playbooks** — e.g., the rule-100001 playbook's `## Composition rules` section escalates when 100002 co-fires regardless of mechanism match. These run unconditionally and force escalation on corroborating signals.
2. **Unconditional `?compromise-followup` / composition-check leads in GATHER** — predict.md §Disciplines notes these as composition-rule checks that should run regardless of hypothesis state.
3. **ANALYZE's `anomalies[]` channel** — when evidence surfaces unexpected shape (e.g., process named `sshd` with non-sshd exepath), ANALYZE can flag it, which feeds the next PREDICT's remediation notes.

**What to verify.**

- Which production signatures actually have composition-rule blocks that trigger escalation independent of the mechanism fork? Survey `soc-agent/knowledge/signatures/*/playbook.md` for `## Composition rules` sections and their trigger conditions.
- Is `?compromise-followup` actually emitted as an unconditional GATHER lead anywhere? Grep and confirm. If not, is this aspirational or load-bearing?
- Is ANALYZE's `anomalies[]` reliably surfaced in the next PREDICT's remediation notes? Check `scripts/handlers/predict.py:_unresolved_prescribed_notes` (and whether it pulls anomalies too).
- Construct a fixture where the agent's first-pass contract-authorized reading would be wrong, and the only rescue is a composition rule. Confirm it escalates.

**Why this matters.**

Rule #32's narrowing is defensible only if integrity catches elsewhere in the pipeline. If the downstream safeguards turn out to be thin or aspirational, we've quietly removed a guard. Re-introduce a narrowed "integrity_considered" discipline at PREDICT time (optional field documenting the integrity rationale in escalations) if the audit shows gaps.

**Related.** Rule #32 narrowing lives in `hooks/scripts/invlang_checks_hypothesis.py:_check_integrity_peer_discipline` and is documented in `agents/predict.md` §Shape A + §Disciplines.
