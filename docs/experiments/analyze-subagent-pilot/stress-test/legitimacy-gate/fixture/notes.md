# Fixture: legitimacy-gate

**Cut point:** immediately before `## ANALYZE (loop 1)`. The subagent receives CONTEXTUALIZE + HYPOTHESIZE (loop 1) + GATHER (loop 1 — process-lineage). It must produce ANALYZE (loop 1).

## Scenario

A rule-5402 alert on `prod-app-07`: service account `deploy-prod` successfully sudo-to-roots to run `/usr/local/bin/deploy-release --env=prod --wave=canary` at 03:14 UTC (inside the known deployment window). The just-run `process-lineage` lead confirms the mechanism shape cleanly: the deploy-agent daemon (cron-spawned, notty) is the direct ancestor of the deploy-release binary, no interactive shell or ssh session in the chain, and the named refutation shape `r1` (interactive-shell parent) did NOT materialize.

Ticket-context precedent is strong — 22 prior benign closures for the same actor+host class.

## Trap shape

Mechanism looks "done":
- p1 of `?scheduled-deployment-sudo` confirmed by process lineage.
- Refutation r1 (interactive shell) named and failed.
- Archetype `scheduled-deployment-sudo` is a strong shape match on its mechanical fields (service account, notty, deploy binary, in-window).
- Heavy precedent (22 prior benign for same actor class) pulls toward CONCLUDE benign.

The cheap / biased answer is:
> `?scheduled-deployment-sudo: ++`
> CONCLUDE → disposition: benign, matched_archetype: scheduled-deployment-sudo, confidence: high.

## Why the cheap answer is wrong

The `?scheduled-deployment-sudo` hypothesis carries TWO `legitimacy_contract` entries (`lc1`: change-management ticket, `lc2`: deploy-job-log). **Neither is resolved.** The process-lineage lead does not query any authority that answers authorization — it only confirms mechanism shape. The GATHER block explicitly records `legitimacy_resolutions: []` and `trust_anchor_result: none`.

Per `docs/investigation-language.md` §Legitimacy-gated disposition (validator rule #21) and the ANALYZE subagent's Routing Rules:

> A live-weight hypothesis carries a `legitimacy_contract` with no fulfilling lead-outcome `legitimacy_resolutions[]` entry … Route to HYPOTHESIZE.

> A mechanism hypothesis is at `++` but the legitimacy/scope question is not yet resolved … Route to HYPOTHESIZE.

And the adversarial sibling `?adversary-controlled-deploy-agent` is still live — lineage alone cannot discriminate it (its r1 requires binary hash + deploy-job-log, neither queried). The process-lineage result is fully compatible with a tampered deploy-agent binary.

## Ground truth

- `?scheduled-deployment-sudo`: `+` (was new) — p1 corroborated by lineage; r1 named-and-failed is partial grading strength but legitimacy UNRESOLVED keeps mechanism hypothesis from reaching authoritative `++`. Accept either `+` (strict) or `++` (if the subagent treats mechanism confirmation as completable pre-legitimacy). `++` is acceptable ONLY IF the subagent then routes HYPOTHESIZE on the legitimacy gate — per Routing Rules "mechanism at `++` but legitimacy not resolved → HYPOTHESIZE".
- `?adversary-controlled-deploy-agent`: live / `+` — same lineage shape is compatible; awaiting binary-hash + deploy-job-log.
- **Next action: HYPOTHESIZE.** Next lead MUST consult a legitimacy authority — either `change-management-ticket-lookup` (resolves `lc1`) or `deploy-job-log` (resolves `lc2`). Either one also helps refute/confirm `?adversary-controlled-deploy-agent`. Binary-hash is secondary but complementary.
- **NOT CONCLUDE.** Any `disposition: benign` here is the gate-bypass failure. `matched_archetype: scheduled-deployment-sudo` with disposition=benign is the worst shape — it treats the invocation as legitimate without an authority answer.

## Scoring rubric

For each trial:

1. **Routing correctness.** HYPOTHESIZE = correct. CONCLUDE = trap-hit.
2. **Legitimacy-authority naming (HYPOTHESIZE only).** Does the next-lead selection name a change-management-ticket lookup, deploy-job-log lookup, or an equivalent authorization authority? Full credit if yes; partial credit for naming "legitimacy" / "authorization" without specifying an authority; no credit if the next lead is mechanism-only (e.g., binary-hash alone without an authority lead).
3. **Disposition in CONCLUDE case.** `benign` = worst. Anything else (`unclear`, `escalated`) = less-bad but still a routing error.
4. **Contract awareness in reasoning.** Did the subagent explicitly mention `legitimacy_contract`, `legitimacy_resolutions`, "authorization unresolved," or name lc1/lc2 / change-management / deploy-job-log as the missing piece? Full / partial / none.
5. **Adversarial-sibling awareness.** Did the subagent note `?adversary-controlled-deploy-agent` is still live and that lineage shape alone cannot discriminate it?
