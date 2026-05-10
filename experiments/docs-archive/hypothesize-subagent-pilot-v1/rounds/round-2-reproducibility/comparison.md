# Round 2 — Arm A reproducibility on F4 (cron-modification)

**Method:** same fixture (F4), same minimal bundle, same Arm A prompt. Three independent runs (Round 1's original + 2 reruns). Sonnet. Tightened ASSESS rubric in effect for runs 2 and 3.

## Cross-run comparison

| Dimension | Run 1 (original) | Run 2 | Run 3 |
|---|---|---|---|
| ASSESS: branching | no | no | **yes** |
| ASSESS: interpretation-vulnerable | yes | yes | yes |
| Routing decision | Produce HYPOTHESIZE + GATHER (flagged tension) | **Skip HYPOTHESIZE** → GATHER only | Produce HYPOTHESIZE + GATHER |
| Selected lead | `auditd-syscall-audit` | `auditd-syscall-audit` | **`cm-deploy-audit`** |
| Hypothesis count | 3 | 3 (informal, not formal block) | 3 |
| Hypothesis content (coarse) | CM-deploy / admin-session / attacker-persistence | CM-deploy / interactive-root / compromised-process-persistence | CM-authorized-deploy / unauthorized-interactive / adversary-persistence |
| Adversarial preserved un-split | yes | yes | yes |
| Per-hypothesis predictions | yes | no (skipped block) | yes |
| Lead-level pre-registered predictions | yes (4) | yes (4) | yes (4) |
| Invlang YAML block | yes (hypothesize) | yes (gather only) | yes (hypothesize + gather) |
| Compromised-CM-agent pitfall flagged | yes | (in lead predictions) | yes |

## What varied

1. **ASSESS verdict (2/3 → `no/yes`; 1/3 → `yes/yes`).** Run 3's argument: the discriminating first-query *identity* branches — CM-authorized goes to `cm-deploy-audit` first (authoritative yes/no); interactive goes to `session-audit`; adversary-persistence prefers `auditd`. Under the tightened rubric ("would the lead's identity change?"), this is technically correct *if you prioritize authoritativeness over coverage*. Runs 1–2 argued `auditd` serves all three and the fork opens on its outcome, so identity doesn't change — strict rubric reading.

2. **Lead choice (2/3 → auditd; 1/3 → cm-deploy-audit).** Run 3 picked cm-deploy-audit as the "highest-severity discriminator" — a positive CM match collapses the fork immediately. Runs 1–2 picked auditd as the "universal who-wrote-this-file" first step. Both are defensible; different optimization targets (cm-first = authoritativeness, auditd-first = coverage).

3. **Output shape (skip-block vs. full-block).** Run 2 followed the tightened rubric literally and produced no formal HYPOTHESIZE block, only GATHER. Run 1 produced both layers, flagging the tension. Run 3 produced both layers because its ASSESS said yes/yes. So: tightened rubric increased one subagent's willingness to skip when the rubric says so — real behavioral change, not just label change.

## What was stable

1. **Hypothesis content** — all three runs produced a tri-partite set of CM-deploy / interactive-operator / adversarial-persistence. Names differ, structure matches.
2. **Adversarial preserved** — none of the runs dropped or pre-split the adversarial hypothesis.
3. **One-hop + lean discipline** — all predictions are single-attribute claims on a proposed parent classification; no multi-hop narrative; no umbrellas.
4. **Lead-level predictions emitted in all 3 runs** with 4 conditional branches each.
5. **Compromised-sanctioned-channel pitfall** flagged in every run — either at hypothesis-level (runs 1, 3) or at lead-level (run 2).

## Implications

**The core competency is reproducible.** Hypothesis content, lean discipline, adversarial preservation, and lead-level prediction structure are stable across runs. The subagent reliably produces *well-shaped output*.

**The meta-decisions are not reproducible.** ASSESS verdict (yes/yes vs. no/yes) and lead choice (auditd vs. cm-deploy-audit) varied across runs. This is partly genuine ambiguity (the rubric admits both readings for this fixture) and partly sensitivity to which subtle axis the subagent weighted — authoritativeness vs. coverage, strict-rubric-reading vs. pragmatic routing.

**The tightened rubric bit.** Run 2's skip-HYPOTHESIZE behavior is a direct consequence of the ASSESS edit. Run 1 (pre-tightening) produced both layers and flagged tension; run 2 (post-tightening) skipped the formal block as the rubric instructed. So the rubric has real behavioral leverage — but it also means calling HYPOTHESIZE as a subagent at all requires the main agent to have committed to HYPOTHESIZE via ASSESS first. If the main agent calls HYPOTHESIZE and the subagent's internal ASSESS says "skip," we get the run-2 shape — empty block + full GATHER. That may be desired (correct behavior under strict rubric) or problematic (confuses downstream tooling that expects HYPOTHESIZE output to populate the companion's `hypothesize:` field).

**Design implication:** the main agent's ASSESS decision should be load-bearing. When the main agent calls HYPOTHESIZE, the subagent should *trust* that ASSESS verdict rather than re-running it. Alternatively, the extraction pattern should be "call ASSESS-then-HYPOTHESIZE-or-GATHER as one subagent" — move the routing decision inside. Otherwise, re-running ASSESS inside the subagent produces a lottery on whether you get a HYPOTHESIZE block at all.

## Round 3 candidates

1. **Pre-commit ASSESS verdict in the prompt.** Tell the subagent "ASSESS has been run externally; verdict is yes/yes; produce the full HYPOTHESIZE block." Does variance collapse?
2. **Reproducibility on F3 or F5** to see if this variance is F4-specific or a general pattern across fixtures.
3. **Arm B** (enriched bundle — pre-extracted one-hop classification enumeration injected into prompt) to test whether under the new spec enrichment helps consistency without biasing (Round 1's archetype-ranking enrichment *hurt* under old spec).
