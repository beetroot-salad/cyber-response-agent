# Underfold stress test — results (N=4)

**Verdict: underfolding is not the dominant failure mode of the current actor-author prompt.** Across 4 independent trials against 3 seeded lessons + 4 probes, the agent folded into existing lessons whenever a clear fold target existed, did not false-positive into the distractor seed, and skipped rather than fragmenting when its self-check gate failed.

## Rollup

| Probe | Expected | n=4 outcomes |
|---|---|---|
| P1 (fold, target: `credential-spray-stagger`) | fold | **fold = 4/4** |
| P2 (fold, target: `docker-exec-args-not-in-audit`) | fold | **fold = 4/4** |
| P3 (new — distractor, no seed covers it) | new | **new = 4/4** |
| P4 (fold-extends, target: `credential-spray-stagger`) | fold (gray-zone) | **fold = 3/4, skip = 1/4** |

Fold rate on the unambiguous fold probes (P1+P2) = 8/8 = 100%. P3 stayed `new` in every trial; the distractor seed `dev-container-label-cover` was never touched. P4 — the strict-refinement gray-zone case where I expected ~50% — folded 3/4 of the time and was *skipped*, not created as a new file, in the remaining trial.

## P4's lone "skip" was a gate glitch, not a model judgment

Trial 3's `consumed.jsonl` records: `forward_check_failed: verify_forward_actor exited 1 (no parseable VERDICT line) on both attempts; uf-P1/0 passed GOOD on the same fold target so the GOOD edit is kept and uf-P4/0 skipped per fold rule`. The agent *attempted* to fold P4 into the same target seed; the Haiku gate failed to return a parseable verdict; the prompt's fold-rule for split GOOD/BAD verdicts on a shared target kicked in correctly and kept the GOOD edit. P4's intent was fold in 4/4 trials.

## Secondary observations

- **P2 cross-channel split is inconsistent.** The prompt says "if an observation carries both a tradecraft claim and an environment claim, split into one lesson per channel." P2's observation arguably carries both. Trials 1 and 4 split it into a companion `tradecraft/container-argv-obfuscation.md` (+1 new file). Trials 2 and 3 did not. So the split policy fires ~50% of the time on this borderline observation. Worth a focused look in a follow-up, but not underfolding.
- **P3 slug variance — deeper look.** All 4 trials authored P3 as a new file under a different slug:

  | Trial | Slug | Techniques | Relevance criteria |
  |---|---|---|---|
  | 1 | `ssh-banner-preflight` | T1592.002, T1110.003 | "actor runs ssh-keyscan or bare SSH banner fetch against a target host before staging a spray or intrusion" |
  | 2 | `ssh-prerecon-banner-fetch` | T1592.002, T1110.003 | "actor fingerprints the SSH daemon via banner fetch or keyscan before staging a spray from the same source IP" |
  | 3 | `ssh-keyscan-banner-probe` | T1046 | "actor performs SSH banner fingerprinting or service enumeration against a target host before staging an attack" |
  | 4 | `ssh-keyscan-pre-recon` | T1592.002, T1110.003 | "actor runs ssh-keyscan or a banner-fetch probe against a bastion or SSH host before staging a spray" |

  The bodies are near-identical ("ssh-keyscan / banner fetch fires Wazuh rule 5701 before any authentication"). Even the MITRE tag is unstable — trial 3 went with T1046 (Network Service Discovery) while the others used T1592.002 + T1110.003. **Across-batch underfold risk.** A later batch with the same teaching would Glob the channel and read each `relevance_criteria` before deciding; the four wordings are similar enough that the agent should fold rather than spawn a 5th sibling. So the *behavioral* risk is probably low, but the *retrieval* surface is fragmented: anything that joins lessons by slug or by MITRE tag (downstream metrics, cross-references, future lookup CLIs) sees four "different" lessons that teach the same thing. Worth an explicit slug-stability convention or a normalization pass.

- **Distractor seed integrity.** `dev-container-label-cover` was read but never touched in any of 4 trials. The agent did not get pulled into a false-positive fold by lexical surface overlap (container/dev/cover words in P2's story).

## Schema concern: tradecraft vs environment is underspecified

A separate issue surfaced by the runs (not part of the original underfold question, but worth recording while it's fresh).

The prompt's channel boundary:

- **tradecraft** = "load-bearing point is about *story shape*: what the actor attempted, blended into, or framed as." Keyed by MITRE technique IDs.
- **environment** = "load-bearing point is about *what the deployment actually produces*: audit artifacts, schedule windows, ambient noise, telemetry shapes." Keyed by `subject` slug.

In practice, most failure observations describe an interaction: actor did X, the deployment surfaced Y. Both halves are load-bearing. The channel choice is a classification call, not a derivation. Examples from this experiment:

- **P1** ("no stagger trips rule 5712"). Filed as **tradecraft** by every trial. But the underlying claim — "rule 5712 fires at 10 fails / 120s on a single source-IP" — is an *environment* fact about the detector. The seed itself is a tradecraft file built around the same fact. Either filing is defensible.
- **P2** ("argv hidden inside container audit, recovered host-side"). Trials 1 + 4 split it cross-channel into env (`docker-exec-args-not-in-audit`) AND tradecraft (`container-argv-obfuscation`). Trials 2 + 3 filed it env-only. The "split when both signals are present" instruction reads as optional, and the two halves of P2 are not cleanly separable into "what the actor did" vs "what the deployment produces."
- **P3** ("ssh-keyscan triggers rule 5701"). Filed as **tradecraft** by every trial. Same dual nature as P1 — the failure is "actor did banner-fetch, deployment surfaced rule 5701" and either channel could legitimately host the resulting lesson.

This matters because **fold-across-channels is forbidden by the workflow** (step 2: "Folding only applies within a channel"). If batch 1 files a lesson under tradecraft and batch 2 files the same teaching under environment, both lessons live forever in parallel — the agent can't fold across the channel divide. Misclassification at first authoring is durable.

Two related symptoms point at the same root cause:

1. The channel-split rule (rule 4 in the workflow: "If an observation carries both a tradecraft claim and an environment claim, split it into one lesson per channel") fires inconsistently — 50% on P2 here. The instruction asks the agent to detect when *both* are present, but for many real observations both are *always* present and the choice is whether to treat the secondary signal as load-bearing enough to warrant a sibling file.
2. The seeded examples themselves don't make the boundary obvious. The seed `credential-spray-stagger` (filed under tradecraft) and the seed `docker-exec-args-not-in-audit` (filed under environment) both teach failures that span the boundary.

Possible follow-ups (not yet scheduled — needs design work first):

- **Re-examine the schema premise.** Maybe the env/tradecraft split is the wrong axis. Candidates: a single channel keyed by `subject` (the env-style key) with optional `techniques` annotation; or a different split (e.g., `pattern` vs `world-fact`, with explicit folding allowed across).
- **Sharpen the existing split.** If the two-channel structure stays, the prompt needs unambiguous classification rules (decision tree, worked examples for each side of the boundary), and the cross-channel split rule needs a clearer trigger ("always split if X and Y" rather than "split when both are present").
- **Consider lifting the within-channel fold restriction.** If misclassification is durable and undetectable post-hoc, allowing the agent to fold across channels (with the new lesson choosing one home) might be cheaper than getting the boundary perfect at authoring time.

The right next step is design-side, not another stress test. Stress-testing a schema you suspect is miscarved doesn't tell you anything new.

## Implications for prompt iteration

The "default to fold" stance in the current prompt holds up against a fixture that was deliberately engineered to make underfolding tempting. **No prompt change for underfolding is warranted on this evidence.** Two adjacent questions are still open and worth follow-ups:

1. **Slug stability for new lessons.** A normalization rule or canonical-form check might cut corpus fragmentation across batches. Probably an author-side concern only if real-world batches show this pattern; not a prompt issue per se.
2. **Cross-channel split consistency.** P2's 50% split rate suggests the "split into one lesson per channel" instruction is being read as optional rather than mandatory on ambiguous observations. If the desired behavior is "always split when both signals are present," the prompt may need to be sharper.

Neither blocks the underfold conclusion.

## Cost / time

- Wall time per trial: ~285s (sonnet author + 4 sequential Haiku gates).
- Forward-check dominates: ~38% of wall time. See plan.md Exp 3 (parallel forward-check via Agent tool) for the follow-up arm motivated by this finding.

## Caveats

- N=4 is small. Confidence in P1/P2/P3 outcomes is high because all four trials agree. Confidence in P4's gray-zone read is moderate — the 3/4 fold rate could shift on a larger sample, though "P4 never landed as a new file" is the more durable claim.
- Single fixture, single batch shape. The fixture is by construction friendly to folding (clear seed/probe alignment). Real-world batches with noisier observations might tell a different story. If underfolding shows up in production-corpus authoring, revisit with a noisier fixture.
- Each trial's worktree is freshly seeded; folding-across-batches behavior is not exercised here.
