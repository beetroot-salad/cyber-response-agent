# Actor retrieval probe — N=5

Empirical observation of how the actor consults the lessons-actor corpus when doing adversarial threat modeling. Subexperiment of `actor-author-discipline/`. Motivated by a schema concern: the env/tradecraft channel split classifies many lessons arbitrarily because their content carries both halves (a deployment fact + a story pattern).

## Method

- **Corpus**: 12 lessons assembled from `fixtures/lessons-actor/` + underfold trial outputs + 3 deliberately-ambiguous lessons (the "Falco catches X" type) — 7 tradecraft, 5 environment. See `lessons-actor/`.
- **5 input bundles** (`bundles/bundle-{1..5}.md`) covering different alert families and archetypes:
  1. SSH 5712 brute force, internal
  2. Falco container shell outside dev-allowlist, external
  3. FIM 550 PAM edit, internal
  4. SSH 5710 invalid user, external
  5. Sudo 5402 systemctl restart docker, internal
- **Instructions** (`instructions.md`): the actor's normal prompt + retrieval instrumentation (narrate the search, emit a verdict-table covering every lesson, name retrieval gaps, name channel-fit ambiguity).
- **Runtime**: 5 parallel general-purpose subagents, each given the instructions + one bundle. Transcripts in `transcripts/`.

## Findings

### 1. Three-stage retrieval pattern — confirmed (5/5)

Every trial: Glob the corpus → emit a verdict for every lesson (read | skim | skip) → deep-read the read tier. Read counts: 5, 7, 3, 4, 7. Robust across alert family and archetype.

The corpus partitions cleanly: SSH/auth cluster vs. container/docker cluster. SSH-alert trials skip the container cluster entirely; container-alert trials skip the SSH cluster entirely. Cross-cluster pulls happen only when the story bridges (T3's bastion + PAM story pulled `credential-spray-stagger` for context on the SSH leg).

### 2. Recurring retrieval gaps

Out of ~12 distinct gaps named across 5 trials, four recur strongly:

| Gap | Trials | Comment |
|---|---|---|
| `alert_rule_ids` / `signal_surface` / `service` tag | T1, T2, T3, T4 | Cleanest filter; would let the actor jump to relevant lessons in one Glob |
| `actor_type` as soft signal, not hard filter | T1, T2, T5 | `[external]`-only tags hide lessons internal actors still need (rule thresholds, source-IP identity, asset-graph linking) |
| `defender_lead_tags` / lead-coverage hint | T1, T2, T5 | Match against the actual lead set, not the technique |
| `defeats_lesson` / `enabled_by_lesson` cross-link | T2, T4, T5 | Env facts and tradecraft patterns are paired; explicit links let the actor pivot without re-Globbing |

Single-trial ideas (less load-bearing): `kill_chain_stage`/tactic on tradecraft (T3, T4), `host_class` (T3), per-lesson self-rating (T1), `controls_mentioned` rule IDs on env (T3, T5), `status: live/stale/refuted` for tradecraft (T5), technique-adjacency map (T5), richer `actor_type` (service-acct vs interactive — T5).

`control_type` was named once (T5) but is largely re-encoded by `alert_rule_ids` + `defender_lead_tags` + the NL description. Not its own dimension.

### 3. Channel-fit — the schema is the dominant complaint

Every trial flagged at least one lesson as miscarved. Strong patterns:

- **`credential-spray-stagger` contains 2 env facts** (rule 5712 threshold, breach enricher) — flagged in T1 and T4. Both proposed splitting into a tradecraft pattern + two `subject:`-keyed env lessons.
- **`container-argv-obfuscation` is a near-duplicate of `docker-exec-args-not-in-audit`** — env states the property, tradecraft restates it as a failed pattern. Flagged T1, T2.
- **`auditd-stdin-not-captured` should split** into env-fact (auditd config + tmux/script transcripts) + tradecraft-pattern (stdin-funnel) — T3.
- **`falco-bypass-via-runtime` should be env** (rule-shape fact, not a tradecraft failure) — T2.
- **`dev-container-label-cover` should be env** (orchestrator-identity-pairing is a deployment property) — T5.
- **`ssh-keyscan-pre-recon` straddles** (half tradecraft "use different IP", half env "asset-graph stitching") — T1, T3.
- **`actor_type: [external]` on env lessons is wrong** (env facts are actor-agnostic) — T1, T3, T5.

Pattern beneath all of these: **almost every lesson has an env-fact half and a tradecraft-pattern half**, and the channel forces a primary pick that loses the other. The channel boundary isn't underspecified — it's wrong-axis.

## Implications for schema v2

1. **One unified corpus, multi-key indexed.** Each lesson carries whichever of `techniques`, `subject`, `alert_rule_ids`, `defender_lead_tags` apply. Retrieval picks the sharpest filter for the situation.
2. **Mutability per-lesson, not per-channel.** A `mutable: true|false` flag; the env-only `status: live/stale/superseded` machinery generalizes.
3. **`actor_type` becomes a soft scoring signal**, not a filter — annotation, not exclusion.
4. **Explicit cross-links.** `see_also` (or directed `enables` / `defeats`) connecting paired env facts and tradecraft patterns. Author no longer has to choose which channel "owns" a teaching with both halves.
5. **Author's job changes from classify to decompose.** When a teaching has both halves (most do), author both files and link them. Within-channel-fold becomes within-corpus-fold; the boundary stops being load-bearing.

What stays untouched: the three-stage retrieval pattern (Glob → verdict pass → deep-read), the `relevance_criteria` one-liner, the body shape.

## Caveats

- N=5 single-shot trials with explicit retrieval-instrumentation prompts. The channel-fit complaints are *prompted* (the `## Channel-fit notes` section asked for them). See "Clean-prompt follow-up" below for the validation that ruled out prompt-induced bias.
- One corpus, ~12 lessons. Bigger corpora may surface different bottlenecks (e.g., the verdict-table-covering-all-lessons step doesn't scale past a few dozen).

## Clean-prompt follow-up (n=2)

To check whether the channel-fit complaints were a prompt artifact, the production-style actor prompt was re-run on bundles 2 and 5 with all retrieval instrumentation removed (no `## Retrieval scan` table required, no `## Retrieval gaps` required, no `## Channel-fit notes` required). The agent was given an *optional* free-form `## Notes on the corpus` section "only if specific frictions came up while you were trying to do the actor's job." Transcripts: `transcripts/clean-{2,5}.md`.

Both clean trials volunteered the section and surfaced channel-fit complaints organically:

| Channel-fit finding | Instrumented trials | Clean trials |
|---|---|---|
| `actor_type: [external]` is wrong-axis on env lessons (env facts are actor-agnostic) | T1, T3, T5 | clean-5 (explicitly: "would have hidden it from a stricter retrieval pass") |
| `container-argv-obfuscation` ≈ `docker-exec-args-not-in-audit` (near-duplicate) | T1, T2 | clean-2 ("could be merged, with the tradecraft pointer being a one-liner") |
| `dev-container-label-cover` belongs in env (orchestrator-identity-pairing is a deployment fact) | T5 | clean-2 ("reads as a tradecraft failure but it's effectively environmental") |
| `auditd-stdin-not-captured` should split (tmux/script transcript exception "buried as a parenthetical") | T3 | clean-5 ("worth its own environment file") |

**Conclusion: channel-fit issues are not prompt-induced.** They reproduce when the agent is just told "feel free to mention frictions if any came up while doing your job, otherwise skip the section." The schema concern is validated on independent runs.

The clean trials also surfaced two corpus *gaps* the instrumented runs missed (plausibly because open-ended framing surfaces what the agent *wished* existed rather than what was wrong with what existed):
- No lesson on `pname=runc` vs `pname=dockerd-exec` spawn-path distinction (clean-2)
- No lesson on tag-without-digest as an actor-exploitable affordance (clean-5; `no-image-hash-emission` is adjacent but framed defender-side)
- No lesson on network-egress baseline (clean-2)

These are content gaps for the next defender batch, not schema issues.

## Layout

```
retrieval-probe/
  README.md                             # this file
  instructions.md                       # the instrumented actor prompt
  bundles/bundle-{1..5}.md              # alert + archetype + leads + menu
  lessons-actor/{tradecraft,environment}/*.md   # the corpus the actor retrieved from
  transcripts/trial-{1..5}.md           # instrumented actor outputs (v1 schema)
  transcripts/clean-{2,5}.md            # un-instrumented validation (v1 schema)
  transcripts/clean-1-v2.md             # un-instrumented validation on v2 corpus (#4b Path A)
```

## v2 validation re-run (#4b Path A, 2026-05-15)

**N=5 clean trials**, one per bundle, against the v2-shape corpus produced by underfold #4a (8 lessons from `underfold/runs-out/trial-3/lessons-actor-final/` — 3 v2-migrated seeds + 5 author-created including `wazuh-rule-5712-threshold`, `breach-corpus-enricher`, `wazuh-rule-5701-banner-probe`, plus the decomposed pattern/env-fact pair for argv obfuscation). Transcripts: `transcripts/clean-{1..5}-v2.md`. Bundles 2-5 carried a light `Retrieval debrief` ask: name each frontmatter key actively reached for.

### Retrieval-axis usage across N=5

| Frontmatter key | Trials that explicitly queried it | Verdict |
|---|---|---|
| `alert_rule_ids` | 5/5 | Universally used. Most natural first query. |
| `defender_lead_tags` | 5/5 | **Surprise** — predicted low use, observed universal use. Agents query it to find which leads have blind spots and which evasions they break. Earning its keep. |
| `techniques` | 4/5 | Used when story is built around a TTP; skipped only when no menu TTP matched the corpus. |
| `subject` | 1/5 | Used by the bundle-2 (Falco container) trial only — explicitly reached for `orchestrator-identity-pairing-required`. Not queried by other 4 trials. |
| `applies_to` | 1/5 | Used by bundle-1 trial to traverse pattern→env-fact dependency. |
| `actor_type` | 1/5 named | Bundle-5 explicitly says "noted but not gated on" — the soft-signal discipline holds. |

### What this says about the field count

The full v2 frontmatter has 10 fields; only 2-4 are load-bearing for the retriever per trial:

- **Always**: `relevance_criteria` (scan) + `alert_rule_ids` + `defender_lead_tags`. The three load-bearing retrieval keys.
- **Often**: `techniques` (4/5). Skipped only when no menu TTP matches.
- **Rarely**: `subject` (1/5), `applies_to` (1/5). These earn their keep in specific scenarios (subject lookup when retriever has a deployment-property query; applies_to when traversing cross-links) but aren't universal.
- **Never queried (correctly)**: `actor_type`, `name`, `mutable`, `status`, `recorded_at`, `source_observation_ids`. These are either soft annotations, bookkeeping, or fold-keys that the retriever doesn't need.

The user prediction ("2-3 maybe 4 fields are justified in retrieval") matches what was observed. The retriever uses 2-3 axes universally and 1-2 more situationally. The author-side fields (subject as fold-key, mutable/status for staleness) earn their keep separately from retrieval.

### Filename-vs-subject friction (the bundle-1 finding)

**Did not reproduce in 4/4 follow-up trials.** Bundle-2 explicitly queried `subject: orchestrator-identity-pairing-required` and found the lesson cleanly; no friction reported. Bundles 3, 4, 5 didn't need that lesson (different alert families).

Reconsidering: the bundle-1 friction was bundle-specific — the SSH-context retriever reached for a container-context lesson and found the lead-tag keying jarring because it was thinking in SSH-telemetry terms. In bundle-2 (container-context), the same lesson was reached for via subject naturally. So the friction is: **lessons get reached for via different axes depending on the bundle's alert family**, and when the wrong axis is queried first, the keying mismatch surfaces as friction.

This is consistent with "different keys = different retrieval axes" (your Point 2). The fix isn't renaming or omitting; it's letting the retriever query multiple axes in order. The retrieval probe shows the agents already do this implicitly (5/5 use 2-3 axes per trial).

### Recurring v1 frictions — confirmed gone

| v1 recurring complaint (N=5+2 trials) | Recurs on v2 (N=5)? |
|---|---|
| `alert_rule_ids` filter missing | No — keys exist, queried 5/5 |
| `actor_type` hard-filter hides lessons | No — soft signal, bundle-5 explicitly confirms "not gated on" |
| `defeats_lesson` / `enabled_by_lesson` cross-link missing | No — `applies_to` provides this; bundle-1 used it |
| Channel-fit miscarves (4 specific) | No — channels removed |

### Content gaps surfaced (not schema issues)

- Bundle-3 (PAM/FIM): entire PAM/FIM/insider-config-modification cluster missing. Underfold corpus came from SSH-focused author runs.
- Bundle-5 (sudo/docker-restart): no 5402-keyed lessons; no internal-sudo precedent.
- Bundle-1 (SSH 5712 internal): 5712 threshold variant doc gap (lesson says ~30/90s, bundle fired at 14/110s); no CI-runner cover-pattern lesson.

These reflect corpus content scope, not schema. Authoring against more diverse defender batches would fill them.

### Conclusions

1. **Schema v2 cleared all four v1 recurring frictions** with no new structural frictions observed at N=5. The filename-vs-subject concern from bundle-1 didn't reproduce.
2. **3 retrieval axes are load-bearing universally** (`relevance_criteria` + `alert_rule_ids` + `defender_lead_tags`); 1-2 more are situational. `subject` is mostly an author-side fold-key, not a retrieval surface.
3. **`defender_lead_tags` is the surprise winner** — predicted to be redundant with `alert_rule_ids`; observed to be universally queried because it answers a distinct question (what does the defender's lead set see vs. what would the rule fire on).
4. **Two surgical changes applied as v2.1** (2026-05-15, evidence from this probe):
   - Dropped `name` from frontmatter (duplicates filename; zero observed value).
   - Dropped `actor_type` from frontmatter (0/5 queried; soft-signal discipline already held).
   - Added the axis cheat-sheet to `defender/learning/actor.md` retrieval section (5 lines naming which key answers which question).

Follow-up candidates still on the watch list, **not** acting on yet:
- Subject-naming convergence across batches (the breach-corpus-enricher 3-way split from underfold #4a).
- Subject=filename consolidation for env-facts (would solve the bundle-1-style first-axis-mismatch friction more thoroughly but needs an authoring stress test).
- Staleness-triad consolidation (needs trials with stale lessons).

#4 (validation step in the schema-v2 sequence) is closed positive.

| v1 recurring complaint | Recurs on v2? |
|---|---|
| `alert_rule_ids` filter missing | No — keys exist, agent used them implicitly |
| `actor_type` hard-filter hides lessons | No — soft signal, agent ignored it for retrieval |
| `defeats_lesson` / `enabled_by_lesson` cross-link missing | No — `applies_to` provides this |
| Channel-fit miscarves (4 specific) | No — channels removed |

All four v1-recurring frictions are gone. The schema rewrite addressed them at the structural level rather than papering over them with prompt edits.

One new v2-specific friction surfaced: **filename ≠ subject naming drift**. `dev-container-label-cover.md` carries `subject: orchestrator-identity-pairing-required`; the actor reached for the file by the body's identity-pairing language and found the lead-tag keying counterintuitive. The v2 spec explicitly allows `name` and `subject` to drift; this trial confirms the cost: retrieval has a small friction step when the filename-concept and subject-concept aren't the same thing. Worth a slug-stability pass if it recurs.

Retrieval pattern: the three-stage shape (Glob → verdict-pass → deep-read) collapsed into one stage on this 8-lesson corpus — the agent enumerated and read everything rather than emitting a verdict pass. This is corpus-size-dependent (a 50+ lesson corpus would force the verdict step); pattern is intact, not regressed.

Two content gaps surfaced (5712 threshold variant; deploy-account cover pattern for internal actors) — corpus-content concerns from the synthetic underfold corpus, not schema concerns.

**Conclusion: schema v2 cleared the friction it was designed to clear, did not regress the retrieval shape, and introduced one minor naming-discipline issue.** #4 (validation step in the schema-v2 sequence) is closed positive.
