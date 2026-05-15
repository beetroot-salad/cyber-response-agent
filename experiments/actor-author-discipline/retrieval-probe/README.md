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
  transcripts/trial-{1..5}.md           # actor outputs (retrieval scan + gaps + channel notes + Section 0)
```
