# Lessons-actor schema v2 — design + v2.1 / v2.2 deltas

**Status: v2 implemented; v2.1 simplification applied 2026-05-15; v2.2 env-fact split applied 2026-06-15.** v2 (flat corpus, multi-key index) is live under `defender/lessons-actor/*.md` and is what `defender/learning/author_actor.md` and `defender/learning/actor.md` target. The v2.1 delta drops two fields the empirical N=5 retrieval probe showed had no retrieval value. When this doc and the code disagree, the code wins.

## v2.2 delta — env-facts moved to the shared environment corpus (issue #298)

The original v2 schema carried **two** lesson shapes — env-fact and pattern — and `author_actor.md` decomposed each observation into both halves. v2.2 removes the env-fact shape from this corpus: `defender/lessons-actor/` is now **pattern/tradecraft-only**. Standing deployment facts are authored exclusively into the shared `defender/lessons-environment/` corpus, which both actors retrieve and which the loop now feeds from both directions — the adversarial judge emits positive-polarity env facts from grounded mispredictions (`environment_observations`), draining via `author_actor_env.py` into the same corpus the benign FP direction writes. The 14 pre-existing env-fact lessons were migrated out of `lessons-actor/` in the same change.

Consequences for this doc's sections below: the env-fact frontmatter (`subject` required, `mutable: true`) and the decomposition/cross-shape-fold rules describe the *historical* v2 design and are retained as design context only. In the live corpus, `subject` is rare (only a pattern bound to one referent), `mutable` is normally `false`, and `applies_to` references env-fact subjects that now live in `lessons-environment/` (a human cross-reference, not a fold target).

## v2.1 delta — dropped fields

Empirical motivation: the N=5 retrieval probe (`experiments/actor-author-discipline/retrieval-probe/`, transcripts `clean-{1..5}-v2.md`) measured which frontmatter keys retrievers actually queried. Results: `alert_rule_ids` 5/5, `defender_lead_tags` 5/5, `techniques` 4/5, `subject` 1/5, `applies_to` 1/5, `actor_type` 0/5 (the soft-signal discipline held — bundle-5 explicitly: "noted but not gated on").

Two fields had no observed retrieval value AND no observed authoring value:

- **`name`** — duplicated the filename. Spec already said "filename matches name." Dropped.
- **`actor_type`** — explicitly soft-signal in v2 spec, never gated on by index or retriever. Dropped from frontmatter; if a lesson's framing is actor-specific, mention it in the body.

Kept fields whose retrieval rate is low but whose role is load-bearing elsewhere:
- `subject` (1/5 retrieval, but the author-side fold equivalence key)
- `applies_to` (1/5 retrieval, but the structural cross-link surface enabling decomposition)
- `mutable` / `status` / `superseded_by` (staleness machinery; not exercised in this probe but load-bearing when world-facts change)

Also: the `--show-actor-type` flag on `lessons_actor_index.py` is removed.

Migration: existing v2 lessons drop the two fields in-place (no rename, no semantic change).

## Why v2

v1 splits lessons into `tradecraft/*.md` (failure-only patterns keyed by MITRE techniques) and `environment/*.md` (deployment facts keyed by `subject`). The split is enforced as a hard channel constraint: folding only works within a channel, and the channel is the equivalence boundary.

The retrieval probe at `experiments/actor-author-discipline/retrieval-probe/` (N=5 instrumented + N=2 clean trials, transcripts in-tree) found that the channel boundary is wrong-axis. Almost every lesson has a deployment-fact half *and* a pattern half; the channel forces a primary pick that loses the other. Specific symptoms reproducing across diverse alerts and across both instrumented and un-instrumented trials:

- `credential-spray-stagger` (filed tradecraft) embeds two env facts (`wazuh-rule-5712-threshold`, `auth-pipeline-breach-enricher`) inside its body.
- `container-argv-obfuscation` (tradecraft) is a near-duplicate of `docker-exec-args-not-in-audit` (environment) — env states the property, tradecraft restates it as a failed pattern.
- `dev-container-label-cover` (tradecraft) is a deployment fact about how this environment scores legitimacy (orchestrator-identity-pairing required).
- `auditd-stdin-not-captured` (environment) carries a tradecraft-shaped prescription (stdin-funnel pattern) that the actor would prefer to retrieve separately.
- `actor_type: [external]` filters on env lessons hide load-bearing facts from internal-actor stories that need them — env facts are actor-agnostic by nature.

Same probe also confirmed the actor's natural retrieval shape: **enumerate (Glob) → verdict-pass every candidate (read | skim | skip) → deep-read the read tier**. v2 must preserve this shape.

## Goals

- **One unified corpus.** No channel split.
- **Multi-key indexing.** Each lesson carries whichever of `techniques`, `subject`, `alert_rule_ids`, `defender_lead_tags` apply; retrieval picks the sharpest filter for the situation.
- **Subject as the equivalence key.** Two lessons with the same subject must be reconciled (folded or one supersedes the other).
- **`actor_type` becomes a soft annotation**, not a filter.
- **Mutability is per-lesson**, not per-channel. The env-only `status: live/stale/superseded_by` machinery generalizes.
- **Explicit cross-links.** A pattern lesson and a deployment-fact lesson that teach the same situation get linked, not folded.
- **Author's job changes from classify to decompose.** When a teaching has both halves (most do), author both files and link them.

Non-goals:
- Don't change the body shape, the `relevance_criteria` one-liner, or the retrieval workflow on the actor side beyond accepting new index filters.
- Don't introduce a control-type taxonomy; `alert_rule_ids` + `defender_lead_tags` + the NL description carry that signal already (validated in the retrieval probe — none of the 5 trials independently asked for it).
- Don't introduce a `kill_chain_stage` / tactic field; recurrence was weak (2/5 trials) and `techniques` already implies it.

## Lesson shape

```yaml
---
# Identity
name: {kebab-case slug}                          # filename-friendly handle, may drift batch-to-batch
subject: {kebab-case-deployment-referent}        # OPTIONAL; required for deployment-fact lessons. The equivalence key — two lessons with the same subject must be reconciled.

# Retrieval keys (all optional, all queryable, AND across keys, OR within a key)
techniques: [T1110.003, T1078]                   # MITRE; primary key for pattern-shaped lessons
alert_rule_ids: [5712]                           # SIEM rule IDs the lesson bites or describes
defender_lead_tags: [wazuh.auth-events-by-srcip] # lead families this lesson is relevant to

# Soft signals (annotation, not filter)
actor_type: [external, internal]                 # who this is most directly framed for; the index never gates on this
applies_to: [{subject-of-other-lesson}]          # cross-links to deployment-fact lessons this one exploits or is bounded by

# Mutability
mutable: true|false                              # true = world-fact that can change; false = append-only pattern
status: live|stale                               # only meaningful when mutable=true; default live
superseded_by: {name-of-newer-lesson}            # only when status=stale and a replacement was authored

# Provenance
recorded_at: {batch-id}
source_observation_ids: [{obs-id}, ...]

relevance_criteria: one-line predicate the actor scans during enumeration
---

{freeform body — 1–3 short paragraphs, attacker-framed prose for the future actor who will read this without seeing the source case}
```

### Field semantics

**`name`** — filename-friendly handle. Allowed to drift between batches (the v1 slug-variance problem is bounded by `subject`, not `name`).

**`subject`** — see §Subject. Required for any lesson whose load-bearing claim is "in this deployment, X has property Y." Optional for pattern-only lessons (e.g. "always stagger the spray," `subject` omitted).

**`techniques`** — MITRE T-IDs. Primary key for pattern-shaped retrieval (the actor's "I'm building a story around T1110.003" path). Optional for pure deployment-fact lessons.

**`alert_rule_ids`** — SIEM rule IDs. Two senses, both legitimate: "this lesson applies when this rule fires" and "this lesson tells you what fires this rule." The retrieval probe flagged this as the highest-leverage filter (4/5 trials). Most deployment-fact lessons should have it.

**`defender_lead_tags`** — `{system}.{kebab-name}` matching the lead-template families under `defender/skills/gather/queries/`. Lets the actor match lessons against the actual lead set the defender ran. Optional but high-value when the lesson is bound to a specific telemetry surface.

**`actor_type`** — soft annotation. The retrieval CLI **must not** gate on this. Multiple trials independently flagged that filtering by `actor_type` hides load-bearing lessons (e.g. `nagios-source-ip-mapping` tagged `[external]` was decisive in trial 4 internal-archetype runs). Use as a hint to the reader, not a filter.

**`applies_to`** — directed cross-link from this lesson to the deployment-fact lesson(s) it depends on. Used by the author when decomposing an observation into env-fact + pattern halves; used by humans during corpus review; not used by the actor's retrieval (the actor finds linked lessons via separate enumeration). Soft dependency: when an `applies_to` target goes stale, dependent lessons surface for review but are not auto-stale.

**`mutable`** — `true` for deployment facts, `false` for append-only patterns. Determines whether `status` and `superseded_by` are meaningful.

**`status`** — `live` (default) or `stale`. Only meaningful when `mutable: true`.

**`superseded_by`** — name of the replacement lesson on a stale entry. Omitted when no replacement was authored (the world-fact changed but the new state isn't clear enough to commit yet — author drops to "stale, awaiting replacement").

**`source_observation_ids`** — same role as v1. The same observation_id may appear in multiple lessons when an observation was decomposed.

## Subject

`subject` is the smallest independently-mutable deployment referent the lesson is about. It is the equivalence key — two lessons with the same subject are talking about the same deployment-state-change unit and must be reconciled (folded, or one supersedes the other).

Three properties make subject load-bearing:

1. **Anchored to a deployment referent**, not a generic concept. `subject: falco-shell-in-container-rule` ✓; `subject: container-detection` ✗ (too generic, would force-fold heterogeneous facts).
2. **Granular at the unit-of-config-change.** If a single config diff invalidates the lesson — the Falco shell rule's allowlist shrinks, the breach-corpus enricher gets disabled, the Nagios IP gets reassigned — that's one subject. If invalidating the lesson would require multiple unrelated changes, the subject is too coarse.
3. **Survives wording variance.** The trial-1 slug-variance problem (4 different `name`s for the same teaching) is what subject prevents. The slug can drift; subject can't, because folding is keyed on it.

### When subject is required vs optional

- **Required** when the lesson asserts a property of a specific deployment referent ("auditd does not capture stdin"; "Falco's shell-in-container rule allowlists `^cra-dev-.*$`"; "172.22.0.10 is the Nagios monitoring station"). Without a subject, the equivalence-key role can't fire and the lesson will accrete duplicates.
- **Optional** when the lesson is purely behavioral advice with no specific deployment anchor ("always stagger the spray," "use a different IP for keyscan than for the spray"). Pattern-only lessons are identified by `techniques` + `alert_rule_ids`.

### Granularity heuristic

Imagine a config diff that changes the deployment. Each set of changes that you'd want to invalidate as a unit corresponds to one subject. If changing the Falco shell-in-container rule's allowlist would invalidate the lesson, that's the subject's scope. If changing Falco's *suricata-bridge* rule would *not* invalidate this lesson, those are separate subjects.

Failure modes the granularity rule guards against:
- Too coarse (`subject: falco`) → over-folds. Heterogeneous facts get force-merged; staleness machinery becomes useless.
- Too narrow (`subject: falco-shell-in-container-rule-v0.36.2`) → under-folds. Versions change without semantics changing; folding never fires.
- Pattern-as-subject (`subject: stagger-the-spray`) → loses the deployment-anchor property. Pattern lessons identify by `techniques` + `alert_rule_ids`, not subject.

## Folding & decomposition

The author's workflow has two new disciplines on top of v1's "fold within channel."

### Decomposition (new)

When an observation carries both a deployment-fact half and a pattern half — which is most observations — author **two lessons** and link them:

- The **deployment-fact lesson** has a `subject:` naming the referent and a `mutable: true` body asserting the property.
- The **pattern lesson** has `techniques:` + `applies_to: [<env-subject>]` and a `mutable: false` body describing the cover/bypass shape that exploits or is bounded by the deployment fact.

The same `observation_id` appears in both files' `source_observation_ids`. The cross-link is one-way (pattern → fact) by default; reverse traversal happens via grep on `applies_to`.

Example. An observation reports "spraying credentials at 14 attempts in 110s tripped Wazuh rule 5712, even though every credential was high-quality." Decompose into:

- `subject: wazuh-rule-5712-threshold` (env-fact, mutable=true, alert_rule_ids: [5712]) — body: "Wazuh rule 5712 fires on 10 failed authentications inside a 120-second window per source-IP/destination pair, regardless of credential quality."
- `techniques: [T1110.003]`, `applies_to: [wazuh-rule-5712-threshold]` (pattern, mutable=false) — body: "Credential spray must throttle below the rule-5712 threshold; high credential quality does not buy speed."

Both files cite the same observation_id.

### Folding (modified from v1)

1. **Same subject ⇒ reconcile.** Two lessons with the same `subject` must be folded (rewrite both bodies into one, append observation_ids, broaden `relevance_criteria` if scope grew) or one supersedes the other (`status: stale, superseded_by: …`). This is now corpus-wide, not channel-scoped.
2. **No subject overlap, but overlapping `techniques` + body content ⇒ candidate fold.** Same as v1's tradecraft-channel fold, applied corpus-wide.
3. **Pattern lesson and env-fact lesson on the same situation ⇒ cross-link, do not fold.** They're complementary. The pattern's `applies_to` names the fact's subject.

The author's first action on a new observation remains: enumerate the corpus, scan `relevance_criteria`, read the bodies of plausible candidates. The decision tree is now `decompose → fold-or-supersede same-subject hits → cross-link cross-shape pairs → write new files for the rest`.

### Forward-check (unchanged)

The `verify_forward_actor.py` Haiku gate still runs per written/rewritten lesson. The gate's prompt asks "would this lesson have made the actor avoid the failure?" — that semantics is unchanged by the schema rework.

## Mutability and staleness

`mutable: true` lessons can go `status: stale` when contradicted. `mutable: false` lessons (append-only patterns) cannot — if a pattern is refuted, the corresponding deployment-fact lesson it `applies_to` should go stale, and the pattern lesson surfaces for review via the dangling `applies_to`.

Stale-with-replacement (`superseded_by:`) is preferred when the world-fact has changed and the new state is clear. Stale-only (`status: stale` without `superseded_by`) is allowed when contradicted but the new state isn't yet clear enough to author a replacement; the next batch will revisit.

Deletion of stale lessons follows v1's rule: only stale, only when authoring this batch surfaces a same-subject collision with an older stale predecessor, only with the deletion noted in the commit message.

## Retrieval keys and composition

The index CLI (`defender/scripts/lessons_actor_index.py`) is extended:

- **Drops `--channel`** (no channels).
- **Accepts** any subset of `--techniques`, `--alert-rule-ids`, `--defender-lead-tags`, `--subject`. AND across keys, OR within a key. Unfiltered call returns the whole corpus.
- **Does not gate on `actor_type`.** The flag is removed from the CLI; a new `--show-actor-type` flag (off by default) surfaces it as a column in the output for context.
- **Output format unchanged:** one `<path>\t<relevance_criteria>` line per matching lesson. Stale lessons hidden by default; `--include-stale` surfaces them (author-only, never the runtime actor).

The actor's three-stage pattern (Glob/index → verdict-pass → deep-read) is preserved. The verdict-pass step now scans richer frontmatter, but the shape is the same.

## Migration

The current `defender/lessons-actor/` corpus on `actor-pending-queue` is essentially empty (one `_TEMPLATE.md` per channel). The probe corpus at `experiments/actor-author-discipline/retrieval-probe/lessons-actor/` is the closest thing to a real seed set; migration applies to it, not to production.

Concrete v2 rewrites for the 12 probe lessons:

| v1 file | v2 outcome |
|---|---|
| `tradecraft/credential-spray-stagger.md` | **Decompose into 3.** New env-fact `subject: wazuh-rule-5712-threshold` (with `alert_rule_ids: [5712]`); new env-fact `subject: auth-pipeline-breach-enricher`; thin pattern lesson `techniques: [T1110.003]`, `applies_to: [wazuh-rule-5712-threshold, auth-pipeline-breach-enricher]`. Same `observation_id` on all three. |
| `tradecraft/container-argv-obfuscation.md` | **Delete.** Near-duplicate of `docker-exec-args-not-in-audit`. Optionally re-author as a thin pattern lesson with `applies_to: [container-side-execve-omits-argv]` and a one-line body pointing at the env-fact, if the pattern framing is independently useful. |
| `tradecraft/dev-container-label-cover.md` | **Convert to env-fact.** `subject: orchestrator-identity-pairing-required`, `mutable: true`, `alert_rule_ids: [<falco shell rule>]` if applicable. |
| `tradecraft/falco-bypass-via-runtime.md` | **Convert to env-fact** or **merge into** `falco-shell-in-container`. The lesson is a rule-shape fact, not a pattern. |
| `tradecraft/credential-spray-monitoring-acct.md` | **Decompose into 2.** New env-fact `subject: per-source-ip-volume-baseline` (mutable=true). Thin pattern lesson `techniques: [T1110.003]`, `applies_to: [per-source-ip-volume-baseline, source-ip-172-22-0-10-identity]`. |
| `tradecraft/ssh-keyscan-pre-recon.md` | **Decompose into 2.** New env-fact `subject: wazuh-rule-5701-banner-fetch` (mutable=true) + an env-fact for the asset-graph cross-window stitching (`subject: asset-graph-cross-window-stitching`). Thin pattern lesson `techniques: [T1592.002]`, `applies_to: […]`. Strip `actor_type: [external]` to also include `internal`. |
| `environment/auditd-stdin-not-captured.md` | **Split into 2.** Keep as env-fact (auditd captures argv but not stdin; tmux/script transcripts under `/var/log/sessions/{user}/{ts}.cast` tailed by Wazuh rule 100403). Author a pattern lesson `techniques: [T1027]`, `applies_to: [auditd-stdin-not-captured]` for the stdin-funnel pattern. |
| `environment/docker-exec-loginuid-auditing.md` | **Keep**, rename `subject: docker-exec-loginuid-propagation`, broaden `actor_type` to include `internal` if not already (it already is). |
| `environment/docker-exec-args-not-in-audit.md` | **Keep**, rename `subject: container-side-execve-omits-argv`. |
| `environment/nagios-source-ip-mapping.md` | **Keep**, `subject: source-ip-172-22-0-10-identity`, broaden `actor_type` to include `internal`. |
| `environment/no-image-hash-emission.md` | **Keep**, broaden `actor_type` to include `internal`, add `alert_rule_ids: []` (no specific rule; this is an audit omission). Optionally author a sibling pattern lesson `subject:` not set, `techniques: [T1525]`, `applies_to: [container-image-hash-audit-omission]` for the local-tag swap pattern (corpus gap surfaced in clean trial 5). |
| `environment/falco-shell-in-container.md` | **Keep**, `subject: falco-shell-in-container-rule`, add `alert_rule_ids: [<falco rule id>]`. Possibly merge `falco-bypass-via-runtime` into it. |

Net delta: ~12 lessons → ~16-18 lessons (more files, smaller per-file scope, with cross-links). Decomposition isn't a corpus-size optimization — it's a retrieval-key alignment.

The migration is manual on this corpus because the corpus is small. A future, larger corpus migration would benefit from a one-shot rewrite tool, but that's not a v2 prerequisite.

## What changes outside the schema

These are listed for completeness but are step-by-step work, not part of this spec:

- **`defender/learning/author_actor.md`**: rewrite Channels + Workflow sections to describe decomposition + corpus-wide folding. Drop the "split into one lesson per channel when both signals are present" rule (replaced with default decomposition). Drop directory-aware enumeration (one corpus, one Glob).
- **`defender/learning/actor.md`**: minimal change. Index CLI invocation drops `--channel`, may add `--alert-rule-ids` / `--defender-lead-tags` filters when relevant. Three-stage retrieval pattern unchanged.
- **`defender/scripts/lessons_actor_index.py`**: drop `--channel`, add multi-key filters, drop `actor_type` gating. Backwards-compat for v1 callers is unnecessary (the corpus migrates atomically; no outside consumers).
- **`defender/tests/`**: add a v2 schema validator test (frontmatter-required-keys, subject-equivalence-uniqueness for live lessons, `applies_to` resolves to a real subject in the corpus).

## Open questions

These are deferred — not blockers for the migration but worth resolving before the schema settles:

- **Dangling `applies_to`.** What happens when a pattern lesson references a `subject` that doesn't have a corresponding env-fact lesson yet? Options: (a) author a stub env-fact lesson with `status: stale`, awaiting content; (b) allow dangling references, surface them in a corpus health check; (c) forbid them, force the author to write the env-fact first. **Tentative answer: (b).** Dangling links are a useful signal for "this pattern depends on a fact we haven't characterized yet."
- **Directional cross-links.** `applies_to` is currently a flat list. Worth distinguishing `exploits` (pattern uses the fact as cover) from `bounded_by` (pattern is constrained by the fact)? **Tentative answer: not yet.** Wait for a real corpus to show whether the distinction is load-bearing. Premature.
- **Subject uniqueness across mutable/immutable.** A `mutable: false` pattern lesson and a `mutable: true` env-fact lesson never share a subject under §Folding rule 1 (because pattern lessons usually don't carry one). Worth codifying as a validator rule? **Tentative answer: yes** — if a pattern lesson does carry a subject (rare but allowed), it shouldn't collide with an env-fact lesson's subject; the validator should flag it.
- **Migration path for the production corpus** (currently `_TEMPLATE.md` only). When real lessons start landing, do they go in v1 shape and migrate later, or do we land v2 first? **Tentative answer: land v2 first.** The current `_TEMPLATE` is a non-blocker; switching the template + author prompt now avoids paying migration cost twice.

## Source

Validated by the retrieval probe at `experiments/actor-author-discipline/retrieval-probe/`. Findings synthesized in that directory's `README.md`. Specific transcripts cited in the §Why v2 examples: trial-1, trial-2, trial-3, trial-5 (instrumented); clean-2, clean-5 (un-instrumented confirmation).
