## Question

**Engineering** — can Haiku author coherent Shape M stories on a hard fixture in a quirky environment, and does providing environment context measurably improve story quality, or do "relative descriptions" (mechanism-class abstraction, no env naming) suffice?

Why this matters: PREDICT's story-authoring is the load-bearing reasoning step where a model can flatten a structurally-open attribute into the most narratively-coherent candidate. If Haiku flunks Shape M on a quirky env, story authoring stays Sonnet. If it survives without env context (relative descriptions), we save the env-context tokens AND we get a structural defense against env-name-baking — the prompt cannot bake what it never saw.

## Variants

All three arms run against a **trimmed harness prompt** — `predict-story-only.md` — that strips the existing `predict/SKILL.md` down to the story-authoring nucleus. The trim is held constant across arms (it is the test harness, not a variant axis); arms differ only on `model:` and env-context inclusion.

### Trimmed harness — `variants/predict-story-only.md`

Drop from current SKILL.md (irrelevant to story authoring):
- §Shapes (E/A/M decision) — replaced by a 1-line directive: "Write Shape M: ≥2 hypotheses whose stories diverge on observable parent-vertex fields."
- §Decision procedure
- §Output format / dense block grammar / `kind` slot / comparison blocks / `:P` sub-blocks / `:R` routing / `:L` branch_plan / `:R lead_hints` / `scope_override` / `composite_secondary` / parser-rejection table
- §Field-presence matrix
- §`:H` row shape (kept as a 1-line stub: `:H [id|name|attached_to|rel|parent_class]` — one row per hypothesis, naming only)
- §Attribute predictions / §Novelty and IDs
- §Worked example — Shape A
- §Lead selection / §Corpus priors / §Inputs (replaced by experiment input spec) / §Progress checkpoint / §Handler owns investigation.md
- §Disciplines bullets: invoker-identity, prior-loop resolutions, weight-is-null, one-observable-per-claim, downstream-event-signals, authorization-vs-integrity, refinement/upstream-fork IDs, append-only, pitfalls-per-hypothesis, lead-names-must-be-real, `authorization_contract` YAML, `impact_predictions` YAML, pre-refuted seeds, presence-test refutations + baseline-value leaks (these bind predicates not stories), headline-vs-instrumental, backward-traversal-on-++.

Keep (story-authoring nucleus):
- *Story first, predictions second* (1 line, predictions-second clause dropped).
- *One hop* (1 sentence).
- *Not in scope* (earlier causes / downstream consequences / disposition claims) — 3 bullets.
- *Baseline grounds predictions* — first sentence only ("name the baseline in one story sentence, or say none exists"); drop the deviation-shape guidance.
- *Labels vs stories* — the concrete-link rule.
- Discipline bullets: *Names and classifications describe mechanism, never verdict*. *Structurally-open attributes are explicit unknowns* (load-bearing for arm B's candidate-bake-in defense). *Structural-consistency check on competing mechanisms* (binds story content). *Refutation-shape adequacy* (story must support a falsifiable refutation). *Story-prediction referent match* — recast as authorship discipline ("each story sentence must be a single noun-anchored claim that a future prediction could cite").
- Output spec: one `### story h-<id>` block per hypothesis (2–4 sentences, each starting `s\d+\.`), plus one stub `:H` row per hypothesis. Nothing else.

Estimated size: ≤ 90 lines / ~6K tokens (vs ~412 lines / ~30K tokens in current SKILL.md).

### current (regression — Sonnet, env context as today)

`variants/predict-story-only.md` with front-matter:
```
model: sonnet
```
Prompt receives the standard `<environment-context>` tag (env knowledge for the relevant systems + identity / criticality patterns).

### proposed-A (Haiku + env context)

Same `variants/predict-story-only.md`. Front-matter:
```
model: haiku
```
Same `<environment-context>` tag. Single-variable diff vs current is `model: sonnet` → `model: haiku`.

### proposed-B (Haiku + relative descriptions, no env context)

Same `variants/predict-story-only.md`. Front-matter:
```
model: haiku
```
`<environment-context>` tag stripped from the input. One-paragraph addition to §Story authoring (≤15 lines):

```
**Relative description discipline (no environment context provided).** This run does not
ship environment-specific knowledge. Author each story in mechanism-class terms only: name
the parent's *class* and the *role* of each attribute (cadence, distinct-image count,
signing distribution, name-pattern stability), never a specific image path, user identity,
IP value, or org-named tool. Env-specific grounding is ANALYZE's job (anchor consultation),
not PREDICT's. PREDICT scaffolds the mechanism-class question; ANALYZE confirms which
env-specific instance fits.
```

Note: arms A and B differ in two places (env-context tag presence + the relative-description instruction). Pure isolation would need a 4-arm design (Haiku × env-context-{with,without} × relative-instruction-{with,without}). User asked for 2 Haiku arms specifically — bundling recorded here so we can decompose if results are ambiguous.

## Fixtures

One quirky-environment Shape M fixture. The "quirk" needs to be load-bearing for the legitimate mechanism in the fork: without env context, Haiku has no concrete legit-mechanism story and may collapse to a malware-only narrative (failing Shape M survivability).

### `tasks-scratch/predict-haiku-story-shapeM/fixtures/shapeM-winword-burst-quirky/`

Built from `tasks-scratch/predict-comparison-experiment/fixtures/network-dns-multi-dim-loop1/` (the Sysmon WINWORD child-burst fixture — kept verbatim) plus a synthesized env-quirk knowledge layer:

- `alert.json` — verbatim copy. Word spawns 142 children / 38 distinct images in 5 min, avg name length 14, avg entropy 3.12.
- `investigation.md` — verbatim CONTEXTUALIZE prologue (4 candidate playbook hypotheses surface: macro-payload-dropper / mailmerge-batch / addin-iterating / compromised-document-vba).
- `environment-quirk.md` — synthesized: org runs `EvidenceLoader` (a 3rd-party e-discovery addin deployed via Word startup folder for legal-team identities); image names match `EvLoader-{caseid}-{step}.exe`, signed by `Acme Legal Software CA`, deployed only on legal-team workstations; `ksilva` is a legal-team identity. Without this layer, the addin-iterating mechanism has no concrete shape and Haiku is expected to skew toward the macro-dropper.

Why this fixture exercises the variable: Shape M is plausible iff there exist ≥2 mechanisms that diverge on observable fields. The quirk supplies the second mechanism (`?legit-edisco-addin-burst` with a recurring image-name-pattern + signing-distribution baseline) that competes with `?macro-payload-dropper` on signing-distribution and image-name-pattern entropy. Arm B's hypothesis: Haiku can still author mutually-exclusive predictions on those *roles* (signing distribution, name-pattern stability) without naming `EvidenceLoader` specifically — and ANALYZE will resolve the env binding via the lead's signing-authority anchor.

One fixture is enough for validation. If validation passes, we discuss adding a second fixture before scale-up.

## Trials

**Validation:** 1 trial per arm per fixture = 3 trials. Confirms the prompt assemblies parse, all three arms produce dense-block output, and the parser accepts each. Inspected manually for shape commitment, story discipline, candidate-bake-in.

**Scale-up:** N = 10 trials per arm (30 total) only after validation passes. Mid-run analysis at trial 3 per arm (30% of 10). Analysis script `analyze.py` written before scale-up — defines metrics (below) and aggregation.

Metrics scored per trial:
1. **Shape commitment** — did the envelope's first line declare `shape=M`? (binary)
2. **Parser validity** — does the dense parser accept the envelope without remediation notes? (binary)
3. **Hypothesis count** — number of `:H` rows (Shape M requires ≥ 2)
4. **Mutual-exclusivity** — pairwise, do the hypotheses' `:P preds` diverge on at least one observable field, or are they negations of each other? Scored by an LLM judge (Sonnet) on the rendered hypotheses, calibrated against 2-3 hand-graded fixtures before scale-up.
5. **Story-prediction referent match** — every `from_story` cell names a sentence ID present in the matching story block. (binary, parser-checked)
6. **Candidate-bake-in** — did the story name a specific env-instance (specific image name, specific user, specific IP, specific tool) that flattens an open attribute? Scored by Sonnet judge on story prose.
7. **Baseline-value leaks** — does any predicate name a specific value/threshold rather than a deviation role? Scored by Sonnet judge on the predicates.

Ranked by per-occurrence mean with `n` shown as support. Per-arm aggregates reported alongside per-fixture rows (one fixture for now).

Per the minimal-A/B-for-repro memory: validation first; before launching N=10, confirm with user whether scale-up is worth the budget over a unit/integration follow-up.

## Decision criteria

**proposed-A wins** (cut PREDICT to Haiku, keep env context) if:
- Validation: parser-valid, Shape M, ≥ 2 mutually-exclusive hypotheses with referent-match passing.
- Scale-up: parser-valid + Shape M + referent-match ≥ 9/10. Mutual-exclusivity ≥ 8/10. Candidate-bake-in ≤ 1/10. Baseline-value leaks ≤ 1/10.

**proposed-B wins** (cut to Haiku AND drop env context) if proposed-A wins **and** proposed-B matches it on every criterion above except candidate-bake-in, where proposed-B must score 0/10 (since with no env names provided, any baked candidate is hallucinated). Cost difference: env-context tokens saved on every PREDICT call.

**current retained** (story authoring stays Sonnet) if either Haiku arm:
- Fails parser validation more than 2/10, OR
- Collapses to Shape A or Shape E in > 2/10 trials (sign that Haiku gives up on mechanism-fork discipline), OR
- Mutual-exclusivity score < 7/10 (sign that Haiku writes near-duplicate hypotheses), OR
- Bakes candidates into mechanism-class story prose > 3/10.

## Layout

```
tasks-scratch/predict-haiku-story-shapeM/
  plan.md                                  # this file
  variants/
    predict-story-only.md                  # trimmed harness (shared by all arms)
    current.frontmatter.yaml               # model: sonnet (+ env-context: include)
    proposed-A.frontmatter.yaml            # model: haiku (+ env-context: include)
    proposed-B.frontmatter.yaml            # model: haiku (+ env-context: omit, +relative-description block)
  fixtures/
    shapeM-winword-burst-quirky/
      alert.json                           # verbatim copy
      investigation.md                     # verbatim copy
      environment-quirk.md                 # synthesized env layer
  runs/
    validation/
      current/trial-1/{stdout.txt, predict-loop-1.yaml}
      proposed-A/trial-1/{stdout.txt, predict-loop-1.yaml}
      proposed-B/trial-1/{stdout.txt, predict-loop-1.yaml}
    scale/                                 # populated only after validation passes
      current/trial-{1..10}/...
      proposed-A/trial-{1..10}/...
      proposed-B/trial-{1..10}/...
  analyze.py                               # written before scale-up
  results/
    validation-summary.md                  # written after validation
    midrun-N3.md                           # written at 30% of scale-up
    final.md                               # written at end of scale-up
```
