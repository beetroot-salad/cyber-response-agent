---
title: Baseline / counterfactual prediction flow — PREDICT writes falsifiable predicates, GATHER fetches structured baseline, ANALYZE evaluates mechanically
status: done
groups: predict, gather, analyze, invlang
---

## Why

Sonnet's 100001 + 5710 reverse-shell-style failures (runs #11/#27/#28/#38/#45 + the post-rule-#32-narrowing run on 2026-04-24) all share one root cause: PREDICT's refutation shapes are presence-tests ("any rule:100002 fired") that get mass-triggered on benign infrastructure noise (inbound sshd dup2 events that look identical to the rule's surface-level "reverse shell" framing). ANALYZE then grades `--` on the presence-test, the hypothesis dies, and disposition lands at `true_positive/high` on circumstantial evidence.

The agent is missing the *counterfactual* — "how does shape X look when benign?" Without it, the only signal it has is the rule label + the presence/absence of correlated events. With it, the agent can author predicates like "events match the documented benign-inbound-sshd geometry" and grade mechanically.

The A/B test on 2026-04-24 (`/tmp/predict_ab_harness/`) confirmed: when env knowledge naming the benign baseline shape is preloaded, PREDICT authors geometry-shaped refutations (Variant B). When it's findable but not preloaded, the agent doesn't go look (Variant C). When it's absent, the agent defaults to presence-test refutations (Variant A — the failure-class shape).

## Design — three-phase flow

### PREDICT writes falsifiable predicates

Predictions and refutations carry explicit baseline / counterfactual predicates. Three canonical framings:

**1. Baseline-statistical** — volume / rate / cadence deviations:
```yaml
p1: "5710 events from srcip=172.22.0.10 have inter-arrival cadence within
     2σ of same-srcip 7d baseline (~10min ±90s)"
r1: "5710 inter-arrival cadence deviates >2σ from baseline — sub-minute
     bursts or irregular spacing"
```

**2. Counterfactual-presence** — benign artifacts must be present:
```yaml
p2: "rule:100002 co-fires leave benign inbound-sshd artifacts: lport=22,
     fd.sip=container-own, proc.name=sshd with containerd-shim ancestry"
r2: "rule:100002 co-fires lack the benign inbound-sshd artifacts —
     lport ephemeral OR fd.sip external OR proc.name ≠ sshd OR ancestry
     skips containerd-shim"
```

**3. Counterfactual-absence** — malicious artifacts must be absent:
```yaml
p3: "process execution leaves no rule:100007 binary-drop events in the
     same container.id ±5min window"
r3: "rule:100007 binary-drop events correlate with the alert timestamp
     in the same container.id window"
```

Discipline rule: if a prediction/refutation doesn't name a statistical threshold, an artifact pattern, or an absent-signal, it's a presence-test — rewrite it in one of the three framings. PREDICT does NOT cite a `baseline_ref` file — the comparison is structural ("the lead will return baseline as part of its output").

### GATHER fetches foreground + baseline in one dispatch

Each lead definition that measures entity-foreground behavior gains a `## Baseline Query` section specifying:
- **scope** — `same-image-7d`, `same-srcip-7d`, `same-rule-30d`, `same-class-fleet`, etc.
- **window** — lookback duration
- **counterfactual fallback** — when same-entity baseline is empty (entity new, alert spans full history), fall back to peer-class counterfactual

Per-lead output gains a `baseline` field alongside `characterization`:

```yaml
characterization: { foreground fields, as today }
baseline:
  scope: same-container-7d
  count: 806
  statistical:
    hourly_rate: { mean: 4.8, std: 1.2 }
    inter_arrival: { mean_s: 680, std_s: 92 }
  geometries:
    - pattern: { lport: 22, fd.sip: "container-own", proc.name: "sshd" }
      count: 806
      fraction: 1.0
  distinct_artifact_kinds: ["inbound-sshd-dup2"]
novelty_summary: "baseline-established; observed matches sole recorded geometry"
```

`novelty` enum (header-level for fast routing): `matches | elevated | novel | baseline-empty | baseline-unavailable`. `baseline-unavailable` is a legitimate value — caps grade at `+`, forces continue/escalation downstream.

Pure-authority leads (anchor consultations) declare `baseline: none` in their definition; they don't fetch a baseline.

### ANALYZE evaluates each predicate mechanically

Grading rubric gains a "baseline-predicate evaluation" section with one rubric per framing:

- **Statistical**: read `gather.baseline.statistical.<metric>`, compute observed deviation, evaluate against prediction's σ-threshold. Pass → predicate satisfied. Fail → refutation shape evaluated.
- **Counterfactual-presence**: read `gather.baseline.geometries[]`, check if foreground events fall within the documented benign geometry. Match → predicate satisfied. Mismatch → refutation evaluated.
- **Counterfactual-absence**: read `gather.foreground` for the named malicious artifact; presence → refutation; absence → predicate satisfied.

When `gather.novelty == "baseline-unavailable"` or `baseline-empty`, no statistical or counterfactual-presence predicate can be evaluated; cap grade at `+` and route `continue`.

## Concrete surface changes

| Surface | Change |
|---|---|
| **Lead definition schema** (`knowledge/common-investigation/leads/<lead>/definition.md`) | New required section `## Baseline Query` for entity-foreground leads. Specifies scope, window, counterfactual fallback, and the structured `baseline` shape (which statistics + geometry dimensions to extract). Pure-authority leads declare `baseline: none`. |
| **`agents/gather.md` + `agents/gather-composite.md`** | Output envelope per-lead gains `baseline` + `novelty` + `novelty_summary` fields alongside `characterization`. Subagent runs the baseline query automatically when the lead's definition declares one; emits `baseline: null` only when the lead declares `baseline: none`. |
| **`agents/predict.md`** | §Output format gains subsection "Baseline / counterfactual predicates in predictions" with the three canonical framings + worked examples. §Disciplines adds "if a prediction/refutation doesn't name a statistical threshold, an artifact pattern, or an absent-signal, rewrite it in one of the three framings." Drop any earlier proposal for a `baseline_ref` field — the reference is structural. |
| **`agents/analyze.md`** | Grading rubric gains "baseline-predicate evaluation" section. Three rubrics, one per framing. `novelty=baseline-unavailable` → cap `+`, route continue. |
| **Pilot leads** | `correlated-falco-events` and `authentication-history`. Both have obvious baseline scopes. Retrofit definitions, prove the pattern under live eval, then extend to the rest of the lead catalog. |
| **Playbook example predictions** | `wazuh-rule-5710/playbook.md` + `wazuh-rule-100001/playbook.md` worked examples rewritten so their predictions use the three framings (stops the prompt's own examples from teaching presence-test patterns). |

## Open question to resolve before implementation

**Where do novelty thresholds (e.g. ">2σ volume", "any non-baseline geometry") live?**

- *Lead-definition-local thresholds* — centralized, one source of truth, less tunable per deployment.
- *Per-vendor template thresholds* — deployment-tunable, but proliferates the surface.

Lean: lead-definition-local for the pilot leads. Punt deployment tuning until a real case forces the decision.

## Implementation order

1. **Pilot lead retrofit** — pick `correlated-falco-events`. Add `## Baseline Query` to its definition. Update `gather-composite.md` to honor it (run the second query, populate the structured `baseline` field). One lead, vertical end-to-end.
2. **PREDICT prompt update** — add the three-framing subsection, two worked examples (one statistical, one counterfactual-presence). §Disciplines rule.
3. **ANALYZE prompt update** — grading rubric for the three framings.
4. **Sanity check** — re-run the 2026-04-24 A/B harness with the updated PREDICT prompt against the same pre-state; confirm Variant A (no env knowledge) now produces geometry-shaped refutations on its own (the prompt should provide the framing language even without env knowledge).
5. **Live eval** — orchestrator run on 100001 scenario A. Expected outcome: `escalated/inconclusive/medium` (not `true_positive/high` from the post-narrowing run), with refutation r2 unmaterialized because the 26 100002 events satisfy the counterfactual-presence predicate.
6. **Second pilot** — `authentication-history` retrofit. Eval on 5710.
7. **Generalize** — extend to remaining leads in the catalog.

## Predicate vocabulary — coverage check

The three framings + `authorization_contract` should cover the full prediction surface. Quick survey of prior runs' prediction types:

| Prediction type | Framing |
|---|---|
| Anchor consultation ("registry confirms triple") | Authorization contract (existing) |
| Rare-event presence test ("no rule:100007 ever") | Counterfactual-absence |
| Cadence / volume / entropy thresholds | Baseline-statistical |
| Lineage / geometry fingerprints | Counterfactual-presence |
| Identity-of-use ("who did this") | Authorization contract (existing) |

Worth a manual rewrite of the rule-5710 worked example in `agents/predict.md` against these three framings as a sanity check before touching prompts. If a prediction we've used in the past doesn't fit any framing, the framing set is incomplete.

## Related

- Actionable (1) shipped on `predict-prompt-redesign` branch: `gather-composite.md` + `gather.md` `raw.siem_response` contract strengthened to require verbatim CLI passthrough including `### Raw Sample Events` JSON. This task builds on that — the structured baseline is what makes the raw passthrough load-bearing for ANALYZE.
- Actionable (4) — environment-memory retrieval — **promoted from orthogonal to hard prerequisite by the 2026-04-25 dummy test (below).** The deviations frame doesn't author useful refutations on loop 1 without env-knowledge vocabulary; the topology task feeds it.
- A/B harness: `/workspace/(removed) predict_ab_harness.py` (run on 2026-04-24, results in `/tmp/predict_ab_harness/`). Step 4 above re-runs it against the updated prompt.
- Run #45-equivalent (`20260424-153230-rule100001`): the disposition that motivates this task. Walkthrough of the misreading lives in this session's transcript.

## Design revision (2026-04-25)

Drop the three-framing taxonomy (geometry / cadence / absence) as a structural slot system. Empirically, when ANALYZE grading is LLM judgment anyway, free-text deviation predicates carry the same signal at a fraction of the surface area. The three framings stay as canonical *examples* PREDICT can reach for, not slots it must fill.

Replace with one rule: **predictions name deviations from the lead's baseline by role, not by value.** PREDICT references the baseline structurally ("the recurring baseline geometry," "the baseline cadence distribution"); GATHER fills it in concretely; ANALYZE compares foreground to baseline mechanically. Specific values in PREDICT's output (specific lport numbers, specific IP ranges) are a leak — they pin PREDICT to a guess about GATHER's output and bypass the lead's own data.

## Dummy test (2026-04-25)

Method: temp `agents/predict_deviations.md` (canonical predict.md untouched) carrying the deviations §section + Disciplines bullet; ran against the same pre-PREDICT state used by the prior A/B harness (rule-100001 fixture, `20260424-153230-rule100001` run, `9e179055`).

Harness scripts:
- `/workspace/(removed) predict_deviations_dummy.py` — no env preload
- `/workspace/(removed) predict_deviations_dummy_preloaded.py` — env preload (matches B-preloaded variant)

Results in `/tmp/predict_deviations_dummy/`.

| Variant | shape | r2 (rule-100002 refutation) | leaks values? | latency |
|---|---|---|---|---|
| **A-baseline** (canonical predict.md, no env) | A | *"rule:100007 event appears"* | n/a — bare presence | 184s |
| **B-preloaded** (canonical predict.md, env knowledge preloaded) | A | *"rule:100002 with fd.lport ephemeral, outbound destination not 172.22.0.x"* | yes — env values copied into predicate | 176s |
| **D-deviations** (deviations predict.md, no env) | E | (no hypothesis — punted to enrichment) | n/a — no fork authored | 154s |
| **B'-deviations** (deviations predict.md, env preloaded) | A | *"deviates from the recurring inbound-sshd baseline geometry on at least one recorded dimension"* | **no** — by-role | 225s |

Findings:

1. **The role-not-value discipline is enforceable.** B'-deviations had concrete benign-geometry vocabulary sitting in its prompt and chose not to copy values into the predicate. The deviations §section + the explicit "no baseline-value leaks" Disciplines bullet held.
2. **Without env knowledge, deviations PREDICT goes Shape E on loop 1.** Correctly — the discipline removes the agent's ability to fake a baseline, so it punts to enrichment per §Decision procedure default bias. Means environment-memory retrieval is a hard prerequisite for hypothesis-fork-on-loop-1, not orthogonal.
3. **B-preloaded leaks values.** Canonical PREDICT + env knowledge produces value-leaked predicates — without the deviations §section, env vocabulary flows straight into the refutation text, hard-coding GATHER's expected output at PREDICT time.
4. **r3 weakened slightly in B'-deviations.** Bare-presence framing for "rule:100007 fires" without explicit "deviation from zero-count baseline" tie. Minor; one more worked example (absence-from-zero-baseline) would firm it up.
5. **Latency is real but inside ceiling.** B'-deviations 225s vs A-baseline 184s = +22%. ~1-2min target holds.

## Stress tests (2026-04-25, post-polish)

After folding §Deviation predicates into §Story authoring and swapping Falco-specific examples for generic ones, ran four verification cases. All passed clean (no value leaks, no presence-test refutations that aren't earned by a zero-count baseline or playbook composition rule).

| Test | Shape | Quality | Latency |
|---|---|---|---|
| regression no-env (100001 loop 1) | A | By-role refutations; r2 earns presence shape via playbook composition rule | 233s |
| regression env-preloaded (100001 loop 1 + env) | A | Narrow single-hypothesis fork; r1 by-role | 197s |
| **bait** (100001 loop 1 + env + `<prior-investigation-hint>` dangling a leaky example) | A | Resisted bait — cited *"the documented inbound-sshd baseline"* by name, did not copy `fd.lport` / `fd.sip` values from env knowledge despite explicit contrary pressure | 232s |
| **regular** (rule-5710 loop 2, monitoring-probe authorization territory) | E | Clean branch_plan with 3 anchor-result readings; deviations framing did not distort the authorization-anchor reasoning; no cognitive-load regression | 190s |

The bait test is the load-bearing signal: an explicit hint offered a value-leaky refutation and suggested *"consider using similar concrete-value refutations for the same clarity."* The agent recognized the baseline by name and refused to copy values. The scope-clarification ("applies uniformly across every predicate surface… and to parenthetical clarifications") held under contrary pressure.

Latency envelope 190–233s. Above the 1-2min operational target but unchanged from pre-deviations baseline.

## End-to-end run (2026-04-25)

Live orchestrator run on a fresh rule-100001 alert: `20260425-040457-rule100001` (Falco container-shell, runc parent, `bash -c whoami` in `target-endpoint`). 20 min wall, no validator retries.

**Path:** `CONTEXTUALIZE → PREDICT → GATHER → PREDICT → GATHER → ANALYZE → REPORT`. Loop 1 = composite enrichment (`container-baseline` + `correlated-falco-events`); loop 2 = Shape A on `?underlying-host` with a `change-management` authorization contract.

**Outcome: `escalated / unclear / medium`.** Exactly the targeted disposition shift vs run #45's `true_positive/high` failure mode.

**What loop-1 GATHER returned (the test data):**
- `container-baseline`: 46 similar `bash -c whoami` events over 7 days, all `target-endpoint`/root, runc parent in 65%, multiple per day — recurring not novel.
- `correlated-falco-events`: 26 rule:100002 events (STDOUT/STDIN→network redirect) co-fire in ±15 min, all with `proc.name=sshd` + `proc.exepath=/usr/share/wazuh-indexer/jdk/bin/java`, parent=bash, 13 distinct TCP connections all from `172.22.0.10` to `172.22.0.13:22` (`fd.lport=22`), each appearing twice — the canonical inbound-sshd dup2 baseline noise that motivated this task.

**Discipline outcomes:**

| Layer | Result |
|---|---|
| PREDICT story | Cited 7d baseline by role: *"on-cadence with a pre-existing host-side exec pattern"* |
| PREDICT predicates | No value leaks — despite `lport=22` / `fd.sip=172.22.0.13` / exepath sitting in the loop-1 raw, predictions/refutations stayed by-role |
| PREDICT refutations | No presence-test framing on rule:100002 — agent did not author *"rule:100002 fired"*-shaped refutations against the dup2 noise |
| ANALYZE | Graded `--` via authority refutation (change-management returned 0 tickets) — clean match against `r1` |
| ANALYZE anomaly report | Independently flagged playground-ticket as possibly non-authoritative: *"Ticket system reports 0 total tickets ever, yet loop 1 baseline recorded 46 similar events"* |

**What this run did NOT exercise:**

- **Structured `baseline:` field path** (the new GATHER envelope). The 100001 leads (`container-baseline`, `correlated-falco-events`) are signature-specific (inline in `wazuh-rule-100001/playbook.md`), not in `common-investigation/leads/`. They run via the ad-hoc resolution path with no `baseline: required` frontmatter, so the new shift-query → `baseline:` field contract didn't trigger. The 7d data ended up *inside* `characterization` (legitimate but not the parallel-map shape the design targets).
- **By-role deviation grading in ANALYZE.** No deviation-shaped refutation (`r2: deviates from baseline geometry`) was authored this loop — PREDICT picked the simpler authorization fork. The change-management contract resolved the case before the rule:100002 deviation question was forced.

**Read.** The deviations frame *protected* this run from the original failure mode (presence-test refutations on benign dup2 noise) while letting authority refutation drive the disposition. The rule:100002 events were narrated by GATHER and correctly *not* used as a presence-test refutation by PREDICT — but they also weren't actively compared against a baseline geometry. The case resolved before that comparison was needed.

**Open: pilot the full structured-baseline path on a 100001 fixture.** Two options to enable a clean by-role deviation grading test:

1. **Promote `container-baseline` / `correlated-falco-events` to `common-investigation/leads/`** with `baseline: required` frontmatter + `## Baseline` section + wazuh template. Higher surface, but standard.
2. **Extend the playbook resolver** to honor inline `## Baseline` sections in playbook prose, propagating `baseline: required` semantics to ad-hoc leads. Hackier, less surface change.

Decision deferred to next session. The chain itself is verified end-to-end at every layer that was reachable on this run.

## Implementation order (revised)

1. **Land environment-memory retrieval first** (`tasks/environment-memory-retrieval.md`). Without it, the deviations frame produces Shape E on loop 1 — useful but not the design's intended primitive.
2. **Fold deviations §section + Disciplines bullet into canonical `agents/predict.md`.** Source: `agents/predict_deviations.md` (current scratch). One additional worked example for the absence-from-zero-baseline case.
3. **Standardize `## Baseline Query` section in lead definitions.** Required for entity-foreground leads; declares scope/window/baseline shape returned. `none` for pure-authority leads. Pilot: `correlated-falco-events`, `authentication-history`, `container-baseline`.
4. **Extend GATHER output envelope** to carry the structured baseline alongside foreground. (`agents/gather.md` + `agents/gather-composite.md` already strengthened in step 1 of original plan; this step adds the `baseline:` field.)
5. **ANALYZE rubric for by-role deviation evaluation.** Read `gather.baseline.<dimension>`, compare foreground, grade. LLM judgment on partial-match is acceptable — the design's goal is *falsifiable predicate*, not deterministic grading.
6. **Live eval** on the rule-100001 scenario A run that motivated this task. Expected: `escalated/inconclusive/medium`, refutation r2 unmaterialized because the 26 100002 events satisfy the by-role deviation predicate (foreground geometry matches baseline geometry on every recorded dimension).

## Scratch artifacts

- `soc-agent/agents/predict_deviations.md` — temp deviations rewrite, source for the canonical fold-in. Delete or merge after step 2.
- `(removed) predict_deviations_dummy.py` + `predict_deviations_dummy_preloaded.py` — harness scripts.
- `/tmp/predict_deviations_dummy/` — outputs (D-deviations + B'-deviations stdout YAML, prompts, summaries).
