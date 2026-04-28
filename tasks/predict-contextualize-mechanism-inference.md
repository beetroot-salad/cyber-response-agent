---
title: CONTEXTUALIZE mechanism-inference pass + PREDICT attribute-vs-edge-extension first-turn rule
status: backlog
groups: predict, contextualize, invlang, signatures
---

**Goal.** Eliminate the "story-shaped hypothesis on a confirmed mechanism" failure mode that drove run #44's `disposition: true_positive` halt with `surviving_hypotheses: []`. Two composable changes plus one signature-rewrite, all reading off the same diagnosis.

## Why

Run #44 (`/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/`) hit `escalated/true_positive/medium` on a `docker exec -t target-endpoint bash -c whoami` alert — the literal operator-debug fingerprint. ANALYZE loop 2 self-flagged the gap (`anomalies[1]: "no adversarial hypothesis was scaffolded, leaving the intrusion-path frontier open and unresolvable"`) but routed `true_positive` rather than `unclear`. Mechanical compose then rejected on the malformed disposition shape (`true_positive + null archetype + [] surviving_hypotheses` is not certifiable by `validate_tier1`), fell through to the Sonnet `report` subagent fallback, which timed out at 300s. No `report.md`.

The proximate fix is `analyze.md` — `true_positive` should require affirmative `++` on an adversarial mechanism, not absence-of-surviving-benign. (Tracked separately if not already addressed.) But the upstream cause is **PREDICT loop 1 emitted a story-shaped hypothesis** (`?operator-runtime-exec` — fused mechanism + actor identity + intent into one yes/no proposition). When ANALYZE refuted the actor-identity half via missing oncall ticket, the whole story died at `--`, taking the mechanism-half with it. The mechanism (docker-daemon-issued exec) was directly observable in the alert body and never warranted being a hypothesis at all.

## Diagnosis

The 100001 alert carries `parent=containerd-shim` + `cmdline="bash -c <oneliner>"` + `k8s.{pod,ns}=null`. That triple is the canonical fingerprint of dockerd-issued `exec_invoked` — runc would not produce a containerd-shim parent process, k8s exec would populate `k8s.*` fields. Single-canonical-generator. Yet contextualize-prologue's actual output (verbatim from run #44):

```yaml
prologue:
  vertices:
    - id: v-001  # root (identity)
    - id: v-002  # bash (process)
    - id: v-003  # containerd-shim (process, runtime-exec-primitive)
    - id: v-004  # 982cf96c79c5 (endpoint)
    - id: v-005  # wazuh.manager (endpoint)
  edges:
    - id: e-001  # v-001 --executed--> v-002
    - id: e-002  # v-003 --spawned--> v-002
```

Faithful to literal alert contents but stops one inference step short. The dockerd vertex and its `exec_invoked` edge to containerd-shim are unambiguous from the fingerprint, but the prologue treats the fingerprint as raw observation rather than promoting it into the confirmed graph. PREDICT then has to invent a story to cover the question "what generated this bash process," and absent structural guidance it picks one full causal narrative (`?operator-runtime-exec`) instead of decomposing the actually-open frontier (who invoked dockerd, from where, under what auth).

The schema already supports the right shape — `proposed_edge` with `parent_vertex: {type, classification}` for unmaterialized upstream vertices, plus `authorization_contract` for anchor-bound resolution (see `knowledge/invlang/schema.md:470-500`, used in the 5710 v2.9 rewrite). PREDICT just doesn't reach for it on the upstream-traversal class of question.

## Three composable changes (dependency order)

### (1) CONTEXTUALIZE mechanism-inference pass

**File:** `agents/contextualize-prologue.md`

After enumerating directly-observed vertices/edges, run a second pass: examine whether the observed pattern matches a **known runtime-topology fingerprint** that implies an upstream vertex+edge not literally named in the alert body. If a match is *unambiguous* (single canonical generator), append the inferred vertex+edge with `authority.kind: siem-event` and a one-sentence inference note in `authority.source` naming the discriminator. If multiple generators could produce the pattern, do not append — the question becomes a PREDICT mechanism-fork.

For the 100001 case the pass would add the **containerd** vertex (not dockerd — see discriminator note):

```yaml
- id: v-006
  type: process
  classification: container-runtime
  identifier: containerd
- id: e-003
  relation: exec_invoked
  source_vertex: v-006
  target_vertex: v-003
  authority:
    kind: siem-event
    source: "rule 100001 — parent=containerd-shim + k8s.*=null excludes runc (would not produce containerd-shim parent) and excludes k8s exec (would populate k8s.{pod,ns}). Identifies the runtime as containerd-issued; does NOT positively discriminate dockerd from nerdctl, direct containerd-API clients, or other containerd consumers — that question stays a PREDICT upstream-edge hypothesis."
```

The inferred vertex sits one rung up the supply chain from "the daemon someone interacted with." Promoting `dockerd` specifically would overclaim — the negative discriminators name what's excluded, not who positively invoked containerd.

**Discipline gate.** `siem-event` authority requires the alert *itself* to be the cited evidence. An inference that requires a second observation (host_query, follow-up SIEM query) to confirm does not qualify and stays in PREDICT as a mechanism-fork. The schema's existing `authority.kind` enum enforces this — don't relax it.

**Why CONTEXTUALIZE, not PREDICT.** The prologue's append-only / never-refuted property is load-bearing. If mechanism inference lives in PREDICT, it enters the grading cycle and may get retroactively `--`'d by ANALYZE — exactly the dynamic that produced run #44's cascade. Keeping it in CONTEXTUALIZE with `siem-event` authority means it's structural ground truth all downstream phases read but none can refute.

**Cost.** One additional discipline section in the contextualize-prologue prompt + one worked example (the 100001 fingerprint shown above). Sized for ~30-50 extra prompt lines, no schema change required.

### (2) PREDICT first-turn classification rule

**File:** `agents/predict.md`

Add a discipline section *before* §Hypothesis formation, branching on the shape of the open frontier:

> **First-turn classification of the open frontier.** For each open question on the confirmed graph:
>
> - If the question is a *property of a confirmed vertex* (loginuid_state, version, started_at, image_baseline_count, etc.) → `attribute_predictions[]` on that vertex, with anchor binding for resolution. ID prefix `aN`.
> - If the question is *what vertex is upstream of a confirmed vertex via a specific relation* (api-called, located-on, authenticated-as, scheduled-by, etc.) → one hypothesis per upstream-edge question, each with `proposed_edge` to a typed-but-unmaterialized parent vertex and an `authorization_contract` against the resolving anchor. ID prefix `hN`, prediction prefix `pN`.
>
> Sibling hypotheses formed via the upstream-edge branch are **not competing stories**. They're different open edges; resolving one does not refute the others. ANALYZE grades each independently against its own anchor.

The worked example must be a 100001-shaped alert (mechanism observable from alert body), showing the three upstream-edge hypotheses each with `proposed_edge.parent_vertex.classification: ???` (unmaterialized) and distinct `authorization_contract.anchor_kind` values. Per meta-finding #18, fields documented in prose without YAML examples get reinvented wrong by Sonnet — the example is the load-bearing piece.

**Strict slot discipline.** Do not let `attribute_predictions[]` and `proposed_edge` collapse into each other. The validator already pattern-matches `aN` vs `hN` IDs; document this as a hard rule and add a validator check that rejects an `aN` id on a `proposed_edge` block (and vice-versa). Without this, agents will collapse edge-extension questions into attributes for convenience and the discipline erodes on the next prompt-rewrite cycle.

**Enumeration ≠ pursuit (path-of-least-resistance is preserved).** Classifying the open frontier in loop 1 does not commit PREDICT to scaffold a hypothesis-with-prediction for each upstream-edge question. The cheapest discriminating question (typically anchor-cheapest, e.g., the auth-context contract) becomes the live hypothesis with a prediction; the others are named in `unknowns[]` for downstream visibility but not pursued in loop 1. The point of slot discipline is to (a) give ANALYZE a structured frontier to grade against and (b) make the open questions legible to the human reader — not to balloon loop 1 into an n-way fork. The existing path-of-least-resistance prose in `predict.md` continues to govern *which* of the classified questions becomes a live hypothesis; the slot-discipline rule only governs *how* each open question is shaped when named.

### (3) 100001 playbook seed rewrite

**File:** `knowledge/signatures/wazuh-rule-100001/playbook.md`

Replace the current story-shaped seeds (`?image-entrypoint`, `?runtime-process`, `?underlying-host`) with three upstream-edge seeds rooted on the inferred-confirmed `v-006: dockerd` vertex:

- `?containerd-client-process`: `proposed_edge.relation: api-called`, parent_vertex type=process, classification=??? (candidates: dockerd | nerdctl | direct-API-client | other), anchor=containerd-socket-audit | containerd-access-log. The classification of this parent vertex *itself* gates which downstream anchor opens — if it resolves to dockerd, the dockerd-access-log becomes consultable for the next hop; if nerdctl, a different anchor; if a direct-API client with no audit, escalate.
- `?client-host-of-invoker`: `proposed_edge.relation: located-on`, parent_vertex type=endpoint, anchor=daemon-socket-binding | host-tag-registry.
- `?auth-context-of-invoker`: `proposed_edge.relation: authenticated-as`, parent_vertex type=identity, anchor=oncall-schedule | change-management-tickets.

Plus a true `attribute_predictions[]` on `v-001: root` (`loginuid_state ∈ {has-session, no-session}`, currently observed `-1` = no-session, attribute is *itself observed* from the alert body so the prediction lands at `++` immediately, but the resolution informs which `?auth-context-of-invoker` parent_vertex classification is plausible).

Each anchor's `on_unauthorized` / `on_indeterminate` policy should follow PR #88's 5710 pattern: `unauthorized → escalate`, `indeterminate → escalate`. ANALYZE then routes `unclear` cleanly when all three contracts return `unavailable`, with `trust_anchors_consulted: [...]` naming each anchor — analyst-facing signal points at *which observability gaps to close to make this signature investigable*, not "we tried our best."

This is the structural analog of the 5710 PR #88 rewrite and the same template generalizes to other thin-playbook signatures (100002, 100110, etc.) once the pattern is established.

## Method

1. Implement (1). Validate by running `eval_run_orchestrate.sh 100001 --window 5m` against scenario A and confirming `v-006: containerd` appears in `prologue.vertices` with `e-003: exec_invoked` from `v-006` to `v-003`. **Hard gate (not spot-check):** run the inference pass against 5710 and confirm no inferred vertex is appended (multiple legitimate generators of "SSH invalid user" exist — the discipline gate must hold). The negative case proves the gate works; the positive case alone does not.
2. Run the side experiment (below) to pick the PREDICT prompt variant. Implement the chosen variant. Validate by re-running 100001 and confirming PREDICT loop 1 names the three upstream-edge questions (one as a live hypothesis with prediction, the rest in `unknowns[]`) — not three competing scaffolds, and not a single fused "operator-runtime-exec" story.
3. Implement (3). Validate by re-running 100001 and confirming the consulted anchor lands in ANALYZE's `trust_anchors_consulted[]`, regardless of whether it resolves `authorized`/`unauthorized`/`unavailable`. Disposition should land `unclear` (anchor unavailable) or `benign` (anchor confirms authorized) cleanly, never `true_positive` from absence-of-surviving-benign.

### Side experiment: PREDICT prompt-variant calibration

Before landing change (2), run a controlled experiment to validate which "unknown as first class" framing actually moves PREDICT behavior in the right direction without breaking path-of-least-resistance. One variable per experiment (per `feedback_isolate_one_variable_in_experiments`).

- **Fixtures.** Pick 4-6 investigations spanning signatures (100001, 5710, 100110, others), domains (container-runtime, ssh-auth, file-integrity), and stages (loop-1 first emission vs. loop-2 after a refutation forces re-prediction). Each fixture is the full upstream context (alert + prologue + prior loops if any) injected into the agent — PREDICT runs fresh on the variant prompt.
- **Prompt variants.** 2-3 independent tweaks plus the current prompt as control. Each variant addresses one aspect of "unknown as first class" — candidates: (a) explicit attribute-vs-edge-extension classifier (the change-2 form), (b) named `unknowns[]` slot separate from `hypotheses[]` with a "name first, decide whether to scaffold second" prose, (c) frontier-decomposition step that lists open questions before any hypothesis is written. Variants must be independent (not bundled).
- **Scoring.** For each fixture × variant: (i) does it enumerate unknowns instead of inventing stories, (ii) does it correctly classify each unknown as attribute vs edge-extension, (iii) does it preserve path-of-least-resistance (one cheapest scaffold + the rest as unknowns, not n-way fork), (iv) does it route cleanly through ANALYZE downstream (no malformed-disposition cascade).
- **Decision rule.** Pick the variant with the best (i)+(ii)+(iii)+(iv) profile across the fixture set. If no variant dominates, prefer the smallest prompt-surface change. Document the losing variants and *why* they lost — the experiment artifact is as valuable as the chosen prompt.

## What "done" looks like

- Run #44 reproduction (same alert shape, scenario A) lands `disposition: unclear` (or `benign` if anchor coverage is added) with named anchors in `trust_anchors_consulted[]` and a `surviving_hypotheses` list that's structurally non-empty (each upstream-edge hypothesis held at its evidence-determined weight, not silently dropped).
- Mechanical-compose path certifies the report on first try (no fallback to Sonnet `report` subagent → no 300s timeout).
- 100001 playbook seeds are pattern-shaped, applicable as a template to other thin-playbook signatures.
- Discipline gate documented: when does mechanism-inference fire (single-generator) vs stay in PREDICT (mechanism-fork). Worked example pair: 100001 (fires) and 5710 (does not fire).

## Out of scope

- ANALYZE's `true_positive` routing rule — extracted to `tasks/analyze-true-positive-routing.md`. Required to fully close run #44's cascade class for ambiguous-fingerprint alerts where mechanism-inference correctly does *not* fire and the frontier legitimately stays open.
- `tasks/analyze-orchestrator-loop1-timeout.md` — the ANALYZE-prompt-trim work is independent of this redesign.
- `report` Sonnet fallback subagent timeout — separate task; this redesign reduces but does not eliminate fallback dispatches.
- Other signatures (100002, 100110, 5710): the same template applies, but evaluation work is per-signature.

## Files / pointers

- Run #44 forensic: `/tmp/soc-agent-orchestrate-eval/20260428-015059-rule100001/runs/29150147-51ee-4eb8-bb47-e9cdc4b9f6d1/`
  - `subagent_outputs/20260428T015253952300Z-contextualize-prologue-*.txt` — the prologue that stopped one inference step short
  - `subagent_outputs/20260428T015435915175Z-predict-*.txt` — PREDICT loop 1 emitting `?operator-runtime-exec` story
  - `investigation.md` — full record showing the cascade
- Schema reference: `soc-agent/knowledge/invlang/schema.md`
  - Lines 463-545 (5710 hypothesis example with `proposed_edge` + `authorization_contract`) — the template to generalize
  - Lines 86-114 (vertex/edge type/classification/relation vocabulary)
  - Lines 126-156 (Edge authorization, anchor_kind enum, grounding_kind enum)
  - Line 113: `authority.kind: siem-event | runtime-audit | authoritative-source` enum (the discipline gate for mechanism-inference)
- Subagent prompt files to edit:
  - `soc-agent/agents/contextualize-prologue.md` (change 1)
  - `soc-agent/agents/predict.md` (change 2)
  - `soc-agent/knowledge/signatures/wazuh-rule-100001/playbook.md` (change 3)
- Reference for the analog 5710 rewrite: PR #88 / commit 1318480 (v2.9 authority-consultation refactor — same primitive, different signature)
- testrun skill (run #44 entry): `/workspace/.claude/skills/testrun/SKILL.md` — see "Findings, ranked by leverage" in the run #44 row

## Discussion notes (preserved for context)

The user's framing in design discussion: "the issue is with the current hypothesis framing — it urges the agent to form stories on the unknown. The missing intermediary step is stating the unknowns, so we can decide which unknown to chase." Correct diagnosis. The fix is not to add a free-form unknowns-listing step (which would land back in story-formation territory under prompt pressure) — invlang already has the structured slots (`attribute_predictions[]` for true attributes, `proposed_edge` for upstream-edge questions). The framing fix is to make those slots the path-of-least-resistance for PREDICT's first turn via (a) confirmed mechanism inference removing the "what generated this" question from the frontier and (b) explicit branch-rule on whether each remaining open question is attribute-shaped or edge-extension-shaped.

User's correction on the attribute/vertex-edge distinction: "client origin isn't an attribute, but is a vertex connected through an edge (though you can look at edges as special attributes)." Adopted in the slot-discipline section above — strict separation, not interchangeable.
