---
title: Defender learning loop V0 — thin orchestrator with flat lessons file
status: todo
groups: defender, learning-loop
---

**Goal.** Wire completed defender runs into the actor → judge → author pipeline and land robustness lessons back into the defender's knowledge surface. Improve robustness only — investigation-efficiency mechanics (e.g. gated lead-template additions vs ad-hoc query authoring, env caches, cost-shaping) are out of scope. Lead-execution *quality* lessons (too-narrow query, wrong window, missing dimension) are explicitly **in** scope — they're robustness-load-bearing.

**Non-goals.** Per-signature playbook layer. Invlang-keyed lesson retrieval. Aggregation across runs. CI gating. Auto-PR. Benign-defender mode (only adversarial actor exists today).

## Wiring

1. **`run.sh` stays scoped to defender runs only.** No learning-side responsibilities.
2. **New `defender/learning/loop.py` (or `loop.sh`, whichever is more convenient).** Takes a completed run dir (`alert.json` + `investigation.md` + `lead_sequence.yaml` + `report.md`) and:
   - Gates on disposition: only runs when `report.md` disposition ∈ {benign, inconclusive/escalate-low-confidence}. Skip resolved-malicious cases at MVP.
   - Sampling decision (run all vs subset) is made at loop-execution level, not per-run.
   - Invokes the actor (gray-box adversarial, sees `alert.json` + lead_sequence with descriptions/results redacted per `defender/learning/actor.md`).
   - If actor emits `SKIP`, stops.
   - Invokes the judge (`defender/learning/judge.md`) on alert + investigation + actor story. Writes `findings.yaml` next to the run.
   - Appends each finding to a checkpoint file: `defender/learning/_pending/findings.jsonl` (in-repo, survives /tmp eviction; the only durable artifact at MVP).
   - Checks pending count. When ≥ N (start with N=5; tunable), invokes the author phase.
3. **All run-side artifacts remain ephemeral in `/tmp/defender-runs/{run_id}/`.** Only `findings.jsonl` and the lessons file are repo-persistent. Replay of actor/judge requires the run dir still exist.
4. **Sequential, one case at a time.** No concurrency at MVP.

## Author phase

1. Triggered by loop when checkpoint count ≥ N.
2. Reads `_pending/findings.jsonl` plus `git log -p` of recent edits to the lessons file (dedup context).
3. Routes each finding by judge `type` (the 5-way split from `defender/learning/judge.md`):
   - `observability` → edit `defender/skills/{system}/SKILL.md` visibility surface (already exists from PR #189). Names a system path; the system doc is the natural home.
   - `lead-set` (gap — no lead exists) → append to **`defender/learning/lessons.md`**, per-rule section, "lead-selection rules" subsection.
   - `lead-quality` (existing lead too weak — narrow query, wrong window, missing dimension) → append to `defender/learning/lessons.md`, per-rule section, "lead-execution rules" subsection. **Co-located with `lead-set` because they're authored against the same dispatch contract.**
   - `analyze-discipline` (defender reasoning failure) → append to `defender/learning/lessons.md`, generic section if cross-signature; per-rule section if it only fires for that rule's archetype.
   - `detection-confirmed` → drop at MVP (future: fixture-seed corpus).
4. Author commits the edits and deletes consumed entries from `_pending/findings.jsonl`.
5. No PR auto-open at MVP — author commits to the current branch and stops; human reviews via normal git workflow.

## Defender-side wiring of `lessons.md`

- Flat markdown file at `defender/learning/lessons.md`. Sections keyed by `alert.rule.id` plus a top "generic" section for cross-signature analyze discipline.
- `defender/SKILL.md` adds one bullet: at PLAN entry, `Skill` the lessons file (or Read it) — this is the only stage where lead-choosing lessons can change behavior. REPORT-time loading deferred.
- Size budget: when the file exceeds ~30 sections or token cost becomes load-bearing, graduate to V0.5 (per-file `lessons/{slug}.md` + frontmatter + grep retrieval). Re-key empirically once we can read clusters off the existing corpus.

## Lesson taxonomy at V0

Mirrors the judge's `type` field one-to-one (no re-bucketing — keeps the loop's emit/consume contract stable):

| Judge type | Land where | Example from existing /tmp runs |
|---|---|---|
| `observability` | `defender/skills/{system}/SKILL.md` visibility section | bastion not Wazuh-enrolled (pilot-01/02); DNS srcip masked by dnsmasq (real-04) |
| `lead-set` | `lessons.md`, per-rule, "lead-selection rules" | for bastion key-match, cross-host auth-history + outbound-pivot leads must run before any benign clearing |
| `lead-quality` | `lessons.md`, per-rule, "lead-execution rules" | a 5710 monitoring-probe lead that pulls only the alert-time window misses the cadence pattern — needs ≥7d window with bucketing |
| `analyze-discipline` | `lessons.md`, generic section (or per-rule if narrow) | `loginuid=-1` does not prove non-human; key-match + corp-internal is not sufficient to clear |
| `detection-confirmed` | drop at MVP | (future: fixture-seed corpus) |

`lead-set` and `lead-quality` are the most discriminating classes — they directly shape the next investigation's contract. They share the per-rule section in `lessons.md` because both are authored against the same dispatch contract (`lead_description` + bound `queries[]`).

## Graduation triggers (deferred work)

- ≥ ~10 lessons in `lessons.md` and visible clustering by archetype/hypothesis-shape → split to per-file + frontmatter (V0.5).
- ≥ ~30 lessons → introduce invlang-predicate top-k retrieval keyed off the current `investigation.md` state (V1).
- Recurrent signature-specific lessons on a single rule → introduce `defender/skills/signatures/{rule-id}.md` and an ORIENT-time load-on-match.
- Author dedup degradation → add a Haiku CI reviewer for dup/bloat checks on the lessons file.

## Open questions

- Does the loop run inline at the end of `run.sh` (one driver, simpler) or as a separate `loop.py` invocation against an existing run dir (better for replay)? Current preference: separate, so re-running judge with a new prompt doesn't require re-running defender.
- Default checkpoint N (5? 10?) and where to set it — env var vs config constant.
- Sampling at loop-execution level: process every benign/inconclusive run, or sample a fraction? Defer until volume forces it.

## Done when

- `defender/learning/loop.py` (or `.sh`) runs end-to-end on at least 3 of the existing /tmp runs and produces `findings.yaml` per run + appends to `_pending/findings.jsonl`.
- Author phase fires once on N=3 (lowered for first exercise) and produces a real edit to `defender/learning/lessons.md` and/or a `defender/skills/{system}/SKILL.md` visibility section.
- `defender/SKILL.md` references `defender/learning/lessons.md` as a PLAN-time load.
- One end-to-end loop pass committed to a branch, ready for human review.
