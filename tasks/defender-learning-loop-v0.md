---
title: Defender learning loop V0 — thin orchestrator with flat lessons file
status: todo
groups: defender, learning-loop
---

**Goal.** Wire completed defender runs into the actor → judge → author pipeline and land robustness lessons back into the defender's knowledge surface. Improve robustness only — investigation-efficiency mechanics (e.g. gated lead-template additions vs ad-hoc query authoring, env caches, cost-shaping) are out of scope. Lead-execution *quality* lessons (too-narrow query, wrong window, missing dimension) are explicitly **in** scope — they're robustness-load-bearing.

**Non-goals.** Per-signature playbook layer. Invlang-keyed lesson retrieval. Aggregation across runs. CI gating. Auto-PR. Benign-defender mode (only adversarial actor exists today). Sampling at the loop level (per-run API only — wrappers handle subset selection).

## Prereq: report.md schema

Today's `report.md` files are heterogeneous (some have YAML frontmatter, some emit `# Disposition:` headings, some `## Disposition:`, casing varies). Before the loop is implementable, structure what already exists:

```yaml
---
case_id: <run id>
disposition: benign | escalate_low_conf | escalate_resolved | malicious_resolved
confidence: high | medium | low
matched_archetype: <slug or null>
---

# Disposition: <human label>

<one paragraph reason>
```

- `disposition` enum is closed and machine-checkable. `escalate_low_conf` = "ran out of data, escalate" (loop in scope). `escalate_resolved` / `malicious_resolved` = confident escalation (loop out of scope at MVP).
- Defender SKILL.md REPORT phase updated to require this frontmatter; gather/judge prompts unchanged.
- Existing /tmp runs are not back-filled — they're ephemeral. Loop's normalizer is best-effort for legacy reports (frontmatter → heading-regex → fail-loud and skip).

## Wiring

1. **`run.sh` stays scoped to defender runs only.** No learning-side responsibilities — the loop is invoked separately so judge replay doesn't require re-running the defender.
2. **New `defender/learning/loop.py`** (Python — multi-stage state + git operations are awkward in bash). Per-run-dir API: `loop.py <run_dir>`. Steps:
   - **Normalize disposition.** Parse `report.md` frontmatter; fall back to `^#+\s*Disposition:` regex; fail-loud if neither resolves. Skip case if disposition ∉ {`benign`, `escalate_low_conf`}.
   - **Project lead sequence for actor.** Strip `lead_description` and `result_ref` from `lead_sequence.yaml`; emit `actor_input.yaml` with `position + queries[].id + queries[].params` only (matches `defender/learning/actor.md` §schema). The older `docs/actor-reviewer-learning-loop.md` text claiming `lead_description` is shown is stale — patch it in this PR.
   - **Invoke actor.** Gray-box adversarial. Output → `actor_story.md`. If `SKIP:` line, persist it and stop (no judge, no findings).
   - **Invoke judge.** Inputs: `alert.json`, `investigation.md`, `actor_story.md`. Output → `judge_findings.yaml` (judge's native output shape).
   - **Persist** (see §Persistence below).
   - **Append** each finding to `defender/learning/_pending/findings.jsonl` (see §Schema below).
   - **Check pending count.** When ≥ `LEARNING_AUTHOR_THRESHOLD` (default 5; env override `LEARNING_AUTHOR_THRESHOLD` for tests / first exercise), invoke author phase.
3. **Sequential, one case at a time.** No concurrency at MVP.

## Persistence

Per-run learning artifacts are persisted into the repo so author dedup and audit survive `/tmp` eviction:

```
defender/learning/runs/{run_id}/
  actor_input.yaml        # projected lead sequence shown to actor
  actor_story.md          # actor output (or SKIP line)
  judge_findings.yaml     # judge output (full, native shape)
  source_refs.yaml        # {alert_path, investigation_path, lead_sequence_path, normalized_disposition}
```

`alert.json`, `investigation.md`, `gather_raw/*` stay ephemeral in `/tmp` — they're large and the judge's `judge_findings.yaml` already quotes the load-bearing pieces. If a future audit needs raw evidence beyond what the judge quoted, the case is replayed by re-running the defender against the same fixture.

## `_pending/findings.jsonl` schema

One line per finding (judge may emit multiple per run):

```json
{
  "schema_version": 1,
  "finding_id": "<run_id>/<n>",
  "run_id": "<run_id>",
  "alert_rule_key": "wazuh-rule-5710",
  "type": "lead-set | lead-quality | analyze-discipline | observability | detection-confirmed",
  "subject": "<as emitted by judge — lead position / system path / inference rule>",
  "finding": "<judge finding body, verbatim>",
  "judge_outcome": "caught | survived | undecidable | incoherent",
  "citations": ["<refs from judge §2 encounter analysis>"],
  "source_run_dir": "defender/learning/runs/<run_id>/",
  "batch_id": null,
  "consumed_at": null,
  "consumed_commit": null
}
```

`batch_id`, `consumed_at`, `consumed_commit` are populated only on successful author commit (see §Author transaction). Author dedup keys on `(type, subject)` against current `lessons.md` and `defender/skills/{system}/SKILL.md` visibility sections.

## Author phase

Triggered by loop when pending count ≥ `LEARNING_AUTHOR_THRESHOLD`.

### Routing

| Judge type | Subject shape | Land where |
|---|---|---|
| `observability` | system path under `defender/skills/{system}/` | edit that system's SKILL.md visibility section |
| `observability` | "no system covers this" + system is deployment-real | **fail-loud, queue for human review** — do not auto-create system docs |
| `observability` | system is `not-deployed` / `deployment-unknown` | append to `lessons.md` generic "deployment gaps" section |
| `lead-set` | lead position / "no lead exists" | `lessons.md`, per-rule, "lead-selection rules" subsection |
| `lead-quality` | lead position | `lessons.md`, per-rule, "lead-execution rules" subsection |
| `analyze-discipline` | inference rule | `lessons.md`, generic section if cross-signature; per-rule if narrow |
| `detection-confirmed` | — | drop at MVP (future: fixture-seed corpus) |

### Rule-key extraction

Used to derive `alert_rule_key` and the per-rule lessons section. Fallback chain on `alert.json`:

1. `rule.id` numeric + Wazuh-shaped alert → `wazuh-rule-{id}`
2. `rule.id` present (any source) → `{source_slug}-rule-{id}` if source identifiable, else `rule-{id}`
3. `signature` field → slugify
4. top-level `id` → slugify
5. otherwise → `unkeyed` (lessons land in generic section)

### Author transaction

1. Preflight: `git status --porcelain` must be empty for tracked files; fail-loud otherwise (refuses to commit unrelated dirty state).
2. Read `_pending/findings.jsonl`, take the first batch (all pending findings up to a cap, e.g. 20).
3. Read current `lessons.md` and any system SKILL.md files referenced in routing for dedup context.
4. Read `git log -p` since the last learning commit (touching `defender/learning/lessons.md` or `defender/skills/*/SKILL.md`) for prior-edit context.
5. Stage edits via `git add` of only the files written; no `git add -A`.
6. `git commit` with batch_id in the message (`learning: batch <batch_id> — N findings`).
7. **Only after commit returns 0**, mark consumed entries in `findings.jsonl` (rewrite the file with `batch_id`, `consumed_at`, `consumed_commit` filled). Crash before this step → idempotent retry on next loop tick (same findings re-batch, same edits — author prompt should be deterministic enough that the dedup re-converges; if not, human resolves).
8. No PR auto-open. Author commits to current branch; human reviews via normal git workflow.

## Defender-side wiring of `lessons.md`

- Flat markdown at `defender/learning/lessons.md`. Sections keyed by `alert_rule_key` (per the extraction chain above), plus a top "generic" section for cross-signature analyze discipline and a "deployment gaps" section.
- `defender/SKILL.md` adds one bullet: at PLAN entry, `Skill` (or Read) the lessons file. Only PLAN-time loading at MVP — REPORT-time deferred.
- Size budget: when the file exceeds ~30 sections or token cost becomes load-bearing, graduate to V0.5 (per-file `lessons/{slug}.md` + frontmatter + grep retrieval).

## Lesson taxonomy at V0

Mirrors the judge's `type` field one-to-one. See routing table above for surfaces.

## Graduation triggers (deferred work)

- ≥ ~10 lessons + visible clustering by archetype/hypothesis-shape → V0.5 split.
- ≥ ~30 lessons → invlang-predicate top-k retrieval (V1).
- Recurrent signature-specific lessons on a single rule → `defender/skills/signatures/{rule_key}.md` + ORIENT-time load-on-match.
- Author dedup degradation → Haiku CI reviewer for dup/bloat on `lessons.md`.

## Done when

- `report.md` schema (frontmatter + closed disposition enum) documented in `defender/SKILL.md` REPORT section and in `defender/run_artifacts.md`.
- `defender/learning/loop.py` runs end-to-end on at least 3 of the existing /tmp runs (those whose disposition normalizes), producing per-run `defender/learning/runs/{run_id}/` artifacts and appending to `_pending/findings.jsonl`.
- Author phase fires once with `LEARNING_AUTHOR_THRESHOLD=3` and produces a real edit to `defender/learning/lessons.md` and/or a `defender/skills/{system}/SKILL.md` visibility section. Transaction contract (preflight + commit-before-mark) verified by a deliberate mid-author crash test.
- `defender/SKILL.md` references `defender/learning/lessons.md` as a PLAN-time load.
- `docs/actor-reviewer-learning-loop.md` updated so its lead-projection schema agrees with `defender/learning/actor.md` (drop `lead_description` from the gray-box reveal).
- One end-to-end loop pass committed to a branch, ready for human review.
