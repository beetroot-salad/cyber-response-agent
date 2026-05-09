---
title: Defender learning loop V0 — orchestrator + stub author
status: doing
groups: defender, learning-loop
---

**Goal.** Wire completed defender runs into the actor → judge → findings-queue pipeline. This PR ships the orchestrator and a stub author; the real author is a follow-up. Scope is robustness lessons only — investigation-efficiency mechanics (gated lead-template additions, env caches, cost-shaping) are out of scope. Lead-execution *quality* lessons (too-narrow query, wrong window, missing dimension) are explicitly **in** scope.

**Non-goals (this PR).** Real author phase. Dedup mechanism. Author transaction model. `lessons.md` schema. Routing edge cases. Per-signature playbook layer. Invlang-keyed retrieval. Aggregation. CI gating. Auto-PR. Benign-defender mode. Sampling at the loop level (per-run API only).

## Prereq: report.md schema

Today's `report.md` files are heterogeneous. Structure what already exists:

```yaml
---
case_id: <run id>
disposition: benign | inconclusive | malicious
confidence: high | medium | low
---

# Disposition: <human label>

<one paragraph reason>
```

- `disposition` enum is closed. `benign` = confident clear. `inconclusive` = ran out of data, escalate (loop runs adversarial actor). `malicious` = confident escalate, story confirmed (loop skips at MVP).
- Defender SKILL.md REPORT phase updated to require this frontmatter; gather/judge prompts unchanged.
- Existing /tmp runs are not back-filled — they predate the schema and must be re-run before being fed to the loop. The normalizer parses YAML frontmatter only; missing/malformed frontmatter is a fail-loud error (no regex fallback).

## Prereq: judge YAML contract

`defender/learning/judge.md` revised to emit strict YAML (no markdown headers, no YAML-in-code-fence). Schema is a 1:1 mirror of the current judge sections — same field names, same semantics — with **one addition**: each `defender_findings` entry gains a `citations` list for downstream author repair. Outcome stays a single field whose first line is the enum keyword and subsequent lines are the rationale paragraph (no separate `outcome_rationale` key).

```yaml
outcome: |
  <enum on first line; rationale paragraph below>
encounter_analysis: |
  <multi-paragraph>
defender_findings:
  - type: lead-set | lead-quality | analyze-discipline | observability | detection-confirmed
    subject: <as defined in judge.md §subject rules>
    finding: |
      <one or two short paragraphs>
    citations:                 # NEW — only delta from current judge.md
      - {source: investigation | actor | alert, quote: "..."}
actor_observations:            # optional, omit key entirely if empty
  - type: misprediction | framing-choice | discarded-class
    subject: ...
    observation: |
      ...
confidence: |
  <one short paragraph>
```

Loop's parse step is plain `yaml.safe_load`; outcome enum validation is `outcome.split('\n', 1)[0].strip()`. Citations are structured for downstream author repair.

## Wiring

1. **`run.sh` stays scoped to defender runs only.**
2. **New `defender/learning/loop.py`.** Per-run-dir API: `loop.py <run_dir>`. Steps:
   - **Normalize disposition.** Parse `report.md` YAML frontmatter; **no regex fallback**. Fail-loud if frontmatter is missing/malformed or disposition is not in the closed enum. Skip case if disposition ∉ {`benign`, `inconclusive`}.
   - **Project actor input.** Invoke `defender/scripts/project_lead_sequence.py <run_dir> --actor-out <learning_run_dir>/actor_input.yaml` — the script projects `lead_sequence.yaml` down to `position + queries[].id + queries[].params` only (matches `defender/learning/actor.md`). The older `docs/actor-reviewer-learning-loop.md` text claiming `lead_description` is shown is stale — patched in this PR.
   - **Invoke actor.** Gray-box adversarial. Output → `actor_story.md`. If `SKIP:` line, persist it; loop continues to persistence, then exits this run with no findings.
   - **Invoke judge.** Inputs: `alert.json`, `investigation.md`, `actor_story.md`. Output → `judge_findings.yaml` (parsed against the YAML contract above; fail-loud on schema violation).
   - **Persist** per-run artifacts (see §Persistence).
   - **Filter + append.** For each finding in `defender_findings`: skip `detection-confirmed` (recorded for audit in `judge_findings.yaml` only, never queued); append the rest to `defender/learning/_pending/findings.jsonl`.
   - **Check threshold.** When pending count ≥ `LEARNING_AUTHOR_THRESHOLD` (default 5; env override), invoke the **stub author**.
3. **Sequential, one case at a time.**

## Persistence

Per-run learning artifacts persisted into the repo so author dedup and audit survive `/tmp` eviction:

```
defender/learning/runs/{run_id}/
  alert.json
  report.md
  investigation.md
  lead_sequence.yaml      # pre-projection
  actor_input.yaml        # projected for actor
  actor_story.md
  judge_findings.yaml
  source_refs.yaml        # {paths, normalized_disposition, alert_rule_key}
```

Skipped: `gather_raw/`, `tool_trace.jsonl` (large; judge quotes the load-bearing pieces; replay against the fixture if needed).

## `_pending/findings.jsonl`

`defender/learning/_pending/` is **git-ignored**. Stays in the working tree (durable across `/tmp` eviction, invisible to preflight).

One line per finding:

```json
{
  "schema_version": 1,
  "finding_id": "<run_id>/<n>",
  "run_id": "<run_id>",
  "alert_rule_key": "wazuh-rule-5710",
  "type": "lead-set | lead-quality | analyze-discipline | observability",
  "subject": "<from judge>",
  "finding": "<from judge, verbatim>",
  "judge_outcome": "caught | survived | undecidable | incoherent",
  "citations": [{"source": "...", "quote": "..."}],
  "source_run_dir": "defender/learning/runs/<run_id>/"
}
```

`detection-confirmed` excluded at append time. Author-side fields (`batch_id`, `consumed_at`, `consumed_commit`, dedup keys) are added in the follow-up author PR.

`alert_rule_key` derivation (POC-grade, vendor-neutral):

1. `rule.id` present → `rule-{id}` (or `{prefix}-rule-{id}` if a source prefix is obvious from the alert envelope).
2. `signature` present → use as the key after light slugify.
3. top-level `id` present → use as the key.
4. otherwise → `unkeyed`.

Formal vendor-shape detection deferred — POC accepts that the key is best-effort and the author can correct downstream.

## Stub author

When threshold met:

1. Log the batch (`finding_ids`, count, source_run_dirs) to stderr.
2. Exit cleanly with a marker line `LEARNING_AUTHOR_STUB: <count> findings ready, real author deferred to follow-up PR`.
3. **No edits, no transaction, no lock, no consumed-mark.** Findings stay in the queue; the next loop tick finds them again and re-stubs (idempotent by trivial means).

The follow-up PR replaces the stub with the real author and defines: `lessons.md` schema (freeform body, frontmatter limited to retrieval keys), dedup mechanism, transaction model (preflight scope, lock file, commit-then-mark), routing for observability findings with no covering system.

## Defender-side wiring (deferred to author PR)

Loading `lessons.md` from PLAN time happens once the author PR ships and produces real lessons. This PR doesn't touch `defender/SKILL.md`.

## Lesson taxonomy (informational)

Mirrors the judge's `type` field. Routing is the author PR's problem; the orchestrator just preserves the type verbatim from judge to queue.

| Judge type | Orchestrator handling |
|---|---|
| `observability` | append to queue |
| `lead-set` | append to queue |
| `lead-quality` | append to queue |
| `analyze-discipline` | append to queue |
| `detection-confirmed` | recorded in per-run yaml only; not queued |

## Graduation triggers (deferred)

Same as before — V0.5 split, V1 invlang retrieval, per-signature surface on recurrence, Haiku CI dedup reviewer.

## Done when

- `report.md` schema (frontmatter + closed enum) documented in `defender/SKILL.md` REPORT section and `defender/run_artifacts.md`.
- `defender/learning/judge.md` revised to emit strict YAML per the contract above; loop parses it with `yaml.safe_load`.
- `docs/actor-reviewer-learning-loop.md` patched so its lead-projection schema agrees with `defender/learning/actor.md`.
- `defender/learning/loop.py` runs end-to-end on at least 3 fresh defender runs (re-execute `defender/run.sh` against existing alert.json fixtures so report.md carries the new frontmatter), producing per-run `defender/learning/runs/{run_id}/` artifacts and appending non-`detection-confirmed` findings to `_pending/findings.jsonl`.
- Stub author fires once with `LEARNING_AUTHOR_THRESHOLD=3`, logs the batch, exits cleanly, leaves the queue intact.
- `_pending/` listed in `.gitignore`.
- Follow-up task file opened for the real author PR.
