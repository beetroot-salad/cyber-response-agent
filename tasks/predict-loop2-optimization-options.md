---
title: PREDICT loop-2 wall-time optimization — option inventory
status: doing
groups: predict, performance, context management
---

> **Update 2026-04-25:** Lever H (`effort: low`) shipped — added to `agents/predict.md` frontmatter. -61% to -82% wall reduction across 4 fixtures, e2e bait scenario clean. See §H. Remaining open levers (A trim, D shape-first, C skill-style §Shapes, E CLI fallback ladders) tracked under sequence below; status remains "doing" until lever A is also evaluated.

# Context

Run `20260424-115003-rule100001` (session `7e045002`), post-lever-1 (signature-knowledge already dropped from the predict preload):

| | Loop 1 | Loop 2 |
|---|---|---|
| Wall | ~92s | **314.5s** (timeout territory) |
| Preload chars | ~6KB | **25,426** |
| Output chars | ~2KB | 5,803 |
| Largest single thinking block | small | **31,177 chars** (Turn 1) |

Forensics in `tasks-scratch/predict-loop2-thinking-20260424.md`. The loop-1 driver that lever-1 killed (signature-knowledge restatement-and-reconcile) has reappeared on loop 2 — now attached to the accumulated `investigation.md` state instead of `<signature-knowledge>`. The 31K-char Turn-1 thinking block re-litigates resolved questions: Shape A vs M vs I (3×), 100002 SSH composition rule (3-4×), ci-pipeline-exec vs operator-runtime-debug (3×), integrity peer (2×), process-lineage as the right lead (4×).

**Driver:** prompt size ↔ Sonnet's upfront restatement, scaling super-linearly with "how much the prompt asks the model to hold in mind". Not a real reasoning loop on hard evidence.

# Optimization options

Ordered by ROI on loop-2. Each option is independent unless noted.

## A. Investigation.md loop-N preload trim *(highest value, gating)*

The `<investigation>` block currently concatenates every prior phase's full output. After 1 loop on a thick signature (e.g. 100001) that's already ~20KB on top of the ~6KB static prompt.

| In current loop-2 preload | Load-bearing for predict? | Action |
|---|---|---|
| CONTEXTUALIZE prologue (vertices/edges) | Yes — defines the proposed-edge anchor | Keep |
| Latest ANALYZE narrative + weights | Yes — defines what's still open | Keep |
| Per-lead outcome summary | Yes — needed to know what's exhausted | Keep, condensed to 1-2 lines/lead |
| Loop-1 raw GATHER observations (Wazuh hits, host_query process tables) | **No** — ANALYZE already extracted what mattered | **Drop** |
| Inline assessment prose duplicating ANALYZE conclusions | No | Drop |
| Already-resolved composition-rule discussion | No, but currently re-triggers re-litigation | Drop or mark `resolved` |

Estimated cut: 25KB → ~10-12KB. Applies to predict, analyze, and conclude (same growth pattern in all three). Generalizes meta-finding #22 from the testrun skill.

## B. Mirror-Sonnet-voice prompt rewrite — **REFUTED**

Hypothesis tested (and rejected): rephrasing the prompt in Sonnet's own first-person running-thought voice would shortcut the restatement pass.

Result on `shape-i-loop2-post-enrichment` fixture, 3 reps each, prompt size held constant (28,714 vs 28,718 chars):

| Variant | Mean | Stdev | Min | Max | Stdout mean |
|---|---|---|---|---|---|
| baseline | 160.3s | 70.3 | 98.4 | 236.7 | 2,223 |
| voice-mirror | 218.6s | 146.1 | 111.0 | **384.9** | 2,942 |

Voice-mirror is +36% slower on mean and 2× the variance, with worst-case 384.9s (exceeds baseline worst by ~150s). Stdout +32% on voice-mirror — the first-person framing invited *more* mirroring in output, not less.

**Refuting reading:** Sonnet's restatement isn't a stylistic translation pass — it's a content-reconciliation pass driven by prompt size + ambiguous input. Voice doesn't shortcut it. Skip this lever.

Artifacts: `soc-agent/experiments/predict-rewrite/predict.voice-mirror.md`, `run_voice_mirror.py`, `voice-mirror-output/`.

## C. Skill-style §Shapes refactor

Static `agents/predict.md` body still carries 5 abstract shape descriptions (~half the static prompt). Only Shape I has a worked example. Move to retrieval pattern (mirroring lever-1):

| Currently inlined | Skill-style replacement |
|---|---|
| 5 shape descriptions | 1-paragraph decision table → `Read knowledge/predict-shapes/<letter>.md` for the matched shape |
| 12-bullet §Disciplines | 3-bullet "always true" + per-shape inline callouts on the example file |
| Worked YAML example for Shape I | Per-shape example file, loaded only on commit |
| §Output format prose | 5-line skeleton + reference to per-shape example |

Retrieval cost: 1 Read (~2-5s) only for the shape that fires. Saved restatement is much larger. Composes additively with A.

## D. Shape-letter as first output token *(lever 2 from optimization doc)*

`agents/predict.md` §Output format: prepend `**Shape:** <letter> — <one-line trigger>` as the literal first line of output, before the YAML fence. Forces commitment, shrinks restatement to fields relevant to the chosen shape. ~30-60s saving estimated. Defer until A/B/C land so the baseline is stable.

## G. Persistent per-phase subagent sessions via `--resume` — **REFUTED**

Hypothesis tested 2026-04-25: `--resume <session_id>` would preserve in-context cache across calls, letting predict-loop-2 reason on a delta instead of re-reading the full investigation.md.

**Empirical test:** resumed session 66e900f2 (prior predict subagent run, final cache_read=49,407) twice with trivial follow-up prompts. Both resumed turns showed:
- t5: `cache_create=37,291, cache_read=11,634`
- t6: `cache_create=37,326, cache_read=11,634`

Identical cache_read on both resumes. If `--resume` had preserved cache, t5 should have shown cache_read ≈ prior 49K + new content. Instead the entire conversation was treated as fresh input and re-cached from scratch on every resume. The only `cache_read` is the cross-session Claude Code internal prefix (smaller without `--plugin-dir`), not our content.

**Conclusion:** `--resume` is wall-clock equivalent to starting a fresh session and replaying — actually WORSE because it pays the full conversation as input on every call, plus cache_creation cost. **Skip lever G.**

The only way to preserve in-context cache across calls under `claude -p` is to keep one process alive and pipe sequential turns to it — not supported by `claude -p`'s one-shot model. The remaining path is F2 (direct SDK with explicit `cache_control` markers on a conversation array we manage ourselves).

## H. Thinking effort = low — **CONFIRMED, biggest single win**

`_subagent.py:215` already supports `--effort` from frontmatter `effort:` or env `SOC_AGENT_{AGENT}_EFFORT`. Tested 2026-04-25 with `SOC_AGENT_PREDICT_EFFORT=low` on `shape-i-loop2-post-enrichment` fixture, 3 reps:

| Variant | Mean | σ | Min | Max |
|---|---|---|---|---|
| baseline default | 160.3s | 70.3 | 98.4 | 236.7 |
| **baseline + effort=low** | **62.3s** | **6.6** | 56.2 | 69.4 |

**−61% wall mean, −91% variance.** All 3 reps:
- Parse cleanly through `parse_predict_output` ✓
- Validate cleanly through `validate_companion` (invlang PreToolUse hook) ✓
- Pick Shape A with 1 hypothesis ✓ (correct for this fixture per predict.md's worked example)
- Pick `selected_lead = monitoring-probe` ✓ (exact match to worked example)
- Output sizes 2,003 / 2,315 / 2,616 chars (vs 2,223 default-effort mean — no truncation)

**Mechanism:** the stochastic restatement-spiral that drove default-effort variance (run-to-run band 90s-300s) disappears at effort=low. Output is structurally identical, just much less thinking-block latency.

**Validation matrix — all gates clear (2026-04-25):**

Synthetic harness (3 reps each, n=4 fixtures total):
| Fixture | Default | effort=low | Δ |
|---|---|---|---|
| shape-i-loop2-post-enrichment (rule-5710 loop 2) | 160.3s | 62.3s (σ 6.6) | −61% |
| shape-a-runc-exec (rule-100001 loop 1, thick playbook) | 263.8s | 92.5s (σ 24.8) | −65% |
| shape-i-monitoring-probe (rule-5710 loop 1 benign) | 149.0s | 36.9s (σ 3.3) | −75% |
| shape-i-bait-5710 (rule-5710 loop 1 synth bait) | 228.1s | 42.0s (σ 11.4) | −82% |

All 12 effort-low outputs parser-clean + invlang-validator-clean. No quality regression.

E2E orchestrator run (`/tmp/soc-agent-orchestrate-eval/20260425-185339-rule5710/`, 5710 bait, full 2-loop):
- Predict loop 1: 32.2s, loop 2: 117.7s (vs documented 314s default-effort loop-2 baseline → −63%)
- Trajectory: CONTEXTUALIZE → SCREEN → PREDICT → GATHER → PREDICT → GATHER → ANALYZE → REPORT, exit 0, hooks passed
- Disposition: `escalated / unclear / low / monitoring-probe` — exemplary bait handling. Anchor `approved-monitoring-sources` returned `confirmed` but the agent correctly escalated due to cadence deviation from the archetype's defining baseline. Zero-false-negative behavior preserved.
- ANALYZE downstream graded effort=low predict hypotheses without issue; REPORT composed coherent escalation.

**SHIPPED 2026-04-25** — `effort: low` added to `agents/predict.md` frontmatter. Single-line change; reversible by removing the frontmatter line. Other Sonnet phases (analyze, conclude, report_narrative) deferred — same restatement pathology likely applies but each needs its own validation.

Artifacts: `soc-agent/experiments/predict-rewrite/{run_effort_low.py, run_h_validation.py, effort-low-output/, h-validation-output/}`, e2e run at `/tmp/soc-agent-orchestrate-eval/20260425-185339-rule5710/`.

## E. Absorb query fallback ladders into GATHER/CLI *(orthogonal, full-loop save)*

Not a predict-prompt optimization but the highest remaining full-loop wall-clock save. Recoverable field-path / indexing mismatches currently cost an entire predict→gather→analyze cycle (run #44: ~396s). Move the fallback ladder (rule-only probe → coverage probe → known aliases) into the lead definition and `wazuh_cli.py`. Only return `data_missing` after the ladder is exhausted.

## F. Cache-friendly user-prompt ordering — **largely moot under `claude -p`**

Empirical cache-telemetry analysis 2026-04-25 (extracted from `~/.claude/projects/-workspace/<session>.jsonl` across the 6 voice-mirror predict reps) shows:

- **Caching is automatic** — no markers needed, Claude Code injects `cache_control` server-side.
- **TTL is 1h** (`ephemeral_1h_input_tokens` populated, `ephemeral_5m` always 0).
- **Within a single subagent invocation, caching is already maximal** — turn 0 creates ~21K tokens, final turn reads back ~44-49K. The model pays full input rate only on turn 0.
- **Cross-session cache is limited to Claude Code's own internal prefix (~18,266 tokens** — built-in tools, `--plugin-dir` defs, claude-code boilerplate). Rep 1 and rep 2 with byte-identical user prompts both showed turn-0 cache_read = 18,266, NOT ~49K. Our user prompt + our agent system prompt do NOT cross-session cache.
- **The 31K-char turn-0 thinking block happens BEFORE any of our content lands in cache.** It's a reasoning cost, not an input-evaluation cost. Caching cannot shrink it.

**Implication:** F1 (reordering for cache-friendliness) is essentially moot under `claude -p` — within-spawn caching already works, and cross-spawn cache doesn't include our content anyway. **Skip F1.**

**F2 — direct SDK migration:** `anthropic.messages.create` with explicit `cache_control` markers MIGHT enable cross-call cache on our stable prefix (signature-knowledge + lead-catalog + alert), which `claude -p` does not. This is a **token-cost** lever, not a wall-time lever — turn-0 reasoning cost remains. Pursue only if token spend becomes the bottleneck. Costs the `--plugin-dir` hook integration unless reimplemented in the wrapper.

**Staleness ranking (kept for reference, in case F2 is pursued — most stale → least stale):**

| Rank | Block | Scope of stability |
|---|---|---|
| 0 | System prompt (`agents/predict.md` body) | only changes on agent-file edit; passed via `--system-prompt-file` |
| 1 | Lead catalog | global — stable across every signature, every loop |
| 2 | Signature knowledge | per-signature within a run |
| 3 | Alert + salt | per-run |
| 4 | run_dir + signature_id (header line, stable portion) | per-run; **must be split from loop_n** |
| 5 | Env memory | depends on env-topology; mostly stable |
| 6 | Investigation.md | grows monotonically per loop (also see lever A) |
| 7 | Past-investigation priors | per-frontier (changes every loop) |
| 8 | loop_n | per-loop |
| 9 | remediation_notes (retry only) | per-attempt |

**Concrete edits:**
1. Split the `run_dir / signature_id / loop_n` block into two — stable pair into the cacheable prefix, `loop_n=N` alone into the mutable tail.
2. Reorder `_assemble_prompt`'s `blocks` list to: lead-catalog → signature-knowledge → alert → run_dir+signature_id → env-memory → loop_n → priors → investigation → remediation_notes.
3. Note: `run_dir` is referenced by `agents/predict.md:323,339` (`{run_dir}/subagent_checkpoints/...` and `{run_dir}/investigation.md`) so it cannot be omitted, only repositioned.


# Sequence (revised after 2026-04-25 testing)

1. ~~B (mirror-voice trick)~~ — **refuted**, see §B.
2. ~~F1 (cache-friendly reorder)~~ — **moot**, see §F.
3. ~~G (`--resume` persistent sessions)~~ — **refuted**, see §G.
4. **H (thinking-effort=low) — SHIP FIRST.** −61% wall, −91% variance, validator-clean on loop-2 fixture. Validate on loop-1 fixture + thicker-playbook signature, then add `effort: low` to `agents/predict.md` (and probably `analyze.md` + `conclude.md`).
5. **A (investigation.md loop-N trim)** — still warranted; cuts orthogonal cost. Smaller marginal value over H but compounds.
6. **D (shape-first output)** — small lift, defer until H+A baseline.
7. **C (skill-style §Shapes)** — bigger refactor; revisit only if 4+5+6 don't close the gap.
8. **E (CLI fallback ladders)** — orthogonal; pursue independently for full-loop saves.
9. **F2 (direct SDK migration)** — token-cost lever only, not wall-time.

# Open questions

- Does the `investigation.md` trim regress quality when an old GATHER observation turns out to be load-bearing two loops later? Probe: keep raw observations behind a `Read knowledge/runs/<run>/loop-N-gather.md` escape hatch.
- Does mirror-voice over-anchor the model on a single reasoning trajectory captured from one fixture? Probe: validate B on a second fixture (e.g. shape-a-runc-exec, shape-m-dns-entropy) before generalizing.
- Does shape-first output cause over-commitment when the shape is genuinely ambiguous? Counter: decision procedure already says "stop at first match".
