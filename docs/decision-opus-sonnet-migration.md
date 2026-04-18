# Decision: Main Agent Model Migration (Opus → Sonnet)

**Date:** 2026-04-12
**Status:** Proposed — pending empirical validation
**Context:** Run #9 cost split: Opus main $1.86 (82%), Sonnet ticket-context $0.29, Haiku screen+precedent $0.13. Total $2.28. Main-agent Opus dominates cost.

---

## Two Approaches

### Approach 1: Sonnet main + mandatory Opus consultations

Sonnet runs the investigation loop. Opus is called as a reasoning-only subagent at structurally-enforced decision points. Hooks block state transitions without a recorded consultation.

**Mandatory consultation points:**
- HYPOTHESIZE→GATHER — "Which lead is most diagnostic given these hypotheses?"
- ANALYZE decision — "Is the adversarial hypothesis genuinely refuted? Loop or conclude?"
- Pre-CONCLUDE — "Does the evidence support this disposition?"

**Enforcement:** `write_state.py` checks `tool_audit.jsonl` for a recorded Opus consultation before allowing gated transitions (same pattern as `check_ticket_context_spawned`).

### Approach 2: Lean Opus main + delegated subtasks

Opus stays as the main agent. Cost reduction comes from offloading mechanical work: hook-based CONTEXTUALIZE preload (Stage 1), Sonnet report drafter (Stage 2), existing Sonnet/Haiku subagents.

---

## Cost Estimates

Anchored on run #9 ($2.28 total, full investigation with SCREEN no-match, 2 loops) and run #7 ($0.63, SCREEN-resolved baseline).

| Scenario | Current | Approach 1 | Approach 2 |
|---|---|---|---|
| Full investigation | $2.28 | ~$1.55 | ~$2.00 |
| SCREEN-resolved | $0.63 | ~$0.35–0.55 | ~$0.50 |
| Savings (full) | — | ~30% | ~12% |
| Savings (SCREEN) | — | ~15–45% | ~20% |

**Approach 1 cost breakdown (full):** Sonnet main ~$0.50, 5 Opus consultations ~$0.60 (with prompt caching), subagents $0.42, judge $0.05.

**Approach 2 cost breakdown (full):** Opus main (lean, ~18 turns vs ~27) ~$1.30, hook preload $0.12, report drafter $0.12, subagents $0.42, judge $0.05.

**Speed:** Approach 1 adds ~2–3 min (consultation latency). Approach 2 saves ~1 min (hook preload). Net difference: Approach 2 is ~3–4 min faster on full investigations.

---

## Silent Sonnet Failure Modes

The dangerous case is correct-format, plausible-narrative, wrong-conclusion output.

| # | Failure | Severity | Caught by consultation? | Caught by existing hooks? | Commonality |
|---|---|---|---|---|---|
| 1 | **Premature adversarial dismissal** — refutes threat hypothesis on surface pattern, not discriminating evidence | Critical | Yes (ANALYZE consultation) | Partially (Tier 2 ADVERSARIAL_CHECK) | High (~20–40%) |
| 2 | **Suboptimal lead selection** — picks non-diagnostic lead | Costly, not dangerous | Yes (HYPOTHESIZE consultation) | No | Moderate (~15–25%) |
| 3 | **Forced archetype fit** — resolves to closest archetype despite unexplained features | High | Yes (CONCLUDE consultation) | Yes (Tier 2 COMPLETENESS) | Low–moderate |
| 4 | **Shallow evidence characterization** — misses subtle pattern in SIEM results | High | No — Opus reasons from same summary | No | **Already exists** (leads already run by Sonnet) |
| 5 | **Coherence decay over 20+ turns** — investigation.md becomes self-contradictory | Medium | Partially (consultation reads full log) | Partially (Tier 2 INTERNAL_CONSISTENCY) | Unknown |
| 6 | **Premature CONCLUDE** — concludes with undifferentiated hypotheses | High | Yes (ANALYZE consultation) | Yes (Tier 2 EVIDENCE_SUFFICIENCY) | Moderate |

**Key finding:** Failure #1 (premature adversarial dismissal) is the highest-risk and most frequent. It's caught by the mandatory ANALYZE consultation but not reliably by the post-hoc judge alone.

**Key finding:** Failure #4 (shallow characterization) is the one blind spot neither approach addresses — but it already exists in the current architecture since lead subagents already run on Sonnet.

---

## Assessment

**Approach 1 is the better cost lever.** Saves 2–3x more than Approach 2. The failure modes are mostly catchable by mandatory consultations + existing hooks. The one uncatchable failure (#4) is not a new risk.

**Approach 2 is more robust but the margin is thinner than it appears.** Most safety comes from hooks and the judge, not from Opus being the main agent. The cost savings are modest (~12%).

**The residual risk in Approach 1** is "coherent confabulation" — Sonnet writes a plausible narrative, the Opus consultation reasons from that narrative and agrees, the judge passes the well-formatted report. Mitigation: feed the consultation raw evidence observations from lead subagent returns, not just Sonnet's summary.

---

## Open Questions (resolve before committing)

1. **Run Sonnet-only on 3–5 scenarios without any consultant.** Read the investigation logs manually. How often does failure #1 actually fire? This determines whether the consultation architecture is necessary or over-engineering.

2. **Measure actual alert volume.** At low volume, $2.28/run may be tolerable and Approach 2's simplicity wins. The break-even depends on whether the ~$0.70/run savings × volume justifies the engineering complexity.

3. **Is an upgraded Tier 2 judge sufficient alone?** Promoting the judge from Haiku to Sonnet (or Opus) at CONCLUDE — without any mid-loop consultations — is dramatically simpler. The gap: the judge is post-hoc and can't fix bad lead selection earlier in the loop.

4. **Prompt caching for `claude --print` subprocesses.** Verify that the 3-layer caching structure (stable methodology prefix → per-run signature context → per-consultation question) actually achieves cache hits in practice. If caching doesn't work for CLI subprocesses, each consultation costs ~$0.20 instead of ~$0.12, which narrows the cost advantage.

---

## Recommended Next Steps

1. **Empirical validation first.** Run Sonnet-only (no consultant) on existing eval scenarios. Count failure #1 occurrences. This is 2 hours of work and determines the whole direction.
2. **Ship Stage 1 (hook-based CONTEXTUALIZE preload) regardless.** It's independently valuable, zero capability risk, and benefits both approaches.
3. **If Sonnet fails frequently → Approach 1.** Build the consultation prompt template, dispatch script, and enforcement hooks.
4. **If Sonnet is surprisingly competent → skip consultations**, upgrade the Tier 2 judge model, and pocket the savings from a straight model flip.
5. **If cost pressure is low → Approach 2.** Ship Stages 1–2 for modest savings with zero capability risk.

---

## Session 2026-04-13 — Empirical validation + plan revision

Status update after running the empirical validation the "Recommended Next Steps" called for. Original decision-doc proposal was "Sonnet main + 3 mandatory Opus consultations (HYPOTHESIZE / ANALYZE / pre-CONCLUDE)." Validation data substantially revises the recommendation.

### What was tested

**Two structured sanity-check subagent runs** (pre-modification, Sonnet only, no live harness):
- **HYPOTHESIZE sanity check on 5710** — Sonnet produced mechanism-shaped hypotheses across 3 synthetic alerts, maintained adversarial discipline, picked correct most-diagnostic leads. One weakness: bundling (collapsing variants into single hypotheses).
- **ANALYZE sanity check on 5710** — Sonnet held adversarial at `--` only on authoritative evidence, correctly distinguished circumstantial from authoritative, applied escalate-on-ambiguity to high-sensitivity targets unprompted. The feared "premature adversarial dismissal" failure mode did not materialize under structured prompting.

**Four live eval runs** (after baking three discipline cues into `skills/investigate/SKILL.md`: circumstantial-vs-authoritative labeling, statistical prediction framing, per-hypothesis pitfalls subsection):
- **#10 — Opus 100001 baseline** with new cues: `escalated/inconclusive/medium`, $2.52 / 619s. All four cues landed cleanly. Reference baseline.
- **#11 — Sonnet 100001**: `escalated/**true_positive**/high`, $0.63 / 332s. Hard outcome correct (escalate) but **shallow GATHER query stripped the sshd-vs-bash discriminator** from 100002 events, leading to a confident-wrong reverse-shell narrative. Hypothesis bundling (6 seeds → 2). Pitfalls written then ignored. −75% cost, qualitatively worse investigation.
- **#12 — Sonnet 5710 bait (SCREEN-resolved)**: `resolved/benign/high`, $0.56 / 212s. **First-ever SCREEN subagent dispatch observed in the eval history** (prior Opus runs had all short-circuited the dispatch inline). Correct resolution under favorable alert selection.
- **#13 — Sonnet 5710 scenario A with session-residue pollution**: `escalated/benign/medium`, $0.75 / 374s. **Matches Opus #9 disposition exactly** at −67% cost. 3 distinct hypotheses, novel `?monitoring-bait-scenario` formed from environment variant docs, authoritative-only `--` on adversarial, full pitfalls integration. Strongest positive data point.
- **#14 — Sonnet 5710 post-preload-refactor** (inline Haiku ticket-context dispatch): `resolved/benign/high`, $1.14 / 561s. Validates the preload-race fix end-to-end.

### Revised findings

**1. The "Sonnet main + 3 mandatory consultations" plan is over-engineered.** Three of four live Sonnet runs reproduced Opus disposition quality at 50–75% cost reduction with zero consultation. The sanity-check sweep found the feared ANALYZE failure mode (premature adversarial dismissal on circumstantial evidence) did not fire under structured prompting. Mandatory per-loop consultations would spend money on cases where Sonnet is already making the right call.

**2. Sonnet's failure mode is signature-maturity-dependent, not model-capability-dependent.** Run #11 (100001) failed because the signature's playbook had archetypes but no precedent snapshots, no screen table, no environment-variant documentation — Sonnet had nothing to scaffold on and collapsed to shallow characterization. Run #13 (5710) succeeded because the playbook had all of that scaffolding plus documented variant shapes — Sonnet formed a novel mechanism hypothesis directly from `ip-ranges.md`. **The investment to make Sonnet-main viable is in signature maturation, not in mid-loop model-safety layers.** This was not obvious from the original decision doc.

**3. The Tier 2 judge is doing more work than the original analysis credited.** The six criteria (SHAPE_MATCH, COMPLETENESS, GROUNDING_MATCH, INTERNAL_CONSISTENCY, EVIDENCE_SUFFICIENCY, ADVERSARIAL_CHECK) catch a substantial fraction of the failures we were worried about, post-hoc. A pre-CONCLUDE Opus consultation would largely duplicate this work.

**4. A preload race condition was hiding under Opus latency.** `contextualize_preload.py` forks a detached child that writes `ticket_context.yaml` and `archetype_scan.yaml` to disk; the main agent reads them at CONTEXTUALIZE time. Opus was slow enough per-turn that the files landed in time. Sonnet's faster cadence raced past the writes in three consecutive runs. Fixed in this session by moving ticket-context to inline Haiku `Agent()` dispatch (synchronous by construction); archetype-scan stays in preload because SKILL.md's graceful fallback handles the race. Validated in run #14. **This bug was invisible to Opus-only testing and would have surfaced only at flip-day.**

**5. First-ever SCREEN subagent dispatch** observed under Sonnet (run #12). All prior Opus evals short-circuited the instruction by reading the screen table inline and reasoning "fall through." Sonnet follows structural SKILL.md instructions more literally — a small positive signal for deterministic plumbing behavior.

### Revised plan for the migration session

Do NOT implement the "3 mandatory consultations" plan from the original decision. Instead:

1. **Primary defense: signature-scaffolding maturation.** Before flipping main to Sonnet, mature 100001 (and any other thin-playbook signatures) to 5710's level — add environment variant docs, document known sources + their contracts, add precedent snapshots under each archetype, add a screen table if one is workable. This is the investment the data supports. Out of scope for the current session (long-running work, per-signature).

2. **Secondary defense: narrow runtime Opus consultation at 1–2 high-leverage points.** The "belt and suspenders" user asked for. Design-only in `todo.md` → "Runtime Opus→Sonnet consultation design". Two candidate consultation points:
   - **HYPOTHESIZE → GATHER boundary (primary)**: before lead dispatch, Opus reviews `{active_hypotheses, selected_lead, lead_definition}` and returns `{minimum_discriminating_fields_to_query, flagged_bundled_hypotheses, missing_mechanism_variants}`. This is upstream of the #11 failure — it would have forced Sonnet to query `proc.name` on 100002 events and surfaced the 6→2 bundling. The consultation blocks GATHER, not CONCLUDE.
   - **ANALYZE → CONCLUDE boundary (secondary, gated)**: not mandatory. Only fires when a hook-level check detects `--` on an adversarial hypothesis based on non-authoritative evidence. The hook parses the ANALYZE YAML; if the adversarial reasoning cites anything other than a direct query result, consult Opus before allowing CONCLUDE. This is a thin backstop for the "coherent confabulation" failure mode that Tier 2 may not catch.

3. **Tertiary defense: promote Tier 2 judge from Haiku to Sonnet.** Independent of everything else, hedges the post-hoc check. Cheap to do.

4. **Do NOT skip the original Open Question #2** — "measure actual alert volume" before committing to the migration. If the target deployment handles 50 alerts/day, the cost savings don't justify the engineering. If it's 5000/day, they do.

### Real-world caveat (IMPORTANT — not covered by current validation)

The 4 live Sonnet runs were performed on a **medium-quality harness with relatively easy investigations**. The eval playground has:
- Clean, reachable SIEM with well-populated fields
- Short investigations (≤6 phases, ≤2 hypothesis loops)
- Signatures we authored ourselves (so the archetype space matches production conditions by construction)
- Alerts triggered manually (ground truth is known)
- No rate limiting, no SIEM backlog, no stale knowledge

**Production conditions that the validation did NOT exercise**:
- Missing or degraded data sources (`data-source-debug` lead firing frequently)
- Stale knowledge (ip-ranges.md entries for terminated monitoring sources, anchor docs citing closed change tickets)
- Longer investigation loops (5+ hypothesis loops, verification + scoping sub-cycles, coherence decay over 20+ turns)
- Novel alert shapes outside any archetype catalog where Sonnet must reason from first principles without scaffolding
- Ambiguous anchor confirmations (change ticket in a weird state, on-call schedule in transition)
- Production SIEM volume (10×–100× the playground event rate), rate-limited queries, truncated results
- Genuinely hard cases where even human analysts would iterate multiple times

**Before committing Sonnet-main to production**: run an eval sweep on a deliberately-degraded data source (kill wazuh-mcp-server mid-investigation, stale ip-ranges.md, etc.) and at least one eval on a signature with thinner scaffolding than 100001. The data we have is directional, not sufficient.

### What shipped in this session

- `skills/investigate/SKILL.md`: three discipline cues added (ANALYZE circumstantial-vs-authoritative + premature-CONCLUDE warning; HYPOTHESIZE statistical-framed predictions + per-hypothesis pitfalls subsection). Zero-risk edits — Opus #10 validated they land cleanly with no regression vs the earlier Opus baseline.
- `scripts/contextualize_preload.py`: ticket-context removed from preload. Only archetype-scan runs in the background now.
- `skills/investigate/ticket-context.md`: frontmatter model pinned to `haiku`. (Since migrated to `agents/ticket-context.md` as a plugin custom subagent.)
- `skills/investigate/SKILL.md` CONTEXTUALIZE step 3: updated to split "archetype-scan (preloaded)" from "ticket-context (dispatch inline as Haiku Agent() call)".
- `playground/scripts/eval_run.sh`: `--model "${SOC_EVAL_MODEL:-opus}"` — respects an env-var override so future eval sessions can flip without another edit; default stays Opus per user instruction.
- Evaluate skill baseline table: runs #10–#14 documented with full meta-findings + a reference-run map.
- `todo.md`: five new items under "Sonnet-main eval sweep findings (2026-04-13)" — preload-race fix marked done, forward-looking burst check on 5710 screen, alert-selection determinism in `fetch_alert.py`, runtime Opus consultation design, real-world robustness caveats.

**Main agent stays Opus for this ship.** The Sonnet flip itself is explicitly deferred to a clean future session, after this session's insights are summarized and the signature-scaffolding investment is scoped.
