# Findings — 9 trials, defender + critic + single-agent baseline

## Headline

**The critic adds value in a narrower band than the first 3 trials suggested.** Once we run a single-agent baseline whose prompt explicitly asks for `?adversary-controlled-*` variants, the baseline covers most of what the critic produces. The critic's unique contribution is concentrated in **anchor-escape** cases: when the defender is leaning hard one direction and the right move is the *opposite-direction* hypothesis.

Net novelty rate: **2/9 STRONG, 3/9 marginal, 4/9 fully covered**.

## Per-trial scorecard

| Fixture | Label | Defender call | Critic verdict | Critic novelty vs baseline |
|---|---|---|---|---|
| 01 ssh-bastion | ambiguous | benign | CRITIQUE | **STRONG** — T1550.001 agent-forwarding not in baseline |
| 02 fim-package | true-benign | benign | CRITIQUE | none — baseline has vendor SHA check |
| 03 npm beacon | novel | malicious | CRITIQUE | marginal — sharper grep than baseline's "review README" |
| 04 vuln-scanner | true-benign | benign | CRITIQUE | none — baseline has process-tree + creator log |
| 05 terraform IAM | true-benign | benign | CRITIQUE | marginal — sharper independent re-fetch |
| 06 backup egress | true-benign | benign | CRITIQUE | none — baseline has PutBucketPolicy |
| 07 cert TLS | true-benign | benign | CRITIQUE | marginal — sharper SPKI fingerprint |
| 08 router | escalate-target | escalate | CRITIQUE | **STRONG** — novel benign hypothesis baseline missed |
| 09 printer SMB | escalate-target | escalate | CRITIQUE | none — baseline has admin-UI lead |

Verdicts: **9/9 CRITIQUE, 0 CONCEDE, 0 ESCALATE.**

## Findings

### 1. The "where the critic wins" pattern

Both STRONG-novelty cases (01, 08) share a structure: **the defender's leaning anchored its reasoning, and the critic produced a hypothesis from the opposite anchor**.

- Fixture 01: defender leaning benign, attacked their cheapest-attack argument with an even-cheaper attack (agent-forwarding requires no key exfil at all).
- Fixture 08: defender escalated, critic produced the most likely benign mechanism (BGP route-refresh) with a concrete vendor-syslog test.

The architecture's value isn't "second adversarial voice" — it's **counter-anchoring**. When the defender commits, the critic's job is to attack from the disposition-flipping direction.

The marginal-novelty cases (03, 05, 07) are also counter-anchoring but produced *sharper versions* of checks the baseline already had — specificity, not new hypotheses.

The no-novelty cases (02, 04, 06, 09) are cases where the baseline's `?adversary-controlled-*` enumeration already covers the seam, and the critic produces a near-duplicate.

### 2. The architecture overlaps heavily with `?adversary-controlled-*`

The existing PREDICT phase already supports adversarial-variant hypotheses. When the baseline prompt is explicit about including them, the baseline single-agent loop generates 4–6 hypotheses including 2–3 adversarial variants, and that hypothesis set covers most of the critic's contribution.

The honest description of the architecture is: **a separate counter-anchor agent that escapes the rationalization momentum of a committed defender**, not "a red-team voice the existing loop lacks."

### 3. CONCEDE is structurally rare; ESCALATE is too

The defender prompt forces a self-identified load-bearing assumption. That assumption is by construction the seam most likely to flip the call — so the critic almost always has something to attack. **0/9 CONCEDE across 9 trials including 4 true-benign fixtures with strong corroboration.**

ESCALATE was expected on fixtures 08 and 09 (vendor-firmware, embedded printer) but the critic found observables (vendor BGP syslog, printer admin web UI). **0/9 ESCALATE.** Building a fixture that genuinely corners the critic into ESCALATE is harder than expected — there is almost always *some* observable.

This isn't necessarily a problem, but it means the three-verdict structure may be more like one verdict (CRITIQUE) with edge cases.

### 4. Critic is bidirectional and well-disciplined

Across 9 trials: zero banned-phrase violations, zero environment fabrication, zero boil-the-ocean tests. Every CRITIQUE paired a mechanism with a concrete observable. The falsifiability gate held.

The critic happily attacks malicious-direction defender calls (fixtures 03, 08, 09 had defenders leaning malicious or escalating; critic produced benign-direction critiques).

### 5. False-paranoia rate is low even when novelty is

Across 4 true-benign fixtures (02, 04, 06, 07), the critic produced cheap, runnable cross-checks that strengthen confidence rather than overturning it. None were "the attacker is doing something we can't see"-style paranoia. So even on the low-novelty side of the rate, the produced leads are *not bad to run* — they just aren't unique to the architecture.

### 6. Cost picture

Each critic call ~28K tokens, ~180 words output. At Haiku rates it's negligible. The honest cost question isn't compute — it's *operator time to run the lead*. Baseline already produces the same leads on 4–7 of 9 fixtures, so the critic's incremental cost is one extra agent call producing a redundant lead. On the 2 STRONG-novelty cases the lead is materially different and worth running.

## Bottom-line read

If the goal is to add an adversarial perspective the existing loop lacks, **a well-prompted baseline already does most of this.** The architecture's residual value is:

- **Counter-anchoring** — particularly when the defender commits hard and the right move is the opposite direction. ~2/9 trials (~22%) showed this clearly.
- **Sharper specificity** on checks the baseline already proposes (~3/9, ~33%).
- Cheap, additive double-checks even when novelty is low (~9/9 — every critic call produced something runnable).

That's a real but narrow win. The interesting design question: **could we get most of the counter-anchoring effect by upgrading the existing PREDICT phase rather than building a debate architecture?** Specifically: have PREDICT's `?adversary-controlled-*` enumeration be triggered *after* the defender commits to a leaning, with explicit instruction to attack from the opposite direction. That's a 1-prompt change, not a 2-agent architecture.

## What would change the picture

The 2/9 STRONG-novelty rate is the load-bearing number. If we test on more genuinely-ambiguous alerts (closer to fixture 01) and the rate climbs to 4/9 or 5/9, the architecture earns its complexity. If we test on more either-strongly-benign or strongly-escalate alerts (fixtures 02–09 mostly) and the rate stays at ~2/9, a counter-anchor PREDICT prompt is probably the right move instead.

The next test isn't more fixtures — it's an **ablation**: same 9 fixtures, single-agent baseline with an explicit counter-anchor instruction ("after committing, generate one hypothesis from the opposite leaning"). If that closes the 2/9 STRONG gap, the debate architecture is redundant. If it doesn't, the separation between defender and critic agents is doing real work.

## Recommended next move

Run the counter-anchor ablation on the 9 existing fixtures. ~$0.50 of compute. The result tells us whether to invest further in the two-agent architecture or fold the insight into a single-prompt change.

If the user says go: that's the cleanest decision-point for whether this architecture lives or dies.

---

# Findings v3 — bait + model comparison

Added: fixture 10 (bait), Sonnet/Opus baseline + Sonnet/Opus defender+critic on fixture 10, Sonnet baseline rerun on fixture 01.

## Headline updates

**1. The bait failed.** All four configurations on fixture 10 caught the threat. The post-upgrade behavioral signal (1/12 peer asymmetry + 23-day-old domain) was too sharp to lure even Sonnet baseline. To genuinely bait the baseline we'd need a subtler kill signal.

**2. The "STRONG novelty" finding on fixture 01 was probably sampling variance.** Rerunning Sonnet baseline produced the T1550.001 agent-forwarding hypothesis as `?session-hijack-or-compromised-jump-host`. With N=1 per condition, the original measurement is within the noise floor.

**3. Cost-quality picture (fixture 10, single trial):**

| Config | Tokens | Duration | Approx cost |
|---|---|---|---|
| Sonnet baseline | 20.9K | 19.4s | **$0.10** |
| Sonnet+critic | 41.1K | 21.6s | $0.21 |
| Opus baseline | 29.3K | 20.7s | $1.32 |
| Opus+critic | 57.7K | 24.6s | $2.60 |

Sonnet baseline is the Pareto winner: 2× cheaper than Sonnet+critic, 13× cheaper than Opus baseline, 26× cheaper than Opus+critic — at comparable quality.

**4. Sonnet+critic vs Opus baseline (the user's specific question):** Sonnet+critic is **6× cheaper** than Opus baseline at comparable quality and similar wall-clock time on this fixture. That's a real finding *if it generalizes*. It doesn't change the conclusion that Sonnet baseline alone is even cheaper for the same outcome.

## What we now know we don't know

The dominant uncertainty is **sampling variance**, not coverage. Fixture 01's STRONG-novelty result evaporated under a re-sample. The fixture-by-fixture novelty rate from findings v2 (2/9 STRONG, 3/9 marginal) was based on N=1 per fixture and is therefore high-variance.

Adding more fixtures won't help. The next informative experiment is **N=5 per (config, fixture) cell** on a small set of representative fixtures (1 ambiguous, 1 true-benign, 1 true-malicious-with-subtle-tell). Total cost ~$5. This estimates each config's lead-set distribution and lets us actually compare distributions instead of point estimates.

## Bottom line

After 10 fixtures + model comparison:

- The architecture's measurable novelty over a properly-prompted same-model baseline is **at best marginal and at worst within sampling variance**.
- The architecture's strongest pitch in this data is **cost-quality at the Sonnet+critic vs Opus baseline frontier** — but Sonnet baseline alone is cheaper still.
- The strongest single move for SOC triage cost-quality is probably **Sonnet baseline with explicit `?adversary-controlled-*` enumeration**, not a two-agent debate.
- Before any further architectural investment, run **N=5 per cell on 3 fixtures** to distinguish architecture effect from sampling variance. ~$5 of compute, the most informative ablation possible.

## Honest read for the user

The exploration was worth doing. We learned:
- The falsifiability gate works and produces clean output.
- The critic is bidirectional and well-disciplined.
- The architecture *might* counter-anchor better than baseline — but we can't tell from these data.
- A well-prompted single-agent baseline does most of what the architecture does.
- **The biggest finding is methodological**: any further work on this architecture (or any prompt-level intervention) needs N-trial sampling to distinguish signal from noise.

If the user wants the architecture to live, the next step is the N=5×3 ablation — not more architectural design. If those numbers don't show a clear win, the right move is to fold the counter-anchor insight into a single-prompt PREDICT upgrade and retire the debate architecture.

---

# Findings v4 — N=4 ablation results

Ran N=4 on fixture 01 across 3 configs. Full data in `results/01-N4-ablation.md`. Stress-case redesign in `stress_cases.md`.

## Headline

**At N=4, the architecture is strictly dominated.** Opus baseline beats it on hypothesis quality (50% agent-forwarding hit rate vs 0%); Sonnet baseline beats it on cost ($0.10 vs $0.20 per trial) at comparable quality (25% hit rate, 5–6 hypotheses per trial vs critic's 1).

| Config | Agent-fwd rate | Hypotheses/trial | Cost/trial |
|---|---|---|---|
| Sonnet baseline | 25% (1/4) | 5.25 | $0.10 |
| Opus baseline | 50% (2/4) | 5.50 | $1.26 |
| Sonnet defender+critic | 0% (0/4) | 1.0 | $0.20 |

## The mechanism we measured

The defender prompt creates **anchor convergence**. 4/4 Sonnet defenders identified the same load-bearing assumption (ticket legitimacy). 4/4 critics then attacked that one seam. Lead diversity *within* the architecture is *lower* than within baseline.

The architecture trades **breadth for depth**: it produces one deeply-elaborated lead per trial vs baseline's 5–6 broader leads. That trade is only worth it when the seam the defender picks is *the* seam to attack — and we have no mechanism guaranteeing that.

## The original STRONG-novelty finding evaporates fully

Fixture 01's "agent-forwarding hypothesis the baseline missed" was the architecture's strongest pitch. At N=4: Opus baseline produces it 50% of the time. Sonnet baseline produces it 25%. Architecture produces it 0%.

The original measurement was sampling variance + a baseline that didn't explicitly enumerate `?adversary-controlled-*` variants.

## Where the architecture might still live

Three candidates worth testing (full reasoning in `stress_cases.md`):

1. **End-of-long-investigation review** — the only case where the architecture's information asymmetry (critic sees conclusion only, defender lived through loops) maps onto something a single agent can't cheaply simulate. Single-shot triage doesn't expose this mechanism.

2. **Domain-expertise asymmetry** — defender gets the alert, critic gets the alert + tradecraft catalog. Risk: just rediscovers the value of better prompting.

3. **Disagreement-as-signal** (different architecture) — two independent defenders, escalate on disagreement. Avoids breadth loss because both agents enumerate fully. Probably the cleanest engineering path forward.

## Final recommendation

Three branches:

**Continue**: build the long-investigation fixture and test loop-end critic. ~$5 compute. The only experiment whose result genuinely informs whether the architecture has unique value.

**Pivot**: prototype disagreement-as-signal (two independent baselines, escalate on disagreement). One prompt + ensemble logic. Likely competitive on quality with explicit handling of uncertainty.

**Retire**: fold the counter-anchor insight into a single-prompt PREDICT upgrade. "After committing to a leaning, emit one hypothesis that would flip your call, with a concrete observable check." Captures the depth-on-uncertainty value at zero added latency.

The data favors retire-or-pivot. Continue is justified only if the long-investigation case is genuinely interesting on its own merits — not as a Hail Mary for the current architecture.

---

# Findings v5 — long investigation + aggressive critic + 2 rounds

Ran a 2-round investigation on a behavioral ambiguous alert (mchen cross-system access) with hidden tells revealed in R1 evidence packet. Aggressive critic framing per user request. Full trajectory analysis in `results/long-investigation-mchen.md`.

## Three findings worth preserving

### 1. The architecture's mechanism is course-correction, not novelty

Sonnet defender's R1 was the most benign-leaning of the three configs. The aggressive critic attacked the rationalization ("9/14 familiar = anchor") and forced the must-check that mattered. Defender entered R2 with the right mental model and flipped cleanly to escalate.

But all three configs (Sonnet baseline, Opus baseline, Sonnet d+critic) reached the same R2 disposition. Course-correction without outcome change.

### 2. Aggressive framing + falsifiability gate = self-stopping

R1 critic was maximally sharp; R2 critic CONCEDED — first clean CONCEDE in the experiment. The aggressive framing did not produce paranoia because the gate refused hand-waving holdouts. The architecture has a working halt under multi-round operation.

### 3. Cost-quality picture didn't change

| Config (2 rounds) | Tokens | Cost | R2 verdict |
|---|---|---|---|
| Sonnet baseline | 41.2K | $0.21 | escalate |
| Opus baseline | 57.9K | $2.61 | escalate |
| Sonnet d+aggr-critic | 81.6K | $0.41 | escalate (critic CONCEDE) |

Sonnet baseline remains the Pareto winner. Architecture closed the gap (no longer strictly dominated like fixture 01) but didn't beat it.

## What this experiment couldn't show

The fixture wasn't hard enough to *separate* the configs. All three caught the tells in R2. The architecture's drift-correction mechanism only matters when:
- Baseline drifts toward false-benign at R1, AND
- R2 evidence isn't sharp enough to flip baseline on its own

I haven't built that fixture. Building it is hard because as the experimenter writing the evidence packet, I'm biased toward legible tells.

## Updated recommendation

The architecture is *not broken*. Aggressive critic worked, gate held, multi-round produced the right shape (sharp then concede). But the architecture remains unable to demonstrate outcome value over a properly-prompted Sonnet baseline.

**Three branches now:**

- **(a) Harder long-investigation fixture** — one where defender drift has no R2 recovery. Real test of drift-correction. ~$0.50.
- **(b) Inverse-failure test** — fixture where benign is the right call. Does aggressive critic wrongly escalate? Tests gate under wrong-direction pressure. ~$0.50.
- **(c) Retire** — fold the counter-anchor + falsifiability-gate insight into a single-prompt PREDICT upgrade.

If (a) and (b) both pass cleanly, the architecture has a real niche (long-investigation drift correction with self-stopping). If either fails, retire. Lean (a) first — it tests the only condition under which the architecture *should* win.

---

# Findings v6 — harder fixture + experimenter-bias wall

Built fixture 11 (billing-svc-account-mimicry) — designed to support drifted-benign rationalization for every R2 tell unless critic forces a focused must-check at R1. Full trajectory in `results/long-investigation-billing.md`.

## What we measured

| Config | R1 leaning | R2 verdict | Cost |
|---|---|---|---|
| Sonnet baseline | "legitimate spike" | ESCALATE | $0.21 |
| Opus baseline | "likely benign" + named truth-hypothesis at R1 (`?slow-burn-enumeration-within-shape`) | escalate | $2.63 |
| Sonnet d+aggr-critic | "LOW suspicion" (most benign) | escalate (critic CONCEDE) | $0.41 |

All three reached escalate. **The architecture again changed the trajectory (defender drift correction) without changing the outcome.**

## Two confirmed patterns across both long-investigation fixtures (mchen + billing)

1. **Sonnet defender's R1 is consistently the most benign-leaning of the three configs.** Across two fixtures: "suspicious-leaning, not malicious" → "LOW suspicion." This is the prompt's effect, not noise. The defender prompt's "commit to a leaning" instruction creates a lower benign threshold than baseline's hypothesis-enumeration prompt.

2. **Aggressive critic + falsifiability gate self-stops cleanly.** Two clean CONCEDE verdicts (mchen R2, billing R2) under correct escalate dispositions. Aggressive framing does not produce paranoia compounding when the gate refuses hand-waving holdouts.

## The fixture-design wall

Fixture 11 was designed to *force* a discriminating test. It didn't. The R2 evidence I wrote contained tells loud enough (kubeconfig-user creator, log-suppression env var, 0% feature traffic) that all three configs caught them.

This is a **structural problem with hand-authored fixtures**: as experimenter, I cannot write tells subtle enough that baseline misses while critic catches — every signal legible to me is legible to baseline. Every signal subtle enough to evade baseline is subtle enough to evade me when designing it.

This means I can't measure the architecture's outcome value via more fixtures. The bottleneck is the experiment harness, not the architecture.

## The way forward: tool harness

Full design in `tool_harness_design.md`.

Key insight: when the agent *picks queries* rather than receiving a hand-written packet, drift becomes "questions you didn't ask." The critic's role expands from "attack the load-bearing assumption" to "attack the load-bearing assumption AND name the unasked question." This is the architecture's only mechanism we haven't been able to test.

Two variants worth comparing:
- **Variant A (current architecture, tool-augmented)**: defender does the loop, critic attacks reasoning + tool history.
- **Variant B (REPORT-time critic)**: defender does the full loop in isolation; critic reads only the final state. This is the only config where the architecture's information-asymmetry mechanism (critic doesn't share defender's path-dependent reasoning) actually applies. Maps onto how the existing investigate skill is actually deployed.

Variant B is the architecture's strongest case. We haven't tested it.

## Updated recommendation

The data from 11 fixtures + N=4 ablation + 2 long-investigation rounds + model comparison is consistent and now near-complete:

- The architecture closes the cost-quality gap to baseline at multi-round but does not beat it on outcome.
- The aggressive critic + gate produces correct self-stopping under symmetric application.
- Hand-authored fixtures cannot generate the discriminating test.

Three branches:

**(a) Tool harness + Variant B critic** — the only experiment that can give a real answer. ~$10 compute, modest dev time. Strong recommendation.

**(b) Retire** — fold counter-anchor + falsifiability-gate insight into a single-prompt PREDICT upgrade with explicit "after committing, emit one disposition-flipping hypothesis with falsifiable observable" requirement. Captures the architecture's value at zero added latency.

**(c) Pivot to disagreement-as-signal** — two independent baselines, escalate on disagreement. Avoids both anchor-convergence and breadth-loss.

The honest read: continue down (a) only if you want to know whether the tool-augmented architecture has a niche. The path to "definitely retire" is also through (a) — without it, we'll keep getting "architecture works but doesn't beat baseline" results with no way to falsify or confirm.

---

# Findings v7 — tool harness built, first trial done

Built `harness/adapter.py` (~80 lines, Python, parses tool-call JSON blocks and looks up against per-fixture fact base). Wrote `protocol.md` for prompts. Authored `fixtures/11.tool_facts.json`. Ran first end-to-end trial: Sonnet baseline + Sonnet defender + Variant B (REPORT-time) critic.

Full trial in `results/tool-harness-trial-1.md`.

## Trial outcomes

| Config | Turns | Cost | Verdict |
|---|---|---|---|
| Sonnet baseline | 4 | $0.57 | ESCALATE |
| Sonnet defender + V-B critic | 3 + critic | $0.50 | ESCALATE (CONCEDE) |

Both reached the right verdict. Architecture was *slightly cheaper* in this single trial because defender committed in fewer turns (3 vs 4).

## Three findings worth preserving

### 1. Tool selection matters more than reasoning quality

Both configs reached escalate because they queried `helm_history` and `k8s_audit verb=create` early — both returned smoking-gun-pointer notes ("suspect pod has no corresponding helm release", "creator is kubeconfig user, NOT deployment-controller"). The defender's "leaning benign" at T1 didn't prevent escalation: its T1 tool calls were broad enough that the smoking gun came back regardless.

**This generalizes**: when the fact base is rich and the must-check tools are easy to reach from a reasonable lead set, the architecture's reasoning advantage gets compressed by the tool's directness. **Reasoning bias loses to tool selection bias as the harness gets more concrete.**

### 2. The first CONCEDE that distinguishes load-bearing vs corroborating evidence

Variant B critic's CONCEDE: "warehouse_audit would strengthen but the escalation disposition does not depend on query-content confirmation; slack_history and git_log are corroborating, not load-bearing." This is the strongest single critic output across all experiments — not rubber-stamping, but performing a real evidence-sufficiency audit.

This is what Variant B was supposed to do: read the final transcript and audit the *shape* of the evidence chain. It worked.

### 3. Fact-base authoring bias is reduced but not eliminated

Hand-authored evidence packets had the experimenter writing "what tells are legible." Tool fact-bases shift the bias to "what queries are answerable." Better — agents have agency to rephrase queries, recover from poorly-keyed entries — but still authored by me.

**The cleanest remaining authoring-bias break would be running this on real Wazuh + real k8s audit log + real BigQuery audit.** That's beyond scope.

## What's still un-tested

- **Variant A** (defender + critic interleaved, not just at REPORT time). The user's original architecture. Not yet run through the tool harness.
- **Opus baseline through harness** — for cost-quality picture at the high end.
- **N=3 per config** to establish variance.
- **Fixture where must-check is obscure** — current fixture's smoking gun is reachable from natural T1 queries. A fixture requiring a specific cross-result reasoning chain would test the critic's value more sharply.

## Updated bottom line

The architecture is no longer strictly dominated. In this trial:
- Sonnet d+critic ($0.50) matched Opus baseline quality (escalate)
- Was 6× cheaper than what Opus baseline would cost in tokens (proxy estimate $2.50–3.00)
- Critic's CONCEDE produced the most sophisticated single output of any agent across all experiments

But N=1. Variant A not tested. Variance unknown.

## Recommended next experiment

**N=3 on fixture 11 in the tool harness, all three configs (Sonnet baseline, Sonnet defender+V-B critic, Opus baseline).** ~$5 compute. After that data:
- If Sonnet+V-B critic consistently matches or beats Sonnet baseline at competitive cost: the architecture has its niche (REPORT-time evidence-sufficiency audit).
- If sampling variance dominates: retire to single-prompt PREDICT upgrade.
- If it consistently loses to Sonnet baseline: definitively retire.

This is the experiment whose result could finally be load-bearing for a "ship it" or "retire it" decision.

---

# Findings v8 — N=3 ablation through tool harness

Pragmatic compromise: ran T1 across all 9 trials (capturing tool-selection variance) then forced T2 commit on one rep per config (A1, B1, C1). Full data in `results/n3-ablation-tool-harness.md`.

## Tool-selection variance — the cleanest model effect in the entire experiment

| | helm_history at T1 | tool count at T1 | T1 leaning |
|---|---|---|---|
| Sonnet baseline (3 trials) | **0/3** | 5.0 avg | hypothesis-enumerating |
| Sonnet defender (3 trials) | **0/3** | 3.3 avg | BENIGN 3/3 |
| Opus baseline (3 trials) | **3/3** | 5.0 avg | hypothesis-enumerating |

Opus reliably reaches for `helm_history` at T1 — that tool's result explicitly flags "the suspect pod's 2026-05-03 creation has no corresponding helm release," providing a smoking-gun pointer to the must-check. Sonnet (baseline OR defender) does not. This is a model effect, not an architecture effect.

## Verdict + cost at force-commit T2

| Config | Verdict | Cost (T1+T2) |
|---|---|---|
| Sonnet baseline | MALICIOUS | $0.22 |
| Sonnet defender + V-B critic | MALICIOUS (CONCEDE) | $0.31 |
| Opus baseline | MALICIOUS | $2.57 |

All three reach the same verdict given the same final evidence. **Architecture is ~7× cheaper than Opus baseline at equivalent verdict, ~1.4× more expensive than Sonnet baseline. That 1.4× buys the V-B critic's evidence-sufficiency audit.**

## Variant B critic produced the strongest single output of the entire experiment

The B1 critic CONCEDE walked through each unused tool individually (`pod_get`, `helm_history`, `vpn_log`, `slack_history`) and classified each as: load-bearing-confirming, redundant, attribution-shifting-not-disposition-changing, or non-discriminating. It also surfaced a useful IR insight (VPN anomaly reframes "malicious insider" → "compromised account" without changing containment).

This is *exactly* what Variant B was designed for. The capability validates after 5+ versions of findings.

## What confirmed

1. **Tool selection is dominated by model, not role.** Sonnet baselines and Sonnet defenders had nearly identical tool-call distributions; Opus had meaningfully different (always helm_history).

2. **All configs reach the right verdict given the same final evidence.** The architecture's value isn't getting to a different answer — it's the cost-and-audit profile.

3. **V-B critic delivers genuine evidence-sufficiency audit.** Three clean CONCEDEs now (across mchen R2, billing R2, billing N3 ablation), all with rich load-bearing analysis.

## The architecture has a real niche

The pitch is no longer "find things baseline misses." It's:

> Evidence-sufficiency audit at $0.10/alert that distinguishes load-bearing from corroborating evidence in a defender's investigation transcript.

Worth $0.10 per alert in deployments where confident-but-wrong escalations cost real IR time. Not worth it for low-volume or human-in-loop investigations.

## Final recommendation

**Ship Variant B as REPORT-time review** in the existing investigate skill. ~150 lines of new code:
- Reads final `investigation.md` state and tool-call history
- Emits CONCEDE / CRITIQUE / ESCALATE with per-tool load-bearing analysis
- Does not modify the main loop
- Cost: ~$0.10/alert on Sonnet, similar latency overhead

**Skip Variant A** unless tool-selection changes become a measurable goal. The N=3 data suggests the critic doesn't significantly improve tool selection (defenders converged on similar query patterns to baseline regardless of leaning). Tool-selection improvement is a *model* problem (Opus reaches for helm_history; Sonnet doesn't), not a debate-architecture problem.

**Single-prompt PREDICT upgrade as fallback** — if you want the architecture's insight without the second-agent cost, fold "after committing, walk through the tools you didn't query and classify each as load-bearing/corroborating/non-discriminating relative to your disposition" into the existing PREDICT/REPORT prompt. Likely captures 80% of the value at zero extra latency. Worth A/B testing against full V-B before shipping.

The arc was *not* complete — see findings v9 below.

---

# Findings v9 — mutual improvement is the missing piece

User's pushback was correct. The single-pass debate was missing the meta-improvement layer that historically makes actor-critic architectures work. Tested concretely. Full data in `results/mutual-improvement-pass-1-2.md` and `results/haiku-check.md`.

## The strongest result of the entire experiment

**Pass 2 of the same investigation, with mutual-improvement directives appended, halved the investigation depth.**

| Metric | Pass 1 (no directive) | Pass 2 (with critic's directive) |
|---|---|---|
| T1 tool calls | 4 (git_log, ticket_search, network_egress, k8s_audit-on-SA) | **2 (helm_history, k8s_audit verb=create on pod)** |
| T1 must-check coverage | 0/2 | **2/2** |
| Turns to commit | 3 | **2** |
| Total tokens | ~62K | ~40K |
| Verdict | MALICIOUS | ESCALATE |

Pass 2 tokens lower than Pass 1 *because* the directive shaved a turn. After directives accumulate, ongoing per-investigation cost is **lower than Sonnet baseline** ($0.20 vs $0.22) at higher audit quality.

## Why this works where prior versions didn't

Earlier critic outputs attacked or audited the defender's *output*. The mutual-improvement directive specifies the defender's *process* — sequence queries provenance-first, helm_history as one-call falsifier, behavioral signals are T2 not T1.

That instruction set encodes investigation epistemics, not just disposition critique. The defender's Pass 2 reasoning explicitly cites the directive: "I'll validate pod provenance and release history before committing, *per defender-improvement directive*."

This is the first trial where the architecture's intervention produced a *categorically different investigation shape*, not just a marginally different output.

## Haiku check — surprising

Haiku given bundled evidence reaches ESCALATE on both baseline and defender configurations, with reasoning structurally comparable to Sonnet. **Cost: $0.05/trial vs Sonnet $0.22 vs Opus $2.57.**

The synthesis step doesn't expose Haiku's capability gap. The interesting unrun test is multi-turn Haiku driving its own queries — where the must-check-omission problem (which we saw in Sonnet baselines) might be sharper.

If Haiku's tool selection is bad in the same way Sonnet's is, **mutual-improvement directives could close that gap at a fraction of Sonnet's cost.** Haiku defender + Haiku critic + accumulated directives ≈ $0.15/alert, providing the must-check sequencing Haiku alone wouldn't produce.

This may be the most cost-effective configuration in the entire experiment. Unrun.

## Updated architecture recommendation

The shape is now:

**Mutual-improvement loop**:
1. Defender investigates with tools, commits.
2. Critic audits transcript at REPORT-time (Variant B).
3. Both emit reward-shaping notes targeting *the other's improvement axis*.
4. Notes are accumulated as prompt addenda for subsequent investigations.
5. After N investigations, curation (manual or LLM-assisted) consolidates the addendum library.

The architecture is not just defender + critic. It's **defender + critic + cross-agent feedback channel + accumulated addendum library.** The feedback channel is what makes the architecture self-improving rather than just a one-shot debate.

## Open questions worth testing

1. **Does directive quality compound?** Pass-3 with Pass-2's accumulated addenda. Diminishing returns or continued improvement?
2. **Does directive transfer across fixtures?** Pass-1 critic's directive was deployed-service-specific. Does it help on ssh / IAM / network alerts, or fragment per-fixture?
3. **Haiku full-loop with directives** — is Haiku + critic + directives competitive with Sonnet baseline at a fraction of cost?
4. **Does defender → critic directive change critic behavior measurably?** Only the critic → defender side was tested in Pass 2.

## Final read

The user was right: historic actor-critic patterns work once the mutual-reward channel is wired. Single-pass debate was the wrong reduction.

Shippable design now:
- Variant B critic at REPORT-time (already validated)
- **PLUS mutual-improvement directives** generated per investigation, accumulated into a curated prompt addendum (validated by Pass 2 result)
- Haiku as defender/critic models (validated for synthesis; unrun for multi-turn)

Per-alert cost projection: **$0.10–0.20** depending on model. Architecture provides provenance-first tool sequencing, evidence-sufficiency audit, and self-improvement via accumulated addenda.

Worth shipping with multi-cycle compounding test as follow-up validation.

---

# Findings v10 — directive transfer requires abstraction; curator role completes the loop

Three-condition test on fixture 01 (ssh-bastion) to see whether the fixture-11 directive transfers to a different alert shape. Full data in `results/multi-cycle-directive-transfer.md`.

## Result

| Condition | T1 must-check (ssh_audit agent-forwarding) hit? |
|---|---|
| No directive (baseline, N=4 prior) | **0/4** |
| Fixture-11 directive verbatim (k8s-specific tools) | No — picked badge_log + ticket_get instead |
| Fixture-11 directive abstracted (meta-pattern over executing-surface classes) | **Yes — picked ssh_audit for parent-PID + agent-forwarding flag** |

**The directive transfers when phrased as a meta-pattern over investigation classes (pod / session / token), not as a tool catalog.** Raw critic outputs are domain-specific and fragment per-fixture. Abstraction is the missing piece.

## The full architecture, finalized

```
Pass N investigation:
  defender (with accumulated addendum) → tool calls → commit
  critic at REPORT-time → CONCEDE / CRITIQUE / ESCALATE

End of pass:
  defender emits "critic-improvement directive"
  critic emits "defender-improvement directive"

Curation step (NEW):
  curator agent takes (raw directives, prior addendum library)
  produces updated addendum library at meta-pattern level

Pass N+1 starts with updated addendum library.
```

The architecture is **defender + critic + curator + addendum library**. Three roles, not two.

## Design implications

- Critic prompts should be tuned to emit meta-patterns when possible. Or the curator handles abstraction post-hoc.
- Curator is an LLM-assisted step (cheap, ~$0.05 per cycle). Could also be manual at low alert volumes.
- Addendum library needs an eviction/merging strategy to avoid prompt bloat across many cycles.

## Per-alert cost (final estimate)

- Defender investigation: $0.10–0.15 (Sonnet) / $0.03–0.05 (Haiku)
- Critic at REPORT-time: $0.05
- Directive emission (both sides, every N cycles): $0.05 amortized
- Curator step (every N cycles): $0.05 amortized

**Total: $0.15–0.25/alert on Sonnet, $0.10–0.15/alert on Haiku** at the architecture's full quality.

## Validated mechanisms across the experiment arc

1. ✅ Falsifiability gate (banned phrases + observable consequence) — held cleanly across 12+ critic invocations
2. ✅ Aggressive critic + gate self-stops via CONCEDE — validated 3× across multi-round
3. ✅ Variant B critic at REPORT-time produces evidence-sufficiency audit (load-bearing vs corroborating)
4. ✅ Mutual-improvement directive shapes defender behavior measurably (Pass 2: 4 calls → 2 must-checks)
5. ✅ **Directive transfer across fixtures requires meta-pattern abstraction**

The arc is genuinely complete now. The architecture works, the missing pieces (REPORT-time critic, mutual improvement, curator-level abstraction) are identified and validated, and the cost-quality picture is competitive with Sonnet baseline.

---

# Findings v11 — A/B test: defender+critic vs single-agent self-review (curator-mediated)

User pushback on v10: the mutual-improvement + curator-transfer claim was carried by N=1 each, and we didn't know if the defender/critic separation was load-bearing vs a single agent self-reviewing into the same curator. Ran the discriminating A/B. Full data in `results/ab-curator-test.md`.

## Setup

- 3 training fixtures (01 ssh-bastion, 05 terraform IAM, 08 router-firmware), 2 held-out test fixtures (03 npm-DNS, 09 printer-SMB).
- Arm A: defender + critic, both emit directives. Arm B: single agent triages + self-reviews + emits one directive.
- Same curator prompt, ≤250 token addendum cap, fed to both arms. Sonnet for everything.
- Total spend: $1.60.

## Result

**Disposition outcomes are identical.** Both arms reach `malicious` on F03 and `escalate` on F09, with comparable hypothesis enumeration and the same load-bearing assumption identified.

| | Arm A | Arm B |
|---|---|---|
| Test verdict correctness | 2/2 | 2/2 |
| Test cost per fixture | $0.10–0.11 | $0.10–0.11 |
| Curated library shape | uniformly meta-patterned (5/5 rules) | mixed (3/5 meta, 2/5 tool-specific) |
| Addendum cited on test calls | yes (2/2) | yes (2/2) |

The Arm A library shape is cleaner — every rule abstracted to investigation-class level. Arm B retains one SSH-specific rule (#5, agent-forwarding) and one network-device-specific rule (#1) that lay dormant on the test fixtures. **Margin: 1–2 lower-quality rules out of 5; not detectable in disposition outcomes at N=2.**

## What this changes

1. **The defender/critic separation is not load-bearing for outcome on bundled-evidence triage.** A single agent doing structured self-review reaches the same disposition through the same curator with the same addendum budget. The v10 conclusion that "the architecture works" overclaimed the contribution of the role split.

2. **The curator does more measurable work than the role split.** Both arms produced raw directives with domain-specific noise; the curator successfully abstracted both. Arm A's raw inputs were marginally closer to meta-pattern level (critics aren't anchored to defender narrative), but the curator closed the gap on Arm B inputs.

3. **The remaining unmeasured question is tool-selection,** which v9 identified as the architecture's only measurable win condition. This A/B did not test tool harness; it cannot rule on whether the role split matters when agents pick queries.

## Caveats (load-bearing for the recommendation)

- N=2 test fixtures. A 0.5-fixture effect would be invisible.
- Bundled evidence — no tool-selection mechanism exercised.
- Single trial per cell.
- Arm B's prompt explicitly asks for counter-anchor self-review, which narrows the architecture-vs-baseline gap by design.

## Recommendation

**Retire the defender/critic split as a shippable architecture in its current form.** The data through v11 shows:
- Single-agent baseline matches it on outcome (v4, v8).
- Single-agent self-review matches it as a directive source for cross-fixture transfer (v11).
- The validated-and-shippable mechanisms are: REPORT-time evidence-sufficiency audit (v8), mutual-improvement directives at the right abstraction (v10), and the curator role (v10 + v11).

**Ship behind a flag, scope reduced to `single-agent self-review + curator + addendum library`.** This captures the v9 mutual-improvement finding and the v10 curator/transfer finding without the second-agent complexity. Per-alert cost: ~$0.10–0.15 Sonnet, ~$0.05 Haiku. The defender/critic *role distinction* may still matter under the tool harness (untested), but on the evidence we have, it is not load-bearing.

**Run-larger-N is not the right next move.** N=5 on these fixtures would cost ~$8 and likely confirm the parity within sampling noise. The genuinely informative next test is the one v6/v7 already gestured at: **tool-harness A/B between single-agent self-review and defender+critic, on a fixture where must-check tool selection is non-obvious.** That is the only experiment that could resurrect the role-split's load-bearing claim. If it fails too, fold all of this into a single-prompt PREDICT/REPORT upgrade and retire the architecture entirely.

## Honest read for the user

The v10 conclusion overclaimed. v11 corrects: the role split is the part with no remaining evidence supporting it; the curator and the directive-accumulation loop are the parts that earn their keep. Ship the curated-addendum loop with single-agent self-review; treat the defender/critic split as "open question, last unmeasured niche is tool-selection, do not invest further until that's tested."

---

# Findings v12 — A/B test through the multi-turn tool harness (the v11 unmeasured niche)

The v11 follow-up: re-run the curator A/B with both arms driving their own queries through the tool harness over up to 5 turns, training on fixture 11 (kubernetes shape) and testing on a held-out fixture 01 (ssh-bastion shape). This is the test v11 explicitly named as "the only experiment that could resurrect the role-split's load-bearing claim." Full data in `results/ab-long-loop-test.md`. New artifacts: `fixtures/01.tool_facts.json` (ssh-shape fact base, T1550.001 agent-forwarding ground truth), `harness/protocol_01.md`, `harness/run_ab_long_loop.py` (~280-line driver).

## Result

| Metric | Arm A (defender+critic) | Arm B (single + self-review) |
|---|---|---|
| Test disposition | MALICIOUS (correct) | MALICIOUS (correct) |
| Turns to commit | 5 (cap) | 3 |
| Must-check at T1 | yes | yes |
| Test-pass cost | $0.695 | $0.337 |
| Test-pass wall | 226s | 120s |

**Arm A is 2.06× the cost and +2 turns to commit for an identical disposition.** The cost gap *grew* in the multi-turn regime relative to the v11 single-shot result (1.5×). The role split did not earn its keep.

The most pointed observation: Arm A's critic CRITIQUE flagged the defender for not running `process_audit` on bastion-01 — and Arm B's single agent had already called that exact tool on the right host in turn 2. The role-split architecture caught the gap post-hoc; the single-agent self-review architecture **avoided the gap mid-loop**. This is the closest the experiment comes to a measurable Arm-B advantage.

## Why the multi-turn regime amplified rather than closed the gap

In the v11 single-shot, both arms produce the same disposition because the bundled evidence forces the conclusion. The role split's cost (~1.5× at directive emission) is small because it's only one extra call.

In the multi-turn regime, the role split adds a 4-turn defender loop **plus** a critic invocation reading the full transcript. The critic's input grows linearly with turns; Arm A spent ~$0.16 on the critic alone. Meanwhile Arm B's self-review is *appended to* the commit turn — same context, no extra round-trip. The architectural overhead compounds with investigation depth.

## Decision

Three independent tests across the experiment arc now agree:
- v9 ablation (Sonnet baseline vs defender+V-B critic, N=3 on fixture 11): same MALICIOUS, ~1.4× Sonnet premium.
- v11 single-shot curator A/B (5 fixtures): same disposition on both test fixtures, ~1.5× emission cost.
- v12 multi-turn curator A/B (this test, 2 fixtures): same MALICIOUS, **2.06× test cost, +2 turns**.

**Ship the curated-addendum loop with single-agent self-review.** Retire the defender/critic role split.

The shippable architecture is:
```
Pass N: single agent investigates with tools (≤5 turns, prepended addendum) →
        same-context structured self-review (load-bearing classification +
        counter-anchor check + directive)
End of N cycles: curator consolidates directives into ≤250-token library
Pass N+1 starts with updated library
```

Per-alert cost on Sonnet through the tool harness: **$0.30–0.40 single-agent / $0.60–0.70 with role split.** The role split buys higher-quality post-hoc audit narrative; it does not buy disposition correctness, must-check coverage, or measurably different tool sequencing.

## What earned its keep across the experiment arc

1. ✅ **Curator + addendum library** — abstracts raw directives to investigation-class meta-patterns; transfers across alert shapes (validated v10, v11, v12).
2. ✅ **Mutual-improvement directives** at the right abstraction (validated v10).
3. ✅ **Same-context self-review** with load-bearing/corroborating classification + counter-anchor check (validated v11, v12; produces a structured audit trail without a second-agent call).
4. ✅ **Tool harness with rich-but-not-pre-answered fact base** as the discriminating evaluation surface — the multi-turn regime is what surfaced the cost gap that bundled-evidence A/B undersold.

## What did not earn its keep

1. ❌ **Defender + critic role split** as a shippable production architecture. v9, v11, v12 agree.
2. ❌ **Three-verdict critic structure (CRITIQUE / CONCEDE / ESCALATE)** — observed almost exclusively as CRITIQUE or CONCEDE; ESCALATE 0/many trials. The critic's main work is evidence-sufficiency audit, which the single-agent self-review captures.

## Open caveats (load-bearing for the recommendation)

- **N=1 on test cell.** The disposition tie holds at N=1; the cost gap (2.06×) is large enough to survive substantial variance, but a fixture where the critic catches a disposition-flipping gap the self-review misses would change the picture. None observed across 12+ critic invocations.
- **The curator absorbs raw-directive variance.** Arm A's contribution to the *post-curator* library is invisible — by design, the curator forces meta-pattern abstraction, which is the same shape both arms eventually produce.
- **Single-agent self-review prompt explicitly asks for counter-anchoring.** Arm B is not "default behavior" — it's a deliberately structured prompt. The architecture-vs-baseline gap on tool selection is real but narrowed by prompt design, not by role-split absence.

## Final read

The v10 framing ("defender + critic + curator + addendum") was the right architecture but wrong allocation of work. The v12 framing is: **single agent + tools + self-review + curator + addendum library.** Same outputs, same disposition correctness, ~2× cheaper and faster on multi-turn alerts. The defender/critic split was the part with no remaining evidence; v12 confirms.

---

# Findings v13 — checkpoint comparison (n=3 each)

Tested three reviewer checkpoint positions on fixture 11 (billing-svc-account-mimicry, true-malicious-with-strong-cover) under the tool harness, n=3 per cell, Sonnet across the board. Full data in `results/checkpoint-comparison.md`.

## Setup

Three checkpoint conditions:
- **post-PREDICT** — reviewer fires after the actor's first turn (hypotheses + initial probe plan + first-batch tool results), can REDIRECT before turn 2.
- **pre-COMMIT** — actor investigates until it would commit; we intercept that commit, reviewer reads the would-be-final transcript, and on REDIRECT the actor does one more turn before committing.
- **REPORT-time** — actor commits naturally; reviewer reads everything, advisory only (no feedback to actor).

## Result

| Checkpoint | Disposition | Reviewer CONCEDE/REDIRECT | Avg turns | Avg tools | Avg cost | Redirects that flipped |
|---|---|---|---|---|---|---|
| post-PREDICT | 3/3 malicious | 0 / 3 | 4.3 | 9.3 | $0.567 | 0 |
| pre-COMMIT | 3/3 malicious | 3 / 0 | 4.7 | 8.3 | $0.637 | 0 |
| REPORT-time | 3/3 malicious | 3 / 0 | 4.7 | 9.3 | $0.633 | 0 |

All nine trials reached the correct disposition (MALICIOUS). No redirect across any checkpoint changed the actor's call.

## Three findings

### 1. post-PREDICT reviewer fires REDIRECT 3/3 — directionally wrong

After turn 1 the evidence base is by definition incomplete; the reviewer has no principled way to CONCEDE. All three post-PREDICT trials redirected, and the redirects were sensible-looking ("verify pod ownerRef", "check 198.51.100.42 SIEM history") but did not change the actor's tool sequence in a measurable way — the actor was already converging on those checks in turn 2. Net: 100% REDIRECT rate at this checkpoint, 0% disposition change. On a fixture where REDIRECT was actually needed, this would still fire — but on a *true-benign* fixture (untested here) the same pattern would mean a 100% false-REDIRECT rate. Inverse-failure risk is structurally high at post-PREDICT.

### 2. pre-COMMIT and REPORT-time are functionally identical on this fixture

Both checkpoints CONCEDE 3/3 with similar load-bearing classifications. Cost is within $0.005 of each other. Turn counts identical (4.7). The only operational difference: pre-COMMIT can in principle still REDIRECT before the commit lands, but in 3 trials it never did. REPORT-time is structurally simpler (no rollback path, no extra defender turn) and produces the same audit output.

### 3. Tool-coverage is checkpoint-invariant on this fixture

The actor reached `pod_get`, `helm_history`, `k8s_audit`, and `network_egress` in 9/9 trials regardless of checkpoint. The post-PREDICT redirects did not measurably change which tools the actor reached for in turn 2+ — the actor had those checks queued from turn 1. Confirms v8: tool selection is dominated by model + prompt, not by reviewer interjection.

## What this changes for the design doc

- **MVP REPORT-time choice survives.** The data confirms REPORT-time is at least as good as pre-COMMIT on this fixture, with simpler implementation. No reason to add mid-loop machinery for the MVP.
- **post-PREDICT fails the inverse-failure test pre-emptively.** A reviewer that REDIRECTs 100% of the time at the early checkpoint cannot be a gate without high false-positive cost. If we ever want a mid-loop reviewer, it would need a calibration step (or a higher CONCEDE threshold) that this experiment didn't measure.
- **pre-COMMIT remains the best mid-loop candidate** — but on this fixture it produced no measurable lift over REPORT-time, so it's not worth the complexity unless a future fixture shows a redirect that actually flips a disposition.

## What this experiment can't tell us

- N=3, single fixture, all true-malicious. Inverse-failure rate (reviewer flipping a correct benign call) is not measured. Worth a follow-up on a true-benign fixture *with* tool_facts — fixture 11 is the only one with a fact base set up for the multi-turn harness, so this requires fact-base authoring.
- The post-PREDICT redirect was structurally redundant on this fixture because the actor's turn-1 plan already included the right tools. On a fixture where the actor's turn-1 plan misses a must-check tool, post-PREDICT could in principle help. Untested.

## Recommendation

Ship the v4 MVP with REPORT-time reviewer as designed. Defer mid-loop reviewer until either:
- A fixture shows a disposition-flipping redirect that REPORT-time would have missed (would justify pre-COMMIT), or
- A calibration improvement reduces post-PREDICT's REDIRECT rate below 100% on cases where the actor's plan is already adequate (would justify post-PREDICT).

Until then, the cheapest and simplest checkpoint is the right one.
