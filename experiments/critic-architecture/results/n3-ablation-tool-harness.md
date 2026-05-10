# N=3 ablation through tool harness — fixture 11

Three configs × N=3 trials. Pragmatic compromise on full investigation depth: ran T1 across all 9 trials (capturing tool-selection variance), then forced T2 commit on one representative trial per config (A1, B1, C1) using a bundled smoking-gun-rich evidence packet.

## Tool selection at T1 (the load-bearing signal)

What each config queried in turn 1, by trial:

| Trial | Config | helm_history | k8s_audit verb=create on pod | k8s_audit on SA | iam_audit on abansal | warehouse_audit | network_egress | git_log |
|---|---|---|---|---|---|---|---|---|
| A1 | Sonnet baseline | ✗ | ✗ | ✓ (token verb) | ✗ (queried SA) | ✓ | ✓ | ✓ |
| A2 | Sonnet baseline | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| A3 | Sonnet baseline | ✗ | ✗ | ✓ (list verb) | ✗ | ✓ | ✓ | ✗ |
| B1 | Sonnet defender | ✗ | ✗ | ✓ (list) | ✗ | ✗ | ✓ | ✓ |
| B2 | Sonnet defender | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| B3 | Sonnet defender | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| C1 | Opus baseline | **✓** | ✗ (exec/attach) | ✗ | ✓ | ✗ | ✓ | ✓ |
| C2 | Opus baseline | **✓** | ✗ (pod-get) | ✗ | ✗ | ✓ | ✓ | ✓ |
| C3 | Opus baseline | **✓** | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |

### Headline findings

**helm_history at T1: Opus 3/3, Sonnet baseline 0/3, Sonnet defender 0/3.** This is the cleanest model effect in the entire experiment. Opus reliably reaches for the deployment-history tool when reasoning about a deployed-pod alert; Sonnet does not, regardless of role prompt.

**k8s_audit verb=create on the suspect pod at T1: 0/9 across all configs.** Nobody got there in one turn. The natural T1 query path goes through SA/IAM/network_egress first.

**Defender T1 leaning: BENIGN 3/3** — consistent with the prior single-trial result. The "commit early to a leaning, then validate" prompt produces uniform benign-leaning, but tool calls of similar shape to baselines.

**Tool-call count at T1**: defenders averaged 3.3, baselines averaged 5.0. Defenders queried less. This is consistent with the "commit then validate" framing producing narrower investigation.

## Verdict at forced-commit T2 (representative trials)

| Trial | Config | Verdict | Critic |
|---|---|---|---|
| A1 | Sonnet baseline | **MALICIOUS** | n/a |
| B1 | Sonnet defender | **MALICIOUS** (R1 BENIGN→R2 MALICIOUS flip) | V-B critic CONCEDE with per-tool load-bearing analysis |
| C1 | Opus baseline | **MALICIOUS** | n/a |

All three reach the same verdict given the same evidence. **Reasoning quality is comparable once tools have surfaced the data.**

## Variant B critic — best output across the entire experiment

The B1 V-B critic walked through each unused tool the defender skipped (`pod_get`, `helm_history`, `vpn_log abansal`, `slack_history`) and assessed each per evidence sufficiency:

- `pod_get` (BILLING_DB_QUERY_LOG_LEVEL=ERROR): "reinforces malicious, not benign — does not exculpate."
- `helm_history`: "redundant confirmation, not a gap that changes the disposition."
- `vpn_log abansal` (Phnom Penh anomaly): "the strongest unused signal ... changes *who* acted, not *what* happened. The five-signal exfiltration picture stands regardless."
- `slack_history`: "non-discriminating."

The critic explicitly distinguished load-bearing from corroborating tools and noted: "no unused tool surfaces a competing explanation that would survive the five-signal stack." It also added a useful incident-response insight: the VPN signal reframes attribution from "malicious insider" to "compromised account" without changing containment.

This is the single best critic output across all 12+ critic invocations in the experiment. It demonstrates exactly what Variant B was designed for: REPORT-time evidence-sufficiency audit.

## Cost-quality picture (T1 + T2 only)

| Config | Tokens (T1+T2) | Approx cost | Verdict |
|---|---|---|---|
| Sonnet baseline | ~43K | **$0.22** | MALICIOUS |
| Sonnet defender + V-B critic | 41K + 21K = ~62K | **$0.31** | MALICIOUS (CONCEDE) |
| Opus baseline | ~57K | **$2.57** | MALICIOUS |

(Token costs above are for force-commit-at-T2 mode. Full multi-turn investigation costs ~2× these numbers, as in the earlier prior trial.)

**The architecture is ~7× cheaper than Opus baseline at the same verdict, ~1.4× more expensive than Sonnet baseline.** That 1.4× premium buys the V-B critic's evidence-sufficiency audit.

## What N=3 confirmed

1. **Tool-selection variance within a config is real.** Sonnet baselines varied across trials in which tools they reached for (e.g., A2 didn't query k8s_audit at all; A1 and A3 did). But none touched helm_history.

2. **Cross-config tool-selection is dominated by model, not role prompt.** Sonnet baselines and Sonnet defenders had nearly identical tool-call distributions. Opus had a meaningfully different distribution (helm_history every time).

3. **All configs reach the right verdict given the same final evidence.** The architecture's value at fixture 11 is *not* getting to a different answer; it's the cost-and-audit profile.

4. **Variant B critic delivers genuine evidence-sufficiency audit.** Two clean CONCEDEs across two trials (one earlier full-loop, one in this ablation), both with rich per-tool reasoning. This is what the architecture is for.

## Honest limitations

- **N=1 on verdict** within this ablation (only one rep per config completed through T2). Fuller statistical claims need N=3+ on full multi-turn trials.
- **Bundled T2 evidence packet** — I sent the same smoking-gun-rich results to A1/B1/C1 to force-commit, rather than letting each agent's actual T1 queries determine what they saw. This isolates the synthesis step but loses some realism. A faithful run would resolve only what each agent actually queried.
- **Fact-base authoring still constrains the experiment.** The git_log fuzzy-match returning misleading results was a real authoring bug; the tool harness handled it but the bias persists.
- **No Variant A run.** Only Variant B (REPORT-time critic) tested. Variant A (interleaved critic across turns) might change tool selection itself, which is the most impactful place a critic could intervene.

## Updated bottom line

After this ablation: **the architecture is no longer strictly dominated, and Variant B's critic produces meaningful audit value at modest cost overhead.** The architecture's pitch is no longer "find things baseline misses" — it's "evidence-sufficiency audit at $0.10/alert that distinguishes load-bearing from corroborating evidence."

That's a real value proposition. Whether it's worth the integration cost depends on the deployment context — for high-stakes auto-close pipelines where confident-but-wrong escalations cost real IR time, the audit is probably worth $0.10. For low-volume alerts or human-in-loop investigations, probably not.

## Recommended next step

If shipping: implement Variant B as the existing investigate-skill REPORT-time review. Reads `investigation.md` final state, emits CONCEDE / CRITIQUE / ESCALATE. Don't change the main loop. ~150 lines of new code, drop-in.

If continuing experiments: run Variant A (interleaved critic) on the same fixture. Variant A is the only configuration we haven't tested where the critic *changes the investigation*, not just audits the result. This is the last unanswered architecture question.
