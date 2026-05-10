# Trial 10-01 — bait-mirror-postinst (model comparison)

Fixture: `10-bait-mirror-postinst` (label: bait-true-malicious — designed to lure baseline into resolving benign).

## Bait design

Surface mirrors fixture 02 (signed apt upgrade, fleet 11/12 match Ubuntu published SHA, debsums clean, no human activity). Kill signal in *post-upgrade behavioral* context: nginx makes outbound TLS to a 23-day-old domain, 0/11 peers replicate. Intent: trick baseline into pattern-matching "strong supply-chain corroboration → benign" and missing the behavioral divergence.

**Bait failed.** All four configurations caught it without difficulty.

## Configurations run

| Config | Model | Tokens | Duration | Verdict |
|---|---|---|---|---|
| Single-agent baseline | Sonnet | 20.9K | 19.4s | escalate (likely supply-chain compromise) |
| Single-agent baseline | Opus | 29.3K | 20.7s | escalate (malicious-leaning, 6 hypotheses) |
| Defender → Critic | Sonnet → Sonnet | 41.1K (20.6+20.5) | 21.6s (12.3+9.3) | malicious + benign-direction nginx-config-diff CRITIQUE |
| Defender → Critic | Opus → Opus | 57.7K (28.9+28.8) | 24.6s (13.4+11.2) | suspicious + benign-direction CMDB-pilot CRITIQUE |

## Quality comparison

All four configurations identified the post-upgrade outbound connection as the load-bearing signal and proposed checks consistent with the truth. Differences:

- **Sonnet baseline** included both adversarial-direction (`?adversary-controlled-host-pre-compromise` with LD_PRELOAD/kernel-module check) and benign-direction (`?beacon-via-new-nginx-feature` with nginx source-diff review) hypotheses — covers what both critics later produced.
- **Opus baseline** committed harder ("malicious — escalate") with a 6-hypothesis lead set including `?fleet-config-drift-benign` (CMDB lookup) and `?compromised-loader-or-ld-preload` (proc/maps inspection). Most thorough.
- **Sonnet defender + critic** — defender committed the strongest call ("malicious"); critic produced a sharp benign hypothesis (nginx 1.27 reporting stub backport, lead = `nginx -T` config diff against a peer).
- **Opus defender + critic** — defender went "suspicious" (more conservative); critic produced canary/pilot CMDB check.

## Cost-per-quality

Approximate API pricing (input+output mixed): Sonnet ~$0.005/K tokens, Opus ~$0.045/K tokens (5x higher).

| Config | Tokens | Approx cost |
|---|---|---|
| Sonnet baseline | 20.9K | $0.10 |
| Sonnet+critic | 41.1K | $0.21 |
| Opus baseline | 29.3K | $1.32 |
| Opus+critic | 57.7K | $2.60 |

**Sonnet baseline is the Pareto winner on this fixture.** Sonnet+critic is 2x cost for marginal sharpening. Opus baseline is 13x cost for similar quality. Opus+critic is 25x cost.

## Interpretation

The bait was too obvious — the 11/12 peer asymmetry plus 23-day-old domain is a strong-enough signal that any reasonable lead-set generator catches it. To genuinely bait the baseline, the kill signal would need to be subtler: a single context detail among many, or a benign-framed signal whose meaning depends on cross-source reasoning.

What this trial *does* tell us: on a fixture where the baseline catches the threat, the architecture provides marginal sharpening at substantial cost overhead. The architecture's value (if any) needs to come from cases where the baseline misses — and we don't yet have a fixture that demonstrates this.
