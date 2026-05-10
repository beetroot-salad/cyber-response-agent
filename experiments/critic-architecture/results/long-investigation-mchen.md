# Long-investigation trajectory — mchen cross-system-access (2 rounds, 3 configs)

Goal: assess how the three configs (Sonnet baseline, Opus baseline, Sonnet defender + AGGRESSIVE critic) handle a multi-round investigation on a behavioral, ambiguous alert. Hidden tells designed to require integration across rounds.

## Fixture summary

Alert: mchen (data engineer) accessed 14 systems on Saturday afternoon, 5 never previously accessed. Valid SSO, no MFA failures.

Hidden tells in R1 evidence packet (returned to all configs identically):
- User-agent flip: Linux/Firefox in alert window vs 90d baseline macOS/Chrome
- VPN underlying client IP: 198.51.100.77 (first seen 4 days ago) vs baseline residential 192.0.2.x
- 2 of 5 new systems have audit tickets; 3 do not

Ground truth: malicious / escalate (SSO token theft, attacker pivoting).

## Trajectory by config

### Config A — Sonnet baseline (2 rounds)

**R1 leaning:** "likely authorized but anomalous." 6 hypotheses including H2 credential-compromise (lead: correlate source IPs and UA across all 14 events).

**R2 outcome:** **ESCALATE — HIGH CONFIDENCE CREDENTIAL COMPROMISE.** Recommended immediate token revocation, P1 incident. Caught all three tells (UA, IP, 3 unticketed systems).

Tokens: 41.2K total. Wall-clock: 30.0s. Approx cost: **$0.21**.

### Config B — Opus baseline (2 rounds)

**R1 leaning:** "suspicious, not yet likely malicious." 6 hypotheses with structured `?prefix` notation. H2 credential-theft lead explicit about device+IP+UA fingerprint comparison.

**R2 outcome:** **escalate (suspicious leaning credential compromise).** Used invlang-style `++/--` weighting on hypotheses. Detailed containment plan: out-of-band contact mchen, hunt for lateral movement from VPN client IP. Most thorough write-up.

Tokens: 57.9K total. Wall-clock: 41.9s. Approx cost: **$2.61**.

### Config C — Sonnet defender + AGGRESSIVE critic (2 rounds)

**R1 defender:** "suspicious-leaning (not malicious)." Argued 9/14 familiar systems "anchor as mchen's working context"; load-bearing assumption "the 5 novel systems are within mchen's legitimate authorization scope." This is the most benign-leaning R1 of the three configs.

**R1 aggressive critic:** sharp attack — quoted "9/14 familiar systems anchor" and called it rationalizing because "a credential thief with mchen's token would *start* on familiar systems to avoid tripping behavioral detectors — the familiar-first pattern is exactly what a prepared adversary looks like, not exculpatory evidence." Demanded fingerprint check across familiar-9 vs novel-5. Set the round-2 must-check.

**R2 defender:** "ESCALATE (malicious-leaning). My round-1 load-bearing assumption is falsified." Cleanly flipped on the evidence. Recognized the critic's hypothesis as the surviving one.

**R2 aggressive critic:** **CONCEDE** — "the defender escalated on strong structural evidence ... no falsifiable critique remains." First clean stop verdict of the entire experiment.

Tokens: 81.6K total. Wall-clock: 38.3s. Approx cost: **$0.41**.

## Comparative summary

| Config | Tokens | Wall-clock | Cost | R1 leaning | R2 verdict | Notes |
|---|---|---|---|---|---|---|
| Sonnet baseline | 41.2K | 30.0s | $0.21 | "authorized but anomalous" | ESCALATE | broad enumeration, caught tells cleanly |
| Opus baseline | 57.9K | 41.9s | $2.61 | "suspicious" | escalate | structured weighting, most thorough writeup |
| Sonnet d+aggr-critic | 81.6K | 38.3s | $0.41 | defender most benign-leaning of all 3 | escalate | critic forced course-correction; CONCEDE in R2 |

All three reached the correct disposition. No false-benign closures.

## What we learned

### 1. The architecture's value mechanism is course-correction, not novelty

The Sonnet defender's R1 was the most benign-leaning of the three configs. Without the aggressive critic, the defender would have entered R2 with a softer mental model — possibly rationalizing the evidence rather than committing cleanly. The critic's R1 attack reframed the must-check as "fingerprint divergence between familiar-9 and novel-5," and when evidence returned, defender flipped cleanly to escalate.

So the architecture *did* alter trajectory — but the trajectory it produced ended at the same place all three configs ended. **Course-correction without outcome change.**

### 2. Aggressive framing did not produce paranoia when paired with the falsifiability gate

The R1 critic was maximally sharp ("the defender is rationalizing, here's why"). The R2 critic correctly CONCEDED rather than manufacturing a benign holdout. This is the first clean CONCEDE in the experiment, and it appeared specifically when:
- The defender had strong evidence aligned with the disposition
- The benign-direction holdouts had no observable consequence to test
- The gate refused hand-waving

This is a generalizable finding: **aggressive critic + falsifiability gate = self-stopping under symmetric application**. Aggressive critic without the gate would have produced "but what if the audit ticket itself is forged" hand-waving — the gate prevented it.

### 3. Aggressive framing did NOT compound across rounds

Running 2 rounds of aggressive critic produced one sharp critique then one CONCEDE, not two compounding pressures. The architecture has a working halt condition under multi-round operation.

### 4. Multi-round didn't change the cost-quality picture meaningfully

| Comparison | Verdict |
|---|---|
| Sonnet baseline vs Opus baseline | Both escalate; Opus 12× more expensive for slightly more thorough writeup |
| Sonnet baseline vs Sonnet d+critic | Both escalate; architecture 2× more expensive for trajectory course-correction |
| Sonnet d+critic vs Opus baseline | Both escalate; architecture 6× cheaper than Opus baseline |

**Sonnet baseline at $0.21 is still the Pareto winner on this fixture.** The architecture closed the gap to baseline (no longer strictly dominated like fixture 01) but didn't beat it.

### 5. The fixture wasn't hard enough to differentiate

All three configs caught the tells. A genuinely discriminating fixture would need:
- Tells subtle enough that one config misses them at the R1-leads stage
- A defender drift severe enough to *not* recover with R2 evidence

Building such a fixture is hard, especially with the experimenter (me) writing the evidence packet — I'm biased toward making the tells legible.

## Honest read on aggressive 2-round architecture

The architecture works. The aggressive critic + falsifiability gate produces sharp R1 critiques and clean R2 CONCEDE. Multi-round operation didn't break it.

But on this fixture, the architecture's value was *trajectory shape* (defender drift correction), not *outcome* (all configs reached escalate). The defender drift it corrected was within the variance window — Opus and Sonnet baselines didn't drift, so drift correction had no effect on them.

The architecture would matter most on a fixture where:
- Single-agent baselines drift toward false-benign at R1
- And R2 evidence isn't sharp enough on its own to flip them
- And the critic's R1 attack provides the missing pressure

I haven't built that fixture yet. The mchen alert was hard enough to test the trajectory but not hard enough to *separate* the configs.

## Recommended next move

Either:

**(a) Build a harder long-investigation fixture** — one where R2 evidence is genuinely ambiguous and defender drift has no recovery path. Real test of the architecture's drift-correction mechanism.

**(b) Test on the inverse failure mode** — a fixture where defender correctly leans benign but evidence eventually proves benign, and aggressive critic might wrongly push to escalate. Tests whether the gate holds under "wrong-direction pressure."

**(c) Retire** — the data continues to favor Sonnet-baseline-with-good-prompting as the cost-quality winner. The architecture isn't broken, but it isn't earning its slot either.

I'd lean (a) before retiring — the trajectory finding is genuinely interesting and the multi-round case is the only one where the architecture *should* win. If it can't win there, retire.
