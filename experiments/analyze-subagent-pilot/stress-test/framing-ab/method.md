# A/B framing experiment — adversarial vs. peer-audit debias probe

## Question

Does framing a Haiku debias probe as a curious/peer audit ("new analyst
auditing on behalf of the on-call") produce better outputs than framing it
as an adversarial critic ("this grade doesn't hold because…")?

"Better" here has two dimensions:
1. **Probe coverage** — does the probe target the actual load-bearing
   evidence, or a straw?
2. **Defender response shape** — does Sonnet engage substantively with the
   probe or flip defensively / cave reflexively?

## Design

- **Source ANALYZE output:** `source-analyze.md` — one past-runs trial
  output from `case-ssh-brute-loop3/trials/trial-2.out`, which produced
  `?opportunistic-scanner: ++` with two named failed refutations. A
  contestable-but-defensible grade.
- **Both arms**:
  - Haiku receives the source ANALYZE + an instruction to pick the
    highest-grade hypothesis and emit one counterfactual probe question of
    the form *"if observation X had come back different value Y, would the
    grade hold?"*. Probe must be one sentence.
  - Sonnet then receives the source ANALYZE + the probe + instruction to
    either defend or revise the grade, emitting a terminal YAML
    `verdict: defend|revise` + `rationale` + `probe_substantive: yes|no`.
- **What differs between arms:** only the tone instruction given to Haiku.
  Arm A = adversarial. Arm B = peer-audit.
- **N**: 3 Haiku samples per arm, 3 Sonnet defenses per arm (one per probe).
  6 probes + 6 defenses = 12 LLM calls total.

## Scoring dimensions

| Dimension | What to measure |
|---|---|
| Probe targeting | Does the probe name a load-bearing observation (wordlist generic-ness, forward-window absence) or a straw (e.g. IP geolocation)? |
| Probe specificity | Does the probe name a concrete counterfactual value, or hand-wave ("what if the evidence were different")? |
| Sonnet verdict | defend / revise — compare distribution across arms |
| Sonnet substance | Does the defense/revise engage with the specific counterfactual, or deflect? |
| Tone contamination | Does Sonnet's response mirror the probe's tone (defensive under adversarial, explanatory under peer)? |

## Hypothesis going in

My prior: framing mostly affects defender response shape, not probe
coverage. Expect adversarial Haiku to write sharper probes but Sonnet to
double down more; expect peer-audit Haiku to write softer but still
targeted probes with Sonnet engaging more substantively. Net benefit of
peer framing depends on whether Sonnet's substantive engagement outweighs
any loss in probe sharpness.

If the experiment shows no meaningful difference between arms, the
framing choice is cosmetic and we should make it on maintainability /
prompt-readability grounds.
