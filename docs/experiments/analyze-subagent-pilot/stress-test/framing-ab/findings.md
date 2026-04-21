# A/B framing experiment — findings

**N = 3 per arm, one fixture.** Single data point per decision axis. Directional,
not conclusive.

## Results table

| Arm | Trial | Verdict | Engaged substantively? | Revised grade |
|---|---|---|---|---|
| adversarial | 1 | defend | yes | — |
| adversarial | 2 | defend | yes | — |
| adversarial | 3 | **revise** | yes | ++ → + |
| peer-audit  | 1 | defend | yes | — |
| peer-audit  | 2 | defend | yes | — |
| peer-audit  | 3 | defend | yes | — |

## Headline

**Tone framing is not the main lever; probe shape is.** Both arms produced
substantive defender engagement in 6/6 trials. The only revision came from an
adversarial probe that did something the other probes didn't — it **asserted
contradicting facts** ("postgres, tomcat, jenkins, nagios are active service
accounts on prod-webserver-01") rather than asking a counterfactual.

That revision is a **false positive risk**: the probe's assertion was never
verified. Haiku may have fabricated the service-account list to strengthen its
challenge under the adversarial framing. Sonnet dutifully engaged and revised
— but the revision rests on an unverifiable claim injected by the probe.

## What each arm actually produced

**Adversarial probes (3/3):** sharp, converged on the env-specific-names angle
(the actually load-bearing observation), tonally accusatory ("why do you claim
otherwise?"). One probe escalated from counterfactual to fact-assertion and
triggered the false-positive revision.

**Peer-audit probes (3/3):** softer phrasing, targeted load-bearing observations
in 2/3 trials, targeted a non-load-bearing observation (rate) in 1/3. Stayed
genuinely counterfactual ("if X had been Y") — no fact-assertion.

**Sonnet defenses (6/6 substantive):**
- Adversarial arm rationales are tonally argumentative ("misidentifies what
  the `++` rests on", "is not an alternative explanation; it is the
  hypothesis"). Sonnet pushes back rather than over-accommodating.
- Peer-audit arm rationales are tonally explanatory ("the load-bearing
  element", "what justifies ++ is…"). Sonnet explains rather than defends.
- Neither arm showed deflection or reflexive capitulation on counterfactual
  probes.

## What this suggests for the sensitivity-probe design

1. **Force counterfactual shape.** Probe template must require `"if
   observation X had come back as Y"` — not `"because X is Y"`. The latter
   invites fact-assertion and false revisions.
2. **Tone matters less than shape.** Adversarial vs. peer framing barely
   changed Sonnet's verdict distribution. Pick on readability/maintenance
   grounds, not effectiveness.
3. **Peer-audit edges ahead on one axis** — it kept Haiku in counterfactual
   mode. Under adversarial pressure Haiku drifted into fact-assertion once out
   of three trials, which introduced a real false-revision risk.
4. **Probe-targeting variance is real.** Peer-audit probe 3 hit a
   non-load-bearing observation (rate instead of env-specific names). Probe
   quality is not 100% even with targeted prompts. If we ship a
   sensitivity probe, running ≥2 probes in parallel and requiring convergence
   on the same load-bearing observation before taking action would catch this.

## Recommendation

If the sensitivity probe ships: **peer-audit framing + explicit counterfactual
shape requirement**. Cost is identical to adversarial (one Haiku + one Sonnet
call per ANALYZE output); the peer framing reduces the observed fact-assertion
risk at no measurable cost to substantive engagement.

But — and this is the bigger read — the probe barely changed anything in this
experiment. Of 6 probes, 5 defends + 1 false-positive revise. The ANALYZE
subagent held its ground on legitimate counterfactuals in all 5. That's good
for ANALYZE robustness, questionable for probe value-add. A broader test on
fixtures where the grade IS stacked-circumstantial (Example 2 trap) would be
needed before committing to this as a runtime feature.

## Caveats

- **N = 3 per arm, one fixture, one hypothesis probed.** Tiny sample.
- **Fixture chosen is a clean-archetype CONCLUDE with ++ backed by authority**
  — not the stacked-circumstantial trap the probe is actually meant to catch.
  A fixture where ++ IS stacked would test whether the probe catches the
  failure we care about.
- **Probe prompts were short.** Longer probes with more explicit "don't assert
  facts, only ask counterfactuals" language might close the one fact-assertion
  failure observed.
